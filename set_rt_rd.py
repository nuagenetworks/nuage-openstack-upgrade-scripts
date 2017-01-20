# Copyright 2014 Alcatel-Lucent USA Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import argparse
import json
import logging
import logging.handlers
import os
try:
    from oslo.config import cfg
except ImportError:
    from oslo_config import cfg
import sys


from neutron.common import config
from neutron import context as ncontext
from neutron.db import db_base_plugin_v2
from neutron.db import extraroute_db
from neutron.db import securitygroups_db

try:
    from neutron.openstack.common import importutils
except ImportError:
    from oslo_utils import importutils

try:
    from neutron.plugins.nuage.common import config as nuage_config
except ImportError:
    from nuage_neutron.plugins.common import config as nuage_config

try:
    from neutron.plugins.nuage import nuage_models
except ImportError:
    from nuage_neutron.plugins.common import nuage_models

try:
    from neutron.plugins.nuage import nuagedb
except ImportError:
    from nuage_neutron.plugins.common import nuagedb

LOG = logging.getLogger('Upgrade_Logger')
REST_SUCCESS_CODES = range(200, 207)


class PopulateIDs(db_base_plugin_v2.NeutronDbPluginV2,
                  extraroute_db.ExtraRoute_db_mixin,
                  securitygroups_db.SecurityGroupDbMixin):

    def __init__(self, nuageclient):
        self.context = ncontext.get_admin_context()
        try:
            self.rest_call = nuageclient.rest_call
        except AttributeError:
            self.rest_call = nuageclient.restproxy.rest_call

    def get_error_msg(self, responsedata):
        errors = json.loads(responsedata)
        return str(errors['errors'][0]['descriptions'][0]['description'])

    def populate_rt_rd(self):
        query = self.context.session.query(nuage_models.NetPartitionRouter)
        routers = query.all()
        for router in routers:
            try:
                response = self.rest_call(
                    'GET',
                    "/domains/" + router['nuage_router_id'], '')
                if response[0] not in REST_SUCCESS_CODES:
                    LOG.error("Error: %s" % self.get_error_msg(response[3]))
                else:
                    resp_obj = response[3][0]
                    rd = resp_obj['routeDistinguisher']
                    rt = resp_obj['routeTarget']
                    ent_rtr_mapping = nuagedb.get_ent_rtr_mapping_by_rtrid(
                        self.context.session, router['router_id'])
                    with self.context.session.begin(subtransactions=True):
                        ns_dict = {}
                        ns_dict['nuage_rtr_rt'] = rt
                        ns_dict['nuage_rtr_rd'] = rd
                        nuagedb.update_entrouter_mapping(ent_rtr_mapping,
                                                         ns_dict)
                        LOG.debug("RT/RD set successfully in neutron for router"
                                  " %s" % router['router_id'])
            except Exception:
                LOG.error("Error in setting RT/RD for router %s" % router[
                    'router_id'])

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config-file", nargs='+',
                        help='List of config files separated by space')
    args = parser.parse_args()

    conffiles = args.config_file
    if conffiles is None:
        parser.print_help()
        return

    # Create a logfile
    log_dir = os.path.expanduser('~') + '/nuageupgrade'
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    hdlr = logging.FileHandler(log_dir + '/upgrade.log')
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    LOG.addHandler(hdlr)
    logging.basicConfig(level=logging.DEBUG)

    conf_list = []
    for conffile in conffiles:
        if not os.path.isfile(conffile):
            LOG.error('File "%s" cannot be found.' % conffile)
            return
        conf_list.append('--config-file')
        conf_list.append(conffile)

    config.init(conf_list)
    nuage_config.nuage_register_cfg_opts()

    server = cfg.CONF.RESTPROXY.server
    serverauth = cfg.CONF.RESTPROXY.serverauth
    serverssl = cfg.CONF.RESTPROXY.serverssl
    base_uri = cfg.CONF.RESTPROXY.base_uri
    auth_resource = cfg.CONF.RESTPROXY.auth_resource
    organization = cfg.CONF.RESTPROXY.organization

    nuageclientinst = importutils.import_module('nuagenetlib.nuageclient')
    try:
        nuageclient = nuageclientinst.NuageClient(server=server,
                                                  base_uri=base_uri,
                                                  serverssl=serverssl,
                                                  serverauth=serverauth,
                                                  auth_resource=auth_resource,
                                                  organization=organization)
    except Exception as e:
        LOG.error("Error in connecting to VSD:%s", str(e))
        return

    try:
        PopulateIDs(nuageclient).populate_rt_rd()
        LOG.debug("Setting rt/rd is now complete")
    except Exception as e:
        LOG.error("Error in setting rt/rd:%s", str(e))
        return

if __name__ == '__main__':
    main()
