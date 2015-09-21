# Copyright 2015 Alcatel-Lucent USA Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
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
import logging
import logging.handlers
import os
import sys

from oslo.config import cfg

from neutron.common import config
from neutron import context as ncontext
from neutron.db import db_base_plugin_v2
from neutron.plugins.nuage import nuage_models
from nuage_neutron.plugins.nuage.common import config as nuage_config
from oslo_utils import importutils

LOG = logging.getLogger('Setting external ID for Vports')
REST_SUCCESS_CODES = range(200, 207)


class VportSync(db_base_plugin_v2.NeutronDbPluginV2):

    def __init__(self, nuageclient):
        super(VportSync, self).__init__()
        self.context = ncontext.get_admin_context()
        self.nuageclient = nuageclient

    def _check_response(self, response, url):
        if response[0] not in REST_SUCCESS_CODES:
            LOG.warn("%s returned code %s" % (url, response[0]))
            return False
        return True

    def get(self, url, data, extra_headers=None):
        return self.nuageclient.restproxy.rest_call(
            'GET', url, data, extra_headers=extra_headers)

    def validate(self, response, resource, id):
        if response[0] not in REST_SUCCESS_CODES:
            err_msg = self.get_error_msg(response[3])
            LOG.error("Setting externalID for resource %(res)s "
                      "id %(id)s failed with error: %(err)s"
                      % {'res': resource, 'id': id, 'err': err_msg})
        else:
            LOG.debug("Setting externalID for resource %(res)s"
                      "id %(id)s is successful" % {'res': resource, 'id': id})

    def set_external_id_for_vports(self):
        subnets_with_port = {}
        query = self.context.session.query(nuage_models.SubnetL2Domain)
        subnets = query.all()
        id_subnet_map = dict([(subnet['subnet_id'], subnet)
                              for subnet in subnets])
        ports = self.get_ports(self.context)

        for port in ports:
            for fixed_ip in port.get('fixed_ips'):
                subnet = id_subnet_map.get(fixed_ip['subnet_id'])
                if subnet:
                    subnets_with_port[subnet['subnet_id']] = subnet

        for idx, subnet_with_port in enumerate(subnets_with_port.values()):
            if (1 + idx) % 100 == 0:
                percent = (100 * (idx + 1) / len(subnets_with_port))
                LOG.info("Processing vports in Subnet... (%s%%)." % percent)
            url_args = subnet_with_port['nuage_subnet_id']
            if subnet_with_port['nuage_managed_subnet']:
                url = '/l2domains/%s/vports' % url_args
                response = self.get(url, '')
                if response[0] not in REST_SUCCESS_CODES:
                    url = '/subnets/%s/vports' % url_args
                    response = self.get(url, '')
            elif subnet_with_port['nuage_l2dom_tmplt_id']:
                url = '/l2domains/%s/vports' % url_args
                response = self.get(url, '')
            else:
                url = '/subnets/%s/vports' % url_args
                response = self.get(url, '')
            if not self._check_response(response, url):
                vports = []
            else:
                vports = response[3]
            for vport in vports:
                if vport['externalID'] or not vport['hasAttachedInterfaces']:
                    continue
                url = '/vports/%s/vminterfaces' % vport['ID']
                response = self.get(url, '')
                vm_interfaces = response[3]
                for vm_interface in vm_interfaces:
                    if not vm_interface['externalID']:
                        continue
                    try:
                        data = ({'externalID': vm_interface['externalID']})
                        response = self.nuageclient.restproxy.rest_call(
                            'PUT',
                            "/vports/" + vport['ID'] + "?responseChoice=1",
                            data
                        )
                        self.validate(response, 'VPort', vport['ID'])
                        break
                    except Exception as e:
                        LOG.error("Error %(err)s while setting "
                                  "externalID for vport %(vm)s"
                                  % {'err': str(e), 'vm': vport['ID']})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config-file", nargs='+', required=True,
                        help='List of config files (nuage_plugin.ini + '
                             'neutron.conf) separated by space')
    args = parser.parse_args()

    cfg_files = args.config_file
    if cfg_files is None:
        parser.print_help()
        return

    # Create a logfile
    log_dir = os.path.expanduser('~') + '/nuageupgrade'
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    hdlr = logging.FileHandler(log_dir + '/setvportexternalid.log')
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    LOG.addHandler(hdlr)
    logging.basicConfig(level=logging.INFO)

    conf_list = []
    for conffile in cfg_files:
        conf_list.append('--config-file')
        if not os.path.isfile(conffile):
            LOG.error('File "%s" cannot be found.' % conffile)
            sys.exit(1)
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
    LOG.info("Going to Start setting of external ID to Vports.")
    VportSync(nuageclient).set_external_id_for_vports()
    LOG.info("Setting ExternalID for Vports on VSD is complete now")

if __name__ == '__main__':
    main()
