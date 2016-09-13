# Copyright 2015 Alcatel-Lucent USA Inc.
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
import os

try:
    from oslo.config import cfg
except ImportError:
    from oslo_config import cfg

try:
    from neutron.openstack.common import importutils
except ImportError:
    from oslo_utils import importutils

from neutron.common import config
from neutron import context as ncontext
try:
    from neutron.plugins.nuage.common import config as nuage_config
except ImportError:
    from nuage_neutron.plugins.common import config as nuage_config

try:
    from neutron.plugins.nuage import nuage_models
except ImportError:
    from nuage_neutron.plugins.common import nuage_models

LOG = logging.getLogger('usergroup_mgmtmode')
REST_SUCCESS_CODES = range(200, 207)
VSD_NO_ATTR_CHANGES_TO_MODIFY_ERR_CODE = '2039'


def set_usergroup_mgmtmode_to_cms(nuageclient):
    context = ncontext.get_admin_context()
    data = {'managementMode': 'CMS'}
    query = context.session.query(nuage_models.SubnetL2Domain)
    # Get all the VSD managed subnet
    subnets = query.all()
    for subnet in subnets:
        # Get the corresponding neutron subnet object for tenant info
        result = nuageclient.restproxy.rest_call(
            'PUT',
            '/users/' + subnet['nuage_user_id'],
            data)
        if result[0] in REST_SUCCESS_CODES:
            LOG.debug('ManagementMode attribute successfully '
                      'updated to CMS for user %s', subnet['nuage_user_id'])
        else:
            if result[0] == 409:
                errors = json.loads(result[3])
                error_code = str(errors.get('internalErrorCode', None))
                if error_code == VSD_NO_ATTR_CHANGES_TO_MODIFY_ERR_CODE:
                    LOG.debug('No change were required for user %s',
                              subnet['nuage_user_id'])
            else:
                LOG.debug('Got %s response (ERROR) for user %s',
                          result[0], subnet['nuage_user_id'])

        result = nuageclient.restproxy.rest_call(
            'PUT',
            '/groups/' + subnet['nuage_group_id'] + '?responseChoice=1',
            data)
        if result[0] in REST_SUCCESS_CODES:
            LOG.debug('ManagementMode attribute successfully '
                      'updated to CMS for group %s', subnet['nuage_group_id'])
        else:
            if result[0] == 409:
                errors = json.loads(result[3])
                error_code = str(errors.get('internalErrorCode', None))
                if error_code == VSD_NO_ATTR_CHANGES_TO_MODIFY_ERR_CODE:
                    LOG.debug('No change were required for group %s',
                              subnet['nuage_group_id'])
            else:
                LOG.debug('Got %s response (ERROR) for group %s',
                          result[0], subnet['nuage_group_id'])


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

    hdlr = logging.FileHandler(log_dir + '/usergroup_mgmtmode.log')
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

    try:
        config.init(conf_list)
    except AttributeError:
        # for stable/icehouse
        config.parse(conf_list)
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
                                                  organization=organization,
                                                  servertimeout=20)
    except Exception as e:
        LOG.error("Error in connecting to VSD:%s", str(e))
        return

    set_usergroup_mgmtmode_to_cms(nuageclient)
    LOG.debug("Script to set User and Group's mgmtmode to CMS completed")

if __name__ == '__main__':
    main()
