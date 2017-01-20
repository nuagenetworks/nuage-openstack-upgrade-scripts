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
import json
import logging
import logging.handlers
import nuage_logging
import os

import sys
import vsdclient_config

from neutron.common import config
from neutron.common import constants
from neutron import context as ncontext
from neutron.db import db_base_plugin_v2
from neutron.db import external_net_db
try:
    from neutron.plugins.nuage import nuage_models
except ImportError:
    from nuage_neutron.plugins.common import nuage_models
from oslo_config import cfg
from restproxy import RESTProxyServer

if not nuage_logging.log_file:
    nuage_logging.init_logging('vport_sync')
LOG = logging.getLogger('VPort_Sync')
REST_SUCCESS_CODES = range(200, 207)
REST_SERV_UNAVAILABLE_CODE = 503

APPD_PORT = 'appd'
DEVICE_OWNER_VIP_NUAGE = 'nuage:vip'
DEVICE_OWNER_IRONIC = 'compute:ironic'
DEVICE_OWNER_NUAGE = 'network:dhcp:nuage'
INHERITED = 'INHERITED'

AUTO_CREATE_PORT_OWNERS = [
    constants.DEVICE_OWNER_DHCP,
    constants.DEVICE_OWNER_ROUTER_INTF,
    constants.DEVICE_OWNER_ROUTER_GW,
    constants.DEVICE_OWNER_FLOATINGIP,
    DEVICE_OWNER_VIP_NUAGE,
    DEVICE_OWNER_IRONIC,
    DEVICE_OWNER_NUAGE
]


class VportSync(db_base_plugin_v2.NeutronDbPluginV2,
                external_net_db.External_net_db_mixin):

    def __init__(self, restproxy):
        super(VportSync, self).__init__()
        self.context = ncontext.get_admin_context()
        self.restproxy = restproxy

    def _check_response(self, response, url):
        if response[0] not in REST_SUCCESS_CODES:
            LOG.user("%s returned code %s" % (url, response[0]))
            return False
        return True

    def get(self, url, data, extra_headers=None):
        return self.restproxy.rest_call(
            'GET', url, data, extra_headers=extra_headers)

    def post_create_vport(self, url, params):
        return self.restproxy.rest_call('POST', url, params)

    def validate(self, response):
        if response[0] == 0:
            return False
        if response[0] not in REST_SUCCESS_CODES:
            if response[0] == REST_SERV_UNAVAILABLE_CODE:
                errors = json.loads(response[3])
                LOG.user('VSD temporarily unavailable, ' +
                         str(errors['errors']))
            return False
        return True

    def get_vm_interface(self, externalID):
        headers = {}
        headers['X-NUAGE-FilterType'] = "predicate"
        headers['X-Nuage-Filter'] = "externalID IS '%s'" % (externalID)
        url = '/vminterfaces/'
        response = self.restproxy.rest_call(
            'GET', url, '', extra_headers=headers)
        if self._check_response(response, url):
            vm_interfaces = response[3]
            if vm_interfaces:
                return vm_interfaces[0]
        else:
            LOG.user("Error in retrieving associated VMInterface from VSD "
                     "so, cannot set ExternalID for portID:" + externalID)
            return None

    def is_vport_externalID_set(self, vportid):
        url = '/vports/' + vportid
        response = self.get(url, '')
        if self._check_response(response, url):
            vport_list = response[3]
            if vport_list:
                if vport_list[0]['externalID']:
                    return True
                else:
                    return False
        else:
            LOG.user("Error in retrieving Vport from VSD of VportID: "
                     + vportid + " so, skipping this Vport")
        return None

    def create_port_on_nuage(self, port, subnet_mapping, description=None):
        vport_data = {
            'description': description,
            'type': 'VM',
            'name': port['id'],
            'externalID': port['id'],
            'addressSpoofing': INHERITED
        }
        if port['device_owner'] == APPD_PORT:
            vport_data['name'] = port['name']
        url_args = subnet_mapping['nuage_subnet_id']
        if subnet_mapping['nuage_managed_subnet']:
            url = '/l2domains/%s/vports' % url_args
            response = self.get(url, '')
            if self._check_response(response, url):
                vport_response = self.post_create_vport(url, vport_data)
            else:
                url = '/subnets/%s/vports' % url_args
                vport_response = self.post_create_vport(url, vport_data)

        elif subnet_mapping['nuage_l2dom_tmplt_id']:
            url = '/l2domains/%s/vports' % url_args
            vport_response = self.post_create_vport(url, vport_data)
        else:
            url = '/subnets/%s/vports' % url_args
            vport_response = self.post_create_vport(url, vport_data)
        if not self.validate(vport_response):
            errors = json.loads(vport_response[3])
            error_code = str(errors.get('internalErrorCode', None))
            if error_code == '7014':
                LOG.debug("Vport for portID:" + port['id'] + " already "
                          "exists, so skipping Vport creation for this port.")
            else:
                msg = errors['errors'][0]['descriptions'][0]['description']
                LOG.user("Error in creating Vport for the portID: "
                         + port['id'] +
                         " and the error message is: " + str(msg))

    def sync_vports(self):
        query = self.context.session.query(nuage_models.SubnetL2Domain)
        ports = self.get_ports(self.context)

        for idx, port in enumerate(ports):
            if (1 + idx) % 100 == 0:
                percent = (100 * (idx + 1) / len(ports))
                LOG.user("Processing vports in Subnet... (%s%%)." % percent)
            vm_interface = self.get_vm_interface(port['id'])
            network = self.get_network(self.context, port['network_id'])
            if vm_interface:
                if self.is_vport_externalID_set(
                        vm_interface['VPortID']) is False:
                    data = {
                        'externalID': vm_interface['externalID']
                    }
                    response = self.restproxy.rest_call(
                        'PUT',
                        "/vports/" + vm_interface['VPortID'] +
                        "?responseChoice=1", data
                        )
                    if not self.validate(response):
                        LOG.user("Error while setting "
                                 "externalID for vport %(vm)s"
                                 % {'vm': vm_interface['VPortID']})
            elif (port['device_owner'] not in AUTO_CREATE_PORT_OWNERS) and (
                  not network['router:external']):
                subnet_id = port['fixed_ips'][0]['subnet_id']
                subnet_mapping = query.filter_by(subnet_id=subnet_id).first()
                if subnet_mapping:
                    self.create_port_on_nuage(port, subnet_mapping)
                else:
                    LOG.user("Error while Syncing Nuage VPorts for ports, "
                             "Cannot find Nuage subnet mapping for subnet"
                             " %(subnet)s"
                             % {'subnet': port['fixed_ips'][0]['subnet_id']})


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

    conf_list = []
    for conffile in cfg_files:
        conf_list.append('--config-file')
        if not os.path.isfile(conffile):
            LOG.user('File "%s" cannot be found.' % conffile)
            sys.exit(1)
        conf_list.append(conffile)

    config.init(conf_list)
    vsdclient_config.nuage_register_cfg_opts()

    server = cfg.CONF.RESTPROXY.server
    serverauth = cfg.CONF.RESTPROXY.serverauth
    serverssl = cfg.CONF.RESTPROXY.serverssl
    base_uri = cfg.CONF.RESTPROXY.base_uri
    auth_resource = cfg.CONF.RESTPROXY.auth_resource
    organization = cfg.CONF.RESTPROXY.organization

    try:
        restproxy = RESTProxyServer(server=server,
                                    base_uri=base_uri,
                                    serverssl=serverssl,
                                    serverauth=serverauth,
                                    auth_resource=auth_resource,
                                    organization=organization)
    except Exception as e:
        LOG.user("Error in connecting to VSD:%s", str(e))
        return
    LOG.user("Starting Vports Sync.")
    VportSync(restproxy).sync_vports()
    LOG.user("Vports Sync on VSD is now complete.")

if __name__ == '__main__':
    main()
