# Copyright 2018 Nokia
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
"""****************************************************************************
File: nuage_upgrade_to_5_3.py

Purpose:
    For ML2 VSD managed, plugin was not setting the spoofing attrbiute when
    the port security is disabled. This script will take care in an upgrade
    scenario where the script will check all the VSD managed subnets
    and for every port security disabled port which has a vport on VSD we
    VPort spoofing will be enabled.
Requirement:
    This script require two configuration files.
    1. nuage_plugin.ini : which has details to connect to VSD
    2. neutron.conf : which has details to connect to neutron database.
Run:
    python nuage_upgrade_to_5_3.py --neutron-conf <neutron.conf>
      --nuage-conf <nuage_plugin.ini>
****************************************************************************"""
import argparse
import logging
import os
import sys

from neutron_lib import exceptions as n_exc
from neutron.common import config

try:
    from neutron import context as neutron_context
except:
    from neutron_lib import context as neutron_context

from neutron.db.portsecurity_db_common import PortSecurityDbCommon as PortSec
from neutron.db.db_base_plugin_common import DbBasePluginCommon
from nuage_neutron.plugins.common import config as nuage_config
from nuage_neutron.plugins.common.nuage_models import SubnetL2Domain
from oslo_config import cfg

from utils import nuage_logging
from utils.restproxy import RESTProxyServer

script_name = 'nuage_upgrade_to_5_3.py'
LOG = logging.getLogger(script_name)

REST_SUCCESS_CODES = range(200, 207)


class UpgradeVSDManagedSubnetPorts(object):
    def __init__(self, restproxy):
        super(UpgradeVSDManagedSubnetPorts, self).__init__()
        self.restproxy = restproxy

    @nuage_logging.step(description="updating spoofing attribute of VSD "
                                    "managed subnet ports to reflect port"
                                    " security configuration in OpenStack")
    def upgrade(self):
        self.enable_spoofing_for_vport(self.restproxy)

    def enable_spoofing_for_vport(self, restproxy):
        subnet_set = 0
        ports_set = 0
        context = neutron_context.get_admin_context()
        session = context.session

        vsd_mngd_subnets = (
            session.query(SubnetL2Domain).filter(
                SubnetL2Domain.nuage_managed_subnet.is_(True)
            )
        ).all()

        for mapping in nuage_logging.iterate(vsd_mngd_subnets, 'subnets'):
            vports = self._get_vports_on_vsd_per_subnet(restproxy, mapping)
            if vports:
                for vport in nuage_logging.iterate(vports, 'Vports in subnet'):
                    if (vport['externalID'] and
                            vport['type'] == 'VM'):
                        port_id = vport['externalID'].split('@')[0]
                        port_details = self._validate_port_exists(context,
                                                                  port_id)
                        if port_details.get('port_security'):
                            port_security = (port_details['port_security']
                                             ['port_security_enabled'])
                        else:
                            port_security = (
                                PortSec()._get_port_security_binding(context,
                                                                     port_id)
                            )
                        if (not port_security and
                                vport['addressSpoofing'] != 'ENABLED'):
                                restproxy.put(
                                    '/vports/%s?responseChoice=1'
                                    % vport['ID'],
                                    {'addressSpoofing': 'ENABLED'})
                                ports_set += 1
                                LOG.debug("Enabled Spoofing for port with"
                                          " id: %s.", port_id)
                        elif (port_security and
                                vport['addressSpoofing'] != 'INHERITED'):
                            restproxy.put(
                                '/vports/%s?responseChoice=1'
                                % vport['ID'],
                                {'addressSpoofing': 'INHERITED'})
                            ports_set += 1
                            LOG.debug("Spoofing set to INHERITED for port with"
                                      " id: %s.", port_id)
                if ports_set:
                    subnet_set += 1
        LOG.user("\n  Changed spoofing state for %(ports)s port(s) across"
                 " %(subnets)s VSD managed subnet(s).",
                 {'ports': ports_set, 'subnets': subnet_set})

    @staticmethod
    def _validate_port_exists(context, port_id):
        try:
            port_details = DbBasePluginCommon()._get_port(context, port_id)
            return port_details
        except n_exc.PortNotFound as e:
            LOG.user("WARNING:" + e.message +
                     " This port id has Vport mapped on VSD")

    @staticmethod
    def _get_vports_on_vsd_per_subnet(restproxy, subnet_mapping):
        if subnet_mapping['nuage_l2dom_tmplt_id']:
            response = restproxy.get(
                '/l2domains/%s/vports/' % subnet_mapping['nuage_subnet_id'])
            if response[0] not in range(200, 207):
                LOG.user("WARNING: Can't find l2domain %(l2domain)s on VSD."
                         " The neutron subnet %(subnet)s is supposed to be"
                         " linked to this. "
                         % {'l2domain': subnet_mapping['nuage_subnet_id'],
                            'subnet': subnet_mapping['subnet_id']})
                return None
            vports = response[3]
        else:
            response = restproxy.get(
                '/subnets/%s/vports/' % subnet_mapping['nuage_subnet_id'])
            if response[0] not in range(200, 207):
                LOG.user(
                    "WARNING: Can't find subnet %(l2domain)s on VSD. The "
                    "neutron subnet %(subnet)s is supposed to be linked to "
                    "this. "
                    % {'l2domain': subnet_mapping['nuage_subnet_id'],
                       'subnet': subnet_mapping['subnet_id']})
                return None
            vports = response[3]
        return vports


def main():
    if not nuage_logging.log_file:
        nuage_logging.init_logging(script_name)

    parser = argparse.ArgumentParser()
    parser.add_argument("--neutron-conf",
                        required=True,
                        help="File path to the neutron configuration file")
    parser.add_argument("--nuage-conf",
                        required=True,
                        help="File path to the nuage plugin configuration "
                             "file")
    args = parser.parse_args()

    conf_list = []
    for conffile in (args.neutron_conf, args.nuage_conf):
        if not os.path.isfile(conffile):
            LOG.user('File "%s" cannot be found.' % conffile)
            sys.exit(1)
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

    try:
        restproxy = RESTProxyServer(server=server,
                                    base_uri=base_uri,
                                    serverssl=serverssl,
                                    serverauth=serverauth,
                                    auth_resource=auth_resource,
                                    organization=organization)

    except Exception as e:
        LOG.user("Error in connecting to VSD: %s", str(e), exc_info=True)
        sys.exit(1)

    try:
        LOG.user("Upgrading VIRTIO ports in VSD managed subnets")
        UpgradeVSDManagedSubnetPorts(restproxy).upgrade()
        LOG.user("Script executed successfully")

    except Exception as e:
        LOG.user("\n\nThe following error occurred:\n  %(error_msg)s\n"
                 "For more information, please find the log file at "
                 "%(log_file)s and contact your vendor.",
                 {'error_msg': e.message,
                  'log_file': nuage_logging.log_file},
                 exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
