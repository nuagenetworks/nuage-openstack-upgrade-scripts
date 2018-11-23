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
File: nuage_upgrade_to_5_4_1.py

Purpose:
    Sharedresources APIs is replaced by normal domain APIs. Subnets created by
    normal domain APIs stored in nuage_subnet_l2dom_mapping table like normal
    domain subnets. The "fip" of underlay subnet is also stored in nuage_subnet
    table. This script will check all subnets created by Sharedresources APIs
    in VSD and populate these subnets info to nuage_subnet_l2dom_mapping and
    nuage_subnet table.
Requirement:
    This script require two configuration files.
    1. nuage_plugin.ini : which has details to connect to VSD
    2. neutron.conf : which has details to connect to neutron database.
Run:
    python nuage_upgrade_to_5_4_1.py --neutron-conf <neutron.conf>
      --nuage-conf <nuage_plugin.ini>
****************************************************************************"""
import argparse
import logging
import os
from oslo_config import cfg
import sys

from neutron.common import config
from neutron_lib import exceptions as n_exc

try:
    from neutron import context as neutron_context
except ImportError:
    from neutron_lib import context as neutron_context
try:
    from neutron.db.models.external_net import ExternalNetwork
except ImportError:
    from neutron.db.external_net_db import ExternalNetwork
from neutron.db.models_v2 import Subnet

from nuage_neutron.plugins.common import config as nuage_config
from nuage_neutron.plugins.common.nuage_models import NetPartition
from nuage_neutron.plugins.common.nuage_models import NuageSubnet
from nuage_neutron.plugins.common.nuage_models import SubnetL2Domain

from utils import nuage_logging
from utils.restproxy import RESTProxyServer

SHARED_INFRASTRUCTURE = 'Shared Infrastructure'
SHARED_DOMAIN_TEMPLATE = 'Shared Domain template'
SHARED_ZONE_TEMPLATE = 'Shared Zone template'
NUAGE_UNDERLAY_FIP = 'fip'
NUAGE_UNDERLAY = 'nuage_underlay'

script_name = 'nuage_upgrade_to_5_4_1.py'
LOG = logging.getLogger(script_name)


class UpgradeSharedSubnets(object):
    def __init__(self, restproxy):
        super(UpgradeSharedSubnets, self).__init__()
        self.restproxy = restproxy

    @nuage_logging.step(description="updating shared subnets created by "
                                    "Sharedresources APIs")
    def upgrade(self):
        context = neutron_context.get_admin_context()
        session = context.session
        netpart = self._get_shared_netpartition()
        self._populate_shared_infrastructure(session, netpart['name'],
                                             netpart['ID'])
        self._populate_shared_subnets(context, netpart['ID'])

    def _get_shared_netpartition(self):
        netpart_name = SHARED_INFRASTRUCTURE
        headers = {
            'X-NUAGE-FilterType': "predicate",
            'X-Nuage-Filter': "name IS '%s'" % netpart_name
        }
        response = self.restproxy.get(resource='/enterprises',
                                      extra_headers=headers)
        if response[0] not in range(200, 207) or not response[3]:
            LOG.user("ERROR: Can't find Shared Infrastructure on VSD")
            raise n_exc.NotFound
        return response[3][0]

    @nuage_logging.step(description="populating the shared infrastructure to "
                                    "neutron DB")
    def _populate_shared_infrastructure(self, session, shared_netpart_name,
                                        shared_netpart_id):
        # Validate the id if Shared Infrastructure exists in neutron and vsd
        netpart_db = session.query(NetPartition).filter_by(
            name=shared_netpart_name).first()
        if netpart_db:
            if shared_netpart_id != netpart_db['id']:
                msg = ("Net-partition %s exists in "
                       "Neutron and VSD, but the id is different"
                       % shared_netpart_name)
                raise n_exc.BadRequest(resource='net_partition', msg=msg)

        headers = {
            'X-NUAGE-FilterType': "predicate",
            'X-Nuage-Filter': ("name IS '%s'" % SHARED_DOMAIN_TEMPLATE)
        }
        response = self.restproxy.get(
            resource='/enterprises/%s/domaintemplates' % shared_netpart_id,
            extra_headers=headers)
        if response[0] not in range(200, 207) or not response[3]:
            LOG.user("ERROR: Can't find Shared Domain template in "
                     "Shared Infrastructure.")
            raise n_exc.NotFound
        with session.begin(subtransactions=True):
            session.merge(NetPartition(
                id=shared_netpart_id,
                name=shared_netpart_name,
                l3dom_tmplt_id=response[3][0]['ID'],
                l2dom_tmplt_id=None,
                isolated_zone=None,
                shared_zone=SHARED_ZONE_TEMPLATE))

    @nuage_logging.step(description="populating mapping and underlay value of "
                                    "shared subnets to neutron DB")
    def _populate_shared_subnets(self, context, netpart_id):
        session = context.session
        ext_nets = session.query(ExternalNetwork.network_id).all()
        for ext_net in ext_nets:
            subnet_ids = session.query(Subnet.id).filter_by(
                network_id=ext_net[0]).all()
            for subnet_id in subnet_ids:
                subnet_id = subnet_id[0]
                nuage_subnet = self._get_shared_subnet(subnet_id)
                if not nuage_subnet:
                    continue
                zone_id = nuage_subnet['parentID']
                domain = self._get_domain_by_zone_id(zone_id)
                with session.begin(subtransactions=True):
                    session.merge(SubnetL2Domain(
                        subnet_id=subnet_id,
                        nuage_subnet_id=nuage_subnet['ID'],
                        net_partition_id=netpart_id,
                        nuage_l2dom_tmplt_id=None,
                        nuage_user_id=None,
                        nuage_group_id=None,
                        nuage_managed_subnet=False,
                        ip_version='4'))
                LOG.debug("The mapping of subnet with ID:%s is put to "
                          "nuage_subnet_l2dom_mapping table", subnet_id)
                if domain['FIPUnderlay']:
                    with session.begin(subtransactions=True):
                        session.merge(NuageSubnet(
                            subnet_id=subnet_id,
                            subnet_parameter=NUAGE_UNDERLAY,
                            parameter_value=NUAGE_UNDERLAY_FIP))
                    LOG.debug("The underlay value of subnet with ID:%s is "
                              "put to nuage_subnet table", subnet_id)

    def _get_shared_subnet(self, subnet_id):
        cms_id = cfg.CONF.RESTPROXY.cms_id
        ext_id = subnet_id + '@' + cms_id
        headers = {
            'X-NUAGE-FilterType': "predicate",
            'X-Nuage-Filter': "externalID IS '%s'" % ext_id
        }
        response = self.restproxy.get(resource='/subnets',
                                      extra_headers=headers)
        if response[0] not in range(200, 207) or not response[3]:
            LOG.user("WARNING: Can't find shared subnet with externalID:%s "
                     "on VSD.", ext_id)
            return None
        return response[3][0]

    def _get_domain_by_zone_id(self, zone_id):
        zone_response = self.restproxy.get('/zones/%s' % zone_id)
        domain_id = zone_response[3][0]['parentID']
        dom_response = self.restproxy.get('/domains/%s' % domain_id)
        return dom_response[3][0]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--neutron-conf",
                        required=True,
                        help="File path to the neutron configuration file")
    parser.add_argument("--nuage-conf",
                        required=True,
                        help="File path to the nuage plugin configuration "
                             "file")
    args = parser.parse_args()

    if not nuage_logging.log_file:
        nuage_logging.init_logging(script_name)

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
        LOG.user("Populating shared subnets created by sharedresources APIs "
                 "to neutron DB")
        UpgradeSharedSubnets(restproxy).upgrade()
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
