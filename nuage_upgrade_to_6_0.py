# Copyright 2019 NOKIA
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
File: nuage_upgrade_to_6_0.py

Purpose:
    Pure IPv6 stack is supported in 6.0.
    1. Raise warning for IPv6-only networks.

    2. If IPv6 subnets are DHCP-enabled, find the first available ip for
    DHCP server and set to IPv6Gateway. If DHCP-disabled, empty the
    IPv6Gateway on VSD.

    3. Update OS DHCP-unmanaged l2domains to DHCP-managed l2domains with
    enableDHCPv4 disabled.

    4. Update enableDHCPv6 in VSD to be TRUE for dualstack subnets if IPV6
    subnet is DHCP-enabled as the default enableDHCPv6 is False in VSD

    5. Fix all os_managed l2domaintemplate/l2domain/subnet external ID and
    other resources sriov bridge port, redirect target/redirect tartget rules,
    generate new external_id as (network_id@cms_id) for each of them,
    and update them on vsd, For l2domains, their templates should also be
    updated.

    6. Refactor PG_FOR_LESS_SECURITY to be domain-independent, and rename it
    to PG_ALLOW_ALL. Merge all PG_FOR_LESS_SECURITY and sriov defaultPG into
    one if they are in the same type(HARDWARE/SOFTWARE).

Requirement:
    This script requires two configuration files.
    1. nuage_plugin.ini : which has details to connect to VSD
    2. neutron.conf : which has details to connect to neutron database.
    The optional argument --dry-run is to run upgrade script in dry-run mode
    and generate a upgrade report named upgrade_report.json.
Run:
    python nuage_upgrade_to_6_0.py --neutron-conf <neutron.conf>
      --nuage-conf <nuage_plugin.ini> [--dry-run]
****************************************************************************"""
import argparse
import json
import logging
import os
import sys
import time

import netaddr
from neutron.common import config
from neutron.db.models_v2 import IPAllocation
from neutron.db.models_v2 import Network
from neutron.db.models_v2 import Port
from neutron.db.models_v2 import Subnet

# Value of external key in network is a ExternalNetwork object
# which only appears when below import is added
# It also makes the networksegments table visible in Queens
from neutron.objects import network as network_object  # noqa

from neutron.ipam.drivers.neutrondb_ipam.db_models import IpamAllocation
from neutron.ipam.drivers.neutrondb_ipam.db_models import IpamSubnet
from neutron.plugins.ml2.models import PortBinding

from nuage_neutron.plugins.common import config as nuage_config
from nuage_neutron.plugins.common import constants
from nuage_neutron.plugins.common.nuage_models import SubnetL2Domain
from nuage_neutron.vsdclient.common import constants as vsd_constants
from oslo_config import cfg

from utils import nuage_logging
from utils.restproxy import PATCH_ADD
from utils.restproxy import RESTProxyError
from utils.restproxy import RESTProxyServer

from neutron_lib.api.definitions import ip_allocation as ipalloc_apidef
from neutron_lib import constants as lib_constants
from neutron_lib.utils import net

try:
    from neutron import context as neutron_context
except ImportError:
    from neutron_lib import context as neutron_context

SCRIPT_NAME = 'nuage_upgrade_to_6_0.py'
REPORT_NAME = 'upgrade_report.json'

LOG = logging.getLogger(SCRIPT_NAME)

MSGS_TO_RETRY = [('l2domain is in use and its properties can neither be '
                  'modified or deleted. Please detach the resources '
                  '(vms/containers) associated with it and retry.'),
                 'Network Gateway IPv6 Address null is not a valid IPv6.']

MSG_INVALID_NETMASK = ('Invalid IPv6 netmask. Netmask can only be between '
                       'a minimum 64 and maximum 64 length.')

MSG_IPV6_EXT_PREFIXES_WARN = ("The IPv6 subnet %s has a prefixlen "
                              "greater than 64. Please set "
                              "ipv6.extended.prefixes.enabled config "
                              "in VSD or delete this subnet.")

MSG_IPV6_EXT_PREFIXES_WARN_DRYRUN = (MSG_IPV6_EXT_PREFIXES_WARN +
                                     (" If ipv6.extended.prefixes.enabled is "
                                      "set to True on VSD, "
                                      "please ignore this warning."))

NR_RETRIES = 20
PGS_NAME_PREFIX = {
    'PG_FOR_LESS_SECURITY', 'defaultPG-VSG-BRIDGE', 'defaultPG-VRSG-BRIDGE',
    'defaultPG-VSG-HOST', 'defaultPG-VRSG-HOST'
}
NUAGE_PLCY_GRP_ALLOW_ALL = 'PG_ALLOW_ALL'


class UpgradeTo6dot0(object):

    def __init__(self, restproxy, is_dry_run):
        self.cms_id = cfg.CONF.RESTPROXY.cms_id
        if not self.cms_id:
            raise cfg.ConfigFileValueError('Missing cms_id in configuration.')
        self.restproxy = restproxy
        self.headers_for_pg = self.extra_header_for_pg()
        self.is_dry_run = is_dry_run
        self.output = {}
        self.is_fatal_warn = False

    def put(self, resource, data):
        self.output_store('PUT: ' + str(resource), 'INFO')
        if not self.is_dry_run:
            self.restproxy.put(resource, data)

    def patch(self, resource, data, patch_type):
        self.output_store('PATCH: ' + str(resource), 'INFO')
        if not self.is_dry_run:
            self.restproxy.patch(resource, data, patch_type)

    def bulk_put(self, resource, data):
        self.output_store('BULK PUT: ' + str(resource), 'INFO')
        if not self.is_dry_run:
            self.restproxy.bulk_put(resource, data)

    def bulk_delete(self, resource, data):
        self.output_store('BULK DELETE: ' + str(resource), 'INFO')
        if not self.is_dry_run:
            self.restproxy.bulk_delete(resource, data)

    def output_store(self, data, data_type):
        if self.output.get(data_type):
            self.output[data_type].append(data)
        else:
            self.output[data_type] = [data]

    def has_warnings(self):
        return self.output.get('WARN') or self.output.get('ERROR')

    def warn(self, msg):
        self.output_store(msg, 'WARN')
        if not self.is_dry_run:
            LOG.user('WARN: ' + msg)  # LOG.warn does not print to console

    def fatal_warn(self, msg):
        self.warn(msg)
        self.is_fatal_warn = True

    def error(self, msg):
        self.output_store(msg, 'ERROR')
        if not self.is_dry_run:
            LOG.user('ERROR: ' + msg)  # LOG.error does not print to console
            raise Exception

    @nuage_logging.step(description='updating object model for '
                                    'OpenStack 6.0 release')
    def upgrade(self):
        context = neutron_context.get_admin_context()
        session = context.session
        networks = session.query(Network.id).all()

        for network in networks:
            network = session.query(Network).filter(Network.id ==
                                                    network.id).first()
            network_types = [segment['network_type']
                             for segment in network.get('segments')]
            if "vxlan" not in network_types:
                # Skip networks without vxlan segments
                continue

            ext_data = {'externalID': self._get_external_id(network['id'])}
            # Find all subnets in the network
            subnets = session.query(Subnet).filter_by(
                network_id=network['id']).all()
            ipv4_subnets, ipv6_subnets = self._separate_ipv4_ipv6_subnets(
                subnets)
            # Create dhcp port for ipv4 subnets
            if not network['external']:
                for ipv4_subnet in ipv4_subnets:
                    mapping = session.query(SubnetL2Domain).filter_by(
                        subnet_id=ipv4_subnet.id).first()
                    if (mapping['nuage_managed_subnet'] and
                            ipv4_subnet['enable_dhcp']):
                        # Check the existence of nuage dhcp port on
                        # vsd managed dhcp enabled v4 subnet
                        ipv4_dhcp_port = self._get_dhcp_port(session,
                                                             ipv4_subnet)
                        if not ipv4_dhcp_port:
                            self.create_dhcp_port_for_vsd_mgd_v4_subs(
                                session, ipv4_subnet, mapping)
            for subnet in subnets:
                mapping = session.query(SubnetL2Domain).filter_by(
                    subnet_id=subnet.id).first()
                if not mapping:
                    # Pure ipv6 in network
                    msg = ("Please delete legacy single-stack ipv6 subnet "
                           "'{}'".format(subnet['id']))
                    self.warn(msg)
                elif not mapping['nuage_managed_subnet']:
                    # os managed subnets
                    if network['external']:
                        # shared subnets, update the externalID
                        self.put('/subnets/%s?responseChoice=1' % mapping[
                            'nuage_subnet_id'], ext_data)
                    elif subnet['ip_version'] == 4:
                        # ipv4 subnet, ipv4 subnet or ipv6 subnet in dualstack
                        # for ipv6 subnet in dualstack, only update the ipv4
                        # subnet
                        ipv6_subnet = None
                        if len(ipv4_subnets) == 1 and len(ipv6_subnets) == 1:
                            # Dualstack
                            ipv6_subnet = ipv6_subnets[0]
                            ipv6_prefix = netaddr.IPNetwork(
                                ipv6_subnet['cidr']).prefixlen
                            if ipv6_prefix > 64 and self.is_dry_run:
                                msg = (MSG_IPV6_EXT_PREFIXES_WARN_DRYRUN %
                                       format(ipv6_subnet["id"]))
                                self.warn(msg)
                                continue
                        try:
                            if (not subnet['enable_dhcp'] and
                                    self._is_l2(mapping)):
                                # update unmanaged subnet to managed
                                self.update_unmanaged_subnet_to_managed(
                                    session, ipv4_subnet=subnet,
                                    mapping=mapping, ipv6_subnet=ipv6_subnet,
                                    ext_data=dict(ext_data),
                                    network_name=network['name'])
                            else:
                                # update IPv6Gateway DHCP IP, enableDHCPv4,
                                # enableDHCPv6
                                self.config_new_flags_for_dhcp_enabled_subnet(
                                    session, ipv4_subnet=subnet,
                                    mapping=mapping,
                                    ipv6_subnet=ipv6_subnet,
                                    ext_data=dict(ext_data),
                                    network_name=network['name'])
                        except RESTProxyError as e:
                            if (MSG_INVALID_NETMASK in e.msg and
                                    ipv6_prefix > 64):
                                msg = (MSG_IPV6_EXT_PREFIXES_WARN %
                                       format(ipv6_subnet["id"]))
                                self.fatal_warn(msg)
                                continue
                            else:
                                raise
                        # Update external id of redirect targets and redirect
                        # target rules, acl templates
                        if self._is_l2(mapping):
                            self.update_external_id_for_res_in_l2domain(
                                subnet, mapping, ext_data)

                        # Change PG_FOR_LESS to be domain independent
                        # Merge PG_FOR_LESS and defaultPG of sriov
                        self.refactor_allow_any_pgs(mapping)
                else:
                    # vsd managed subnet
                    if subnet['ip_version'] == 6 and subnet['enable_dhcp']:
                        if self._is_l2(mapping):
                            response = self.restproxy.get(
                                '/l2domains/%s' % mapping['nuage_subnet_id'])
                        else:
                            response = self.restproxy.get(
                                '/subnets/%s' % mapping['nuage_subnet_id'])
                        dhcpv6_ip = response[0]['IPv6Gateway']
                        if not response[0]['enableDHCPv6']:
                            msg = ("Subnet '{}' is DHCP-enabled on "
                                   "OpenStack but it is DHCP-disabled on VSD. "
                                   "Please fix this inconsistent DHCP setting."
                                   .format(subnet['id']))
                            self.fatal_warn(msg)
                        else:
                            if dhcpv6_ip:
                                ip_allocation = session.query(
                                    IPAllocation).filter_by(
                                    ip_address=dhcpv6_ip,
                                    subnet_id=subnet['id']).first()
                                if ip_allocation:
                                    msg = (
                                        "For VSD managed dhcp enabled subnet "
                                        "{}, the IPv6Gateway {} is used by "
                                        "port {}. Please use an available IP "
                                        "as IPv6Gateway.".format(
                                            subnet['id'], dhcpv6_ip,
                                            ip_allocation['port_id']))
                                    self.fatal_warn(msg)
                                else:
                                    ipv4_subnet = (
                                        self.get_vsd_managed_dual_subnet(
                                            session, subnets=ipv4_subnets,
                                            nuage_subnet_id=mapping[
                                                'nuage_subnet_id']))
                                    self.create_dhcp_port_for_vsd_mgd_v6_subs(
                                        session, ipv6_subnet=subnet,
                                        ipv4_subnet=ipv4_subnet,
                                        dhcpv6_ip=dhcpv6_ip)
                            else:
                                # This shouldn't happen because gateway
                                # can't be null if the user enable DHCP on vsd
                                msg = ("For VSD managed dhcp enabled subnet "
                                       "'{}', IPv6Gateway: Network Gateway "
                                       "IPv6 Address null is not a valid "
                                       "IPv6 on VSD.".format(subnet['id']))
                                self.fatal_warn(msg)

        return self.output

    def create_dhcp_port_for_vsd_mgd_v4_subs(self, session, ipv4_subnet,
                                             mapping):
        if self._is_l2(mapping):
            response = self.restproxy.get(
                '/l2domains/%s' % mapping['nuage_subnet_id'])
        else:
            response = self.restproxy.get(
                '/subnets/%s' % mapping['nuage_subnet_id'])
        dhcpv4_ip = response[0]['gateway']
        if dhcpv4_ip:
            ip_allocation = session.query(IPAllocation).filter_by(
                ip_address=dhcpv4_ip, subnet_id=ipv4_subnet['id']).first()
            if ip_allocation:
                msg = ("For VSD managed dhcp enabled subnet {}, the gateway "
                       "{} is used by port {}. Please use an available IP as "
                       "gateway.".format(ipv4_subnet['id'],
                                         dhcpv4_ip,
                                         ip_allocation['port_id']))
                self.fatal_warn(msg)
            else:
                self._create_update_dhcp_port_for_subnet(
                    session, subnet=ipv4_subnet, dhcp_ip=dhcpv4_ip)

    def create_dhcp_port_for_vsd_mgd_v6_subs(self, session, ipv6_subnet,
                                             ipv4_subnet, dhcpv6_ip):
        # Create new correct dhcp port for ipv6 or add correct dhcp ip
        # to the existing dhcp port for ipv4 and delete incorrect
        # existing dhcp port for v6
        ipv6_dhcp_port = self._get_dhcp_port(session, ipv6_subnet)
        ipv4_dhcp_port = None
        if ipv4_subnet:
            ipv4_dhcp_port = self._get_dhcp_port(session, ipv4_subnet)
        if ipv6_dhcp_port and (ipv6_dhcp_port[1]['ip_address'] != dhcpv6_ip or
                               (ipv4_dhcp_port and ipv4_dhcp_port[0]['id'] !=
                                ipv6_dhcp_port[0]['id'])):
            if not self.is_dry_run:
                self._create_update_dhcp_port_for_subnet(
                    session,
                    subnet=ipv6_subnet,
                    dual_subnet=ipv4_subnet,
                    dhcp_ip=dhcpv6_ip,
                    delete_existing_dhcp_port=True)
        elif not ipv6_dhcp_port:
            if not self.is_dry_run:
                self._create_update_dhcp_port_for_subnet(
                    session,
                    subnet=ipv6_subnet,
                    dual_subnet=ipv4_subnet,
                    dhcp_ip=dhcpv6_ip,
                    delete_existing_dhcp_port=False)

    @staticmethod
    def _delete_dhcp_port(session, ipv6_dhcp_port_id):
        session.query(Port).filter_by(id=ipv6_dhcp_port_id).delete()

    def refactor_allow_any_pgs(self, mapping):
        if self._is_l2(mapping):
            resource = 'l2domains'
            vsd_domain_id = mapping['nuage_subnet_id']
        else:
            resource = 'domains'
            vsd_domain_id = self.get_router_id_by_subnet(
                mapping['nuage_subnet_id'])
        pgs_to_update = {
            'SOFTWARE': [],
            'HARDWARE': []
        }
        response = self.restproxy.get(
            '/%s/%s/policygroups' % (resource, vsd_domain_id),
            extra_headers=self.headers_for_pg)
        if response:
            for pg in response:
                pgs_to_update[pg['type']].append(pg)
        if pgs_to_update['SOFTWARE'] or pgs_to_update['HARDWARE']:
            for sg_type in pgs_to_update:
                pgs_with_same_type = pgs_to_update[sg_type]
                pg_vports = {}
                pgs_to_delete = []
                for pg in pgs_with_same_type:
                    vports = self.restproxy.get(
                        '/policygroups/%s/vports' % pg['ID'])
                    if vports:
                        pg_vports[pg['ID']] = [vport['ID'] for vport in vports]
                    else:
                        # If no Vports, delete that policy group.
                        pgs_to_delete.append(pg['ID'])
                if pg_vports:
                    updated_pg_id = self.get_update_pg_with_max_vports(
                        resource=resource, vsd_domain_id=vsd_domain_id,
                        pg_vports=pg_vports, sg_type=sg_type)
                    for pg_id in pg_vports:
                        if pg_id != updated_pg_id:
                            self.patch(
                                '/policygroups/%s/vports?'
                                'responseChoice=1' % updated_pg_id,
                                pg_vports[pg_id], PATCH_ADD)
                            self.put('/policygroups/%s/vports?'
                                     'responseChoice=1' % pg_id, [])
                            # Delete old pg_for_less after migrating vport to
                            # updated pg
                            pgs_to_delete.append(pg_id)
                if pgs_to_delete:
                    self.bulk_delete('/policygroups/?responseChoice=1',
                                     pgs_to_delete)

    def get_router_id_by_subnet(self, subnet_vsd_id):
        response = self.restproxy.get('/subnets/%s' % subnet_vsd_id)
        zone_response = self.restproxy.get('/zones/%s' %
                                           response[0]['parentID'])
        return zone_response[0]['parentID']

    def get_update_pg_with_max_vports(self, resource, vsd_domain_id, pg_vports,
                                      sg_type):
        suffix = ('' if sg_type == vsd_constants.SOFTWARE else
                  '_' + vsd_constants.HARDWARE)
        data = {
            'name': NUAGE_PLCY_GRP_ALLOW_ALL + suffix,
            'description': NUAGE_PLCY_GRP_ALLOW_ALL + suffix,
            'externalID': self._get_pg_external_id(sg_type)
        }
        headers = {
            'X-NUAGE-FilterType': 'predicate',
            'X-Nuage-Filter': "name IS '%s'" % data['name']
        }
        # Default PG externalID change
        response = self.restproxy.get(
            '/%s/%s/policygroups' % (resource, vsd_domain_id),
            extra_headers=headers)
        if response:
            # There is one updated policy group
            pg_id_with_max_vports = response[0]['ID']
        else:
            pg_id_with_max_vports = max(pg_vports,
                                        key=lambda x: len(pg_vports[x]))
            self.put('/policygroups/%s?responseChoice=1' %
                     pg_id_with_max_vports, data)
        rule_resources = ['egressaclentrytemplates',
                          'ingressaclentrytemplates']
        for rule_resource in rule_resources:
            headers = {
                'X-NUAGE-FilterType': 'predicate',
                'X-Nuage-Filter': "locationID IS '%s'" %
                                  pg_id_with_max_vports}
            response = self.restproxy.get(
                resource='/%s/%s/%s' % (resource, vsd_domain_id,
                                        rule_resource),
                extra_headers=headers)
            for result in response:
                data = {'externalID': self._get_pg_external_id(
                    sg_type='')}
                if result['externalID'] != data['externalID']:
                    self.put('/%s/%s?responseChoice=1' %
                             (rule_resource, result['ID']), data)
        return pg_id_with_max_vports

    def _get_pg_external_id(self, sg_type):
        prefix = '' if (sg_type == 'SOFTWARE' or sg_type == '') else 'hw:'
        return prefix + NUAGE_PLCY_GRP_ALLOW_ALL + '@' + self.cms_id

    def update_external_id_for_res_in_l2domain(self, subnet, mapping,
                                               ext_data):
        headers = {
            'X-NUAGE-FilterType': 'predicate',
            'X-Nuage-Filter': "externalID IS '%s'" %
                              self._get_external_id(subnet['id'])
        }
        resources = ['redirectiontargets',
                     'ingressacltemplates', 'egressacltemplates',
                     'ingressadvfwdtemplates']
        for resource in resources:
            if resource == 'ingressadvfwdtemplates':
                # Here must specify the l2domain, otherwise can't find
                # ingressadvfwdtemplates
                response = self.restproxy.get(
                    resource='/l2domains/%s/ingressadvfwdtemplates' %
                             mapping['nuage_subnet_id'], extra_headers=headers)
            else:
                response = self.restproxy.get(
                    resource='/%s' % resource, extra_headers=headers)
            check_res = self._check_response(response, resource, subnet['id'])
            if check_res:
                self.put('/%s/%s?responseChoice=1' % (resource,
                                                      response[0]['ID']),
                         ext_data)
                if resource == 'redirectiontargets':
                    resource = 'ingressadvfwdentrytemplates'
                    # Update external id of redirect target rules
                    response = self.restproxy.get(
                        resource='/ingressadvfwdentrytemplates/',
                        extra_headers=headers)
                    check_res = self._check_response(
                        response, resource, subnet['id'])
                    if check_res:
                        self.put('/%s/%s?responseChoice=1' % (
                            resource, response[0]['ID']), ext_data)

    @staticmethod
    def _check_response(response, resource, subnet_id):
        if not response:
            LOG.debug('There is no {} under subnet:{}.'.format(
                resource, subnet_id))
            return False
        else:
            return True

    def config_new_flags_for_dhcp_enabled_subnet(self, session, ipv4_subnet,
                                                 mapping, ipv6_subnet,
                                                 ext_data, network_name):
        is_l2 = self._is_l2(mapping)
        data = {
            'enableDHCPv4': ipv4_subnet['enable_dhcp']
        }

        if is_l2:
            # If no dhcp port for dhcp managed l2 subnet,
            # create a dhcp port using the first available ip
            # and update the gateway on VSD l2domain
            ipv4_dhcp_port = self._get_dhcp_port(session, ipv4_subnet)
            if not ipv4_dhcp_port:
                data['gateway'] = self._create_update_dhcp_port_for_subnet(
                    session, subnet=ipv4_subnet)

        if ipv6_subnet:
            data.update({
                'enableDHCPv6': ipv6_subnet['enable_dhcp']
            })
            if is_l2:
                if ipv6_subnet['enable_dhcp']:
                    data['IPv6Gateway'] = (
                        self._create_update_dhcp_port_for_subnet(
                            session, subnet=ipv6_subnet,
                            dual_subnet=ipv4_subnet))
                else:
                    data['IPv6Gateway'] = None

        if ipv4_subnet and ipv6_subnet:
            # Dualstack domain will keep ipv4_subnet id as name as name
            # can't be changed in vsd.
            ext_data['description'] = network_name
        data.update(ext_data)
        if is_l2:
            update_succeeded = False
            for attempt in range(NR_RETRIES):
                try:
                    self.put('/l2domaintemplates/%s?responseChoice=1' %
                             mapping['nuage_l2dom_tmplt_id'], data)
                    self.put('/l2domains/%s?responseChoice=1' %
                             mapping['nuage_subnet_id'], ext_data)
                    update_succeeded = True
                    break
                except RESTProxyError as e:
                    if any(msg in e.msg for msg in MSGS_TO_RETRY):
                        LOG.user("Attempt {}/{} to update l2domain "
                                 "for new DHCP flags failed because VSD is "
                                 "temporarily unavailable. "
                                 "Retrying.".format(attempt + 1,
                                                    NR_RETRIES))
                        time.sleep(0.5)
                        continue
                    else:
                        raise
            if not update_succeeded:
                self.error("Failed in updating l2domain {} or "
                           "l2domaintemplate {} "
                           "after {} retries because VSD is temporarily "
                           " unavailable. Rerunning the upgrade script after "
                           "VSD has become available again should resolve "
                           "the issue.".format(mapping['nuage_subnet_id'],
                                               mapping['nuage_l2dom_tmplt_id'],
                                               NR_RETRIES))
        else:
            self.put('/subnets/%s?responseChoice=1' %
                     mapping['nuage_subnet_id'], data)

    def update_unmanaged_subnet_to_managed(self, session, ipv4_subnet,
                                           mapping, ipv6_subnet, ext_data,
                                           network_name):
        ipv4_net = netaddr.IPNetwork(ipv4_subnet['cidr'])
        data = {
            'DHCPManaged': True,
            'enableDHCPv4': False,
            'address': str(ipv4_net.ip),
            'netmask': str(ipv4_net.netmask),
            'IPType': vsd_constants.IPV4
        }
        if ipv6_subnet:
            data.update({
                'IPv6Address': str(ipv6_subnet['cidr']),
                'IPType': vsd_constants.DUALSTACK
            })
        if ipv4_subnet and ipv6_subnet:
            # Dualstack domain will keep ipv4_subnet id as name because name
            # can't be changed in vsd.
            ext_data['description'] = network_name
        data.update(ext_data)
        # Update the l2domain externalID
        can_continue_upgrade = False
        for attempt in range(NR_RETRIES):
            try:
                self.put('/l2domaintemplates/%s?responseChoice=1' %
                         mapping['nuage_l2dom_tmplt_id'], data)
                self.put('/l2domains/%s?responseChoice=1' %
                         mapping['nuage_subnet_id'], ext_data)
                resp = self.restproxy.get(
                    '/l2domains/%s/vminterfaces' % mapping[
                        'nuage_subnet_id'])
                if resp:
                    # Do a bulk call for all vm_interfaces
                    vminterfaces = []
                    for vminterface in resp:
                        # [Port, IpAllocation]
                        result = session.query(Port, IPAllocation).filter(
                            Port.id == IPAllocation.port_id,
                            Port.id == vminterface['externalID'].split('@')[0],
                            Port.device_id == vminterface['VMUUID']).first()
                        fixed_ips = result[0]['fixed_ips']
                        ips = {4: [], 6: []}
                        for fixed_ip in fixed_ips:
                            if fixed_ip['subnet_id'] == ipv4_subnet['id']:
                                ips[4].append(fixed_ip['ip_address'])
                            else:
                                ips[6].append(fixed_ip['ip_address'])
                        for key in ips:
                            ips[key] = self.sort_ips(ips[key])
                        interface_data = {
                            'ID': vminterface['ID'],
                            'IPAddress': ips[4][-1] if ips[4] else None,
                            'IPv6Address': ips[6][-1] if ips[6] else None
                        }
                        vminterfaces.append(interface_data)
                    self.bulk_put('/vminterfaces/?responseChoice=1',
                                  vminterfaces)
                if ipv6_subnet and ipv6_subnet['enable_dhcp']:
                    data = {
                        'enableDHCPv6': ipv6_subnet['enable_dhcp'],
                        'IPv6Gateway':
                            self._create_update_dhcp_port_for_subnet(
                                session, subnet=ipv6_subnet)
                    }
                    self.put(
                        '/l2domaintemplates/%s?responseChoice=1' %
                        mapping['nuage_l2dom_tmplt_id'], data)
                can_continue_upgrade = True
                break
            except RESTProxyError as e:
                if any(msg in e.msg for msg in MSGS_TO_RETRY):
                    LOG.user("Attempt {}/{} to update l2domain "
                             "failed because VSD is temporarily "
                             "unavailable. Retrying.".format(attempt + 1,
                                                             NR_RETRIES))
                    time.sleep(0.5)
                    continue
                # IPv4 cidr or IPv6 cidr is invalid
                msg_to_skipv4 = ('IP Address {} is not valid or cannot be in '
                                 'reserved address space.'
                                 .format(data['address']))
                msg_to_skipv6 = None
                if ipv6_subnet:
                    msg_to_skipv6 = (
                        'IP Address {} is not valid or cannot be in '
                        'reserved address space.'
                        .format(data['IPv6Address']))
                if msg_to_skipv4 in e.msg:
                    self.fatal_warn(msg_to_skipv4 +
                                    ' Please recreate subnet {} with a valid '
                                    'cidr.'.format(ipv4_subnet['id']))
                    can_continue_upgrade = True
                    break
                elif msg_to_skipv6 and msg_to_skipv6 in e.msg:
                    self.fatal_warn(msg_to_skipv6 +
                                    ' Please recreate subnet {} with a valid '
                                    'cidr.'.format(ipv6_subnet['id']))
                    can_continue_upgrade = True
                    break
                else:
                    raise
        if not can_continue_upgrade:
            self.error("Failed in updating l2domain {} or "
                       "l2domaintemplate {} "
                       "after {} retries because VSD is temporarily "
                       "unavailable. Rerunning the upgrade script after "
                       "VSD has become available again should resolve the "
                       "issue.".format(mapping['nuage_subnet_id'],
                                       mapping['nuage_l2dom_tmplt_id'],
                                       NR_RETRIES))

    @staticmethod
    def sort_ips(ips):
        return [str(ip) for ip in sorted([netaddr.IPAddress(ip)
                                          for ip in ips])]

    def _create_update_dhcp_port_for_subnet(self, session, subnet,
                                            dual_subnet=None, dhcp_ip=None,
                                            delete_existing_dhcp_port=False):
        # [Port, IpAllocation]
        dhcp_port = self._get_dhcp_port(session, subnet)
        if dhcp_port and not delete_existing_dhcp_port:
            return dhcp_port[1]['ip_address']
        else:
            if not dhcp_ip:
                # Get the first available IP from the allocation pool
                dhcp_ip = self._allocate_ip_for_port(session, subnet)
            if dual_subnet and dual_subnet['enable_dhcp']:
                # Update port with DHCP ipv6
                ipv4_dhcp_port = self._get_dhcp_port(session, dual_subnet)
                msg = (
                    'Adding ipv6 ip {dhcpv6_ip} to DHCP port {dhcp_port_id} '
                    'to enable DHCP for IPv6 subnet {ipv6_sub_id} '.format(
                        dhcpv6_ip=dhcp_ip,
                        dhcp_port_id=ipv4_dhcp_port[0]['id'],
                        ipv6_sub_id=subnet['id']))
                self.output_store(msg, 'INFO')
                if not self.is_dry_run:
                    # Add entry to ipallocation table
                    with session.begin(subtransactions=True):
                        session.merge(IPAllocation(
                            port_id=ipv4_dhcp_port[0]['id'],
                            ip_address=dhcp_ip,
                            subnet_id=subnet['id'],
                            network_id=subnet['network_id']))

            else:
                msg = (
                    'Creating DHCP port with ip {dhcp_ip} to enable DHCP for '
                    'subnet {sub_id}'.format(
                        dhcp_ip=dhcp_ip, sub_id=subnet['id']))
                self.output_store(msg, 'INFO')
                if not self.is_dry_run:
                    port_data = dict(
                        tenant_id=subnet['tenant_id'],
                        name='',
                        network_id=subnet['network_id'],
                        admin_state_up=True,
                        status=lib_constants.PORT_STATUS_ACTIVE,
                        device_owner=constants.DEVICE_OWNER_DHCP_NUAGE,
                        device_id='',
                        ip_allocation=ipalloc_apidef.IP_ALLOCATION_IMMEDIATE)
                    mac_address = net.get_random_mac(
                        cfg.CONF.base_mac.split(':'))
                    dhcp_port = Port(mac_address=mac_address, **port_data)
                    session.add(dhcp_port)

                    with session.begin(subtransactions=True):
                        session.merge(IPAllocation(
                            port_id=dhcp_port['id'],
                            ip_address=dhcp_ip,
                            subnet_id=subnet['id'],
                            network_id=subnet['network_id']))
                    session.merge(PortBinding(port_id=dhcp_port['id'],
                                              vif_type='unbound',
                                              vnic_type='normal'))
            if not self.is_dry_run:
                # Add entry to ipamallocation table which is needed by port
                # deletion
                ipam_subnet = session.query(IpamSubnet).filter_by(
                    neutron_subnet_id=subnet['id']).first()
                with session.begin(subtransactions=True):
                    session.merge(IpamAllocation(
                        ip_address=dhcp_ip,
                        status='ALLOCATED',
                        ipam_subnet_id=ipam_subnet['id']))
                # Delete existing dhcp port if needed
                if delete_existing_dhcp_port and dhcp_port:
                    msg = ('Delete wrong dhcp port for subnet '
                           '\'{}\''.format(subnet['id']))
                    self.output_store(msg, 'INFO')
                    self._delete_dhcp_port(session, dhcp_port[0]['id'])
            return dhcp_ip

    @staticmethod
    def _get_dhcp_port(session, subnet):
        dhcp_port = session.query(Port, IPAllocation).filter(
            IPAllocation.subnet_id == subnet['id'],
            Port.device_owner ==
            constants.DEVICE_OWNER_DHCP_NUAGE,
            Port.id == IPAllocation.port_id
        ).first()
        return dhcp_port

    def _allocate_ip_for_port(self, session, subnet):
        dhcp_ip = None
        first_ip = subnet['allocation_pools'][0]['first_ip']
        last_ip = subnet['allocation_pools'][0]['last_ip']
        ip = netaddr.IPAddress(first_ip)
        while ip <= netaddr.IPAddress(last_ip):
            port_allocation = session.query(IPAllocation).filter_by(
                subnet_id=subnet['id'], ip_address=str(ip)).first()
            if not port_allocation:
                dhcp_ip = str(ip)
                break
            ip += 1
        if not dhcp_ip:
            msg = ("Can't find an available IP to create DHCP port for "
                   "ipv6 subnet {}".format(subnet['id']))
            self.error(msg)
        return dhcp_ip

    def _get_external_id(self, neutron_id):
        return neutron_id + '@' + self.cms_id

    @staticmethod
    def _separate_ipv4_ipv6_subnets(subnets):
        ipv4_subnets = []
        ipv6_subnets = []
        for subnet in subnets:
            if subnet['ip_version'] == lib_constants.IP_VERSION_4:
                ipv4_subnets.append(subnet)
            else:
                ipv6_subnets.append(subnet)
        return ipv4_subnets, ipv6_subnets

    @staticmethod
    def _is_l2(subnet_mapping):
        return bool(subnet_mapping['nuage_l2dom_tmplt_id'])

    @staticmethod
    def get_vsd_managed_dual_subnet(session, subnets, nuage_subnet_id):
        for subnet in subnets:
            dual_subnet_mapping = session.query(SubnetL2Domain).filter_by(
                subnet_id=subnet.id).first()
            if dual_subnet_mapping['nuage_subnet_id'] == nuage_subnet_id:
                return subnet
        return None

    @staticmethod
    def extra_header_for_pg():
        filter = ''
        for value in PGS_NAME_PREFIX:
            if filter:
                filter += " or "
            filter += "(name BEGINSWITH '{}')".format(value)
        return {'X-NUAGE-FilterType': 'predicate',
                'X-Nuage-Filter': filter}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--neutron-conf',
                        required=True,
                        help='File path to the neutron configuration file')
    parser.add_argument('--nuage-conf',
                        required=True,
                        help='File path to the nuage plugin configuration '
                             'file')
    parser.add_argument('--dry-run',
                        action='store_true',
                        help='Run the upgrade script in dry-run mode')
    args = parser.parse_args()

    if not nuage_logging.log_file:
        nuage_logging.init_logging(SCRIPT_NAME)

    conf_list = []
    for conffile in (args.neutron_conf, args.nuage_conf):
        if not os.path.isfile(conffile):
            LOG.user("File '%s' cannot be found." % conffile)
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
    verify_cert = cfg.CONF.RESTPROXY.verify_cert

    if not args.dry_run and 'v6' not in base_uri:
        LOG.user("Can't upgrade because plugin doesn't have v6 API set. "
                 "Please change it ({}) to v6 api (e.g. /nuage/api/v6) "
                 "and run again.".format(base_uri))
        sys.exit(1)

    try:
        restproxy = RESTProxyServer(server=server,
                                    base_uri=base_uri,
                                    serverssl=serverssl,
                                    serverauth=serverauth,
                                    auth_resource=auth_resource,
                                    organization=organization,
                                    verify_cert=verify_cert)
        restproxy.generate_nuage_auth()
    except Exception as e:
        LOG.user('Error in connecting to VSD: %s', str(e), exc_info=True)
        sys.exit(1)

    try:
        if args.dry_run:
            LOG.user('Starting dry-run for 6.0 upgrade\n')
        else:
            LOG.user('Upgrading resources for 6.0 support\n')

        upgrade = UpgradeTo6dot0(restproxy, args.dry_run)

        with open(REPORT_NAME, 'w') as outfile:
            output = upgrade.upgrade()
            json.dump(output, outfile, indent=4, sort_keys=True)

        if args.dry_run:
            if upgrade.has_warnings():
                LOG.user('Dry-run finished with warnings/errors raised.\n'
                         'Please inspect the report {}, as corrective '
                         'actions are needed before running in '
                         'production mode.'.format(REPORT_NAME))
            else:
                LOG.user('Dry-run finished without any warnings raised.\n'
                         'System is good to be upgraded.')
        else:
            if upgrade.has_warnings():
                msg = ("The upgrade finished with warnings raised.\n"
                       "Please inspect the report {}, as corrective "
                       "actions are needed. ").format(REPORT_NAME)
                if upgrade.is_fatal_warn:
                    LOG.user(msg + 'Please re-run after applying those.')
                else:
                    LOG.user(msg + 'No need to re-run the script.')
            else:
                LOG.user('The upgrade executed successfully.')

    except Exception as e:
        LOG.user('\n\nThe following error occurred:\n'
                 '  %(error_msg)s\n'
                 'For more information, please find the log file at '
                 '%(log_file)s and contact your vendor.',
                 {'error_msg': str(e),
                  'log_file': nuage_logging.log_file},
                 exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
