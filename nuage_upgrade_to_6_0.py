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

Requirement:
    This script require two configuration files.
    1. nuage_plugin.ini : which has details to connect to VSD
    2. neutron.conf : which has details to connect to neutron database.
Run:
    python nuage_upgrade_to_6_0.py --neutron-conf <neutron.conf>
      --nuage-conf <nuage_plugin.ini>
****************************************************************************"""
import argparse
import logging
import os
import sys

import netaddr
from neutron.common import config
from neutron.db.models_v2 import IPAllocation
from neutron.db.models_v2 import Network
from neutron.db.models_v2 import Port
from neutron.db.models_v2 import Subnet
from neutron.ipam.drivers.neutrondb_ipam.db_models import IpamAllocation
from neutron.ipam.drivers.neutrondb_ipam.db_models import IpamSubnet
from neutron.objects import network as net_obj
from neutron.plugins.ml2.models import PortBinding

from nuage_neutron.plugins.common import config as nuage_config
from nuage_neutron.plugins.common import constants
from nuage_neutron.plugins.common.nuage_models import NuageSwitchportBinding
from nuage_neutron.plugins.common.nuage_models import SubnetL2Domain
from nuage_neutron.vsdclient.common import constants as vsd_constants
from oslo_config import cfg

from utils import nuage_logging
from utils.restproxy import RESTProxyError
from utils.restproxy import RESTProxyServer

from neutron_lib.api.definitions import ip_allocation as ipalloc_apidef
from neutron_lib import constants as lib_constants
from neutron_lib.utils import net

try:
    from neutron import context as neutron_context
except ImportError:
    from neutron_lib import context as neutron_context

script_name = 'nuage_upgrade_to_6_0.py'
bash_script_name = 'nuage_upgrade_to_6_0.sh'
LOG = logging.getLogger(script_name)

connect_failure_msg = ("Cannot communicate with Nuage VSD. Please do not "
                       "perform any further operations and contact the"
                       "administrator.")


class UpgradeTo6dot0(object):
    def __init__(self, restproxy):
        self.cms_id = cfg.CONF.RESTPROXY.cms_id
        if not self.cms_id:
            raise cfg.ConfigFileValueError('Missing cms_id in configuration.')
        self.restproxy = restproxy

    @nuage_logging.step(description="updating for supporting pure IPv6")
    def upgrade(self):
        context = neutron_context.get_admin_context()
        session = context.session
        networks = session.query(Network.id).all()
        ipv6_subnets = []

        # update externalID of sriov bridge port to network_id@cms_id
        self.update_sriov_bridge_port(session)

        for network in networks:
            network = session.query(Network).filter(Network.id ==
                                                    network.id).first()
            ext_data = {'externalID': self._get_external_id(network['id'])}

            # Find all subnets in the network
            subnets = session.query(Subnet).filter_by(
                network_id=network['id']).all()

            for subnet in subnets:
                mapping = session.query(SubnetL2Domain).filter_by(
                    subnet_id=subnet.id).first()
                if not mapping:
                    # Pure ipv6 in net
                    ipv6_subnets.append(subnet)
                elif not mapping['nuage_managed_subnet']:
                    # os managed subnets
                    if net_obj.ExternalNetwork.objects_exist(
                            context, network_id=network['id']):
                        # shared subnets, update the externalID
                        self.restproxy.put('/subnets/%s?responseChoice=1' %
                                           mapping['nuage_subnet_id'],
                                           ext_data)
                    elif subnet['ip_version'] == 4:
                        # ipv4 subnet, ipv4 subnet or ipv6 subnet in dualstack
                        # for ipv6 subnet in dualstack, only update the ipv4
                        # subnet
                        ipv6_subnet = None
                        if (len(subnets) == 2 and subnets[0]['ip_version'] !=
                                subnets[1]['ip_version']):
                            # Dualstack
                            ipv4_subnet, ipv6_subnet = \
                                self._seperate_ipv4_ipv6_subnet(subnets)
                        if not subnet['enable_dhcp'] and self._is_l2(mapping):
                            # update unmanaged subnet to managed
                            self.update_unmanaged_subnet_to_managed(
                                session, ipv4_subnet=subnet,
                                mapping=mapping, ipv6_subnet=ipv6_subnet,
                                ext_data=dict(ext_data),
                                network_name=network['name'])
                        else:
                            # update IPv6Gateway DHCP IP, enableDHCPv4,
                            # enableDHCPv6, dynamicaddressIPv4
                            self.config_new_flags_for_dhcp_enabled_subnet(
                                session, ipv4_subnet=subnet, mapping=mapping,
                                ipv6_subnet=ipv6_subnet,
                                ext_data=dict(ext_data),
                                network_name=network['name'])

                        # Update external id of redirect targets and redirect
                        # target rules, acl templates
                        if self._is_l2(mapping):
                            self.update_external_id_for_res_in_l2domain(
                                subnet, mapping, ext_data)
                else:
                    # vsd managed subnet
                    if subnet['ip_version'] == 6 and subnet['enable_dhcp']:
                        LOG.warn("Subnet '{}' is DHCP-enabled on "
                                 "OpenStack but it is DHCP-disabled on VSD. "
                                 "Please fix this inconsistent DHCP setting."
                                 .format(subnet['id']))

        if ipv6_subnets:
            for ipv6_subnet in ipv6_subnets:
                LOG.warn("Please delete legacy single-stack ipv6 subnet "
                         "'{}'".format(ipv6_subnet['id']))

    def update_sriov_bridge_port(self, session):
        switch_port_bindings = session.query(NuageSwitchportBinding).all()
        for switch_port_binding in switch_port_bindings:
            ip_allocation = session.query(IPAllocation).filter_by(
                port_id=switch_port_binding['neutron_port_id']).first()
            data = {'externalID': self._get_external_id(
                ip_allocation['network_id'])}
            self.restproxy.put('/vports/%s?responseChoice=1' %
                               switch_port_binding['nuage_vport_id'], data)

            hw_pg_name = 'defaultPG-VSG-BRIDGE-'
            hw_ext_data = {'externalID': 'hw:' + data['externalID']}
            sw_pg_name = 'defaultPG-VRSG-BRIDGE-'
            headers = {
                'X-NUAGE-FilterType': "predicate",
                'X-Nuage-Filter': "name BEGINSWITH '%s'" % hw_pg_name
            }
            # default PG externalID change
            hw_default_pgs = self.restproxy.get(
                '/vports/%s/policygroups' %
                switch_port_binding['nuage_vport_id'],
                extra_headers=headers)[3]
            if hw_default_pgs:
                self.restproxy.put('/policygroups/%s?responseChoice=1' %
                                   hw_default_pgs[0]['ID'], hw_ext_data)
            else:
                headers = {
                    'X-NUAGE-FilterType': "predicate",
                    'X-Nuage-Filter': "name BEGINSWITH '%s'" % sw_pg_name
                }
                sw_default_pgs = self.restproxy.get(
                    '/vports/%s/policygroups' %
                    switch_port_binding['nuage_vport_id'],
                    extra_headers=headers)[3]
                if sw_default_pgs:
                    self.restproxy.put('/policygroups/%s?responseChoice=1' %
                                       sw_default_pgs[0]['ID'], data)
            # rule externalID change
            headers = {
                'X-NUAGE-FilterType': "predicate",
                'X-Nuage-Filter': "externalID IS '%s'" % self._get_external_id(
                    ip_allocation['subnet_id'])
            }
            resources = ['egressaclentrytemplates', 'ingressaclentrytemplates']
            for resource in resources:
                response = self.restproxy.get(
                    resource='/%s' % resource, extra_headers=headers)
                check_res = self._check_response(response,
                                                 resource,
                                                 ip_allocation['subnet_id'])
                if check_res:
                    for response in response[3]:
                        self.restproxy.put(
                            '/%s/%s?responseChoice=1' %
                            (resource, response['ID']), data)

    def update_external_id_for_res_in_l2domain(self, subnet, mapping,
                                               ext_data):
        headers = {
            'X-NUAGE-FilterType': "predicate",
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
                self.restproxy.put(
                    '/%s/%s?responseChoice=1' %
                    (resource, response[3][0]['ID']), ext_data)
                if resource == 'redirectiontargets':
                    resource = 'ingressadvfwdentrytemplates'
                    # Update external id of redirect target rules
                    response = self.restproxy.get(
                        resource='/ingressadvfwdentrytemplates/',
                        extra_headers=headers)
                    check_res = self._check_response(
                        response, resource, subnet['id'])
                    if check_res:
                        self.restproxy.put(
                            '/%s/%s?responseChoice=1' %
                            (resource, response[3][0]['ID']), ext_data)

    def _check_response(self, response, resource, subnet_id):
        if response[0] == 404 or not response[3]:
            LOG.debug("There is no {} under subnet:{}.".format(
                resource, subnet_id))
            return False
        elif response[0] not in self.restproxy.success_codes:
            LOG.user(connect_failure_msg)
            raise Exception
        else:
            return True

    def config_new_flags_for_dhcp_enabled_subnet(self, session, ipv4_subnet,
                                                 mapping, ipv6_subnet,
                                                 ext_data, network_name):
        is_l2 = self._is_l2(mapping)
        data = {
            'enableDHCPv4': ipv4_subnet['enable_dhcp']
        }
        if ipv6_subnet:
            data.update({
                'enableDHCPv6': ipv6_subnet['enable_dhcp']
            })
            if is_l2:
                if ipv6_subnet['enable_dhcp']:
                    data['IPv6Gateway'] = self._create_dhcp_ip_for_ipv6(
                        session, ipv6_subnet, ipv4_subnet)
                else:
                    data['IPv6Gateway'] = None

        if ipv4_subnet and ipv6_subnet:
            # Dualstack domain will keep ipv4_subnet id as name as name
            # can't be changed in vsd.
            ext_data['description'] = network_name
        data.update(ext_data)
        if is_l2:
            for attempt in range(3):
                try:
                    self.restproxy.put(
                        '/l2domaintemplates/%s?responseChoice=1' %
                        mapping['nuage_l2dom_tmplt_id'], data)
                    self.restproxy.put('/l2domains/%s?responseChoice=1' %
                                       mapping['nuage_subnet_id'], ext_data)
                    break
                except RESTProxyError as e:
                    msg = ('l2domain is in use and its properties can '
                           'neither be modified or deleted. Please detach '
                           'the resources (vms/containers) associated with '
                           'it and retry.')
                    if e.msg == msg:
                        LOG.user("Can't update l2domain because of unstable "
                                 "vsd. Retrying to update l2domain.")
                        continue
                    else:
                        raise
        else:
            self.restproxy.put('/subnets/%s?responseChoice=1' %
                               mapping['nuage_subnet_id'], data)

    def update_unmanaged_subnet_to_managed(self, session, ipv4_subnet,
                                           mapping, ipv6_subnet, ext_data,
                                           network_name):
        ipv4_net = netaddr.IPNetwork(ipv4_subnet['cidr'])
        data = {
            "DHCPManaged": True,
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
        for attempt in range(3):
            try:
                self.restproxy.put('/l2domaintemplates/%s?responseChoice=1' %
                                   mapping['nuage_l2dom_tmplt_id'], data)
                self.restproxy.put('/l2domains/%s?responseChoice=1' %
                                   mapping['nuage_subnet_id'],
                                   ext_data)
                resp = self.restproxy.get(
                    '/l2domains/%s/vminterfaces' % mapping[
                        'nuage_subnet_id'])
                if resp[3]:
                    # Do a bulk call for all vm_interfaces
                    vminterfaces = []
                    for vminterface in resp[3]:
                        # [Port, IpAllocation]
                        result = session.query(Port, IPAllocation).filter(
                            Port.id == IPAllocation.port_id,
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
                    self.restproxy.bulk_put('/vminterfaces/?responseChoice=1',
                                            vminterfaces)
                if ipv6_subnet and ipv6_subnet['enable_dhcp']:
                    data = {
                        'enableDHCPv6': ipv6_subnet['enable_dhcp'],
                        'IPv6Gateway': self._create_dhcp_ip_for_ipv6(
                            session, ipv6_subnet)
                    }
                    self.restproxy.put(
                        '/l2domaintemplates/%s?responseChoice=1' %
                        mapping['nuage_l2dom_tmplt_id'], data)
                break
            except RESTProxyError as e:
                msg_to_retry = ('l2domain is in use and its properties can '
                                'neither be modified or deleted. Please '
                                'detach the resources (vms/containers) '
                                'associated with it and retry.')
                msg_to_skipv4 = ('IP Address {} is not valid or cannot be in '
                                 'reserved address space.'
                                 .format(data['address']))
                msg_to_skipv6 = None
                if ipv6_subnet:
                    msg_to_skipv6 = (
                        'IP Address {} is not valid or cannot be in '
                        'reserved address space.'
                        .format(data['IPv6Address']))
                if e.msg == msg_to_retry:
                    LOG.user("Can't update l2domain because of unstable "
                             "vsd. Retrying to update l2domain.")
                    continue
                # IPv4 cidr or IPv6 cidr is invalid
                if e.msg == msg_to_skipv4:
                    LOG.warn(msg_to_skipv4 +
                             ' Please recreate subnet {} with a valid '
                             'cidr.'.format(ipv4_subnet['id']))
                    break
                elif msg_to_skipv6 and e.msg == msg_to_skipv6:
                    LOG.warn(msg_to_skipv6 +
                             ' Please recreate subnet {} with a valid '
                             'cidr.'.format(ipv6_subnet['id']))
                    break
                else:
                    raise

    @staticmethod
    def sort_ips(ips):
        return [str(ip) for ip in sorted([netaddr.IPAddress(ip)
                                          for ip in ips])]

    def _create_dhcp_ip_for_ipv6(self, session, ipv6_subnet,
                                 ipv4_subnet=None):
        # [Port, IpAllocation]
        ipv6_dhcp_port = self._get_dhcp_port(session, ipv6_subnet)
        if ipv6_dhcp_port:
            return ipv6_dhcp_port[1]['ip_address']
        else:
            # Get the first available IP from the allocation pool
            dhcpv6_ip = self._allocate_ip_for_port(session,
                                                   ipv6_subnet)
            if ipv4_subnet and ipv4_subnet['enable_dhcp']:
                # Update port with DHCP ipv6
                ipv4_dhcp_port = self._get_dhcp_port(session, ipv4_subnet)
                if not ipv4_dhcp_port:
                    LOG.user(
                        "Can't find DHCP port for ipv4 subnet {}".format(
                            ipv4_subnet['id']))
                    raise Exception
                # Add entry to ipallocation table
                with session.begin(subtransactions=True):
                    session.merge(IPAllocation(
                        port_id=ipv4_dhcp_port[0]['id'],
                        ip_address=dhcpv6_ip,
                        subnet_id=ipv6_subnet['id'],
                        network_id=ipv6_subnet['network_id']))
            else:
                port_data = dict(
                    tenant_id=ipv6_subnet['tenant_id'],
                    name='',
                    network_id=ipv6_subnet['network_id'],
                    admin_state_up=True,
                    status=lib_constants.PORT_STATUS_ACTIVE,
                    device_owner=constants.DEVICE_OWNER_DHCP_NUAGE,
                    device_id='',
                    ip_allocation=ipalloc_apidef.IP_ALLOCATION_IMMEDIATE)
                mac_address = net.get_random_mac(cfg.CONF.base_mac.split(':'))
                dhcp_port = Port(mac_address=mac_address, **port_data)
                session.add(dhcp_port)

                with session.begin(subtransactions=True):
                    session.merge(IPAllocation(
                        port_id=dhcp_port['id'],
                        ip_address=dhcpv6_ip,
                        subnet_id=ipv6_subnet['id'],
                        network_id=ipv6_subnet['network_id']))
                session.merge(PortBinding(port_id=dhcp_port['id'],
                                          vif_type='unbound',
                                          vnic_type='normal'))
            ipam_subnet = session.query(IpamSubnet).filter_by(
                neutron_subnet_id=ipv6_subnet['id']).first()
            # Add entry to ipamallocation table which is needed by port
            # deletion
            with session.begin(subtransactions=True):
                session.merge(IpamAllocation(
                    ip_address=dhcpv6_ip,
                    status='ALLOCATED',
                    ipam_subnet_id=ipam_subnet['id']))
            return dhcpv6_ip

    def _get_dhcp_port(self, session, subnet):
        dhcp_port = session.query(Port, IPAllocation).filter(
            IPAllocation.subnet_id == subnet['id'],
            Port.device_owner ==
            constants.DEVICE_OWNER_DHCP_NUAGE,
            Port.id == IPAllocation.port_id
        ).first()
        return dhcp_port

    def _allocate_ip_for_port(self, session, ipv6_subnet):
        dhcpv6_ip = None
        first_ip = ipv6_subnet['allocation_pools'][0]['first_ip']
        last_ip = ipv6_subnet['allocation_pools'][0]['last_ip']
        ip = netaddr.IPAddress(first_ip)
        while ip <= netaddr.IPAddress(last_ip):
            port_allocation = session.query(IPAllocation).filter_by(
                subnet_id=ipv6_subnet['id'], ip_address=str(ip)).first()
            if not port_allocation:
                dhcpv6_ip = str(ip)
                break
            ip += 1
        if not dhcpv6_ip:
            LOG.user("Can't find an available IP to create DHCP port for "
                     "ipv6 subnet {}".format(ipv6_subnet['id']))
            raise Exception
        return dhcpv6_ip

    def _get_external_id(self, neutron_id):
        return neutron_id + '@' + self.cms_id

    def _seperate_ipv4_ipv6_subnet(self, subnets):
        if subnets[0]['ip_version'] == lib_constants.IP_VERSION_4:
            ipv4_subnet, ipv6_subnet = subnets[0], subnets[1]
        else:
            ipv4_subnet, ipv6_subnet = subnets[1], subnets[0]
        return ipv4_subnet, ipv6_subnet

    def _is_l2(self, subnet_mapping):
        return bool(subnet_mapping['nuage_l2dom_tmplt_id'])


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

    if 'v6' not in base_uri:
        LOG.user("Can't upgrade because plugin doesn't have v6 API set. "
                 "Please change it ({}) to v6 api (e.g. /nuage/api/v6) "
                 "and run upgrade again.".format(base_uri))
        sys.exit(1)

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
        LOG.user("Updating resources for 6.0 support")
        UpgradeTo6dot0(restproxy).upgrade()
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
