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

import json
import logging
import logging.handlers
import os
from oslo.config import cfg
import sys


from neutron.common import config
from neutron import context as ncontext
from neutron.db import db_base_plugin_v2
from neutron.db import extraroute_db
from neutron.db import securitygroups_db
from neutron.openstack.common import importutils
from neutron.plugins.nuage.common import config as nuage_config
from neutron.plugins.nuage import nuage_models
from neutron.plugins.nuage import nuagedb

LOG = logging.getLogger('Upgrade_Logger')
NEUTRON_CONFIG_FILE = '/etc/neutron/neutron.conf'
NUAGE_CONFIG_FILE = '/etc/neutron/plugins/nuage/nuage_plugin.ini'
REST_SUCCESS_CODES = range(200, 207)


class PopulateIDs(db_base_plugin_v2.NeutronDbPluginV2,
                  extraroute_db.ExtraRoute_db_mixin,
                  securitygroups_db.SecurityGroupDbMixin):

    def __init__(self, nuageclient):
        self.context = ncontext.get_admin_context()
        self.nuageclient = nuageclient

    def get_error_msg(self, responsedata):
        errors = json.loads(responsedata)
        return str(errors['errors'][0]['descriptions'][0]['description'])

    def validate(self, response, resource, id):
        if response[0] not in REST_SUCCESS_CODES:
            err_msg = self.get_error_msg(response[3])
            LOG.error("Setting externalID for resource %(res)s "
                      "id %(id)s failed with error: %(err)s"
                      % {'res': resource,
                         'id': id,
                         'err': err_msg })
        else:
            LOG.debug("Setting externalID for resource %(res)s"
                      "id %(id)s is successful" % {'res': resource,
                                                   'id': id})

    def populate_externalid(self):
        self.handle_subnets()
        self.handle_routers()
        self.handle_ext_networks()
        self.handle_fips()
        self.handle_routes()
        self.handle_secgroups()
        self.handle_secgrouprules()
        self.handle_vm_ports()

    def populate_rt_rd(self):
        query = self.context.session.query(nuage_models.NetPartitionRouter)
        routers = query.all()
        for router in routers:
            try:
                response = self.nuageclient.rest_call(
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
                                  "%s" % router['router_id'])
            except Exception:
                LOG.error("Error in setting RT/RD for router %s" % router[
                    'router_id'])

    def handle_routers(self):
        query = self.context.session.query(nuage_models.NetPartitionRouter)
        routers = query.all()
        for router in routers:
            try:
                data = {
                    'externalID': router['router_id']
                }
                response = self.nuageclient.rest_call(
                    'PUT',
                    "/domains/" + router['nuage_router_id'] +
                    "?responseChoice=1",
                    data)
                self.validate(response, 'Router', router['router_id'])
            except Exception as e:
                LOG.error("Error %(err)s while setting externalID for router "
                          "%(rtr)s" % {'err': str(e),
                                       'rtr': router['router_id']})

    def handle_subnets(self):
        query = self.context.session.query(nuage_models.SubnetL2Domain)
        subnets = query.all()
        for subnet in subnets:
            try:
                data = {
                    'externalID': subnet['subnet_id']
                }

                if subnet['nuage_l2dom_tmplt_id']:
                    url_str = "/l2domains/" + subnet['nuage_subnet_id'] + \
                              "?responseChoice=1"
                else:
                    url_str = "/subnets/" + subnet['nuage_subnet_id'] \
                              + "?responseChoice=1"

                response = self.nuageclient.rest_call('PUT', url_str, data)
                self.validate(response, 'Subnet', subnet['subnet_id'])
            except Exception as e:
                LOG.error("Error %(err)s while setting externalID for subnet "
                          "%(sub)s" % {'err': str(e),
                                       'sub': subnet['subnet_id']})

    def handle_ext_networks(self):
        query = self.context.session.query(nuage_models.FloatingIPPoolMapping)
        networks = query.all()
        for network in networks:
            try:
                response = self.nuageclient.rest_call(
                    'GET',
                    "/sharednetworkresources/" + network['fip_pool_id'], '')

                sharednet = response[3][0]
                cidr = self.convert_to_cidr(sharednet['address'],
                                            sharednet['netmask'])
                filter = {
                    'network_id': [network['net_id']],
                    'cidr': [cidr]
                }
                subnet = self.get_subnets(self.context, filters=filter)

                data = {
                    'externalID': subnet[0]['id']
                }
                response = self.nuageclient.rest_call(
                    'PUT',
                    "/sharednetworkresources/" + network['fip_pool_id'] +
                    "?responseChoice=1",
                    data)
                self.validate(response, 'ExternalNetwork', subnet[0]['id'])
            except Exception as e:
                LOG.error("Error %(err)s while setting externalID for ext-net "
                          "%(net)s" % {'err': str(e),
                                       'net': subnet[0]['id']})

    def handle_fips(self):
        query = self.context.session.query(nuage_models.FloatingIPMapping)
        fips = query.all()
        for fip in fips:
            try:
                data = {
                    'externalID': fip['fip_id']
                }
                response = self.nuageclient.rest_call(
                    'PUT',
                    "/floatingips/" + fip['nuage_fip_id'] + "?responseChoice=1",
                    data)
                self.validate(response, 'FloatingIP', fip['fip_id'])
            except Exception as e:
                LOG.error("Error %(err)s while setting externalID for fip "
                          "%(fip)s" % {'err': str(e),
                                       'fip': fip['fip_id']})

    def handle_routes(self):
        query = self.context.session.query(nuage_models.RouterRoutesMapping)
        routes = query.all()
        for route in routes:
            try:
                ent_rtr_mapping = nuagedb.get_ent_rtr_mapping_by_rtrid(route[
                    'router_id'])
                data = {
                    'externalID': ent_rtr_mapping['nuage_router_id']
                }

                response = self.nuageclient.rest_call(
                    'PUT',
                    "/staticroutes/" + route['nuage_route_id'] +
                    "?responseChoice=1",
                    data)
                self.validate(response, 'Route', route['destination'] + ':' +
                              route['nexthop'])
            except Exception as e:
                LOG.error("Error %(err)s while setting externalID for route "
                          "with destination %(dest)s and nexthop %(hop)s"
                          % {'err': str(e),
                             'dest': route['destination'],
                             'hop': route['nexthop']})

    def handle_secgroups(self):
        query = self.context.session.query(
            nuage_models.SecGroupVPortTagMapping)
        secgroups = query.all()
        for secgrp in secgroups:
            try:
                data = {
                    'externalID': secgrp['secgroup_id']
                }
                response = self.nuageclient.rest_call(
                    'PUT',
                    "/policygroups/" + secgrp['nuage_vporttag_id'] +
                    "?responseChoice=1",
                    data)
                self.validate(response,
                              'SecurityGroup', secgrp['secgroup_id'])
            except Exception as e:
                LOG.error("Error %(err)s while setting externalID for secgrp"
                          "%(sec)s" % {'err': str(e),
                                       'sec': secgrp['secgroup_id']})

    def handle_secgrouprules(self):
        query = self.context.session.query(
            nuage_models.SecGroupRuleACLMapping)
        secgrouprules = query.all()
        for secrule in secgrouprules:
            try:
                sgrule = self.get_security_group_rule(self.context,
                                                      secrule['sgrule_id'])
                data = {
                    'externalID': secrule['sgrule_id']
                }

                if sgrule['direction'] == 'ingress':
                    url_str = "/ingressaclentrytemplates/"+secrule['nuage_acl_id']\
                              + "?responseChoice=1"
                else:
                    url_str = "/egressaclentrytemplates/"+secrule['nuage_acl_id']\
                              + "?responseChoice=1"

                response = self.nuageclient.rest_call('PUT', url_str, data)
                self.validate(response, 'SecurityGroupRule', secrule['sgrule_id'])
            except Exception as e:
                LOG.error("Error %(err)s while setting externalID for secrule"
                          "%(sec)s" % {'err': str(e),
                                       'sec': secrule['sgrule_id']})

    def handle_vm_ports(self):
        query = self.context.session.query(nuage_models.PortVPortMapping)
        vports = query.all()
        for vport in vports:
            try:
                data = {
                    'externalID': vport['port_id']
                }
                response = self.nuageclient.rest_call(
                    'PUT',
                    "/vminterfaces/" + vport['nuage_vif_id'] +
                    "?responseChoice=1",
                    data
                )
                self.validate(response, 'VMInterface', vport['nuage_vif_id'])
            except Exception as e:
                LOG.error("Error %(err)s while setting externalID for "
                          "vport %(vm)s" % {'err': str(e),
                                            'vm': vport['port_id']})

    def get_net_size(self, netmask):
        binary_str = ''
        for octet in netmask:
            binary_str += bin(int(octet))[2:].zfill(8)
        return str(len(binary_str.rstrip('0')))

    def convert_to_cidr(self, address, mask):

        ipaddr = address.split('.')
        netmask = mask.split('.')

        # calculate network start
        net_start = [str(int(ipaddr[x]) & int(netmask[x]))
                     for x in range(0,4)]

        return '.'.join(net_start) + '/' + self.get_net_size(netmask)


def main():

    set_extID = False
    set_rtrd = False
    for arg in sys.argv:
        if arg == 'setexternalid':
            set_extID = True
        elif arg == 'setrtrd':
            set_rtrd = True

    if not set_extID and not set_rtrd:
        print "Usage: python icehouse_juno_upgrade.py <setexternalid> " \
              "<setrtrd>"
        print "<setrtrd> should be used on icehouse"
        print "<setexternalid> should be used on juno"
        return

    args = ['--config-file', NEUTRON_CONFIG_FILE, '--config-file',
            NUAGE_CONFIG_FILE]

    if set_extID:
        config.parse(args)
    else:
        config.init(args)
        
    nuage_config.nuage_register_cfg_opts()

    server = cfg.CONF.RESTPROXY.server
    serverauth = cfg.CONF.RESTPROXY.serverauth
    serverssl = cfg.CONF.RESTPROXY.serverssl
    base_uri = cfg.CONF.RESTPROXY.base_uri
    auth_resource = cfg.CONF.RESTPROXY.auth_resource
    organization = cfg.CONF.RESTPROXY.organization

    # Create a logfile
    log_dir = os.path.expanduser('~') + '/nuageupgrade'
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    hdlr = logging.FileHandler(log_dir + '/upgrade.log')
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    LOG.addHandler(hdlr)
    logging.basicConfig(level=logging.DEBUG)

    nuageclientinst = importutils.import_module('nuagenetlib.nuageclient')
    try:
        if set_extID:
            nuageclient = nuageclientinst.NuageClient(server, base_uri,
                                                  serverssl, serverauth,
                                                  auth_resource,20,
                                                  organization)
        else:
            nuageclient = nuageclientinst.NuageClient(server, base_uri,
                                                  serverssl, serverauth,
                                                  auth_resource,
                                                  organization)

    except Exception as e:
        LOG.error("Error in connecting to VSD:%s", str(e))
        return

    if set_extID:
        try:
            PopulateIDs(nuageclient).populate_externalid()
            LOG.debug("Setting externalids is now complete")
        except Exception as e:
            LOG.error("Error in setting external ids:%s", str(e))
            return

    if set_rtrd:
        try:
            PopulateIDs(nuageclient).populate_rt_rd()
            LOG.debug("Setting rt/rd is now complete")
        except Exception as e:
            LOG.error("Error in seting rt/rd:%s", str(e))
            return

if __name__ == '__main__':
    main()
