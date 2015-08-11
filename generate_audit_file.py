# Copyright 2014 Alcatel-Lucent USA Inc.
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
import datetime
import logging
import logging.handlers
import os
import sys
import yaml

from oslo.config import cfg

from neutron.common import config
from neutron import context as ncontext
from neutron.db import db_base_plugin_v2
from neutron.db import extraroute_db
from neutron.db import securitygroups_db
from neutron.db import external_net_db
from neutron.plugins.nuage import nuage_models
from nuage_neutron.plugins.nuage.common import config as nuage_config
from nuage_neutron.plugins.nuage.common import exceptions
from oslo_utils import importutils

LOG = logging.getLogger('Upgrade_Logger')
REST_SUCCESS_CODES = range(200, 207)


class CmsAuditor(db_base_plugin_v2.NeutronDbPluginV2,
                 extraroute_db.ExtraRoute_db_mixin,
                 securitygroups_db.SecurityGroupDbMixin,
                 external_net_db.External_net_db_mixin):
    def __init__(self, nuageclient, cms_id):
        super(CmsAuditor, self).__init__()
        self.context = ncontext.get_admin_context()
        self.nuageclient = nuageclient
        self.cms_id = cms_id
        self.discrepancies = []

    def audit_cms_id(self):
        self.audit_subnets()
        self.audit_domains()
        self.audit_staticroutes()
        self.audit_aclentrytemplates()
        self.audit_policygroups()
        self.audit_floatingips()
        self.audit_vports()
        self.audit_shared_resources()
        self.audit_applicationdomains()
        self.write_audit_file()

    def get(self, url, data, extra_headers=None):
        return self.nuageclient.restproxy.rest_call(
            'GET', url, data, extra_headers=extra_headers)

    def add_descrepancy(self, vsp_type, vsp_id,):
        desc = "[cmsId] expected: %s, found: null"
        discrepancy = {'vsp_type': vsp_type,
                       'action': 'UPDATE',
                       'description': desc % self.cms_id,
                       'vsp_id': str(vsp_id)}
        self.discrepancies.append(discrepancy)

    def audit_subnets(self):
        query = self.context.session.query(nuage_models.SubnetL2Domain)
        subnets = query.all()

        url = '/subnets'
        response = self.get(url, '')
        nuage_subnets = response[3]
        nuageid_nuagesubnet_map = dict([(subnet['externalID'], subnet)
                                       for subnet in nuage_subnets])

        url = '/l2domains'
        response = self.get(url, '')
        l2domains = response[3]
        nuageid_nuagel2domain_map = dict([(l2domain['externalID'], l2domain)
                                         for l2domain in l2domains])
        for subnet in subnets:
            if subnet['nuage_managed_subnet']:
                LOG.info("externalID will not be set for subnet %s as it is a "
                         "VSD managed subnet", subnet['subnet_id'])
                continue

            neutron_id = subnet['subnet_id']
            nuage_id = subnet['nuage_subnet_id']
            if subnet['nuage_l2dom_tmplt_id']:
                nuage_subnet = nuageid_nuagel2domain_map.get(neutron_id)
                if nuage_subnet:
                    self.add_descrepancy('L2DOMAIN', nuage_id)
            else:
                l2domain = nuageid_nuagesubnet_map.get(neutron_id)
                if l2domain:
                    self.add_descrepancy('SUBNET', nuage_id)

    def audit_domains(self):
        query = self.context.session.query(nuage_models.NetPartitionRouter)
        routers = query.all()

        url = '/domains'
        response = self.get(url, '')
        domains = response[3]
        nuageid_nuagedomain_map = dict([(domain['externalID'], domain)
                                        for domain in domains])
        for router in routers:
            neutron_id = router['router_id']
            nuage_id = router['nuage_router_id']
            domain = nuageid_nuagedomain_map.get(neutron_id)
            if domain:
                self.add_descrepancy('DOMAIN', nuage_id)

    def audit_staticroutes(self):
        query = self.context.session.query(nuage_models.NetPartitionRouter)
        routers = query.all()
        for router in routers:
            url = '/domains/%s/staticroutes' % router['nuage_router_id']
            try:
                response = self.get(url, '')
                if response[0] not in REST_SUCCESS_CODES:
                    raise exceptions.NuageAPIException()
            except Exception as e:
                LOG.error("Error retrieving staticroutes for neutron router "
                          "%s: %s" % (router['id'], e.message))
                continue

            for route in response[3]:
                # weird, externalID = nuage ID
                if not route['externalID'] == router['nuage_router_id']:
                    self.add_descrepancy('STATICROUTE', route['ID'])

    def audit_aclentrytemplates(self):
        sgs = self.get_security_groups(self.context)
        try:
            response = self.get('/policygroups', '')
            if response[0] not in REST_SUCCESS_CODES:
                raise exceptions.NuageAPIException()
        except Exception as e:
            LOG.error("Error retrieving policygroups: %s", e.message)
            return
        sg_polgroup_map = dict([(pol_group['externalID'], pol_group)
                                for pol_group in response[3]])

        for sg in sgs:
            pol_group = sg_polgroup_map.get(sg['id'])
            if not pol_group:
                continue

            domain_id = pol_group['parentID']
            if pol_group['parentType'] == 'l2domain':
                in_url = '/l2domains/%s/ingressacltemplates' % domain_id
                eg_url = '/l2domains/%s/egressacltemplates' % domain_id
            else:
                in_url = '/domains/%s/ingressacltemplates' % domain_id
                eg_url = '/domains/%s/egressacltemplates' % domain_id
            self._audit_gress('in', in_url)
            self._audit_gress('e', eg_url)

    def _audit_gress(self, gress_type, url):
        response = self.get(url, '')
        if not response[3]:
            LOG.error("No response from %s." % url)
            pass
        template = response[3][0]
        template_id = template['ID']
        url = ('/%sgressacltemplates/%s/%sgressaclentrytemplates'
               % (gress_type, template_id, gress_type))
        response = self.get(url, '')
        for acl_entry_template in response[3]:
            if '@' not in (acl_entry_template['externalID'] or ''):
                vsp_type = "%sGRESS_ACLTEMPLATES_ENTRIES" % gress_type.upper()
                self.add_descrepancy(vsp_type, acl_entry_template['ID'])

    def audit_policygroups(self):
        sgs = self.get_security_groups(self.context)
        try:
            response = self.get('/policygroups', '')
            if response[0] not in REST_SUCCESS_CODES:
                raise exceptions.NuageAPIException()
        except Exception as e:
            LOG.error("Error retrieving policygroups: %s", e.message)
            return

        for sg in sgs:
            for pol_group in response[3]:
                if pol_group['externalID'] == sg['id']:
                    self.add_descrepancy('POLICY_GROUP', pol_group['ID'])

    def audit_floatingips(self):
        query = self.context.session.query(nuage_models.SubnetL2Domain)
        subnet_mapping = query.all()
        id_subnetmapping_map = dict([(subnet['subnet_id'], subnet)
                                     for subnet in subnet_mapping])
        neutron_fips = self.get_floatingips(self.context)
        neutron_ports = self.get_ports(self.context)
        id_neutronport_map = dict([(port['id'], port)
                                   for port in neutron_ports])
        url = '/floatingips'
        response = self.get(url, '')
        floatingips = response[3]
        neutronid_nuagefip_map = dict([(fip['externalID'], fip)
                                       for fip in floatingips])

        for fip in neutron_fips:
            if fip.get('port_id'):
                port = id_neutronport_map[fip['port_id']]
                for fixed_ip in port.get('fixed_ips'):
                    subnet_id = fixed_ip['subnet_id']
                    mapping = id_subnetmapping_map[subnet_id]
                    nuage_subnet_id = mapping['nuage_subnet_id']
                    if mapping['nuage_l2dom_tmplt_id']:
                        url = '/l2domains/%s/vports' % nuage_subnet_id
                    else:
                        url = '/subnets/%s/vports' % nuage_subnet_id
                    response = self.get(url, '',
                                        extra_headers={
                                            'X-NUAGE-FilterType': 'predicate',
                                            'X-Nuage-Filter': (
                                                "externalID IS '%s'" %
                                                fip['port_id'])
                                        })
                    vport = response[3][0] if response[3] else None
                    if vport:
                        vport_id = vport['ID']
                    else:
                        vport_id = None
                        if mapping['nuage_l2dom_tmplt_id']:
                            itf_url = ('/l2domains/%s/vminterfaces'
                                       % nuage_subnet_id)
                        else:
                            itf_url = ('/subnets/%s/vminterfaces'
                                       % nuage_subnet_id)
                        response = self.get(itf_url, '')
                        vminterfaces = response[3]
                        for vminterface in vminterfaces:
                            if vminterface['externalID'] == fip['port_id']:
                                vport_id = vminterface['VPortID']

                    if not vport_id:
                        continue
                    url = '/vports/%s/qos' % vport_id
                    response = self.get(url, '')
                    for qos in response[3]:
                        if qos['externalID'] == fip['id']:
                            self.add_descrepancy('FIP_RATE_LIMITING_QOS',
                                                 qos['ID'])

            nuage_fip = neutronid_nuagefip_map.get(fip['id'])
            if not nuage_fip:
                continue
            self.add_descrepancy('FLOATING_IP', nuage_fip['ID'])

    def audit_vports(self):
        query = self.context.session.query(nuage_models.SubnetL2Domain)
        subnets = query.all()
        id_subnet_map = dict([(subnet['subnet_id'], subnet)
                              for subnet in subnets])
        ports = self.get_ports(self.context)

        for port in ports:
            for fixed_ip in port.get('fixed_ips'):
                subnet = id_subnet_map.get(fixed_ip['subnet_id'])
                if not subnet:
                    continue
                url_args = (subnet['nuage_subnet_id'])
                if subnet['nuage_l2dom_tmplt_id']:
                    url = '/l2domains/%s/vports' % url_args
                else:
                    url = '/subnets/%s/vports' % url_args
                response = self.get(url, '')
                vports = response[3]
                for vport in vports:
                    if vport['externalID'] == port['id']:
                        self.add_descrepancy("VPORT", vport['ID'])
                    url = '/vports/%s/vminterfaces' % vport['ID']
                    response = self.get(url, '')
                    vm_interfaces = response[3]
                    for vm_interface in vm_interfaces:
                        if vm_interface['externalID'] == port['id']:
                            self.add_descrepancy('VM_INTERFACE',
                                                 vm_interface['ID'])

    def audit_shared_resources(self):
        filter = {'router:external': [True]}
        networks = self.get_networks(self.context, filters=filter)
        url = '/sharednetworkresources'
        response = self.get(url, '')
        shared_resources = response[3]
        subnet_sharedresource_map = dict([(resource['externalID'], resource)
                                          for resource in shared_resources])

        for network in networks:
            for subnet_id in network.get('subnets'):
                resource = subnet_sharedresource_map.get(subnet_id)
                if resource:
                    self.add_descrepancy('SHARED_NETWORK', resource['ID'])

    def audit_applicationdomains(self):
        networks = self.get_networks(self.context)
        url = '/domains'
        response = self.get(url, '')
        l3domains = response[3]
        ext_id_domain_map = dict([(domain['externalID'], domain)
                                  for domain in l3domains])
        for network in networks:
            l3domain = ext_id_domain_map.get(network['id'])
            if (not l3domain
                    or l3domain['applicationDeploymentPolicy'] == 'NONE'):
                continue
            self.add_descrepancy('DOMAIN', l3domain['ID'])

    def write_audit_file(self):
        now = datetime.datetime.now()
        yaml_output = {'Date': now.strftime("%Y-%m-%d %H:%M:%S"),
                       'discrepancies': self.discrepancies}
        with open('audit.yaml', 'w') as out:
            out.write(yaml.dump(yaml_output, default_flow_style=False))
        LOG.info('File "audit.yaml" created.')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config-file", nargs='+',
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
            LOG.error('File "%s" cannot be found.' % conffile)
            sys.exit(1)
        conf_list.append(conffile)

    config.init(conf_list)
    nuage_config.nuage_register_cfg_opts()

    # Create a logfile
    log_dir = os.path.expanduser('~') + '/nuageupgrade'
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    server = cfg.CONF.RESTPROXY.server
    serverauth = cfg.CONF.RESTPROXY.serverauth
    serverssl = cfg.CONF.RESTPROXY.serverssl
    base_uri = cfg.CONF.RESTPROXY.base_uri
    auth_resource = cfg.CONF.RESTPROXY.auth_resource
    organization = cfg.CONF.RESTPROXY.organization
    cms_id = cfg.CONF.RESTPROXY.cms_id

    hdlr = logging.FileHandler(log_dir + '/upgrade.log')
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    LOG.addHandler(hdlr)
    logging.basicConfig(level=logging.INFO)

    nuageclientinst = importutils.import_module('nuagenetlib.nuageclient')
    try:
        nuageclient = nuageclientinst.NuageClient(cms_id=cms_id,
                                                  server=server,
                                                  base_uri=base_uri,
                                                  serverssl=serverssl,
                                                  serverauth=serverauth,
                                                  auth_resource=auth_resource,
                                                  organization=organization)

    except Exception as e:
        LOG.error("Error in connecting to VSD:%s", str(e))
        return

    CmsAuditor(nuageclient, cms_id).audit_cms_id()
    LOG.debug("Upgrading CMS ID is now complete")


if __name__ == '__main__':
    main()
