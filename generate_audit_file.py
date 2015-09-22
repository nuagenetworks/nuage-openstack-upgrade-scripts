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
import vsdclient_config
import yaml

from oslo.config import cfg

from neutron.common import config
from neutron import context as ncontext
from neutron.db import db_base_plugin_v2
from neutron.db import extraroute_db
from neutron.db import securitygroups_db
from neutron.db import external_net_db
from neutron.plugins.nuage import nuage_models
from restproxy import RESTProxyServer

LOG = logging.getLogger('Upgrade_Logger')
REST_SUCCESS_CODES = range(200, 207)


class CmsAuditor(db_base_plugin_v2.NeutronDbPluginV2,
                 extraroute_db.ExtraRoute_db_mixin,
                 securitygroups_db.SecurityGroupDbMixin,
                 external_net_db.External_net_db_mixin):
    def __init__(self, restproxy, cms_id):
        super(CmsAuditor, self).__init__()
        self.context = ncontext.get_admin_context()
        self.restproxy = restproxy
        self.cms_id = cms_id
        self.discrepancies = []

    def audit_cms_id(self):
        LOG.info("Audit begins.")
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
        LOG.info("Audit Finished.")

    def get(self, url, data, extra_headers=None):
        return self.restproxy.rest_call(
            'GET', url, data, extra_headers=extra_headers)

    def add_descrepancy(self, vsp_type, vsp_id,):
        desc = "[cmsId] expected: %s, found: null"
        discrepancy = {'vsp_type': vsp_type,
                       'action': 'UPDATE',
                       'description': desc % self.cms_id,
                       'vsp_id': str(vsp_id)}
        self.discrepancies.append(discrepancy)

    def _check_response(self, response, url):
        if response[0] not in REST_SUCCESS_CODES:
            LOG.warn("%s returned code %s" % (url, response[0]))
            return False
        return True

    def audit_subnets(self):
        LOG.info("Checking subnets.")
        query = self.context.session.query(nuage_models.SubnetL2Domain)
        subnets = query.all()

        url = '/subnets'
        response = self.get(url, '')
        if not self._check_response(response, url):
            nuage_subnets = []
        else:
            nuage_subnets = response[3]
        nuageid_nuagesubnet_map = dict([(subnet['externalID'], subnet)
                                       for subnet in nuage_subnets])

        url = '/l2domains'
        response = self.get(url, '')
        if not self._check_response(response, url):
            l2domains = []
        else:
            l2domains = response[3]
        nuageid_nuagel2domain_map = dict([(l2domain['externalID'], l2domain)
                                         for l2domain in l2domains])
        for idx, subnet in enumerate(subnets):
            if (1 + idx) % 100 == 0:
                percent = (100 * (idx + 1) / len(subnets))
                LOG.info("Processing subnets... (%s%%)." % percent)
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
        LOG.info("Subnets done.")

    def audit_domains(self):
        LOG.info("Checking domains.")
        query = self.context.session.query(nuage_models.NetPartitionRouter)
        routers = query.all()

        url = '/domains'
        response = self.get(url, '')
        if not self._check_response(response, url):
            domains = []
        else:
            domains = response[3]
        nuageid_nuagedomain_map = dict([(domain['externalID'], domain)
                                        for domain in domains])
        for idx, router in enumerate(routers):
            if (1 + idx) % 100 == 0:
                percent = (100 * (idx + 1) / len(routers))
                LOG.info("Processing domains... (%s%%)." % percent)
            neutron_id = router['router_id']
            nuage_id = router['nuage_router_id']
            domain = nuageid_nuagedomain_map.get(neutron_id)
            if domain:
                self.add_descrepancy('DOMAIN', nuage_id)
        LOG.info("Domains done.")

    def audit_staticroutes(self):
        LOG.info("Checking static routes.")
        query = self.context.session.query(nuage_models.NetPartitionRouter)
        routers = query.all()
        for idx, router in enumerate(routers):
            if (1 + idx) % 100 == 0:
                percent = (100 * (idx + 1) / len(routers))
                LOG.info("Processing static routes... (%s%%)." % percent)
            url = '/domains/%s/staticroutes' % router['nuage_router_id']
            try:
                response = self.get(url, '')
                if response[0] not in REST_SUCCESS_CODES:
                    raise ValueError('%s did not return successfully (%s).'
                                     % (url, response[0]))
            except Exception as e:
                LOG.error("Error retrieving staticroutes for neutron router "
                          "%s: %s" % (router['id'], e.message))
                continue

            for route in response[3]:
                if route['externalID'] == router['router_id']:
                    self.add_descrepancy('STATICROUTE', route['ID'])
        LOG.info("Static routes done.")

    def audit_aclentrytemplates(self):
        LOG.info("Checking acl entry templates.")
        sgs = self.get_security_groups(self.context)
        try:
            response = self.get('/policygroups', '')
            if response[0] not in REST_SUCCESS_CODES:
                raise ValueError('/policygroups did not return successfully '
                                 '(%s).' % response[0])
        except Exception as e:
            LOG.error("Error retrieving policygroups: %s", e.message)
            return
        sg_polgroup_map = dict([(pol_group['externalID'], pol_group)
                                for pol_group in response[3]])

        for idx, sg in enumerate(sgs):
            if (1 + idx) % 100 == 0:
                percent = (100 * (idx + 1) / len(sgs))
                LOG.info("Processing acl entry templates... (%s%%)." % percent)
            filter = {'security_group_id': [sg['id']]}
            sg_rules = self.get_security_group_rules(self.context,
                                                     filters=filter)
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
            self._audit_gress('in', in_url, sg_rules)
            self._audit_gress('e', eg_url, sg_rules)
        LOG.info("Acl entry templates done.")

    def _audit_gress(self, gress_type, url, sg_rules):
        response = self.get(url, '')
        if not self._check_response(response, url):
            return
        if not response[3]:
            LOG.error("No response from %s." % url)
            return
        template = response[3][0]
        template_id = template['ID']
        url = ('/%sgressacltemplates/%s/%sgressaclentrytemplates'
               % (gress_type, template_id, gress_type))
        response = self.get(url, '')
        if not self._check_response(response, url):
            return
        for acl_entry_template in response[3]:
            for sg_rule in sg_rules:
                if sg_rule['id'] == acl_entry_template['externalID']:
                    vsp_type = ("%sGRESS_ACLTEMPLATES_ENTRIES"
                                % gress_type.upper())
                    self.add_descrepancy(vsp_type, acl_entry_template['ID'])

    def audit_policygroups(self):
        LOG.info("Checking policy groups.")
        sgs = self.get_security_groups(self.context)
        try:
            response = self.get('/policygroups', '')
            if response[0] not in REST_SUCCESS_CODES:
                raise ValueError('/policygroups did not return successfully '
                                 '(%s).' % response[0])
        except Exception as e:
            LOG.error("Error retrieving policygroups: %s", e.message)
            return

        for idx, sg in enumerate(sgs):
            if (1 + idx) % 100 == 0:
                percent = (100 * (idx + 1) / len(sgs))
                LOG.info("Processing policy groups... (%s%%)." % percent)
            for pol_group in response[3]:
                if pol_group['externalID'] == sg['id']:
                    self.add_descrepancy('POLICY_GROUP', pol_group['ID'])
        LOG.info("Policy groups done.")

    def audit_floatingips(self):
        LOG.info("Checking floating ips.")
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
        if not self._check_response(response, url):
            floatingips = []
        else:
            floatingips = response[3]
        neutronid_nuagefip_map = dict([(fip['externalID'], fip)
                                       for fip in floatingips])

        for idx, fip in enumerate(neutron_fips):
            if (1 + idx) % 100 == 0:
                percent = (100 * (idx + 1) / len(neutron_fips))
                LOG.info("Processing floating ips... (%s%%)." % percent)
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
                    if not self._check_response(response, url):
                        vport = None
                    else:
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
                        if not self._check_response(response, url):
                            vminterfaces = []
                        else:
                            vminterfaces = response[3]
                        for vminterface in vminterfaces:
                            if vminterface['externalID'] == fip['port_id']:
                                vport_id = vminterface['VPortID']

                    if not vport_id:
                        continue
                    url = '/vports/%s/qos' % vport_id
                    if not self._check_response(response, url):
                        continue
                    response = self.get(url, '')
                    for qos in response[3]:
                        if qos['externalID'] == fip['id']:
                            self.add_descrepancy('FIP_RATE_LIMITING_QOS',
                                                 qos['ID'])

            nuage_fip = neutronid_nuagefip_map.get(fip['id'])
            if not nuage_fip:
                continue
            self.add_descrepancy('FLOATING_IP', nuage_fip['ID'])
        LOG.info("Floating ips done.")

    def audit_vports(self):
        LOG.info("Checking vports.")
        query = self.context.session.query(nuage_models.SubnetL2Domain)
        subnets = query.all()
        id_subnet_map = dict([(subnet['subnet_id'], subnet)
                              for subnet in subnets])
        ports = self.get_ports(self.context)

        for idx, port in enumerate(ports):
            if (1 + idx) % 100 == 0:
                percent = (100 * (idx + 1) / len(ports))
                LOG.info("Processing vports... (%s%%)." % percent)
            for fixed_ip in port.get('fixed_ips'):
                subnet = id_subnet_map.get(fixed_ip['subnet_id'])
                if not subnet:
                    continue
                url_args = (subnet['nuage_subnet_id'])
                if subnet['nuage_managed_subnet']:
                    url = '/l2domains/%s/vports' % url_args
                    response = self.get(url, '')
                    if response[0] not in REST_SUCCESS_CODES:
                        url = '/subnets/%s/vports' % url_args
                        response = self.get(url, '')
                elif subnet['nuage_l2dom_tmplt_id']:
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
                    if vport['externalID'] == port['id']:
                        self.add_descrepancy("VPORT", vport['ID'])
                    url = '/vports/%s/vminterfaces' % vport['ID']
                    response = self.get(url, '')
                    vm_interfaces = response[3]
                    for vm_interface in vm_interfaces:
                        if vm_interface['externalID'] == port['id']:
                            self.add_descrepancy('VM_INTERFACE',
                                                 vm_interface['ID'])
        LOG.info("Vports done.")

    def audit_shared_resources(self):
        LOG.info("Checking shared network resources.")
        filter = {'router:external': [True]}
        networks = self.get_networks(self.context, filters=filter)
        url = '/sharednetworkresources'
        response = self.get(url, '')
        if not self._check_response(response, url):
            shared_resources = []
        else:
            shared_resources = response[3]
        subnet_sharedresource_map = dict([(resource['externalID'], resource)
                                          for resource in shared_resources])

        for idx, network in enumerate(networks):
            if (1 + idx) % 100 == 0:
                percent = (100 * (idx + 1) / len(networks))
                LOG.info("Processing shared network resources... (%s%%)."
                         % percent)
            for subnet_id in network.get('subnets'):
                resource = subnet_sharedresource_map.get(subnet_id)
                if resource:
                    self.add_descrepancy('SHARED_NETWORK', resource['ID'])
        LOG.info("Shared network resources done.")

    def audit_applicationdomains(self):
        LOG.info("Checking application domains.")
        networks = self.get_networks(self.context)
        url = '/domains'
        response = self.get(url, '')
        if not self._check_response(response, url):
            l3domains = []
        else:
            l3domains = response[3]
        ext_id_domain_map = dict([(domain['externalID'], domain)
                                  for domain in l3domains])
        for idx, network in enumerate(networks):
            if (1 + idx) % 100 == 0:
                percent = (100 * (idx + 1) / len(networks))
                LOG.info("Processing application domains... (%s%%)." % percent)
            l3domain = ext_id_domain_map.get(network['id'])
            if (not l3domain
                    or l3domain['applicationDeploymentPolicy'] == 'NONE'):
                continue
            self.add_descrepancy('DOMAIN', l3domain['ID'])
        LOG.info("Application domains done.")

    def write_audit_file(self):
        now = datetime.datetime.now()
        yaml_output = {'Date': now.strftime("%Y-%m-%d %H:%M:%S"),
                       'discrepancies': self.discrepancies}
        with open('audit.yaml', 'w') as out:
            out.write(yaml.dump(yaml_output, default_flow_style=False))
        LOG.info('File "audit.yaml" created.')


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

    hdlr = logging.FileHandler(log_dir + '/upgrade.log')
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
    vsdclient_config.nuage_register_cfg_opts()

    server = cfg.CONF.RESTPROXY.server
    serverauth = cfg.CONF.RESTPROXY.serverauth
    serverssl = cfg.CONF.RESTPROXY.serverssl
    base_uri = cfg.CONF.RESTPROXY.base_uri
    auth_resource = cfg.CONF.RESTPROXY.auth_resource
    organization = cfg.CONF.RESTPROXY.organization
    cms_id = cfg.CONF.RESTPROXY.cms_id

    try:
        restproxy = RESTProxyServer(server=server,
                                    base_uri=base_uri,
                                    serverssl=serverssl,
                                    serverauth=serverauth,
                                    auth_resource=auth_resource,
                                    organization=organization)

    except Exception as e:
        LOG.error("Error in connecting to VSD:%s", str(e))
        return

    CmsAuditor(restproxy, cms_id).audit_cms_id()
    LOG.debug("Upgrading CMS ID is now complete")


if __name__ == '__main__':
    main()
