import argparse
import json
import logging
import logging.handlers
from neutron.common import constants
import nuage_logging
import os
import sys
import time
import vsdclient_config
from uuid import UUID
from neutron.common import config
from neutron import context as ncontext
from neutron.db import db_base_plugin_v2
from neutron.db import l3_db
from neutron.db import securitygroups_db

try:
    from neutron.plugins.nuage import nuage_models
except ImportError:
    from nuage_neutron.plugins.common import nuage_models
try:
    from neutron_vpnaas.db.vpn import vpn_models as vpn_model
except ImportError:
    vpn_model = None
    print "Neutron VPNaaS will not be part of this Nuage upgrade"
from oslo_config import cfg
from restproxy import RESTProxyServer

nuage_logging.init_logging('set_externalid_with_cmsid')
LOG = logging.getLogger('ExternalID_Logger')
LOG_DIR = os.path.expanduser('~') + '/nuageupgrade'
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


class SetExternalIDs(db_base_plugin_v2.NeutronDbPluginV2,
                     securitygroups_db.SecurityGroupDbMixin,
                     l3_db.L3_NAT_dbonly_mixin):
    def __init__(self, restproxy, cms_id, audit):
        super(SetExternalIDs, self).__init__()
        self.context = ncontext.get_admin_context()
        self.restproxy = restproxy
        self.cms_id = cms_id
        self.audit = audit
        if audit:
            self.init_audit_logger()
        vpn_service_provider = ("VPN:Nuage:nuage_neutron.vpnaas."
                                "service_drivers.driver."
                                "NuageIPsecVPNDriver:default")
        if vpn_model and (vpn_service_provider in
                          cfg.CONF.service_providers.service_provider):
            self.vpn_service_enabled = True
        else:
            self.vpn_service_enabled = False

    def init_audit_logger(self):
        file_details = (LOG_DIR + '/set-externalIDs-discrepancies-%s.log'
                        % time.strftime("%d-%m-%Y_%H:%M:%S"))
        hdlr = logging.FileHandler(file_details)
        LOG.user("Audit Log is located at: %s" % file_details)
        console_handler = logging.StreamHandler(sys.stdout)
        self.discrepancies.addHandler(console_handler)
        formatter = logging.Formatter('%(message)s')
        hdlr.setFormatter(formatter)
        self.discrepancies = logging.getLogger('discrepancies')
        self.discrepancies.propagate = False
        self.discrepancies.addHandler(hdlr)
        self.discrepancies.setLevel(logging.INFO)

    def get(self, url, extra_headers=None):
        return self.restproxy.rest_call(
            'GET', url, '', extra_headers=extra_headers)

    def extra_headers_get_locationid(self, policygroup_id):
        headers = {}
        headers['X-NUAGE-FilterType'] = "predicate"
        headers['X-Nuage-Filter'] = "locationID IS '%s'" % policygroup_id
        return headers

    def is_valid_uuid(self, uuid_to_test):
        for i in [1, 2, 3, 4]:
            try:
                UUID(uuid_to_test, version=i)
                return True
            except:
                continue
        return False

    def validate(self, response, url):
        if response[0] not in REST_SUCCESS_CODES:
            if response[0] == REST_SERV_UNAVAILABLE_CODE:
                errors = json.loads(response[3])
                LOG.user('VSD temporarily unavailable, ' +
                         str(errors['errors']))
            LOG.user("%s returned code %s" % (url, response[0]))
            return False
        return True

    def populate_external_id(self):
        self.router_zones_and_security_policies()
        self.subnet_dhcp_opts_and_security_policies()
        self.update_vms()

    def set_external_id(self, url_ext, ext_id):
        args = (url_ext.split('/')[1][:-1], url_ext.split('/')[2], ext_id)
        if self.audit:
            self.discrepancies.info("%s %s should have externalID %s" % args)
        else:
            LOG.user("Updating %s %s's externalID to %s" % args)
            data = {'externalID': ext_id}
            response = self.restproxy.rest_call('PUT',
                                                url_ext + "?responseChoice=1",
                                                data)
            self.validate(response, url_ext)

    def router_zones_and_security_policies(self):
        LOG.user("Updating Router's...")
        query = self.context.session.query(nuage_models.NetPartitionRouter)
        routers = query.all()
        for router in routers:
            ctx_admin = self.context.elevated()
            router_details = self.get_router(ctx_admin, router['router_id'])
            url = "/domains/" + router['nuage_router_id']
            resp = self.get(url + '/zones')
            if self.validate(resp, url):
                external_id = router['router_id'] + '@' + self.cms_id
                for zone in resp[3]:
                    if 'def_zone-' in zone['name']:
                        if zone['externalID']:
                            LOG.user("Ignoring Zone %s because it already has"
                                     " externalID %s" % (zone['ID'],
                                                         zone['externalID']))
                        else:
                            url_ext = '/zones/' + zone['ID']
                            self.set_external_id(url_ext, external_id)
                        self.update_resource_permissions(
                            zone, 'zone', router_details['tenant_id'])
                self.handle_security_policies(url, external_id)
                name_match = 'r_d_' in router_details['name']
                if self.vpn_service_enabled and name_match:
                    router_id = router_details['name'].split('r_d_')[1]
                    if self.is_valid_uuid(router_id):
                        self.update_vpn_floating_ips(
                            router_id=router_id,
                            router_nuage_id=router['nuage_router_id'])
            else:
                LOG.user("Inconsistency-: Cannot Find Mapping for the"
                         " router %s on"
                         " VSP" % router['router_id'])

    def update_vpn_floating_ips(self, router_id, router_nuage_id):
        query = self.context.session.query(vpn_model.VPNService)
        vpn_service = query.filter(vpn_model.VPNService.router_id == router_id
                                   ).first()
        if vpn_service:
            if vpn_service['subnet_id']:
                url = '/domains/%s/floatingips' % router_nuage_id
                resp = self.get(url)
                if self.validate(resp, url):
                    found_fip = False
                    for floating_ip in resp[3]:
                        if floating_ip[
                            'address'] == vpn_service.external_v4_ip and (
                                floating_ip['assigned']):
                            found_fip = True
                            fip_url_ext = '/floatingips/' + floating_ip['ID']
                            external_id = vpn_service.id + '@' + self.cms_id
                            if floating_ip['externalID']:
                                LOG.user("Ignoring Floating IP"
                                         " %s because it already"
                                         " has externalID %s" %
                                         (floating_ip['ID'],
                                          floating_ip['externalID']
                                          ))
                                break
                            self.set_external_id(fip_url_ext, external_id)
                            break
                    if not found_fip:
                        LOG.user("Inconsistency-: Cannot find Floating-IP for"
                                 " the"
                                 " VPN Service %s on"
                                 " VSP" % vpn_service['id'])
                else:
                    LOG.user("Cannot get Floating-IP for the"
                             " VPN Service %s on"
                             " VSP" % vpn_service['id'])
        else:
            LOG.user("Inconsistency-: Cannot find VPN service associated with"
                     " the router with ID %s" % router_id)

    def update_resource_permissions(self, resource, resource_name, tenant_id):
        LOG.debug("Updating use permissions for %s with ID %s:" % (
            resource_name, resource['ID']))
        url = "/%ss/%s/permissions" % (resource_name, resource['ID'])
        response = self.get(url)
        if not (self.validate(response, url) and response[3]):
            return
        for permission in response[3]:
            if permission['externalID']:
                LOG.user("Ignoring permission %s object on VSD because it "
                         "already has externalID %s"
                         % (permission['ID'], permission['externalID']))
                continue
            if permission['permittedEntityName'] == 'Everybody':
                self.set_external_id("/permissions/%s" % permission['ID'],
                                     tenant_id + '@' + self.cms_id)
            else:
                self.set_external_id(
                    "/permissions/%s" % permission['ID'],
                    permission['permittedEntityName'] + '@' + self.cms_id)
                self._update_tenant(permission['permittedEntityName'],
                                    'group', 'name',
                                    parent='enterprise')
            self._update_tenant(tenant_id, 'user', 'userName')

    def update_l2domain_template(self, l2domain_tmplt_id, subnet_id):
        url = '/l2domaintemplates/%s' % l2domain_tmplt_id
        response = self.get(url)
        if not (self.validate(response, url) and response[3]):
            LOG.user("Inconsistency-: Could not retrieve "
                     "l2domain template %s from VSD."
                     % l2domain_tmplt_id)
            return
        if '_def_L2_Template' in response[3][0]['name']:
            return
        elif response[3][0]['externalID']:
            LOG.user("Ignoring L2Domain Template %s because it already has"
                     " externalID %s"
                     % (response[3][0]['ID'], response[3][0]['externalID']))
            return
        self.set_external_id(
            "/l2domaintemplates/%s" % l2domain_tmplt_id,
            subnet_id + '@' + self.cms_id)

    def subnet_dhcp_opts_and_security_policies(self):
        LOG.user("Updating Subnets...")
        query = self.context.session.query(nuage_models.SubnetL2Domain)
        subnets = query.all()
        for subnet in subnets:
            subnet_details = self.get_subnet(context=self.context,
                                             id=subnet['subnet_id'])
            external_id = subnet['subnet_id'] + '@' + self.cms_id
            if subnet.get('nuage_l2dom_tmplt_id'):
                url_str = "/l2domains/" + subnet['nuage_subnet_id']
                response = self.get(url_str)
                if not self.validate(response, url_str):
                    LOG.user("Inconsistency-: Could not retrieve "
                             "l2domain %s from VSD."
                             % subnet['nuage_subnet_id'])
                    continue
                self.update_resource_permissions(
                    response[3][0], 'l2domain',
                    subnet_details['tenant_id'])
                self.update_dhcp_options(subnet_details, url_str, True,
                                         subnet['nuage_managed_subnet'])
                if not subnet['nuage_managed_subnet']:
                    self.handle_security_policies(url_str, external_id)
                    self.update_l2domain_template(
                        subnet.get('nuage_l2dom_tmplt_id'),
                        subnet['subnet_id'])
            else:
                url_str = "/subnets/" + subnet['nuage_subnet_id']
                response = self.get(url_str)
                if not self.validate(response, url_str):
                    LOG.user("Inconsistency-: Could not retrieve "
                             "subnet %s from VSD."
                             % subnet['nuage_subnet_id'])
                    continue
                self.update_dhcp_options(subnet_details, url_str, False,
                                         subnet['nuage_managed_subnet'])
                resource = {"ID": response[3][0]['parentID']}
                self.update_resource_permissions(
                    resource,
                    response[3][0]['parentType'],
                    subnet_details['tenant_id'])

    def update_dhcp_options(self, subnet_details, url_str, l2=False,
                            vsd_managed=False):
        external_id = subnet_details['id'] + '@' + self.cms_id
        response = self.get(url_str + '/dhcpoptions')
        if self.validate(response, url_str + '/dhcpoptions'):
            set_only_for = []
            if subnet_details.get('dns_nameservers'):
                set_only_for.append(6)
            if subnet_details.get('host_routes'):
                set_only_for.append(121)
                set_only_for.append(249)
            if subnet_details.get('gateway_ip') and l2 and not vsd_managed:
                set_only_for.append(3)
            found_opts = []
            for dhcp_opt in response[3]:
                if dhcp_opt.get('actualType') in set_only_for:
                    found_opts.append(dhcp_opt.get('actualType'))
                    if dhcp_opt['externalID']:
                        LOG.user("Ignoring DHCP Option %s because it"
                                 " already"
                                 " has externalID %s" %
                                 (dhcp_opt['ID'],
                                  dhcp_opt['externalID']))
                    else:
                        url_ext = '/dhcpoptions/' + dhcp_opt['ID']
                        self.set_external_id(url_ext, external_id)
            self.validate_dhcp_opts_setting(found_opts, set_only_for,
                                            subnet_details['id'])
        else:
            LOG.user("Inconsistency-: Cannot retrieve DHCP options"
                     " from VSD for subnet with"
                     " ID on OpenStack as %s " % subnet_details['id'])

    def validate_dhcp_opts_setting(self, found_opts, actual_opts, subnet_id):
        val_to_name_mapping = {3: 'gateway_ip', 6: 'dns_nameservers',
                               121: 'host_routes', 249: 'host_routes'}
        if len(found_opts) != len(actual_opts):
            diff = set(actual_opts) - set(found_opts)
            for opt in list(diff):
                LOG.user("Inconsistency-: Cannot Find Mapping for "
                         "the Subnet parameter %s on"
                         " VSP for subnet with ID %s"
                         % (val_to_name_mapping.get(opt), subnet_id))

    def handle_port_security_rule(self, rule_url, port_spg_name, external_id):
        extra_headers = {'X-Nuage-Filter': "externalID IS '%s'"
                                           % (port_spg_name + '@' +
                                              self.cms_id)}
        policy_group_response = self.get('/policygroups',
                                         extra_headers=extra_headers)
        if self.validate(policy_group_response, '/policygroups'):
            if not policy_group_response[3]:
                return
            header = self.extra_headers_get_locationid(
                policygroup_id=policy_group_response[3][0]['ID'])
            rules_response = self.get(rule_url, extra_headers=header)
            if self.validate(rules_response, rule_url):
                if rules_response[3]:
                    set_external_id = rules_response[3].pop(0)
                    for rule in rules_response[3]:
                        if not rule['externalID']:
                            del_url = ('/' + rule_url.split('/')[3] +
                                       '/' + rule['ID'] +
                                       '?responseChoice=1')
                            del_reponse = self.restproxy.rest_call(
                                'DELETE', del_url, '')
                            if not self.validate(del_reponse, del_url):
                                LOG.user("Deleting duplicate rule for"
                                         " port securty failed with"
                                         " rule ID on VSD as %s"
                                         % rule['ID'])
                    url_ext = ('/' + rule_url.split('/')[3] +
                               '/' + set_external_id['ID'])
                    if not set_external_id['externalID']:
                        self.set_external_id(url_ext, external_id)
                    else:
                        LOG.user("Ignoring port security related ACL"
                                 " rule %s because it already has"
                                 " externalID %s"
                                 % (set_external_id['ID'],
                                    set_external_id['externalID']))
                else:
                    LOG.user("Inconsistency-: Could not retrieve security"
                             " rule for port security from VSD")
            else:
                LOG.user("Could not fetch a rule for port"
                         " security setting from VSD")

    def handle_security_policies(self, url, external_id):
        port_spg_name = ('PG_FOR_LESS_SECURITY_' +
                         url.split('/')[2] + '_VM')
        ingress_tmpls = self.get(url + '/ingressacltemplates')
        if self.validate(ingress_tmpls, url + '/ingressacltemplates'):
            for ingress_tmpl in ingress_tmpls[3]:
                url_ext = '/ingressacltemplates/' + ingress_tmpl['ID']
                if ingress_tmpl['externalID']:
                    LOG.user("Ignoring ingress_template %s because it"
                             " already has"
                             " externalID %s"
                             % (ingress_tmpl['ID'],
                                ingress_tmpl['externalID']))
                elif 'default ACL' == ingress_tmpl['description']:
                    self.set_external_id(url_ext, external_id)
                rule_url = url_ext + '/ingressaclentrytemplates'
                self.handle_port_security_rule(rule_url, port_spg_name,
                                               external_id)
        else:
            LOG.user("Inconsistency-: Could not retrieve ingress"
                     " template from VSD")
        egress_tmpls = self.get(url + '/egressacltemplates')
        if self.validate(egress_tmpls, url + '/egressacltemplates'):
            for egress_tmpl in egress_tmpls[3]:
                url_ext = '/egressacltemplates/' + egress_tmpl['ID']
                if egress_tmpl['externalID']:
                    LOG.user("Ignoring egress_template %s because it"
                             " already has"
                             " externalID %s"
                             % (egress_tmpl['ID'], egress_tmpl['externalID']))
                elif 'default ACL' == egress_tmpl['description']:
                    self.set_external_id(url_ext, external_id)
                rule_url = url_ext + '/egressaclentrytemplates'
                self.handle_port_security_rule(rule_url, port_spg_name,
                                               external_id)
        else:
            LOG.user("Inconsistency-: Could not retrieve egress"
                     " template from VSD")
        adv_fwd_tmpls = self.get(url + '/ingressadvfwdtemplates')
        if self.validate(egress_tmpls, url + '/ingressadvfwdtemplates'):
            for adv_fwd_tmpl in adv_fwd_tmpls[3]:
                if adv_fwd_tmpl['externalID']:
                    LOG.user("Ignoring advanced forward template %s because it"
                             " already has externalID %s"
                             % (adv_fwd_tmpl['ID'],
                                adv_fwd_tmpl['externalID']))
                elif 'default Policy' == adv_fwd_tmpl['description']:
                    url_ext = '/ingressadvfwdtemplates/' + adv_fwd_tmpl['ID']
                    self.set_external_id(url_ext, external_id)
        else:
            LOG.user("Inconsistency-: Could not retrieve advanced forwarding"
                     " template from VSD")

    def _set_external_id_for_vm(self, vm_interface):
        response = self.get('/vms/' + vm_interface['parentID'])
        if not (self.validate(response, '/vms') and response[3]):
            LOG.user("Inconsistency-: Could not retrieve VM from VSD with"
                     " ID on VSD as %s"
                     % vm_interface['parentID'])
            return
        vm = response[3][0]
        if vm['externalID']:
            LOG.user("Ignoring VM %s because it already has externalID %s"
                     % (vm['ID'], vm['externalID']))
            return
        external_id = vm['UUID'] + "@" + self.cms_id
        self.set_external_id("/vms/%s" % vm['ID'], external_id)

    def update_vms(self):
        LOG.user("Updating VM's...")
        ports = self.get_ports(self.context)
        for port in ports:
            if port['device_owner'] not in AUTO_CREATE_PORT_OWNERS:
                vminterface_external_id = port['id'] + '@' + self.cms_id
                vminterface_resp = self.get(
                    '/vminterfaces',
                    extra_headers={'X-Nuage-Filter': "externalID IS '%s'" %
                                                     vminterface_external_id})
                if self.validate(vminterface_resp, '/vminterfaces'):
                    if vminterface_resp[3]:
                        for vm_interface in vminterface_resp[3]:
                            self._set_external_id_for_vm(vm_interface)

    def _update_tenant(self, neutron_resource_id, resource, filter_key,
                       parent=None):
        LOG.user("Updating %s for tenant with ID:  %s " %
                 (resource, neutron_resource_id))
        extra_headers = {'X-Nuage-Filter': "%s IS '%s'"
                                           % (filter_key, neutron_resource_id)}
        vsd_resources = []
        if not parent:
            response = self.get('/%ss' % resource, extra_headers=extra_headers)
            if not self.validate(response, '/%ss' % resource) or (
                    not response[3]):
                LOG.user("Inconsistency-:Could not retrieve %s from VSD for"
                         " tenant %s"
                         % (resource, neutron_resource_id))
                return
            vsd_resources = response[3]

        else:
            response = self.get('/%ss' % parent)
            if not self.validate(response, '/%ss' % parent) or not response[3]:
                LOG.user("Inconsistency-:Could not retrieve %s from VSD for"
                         " tenant %s"
                         % (resource, neutron_resource_id))
                return
            for p in response[3]:
                grps_response = self.get(
                    '/%ss/%s/%ss' % (parent, p['ID'], resource),
                    extra_headers=extra_headers)
                if self.validate(grps_response, '/%ss/%s/%ss' % (
                        parent, p['ID'], resource)) and (grps_response[3]):
                        vsd_resources += grps_response[3]
        for vsd_resource in vsd_resources:
            if vsd_resource['externalID']:
                LOG.user("Ignoring vsd %s %s because it already has "
                         "externalID %s"
                         % (resource, vsd_resource['ID'],
                            vsd_resource['externalID']))
                continue
            external_id = neutron_resource_id + "@" + 'openstack'
            self.set_external_id("/%ss/%s" % (resource, vsd_resource['ID']),
                                 external_id)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config-file", nargs=2, required=True,
                        help='List of config files (nuage_plugin.ini + '
                             'neutron.conf) separated by space')
    parser.add_argument("--audit", action='store_true', default=False,
                        help="Don't do any updates but log the discrepancies.")
    args = parser.parse_args()

    cfg_files = args.config_file
    if cfg_files is None:
        parser.print_help()
        return
    elif cfg_files[0] == cfg_files[1]:
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

    try:
        cfg.CONF.database._group._opts['connection']['default'] = ''
        from sqlalchemy import engine
        engine.create_engine(cfg.CONF.database.connection).connect()
    except Exception as e:
        LOG.debug(e.message, exc_info=True)
        LOG.user("Can't create valid connection to neutron database.")
        return

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
        restproxy.generate_nuage_auth()
    except Exception as e:
        LOG.debug(e.message, exc_info=True)
        LOG.user("Error in connecting to VSD:%s", str(e))
        return
    LOG.user("Starting Setting of External-ID's.")
    SetExternalIDs(restproxy, cms_id, args.audit).populate_external_id()
    LOG.user("Setting ExternalID's on VSD is now complete.")


if __name__ == '__main__':
    main()
