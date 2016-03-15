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

import argparse
import itertools
import json
import logging
import logging.handlers
import os
from oslo_config import cfg
import sys


from neutron.common import config
from neutron import context as ncontext
from neutron.db import db_base_plugin_v2
from neutron.db import extraroute_db
from neutron.db import securitygroups_db

try:
    from neutron.openstack.common import importutils
except ImportError:
    from oslo_utils import importutils

from nuage_neutron.plugins.common import config as nuage_config


LOG = logging.getLogger('Upgrade_Logger')
REST_SUCCESS_CODES = range(200, 207)
STATEFUL_ICMP_TYPES = [8, 13, 15, 17]


class UpdatePGRules(db_base_plugin_v2.NeutronDbPluginV2,
                    extraroute_db.ExtraRoute_db_mixin,
                    securitygroups_db.SecurityGroupDbMixin):

    def __init__(self, nuageclient, cms_id):
        self.context = ncontext.get_admin_context()
        self.nuageclient = nuageclient
        self.cms_id = cms_id

    def get_error_msg(self, responsedata):
        errors = json.loads(responsedata)
        return str(errors['errors'][0]['descriptions'][0]['description'])

    def validate(self, response, action, vsd_rule_id, neutron_rule_id):
        if response[0] not in REST_SUCCESS_CODES:
            err_msg = self.get_error_msg(response[3])
            LOG.error(err_msg)
            return False
        else:
            LOG.info("Action %(action)s on ACLrule %(rule_id)s (with "
                     "neutron external id %(neutron_rule_id)s) is "
                     "successful" % {'action': action,
                                     'rule_id': vsd_rule_id,
                                     'neutron_rule_id': neutron_rule_id})
            return True


    def update_pg_rules(self):
        self.update_proto_any_rules()
        #removing icmp update, as icmp behavior is same as 3.2 in 4.0
        self.update_icmp_rules()

    def update_proto_any_rules(self):
        # Get all rules on VSD with externelID set to neutron 'ANY' rule
        query = self.context.session.query(
           securitygroups_db.SecurityGroupRule)
        ethertype_col = getattr(securitygroups_db.SecurityGroupRule,
                                "ethertype")
        protocol_col = getattr(securitygroups_db.SecurityGroupRule, "protocol")
        sgrules = query.filter(ethertype_col.in_(['IPv4']),
                               protocol_col.is_(None)).all()

        for sgrule in sgrules:
            try:
                ingress_url_str = ("/ingressaclentrytemplates" +
                                   "?responseChoice=1")
                egress_url_str = ("/egressaclentrytemplates"+
                                  "?responseChoice=1")
                headers = {}
                extra_headers = "externalID IS '%s@%s'" % (
                    sgrule['id'], self.cms_id)
                headers['X-Nuage-Filter'] = extra_headers

                in_response = self.nuageclient.restproxy.rest_call(
                    'GET', ingress_url_str, '', extra_headers=headers)
                eg_response = self.nuageclient.restproxy.rest_call(
                    'GET', egress_url_str, '', extra_headers=headers)
                delete_rule_list = []
                if sgrule['direction'] == 'egress':
                    if in_response[3]:
                        acllist = in_response[3]
                        sorted_acls = sorted(acllist,
                                             key=lambda item: item["parentID"])
                        for key, group in itertools.groupby(
                                sorted_acls, lambda item: item["parentID"]):
                            update_rule_list = []
                            for item in group:
                                update_rule_list.append(item['ID'])
                            update = True
                            for rule in update_rule_list:
                                update_in_rule =  (
                                    "/ingressaclentrytemplates/"+rule+
                                    "?responseChoice=1")
                                #update the rule to stateful=true and
                                # protocol
                                #set to any
                                if update:
                                    update = False
                                    data = {
                                        "reflexive": True,
                                        "stateful": True,
                                        "protocol": "ANY",
                                        "sourcePort": None,
                                        "destinationPort": None
                                    }
                                    response = (
                                        self.nuageclient.restproxy.rest_call(
                                            'PUT', update_in_rule, data=data))
                                    self.validate(response, 'PUT', rule,
                                                  sgrule['id'])
                                else:
                                    #delete the remaining rules with the
                                    # same neutron ANY rule id as external ID
                                    response = (
                                        self.nuageclient.restproxy.rest_call(
                                            'DELETE', update_in_rule, ''))
                                    self.validate(response, 'DELETE', rule,
                                                  sgrule['id'])
                    if eg_response[3]:
                        # these are the extra ICMP rules created in opposite
                        #  direction. Delete all these ICMP rules.
                        acllist = eg_response[3]
                        for key, group in itertools.groupby(
                                acllist, lambda item: item["parentID"]):
                            for item in group:
                                delete_rule_list.append(item['ID'])
                        for rule in delete_rule_list:
                            delete_eg_rule = ("/egressaclentrytemplates/"+
                                              rule+"?responseChoice=1")
                            response = self.nuageclient.restproxy.rest_call(
                                'DELETE', delete_eg_rule, '')
                            self.validate(response, 'DELETE', rule,
                                          sgrule['id'])
                elif sgrule['direction'] == 'ingress':
                    if eg_response[3]:
                        acllist = eg_response[3]
                        sorted_acls = sorted(acllist,
                                             key=lambda item: item["parentID"])
                        for key, group in itertools.groupby(
                                sorted_acls, lambda item: item["parentID"]):
                            update_rule_list = []
                            for item in group:
                                update_rule_list.append(item['ID'])
                            update = True
                            for rule in update_rule_list:
                                update_eg_rule =  (
                                    "/egressaclentrytemplates/"+rule+
                                    "?responseChoice=1")
                                if update:
                                    update = False
                                    data = {
                                        "reflexive": True,
                                        "stateful": True,
                                        "protocol": "ANY",
                                        "sourcePort": None,
                                        "destinationPort": None
                                    }
                                    response = (
                                        self.nuageclient.restproxy.rest_call(
                                            'PUT', update_eg_rule, data=data))
                                    self.validate(response, 'PUT', rule,
                                                  sgrule['id'])
                                else:
                                    #delete the remaining rules with the
                                    # same neutron ANY rule id as external ID
                                    response = (
                                        self.nuageclient.restproxy.rest_call(
                                            'DELETE', update_eg_rule, ''))
                                    self.validate(response, 'DELETE', rule,
                                                  sgrule['id'])
                    if in_response[3]:
                        acllist = in_response[3]
                        for key, group in itertools.groupby(
                                acllist, lambda item: item["parentID"]):
                            for item in group:
                                delete_rule_list.append(item['ID'])
                            for rule in delete_rule_list:
                                delete_in_rule =(
                                    "/ingressaclentrytemplates/"+rule+
                                    "?responseChoice=1")
                                response = (
                                    self.nuageclient.restproxy.rest_call(
                                        'DELETE', delete_in_rule, ''))
                                self.validate(response, 'DELETE', rule,
                                              sgrule['id'])
            except Exception as e:
                LOG.error(str(e))


    def update_icmp_rules(self):
        sgrules = sg_rules = self.get_security_group_rules(
                        self.context,
                        {'protocol': ['icmp']})
        for sgrule in sgrules:
            try:
                ingress_url_str = ("/ingressaclentrytemplates" +
                                   "?responseChoice=1")
                egress_url_str = ("/egressaclentrytemplates"+
                                  "?responseChoice=1")
                headers = {}
                extra_headers = "externalID IS '%s@%s'" % (sgrule['id'],
                                                           self.cms_id)
                headers['X-Nuage-Filter'] = extra_headers

                in_response = self.nuageclient.restproxy.rest_call(
                    'GET', ingress_url_str, '', extra_headers=headers)
                eg_response = self.nuageclient.restproxy.rest_call(
                    'GET', egress_url_str, '', extra_headers=headers)
                update_rule_list = []
                delete_rule_list = []

                if sgrule['direction'] == 'egress':
                    if in_response[3]:
                        acllist = in_response[3]
                        for key, group in itertools.groupby(
                                acllist, lambda item: item["parentID"]):
                            for item in group:
                                update_rule_list.append(item['ID'])
                    if eg_response[3]:
                        acllist = eg_response[3]
                        for key, group in itertools.groupby(
                                acllist, lambda item: item["parentID"]):
                            for item in group:
                                delete_rule_list.append(item['ID'])

                    for rule in update_rule_list:
                        # rules with ICMPCode and ICMPType None
                        # do nothing
                        update_in_rule =  ("/ingressaclentrytemplates/"+rule+
                                           "?responseChoice=1")
                        if (not sgrule['port_range_min']):
                            continue
                        elif (sgrule['port_range_min'] in STATEFUL_ICMP_TYPES):
                            data = {
                                "stateful": True,
                                "ICMPType": sgrule['port_range_min'],
                                "ICMPCode": sgrule['port_range_max']
                            }
                            response = self.nuageclient.restproxy.rest_call(
                                'PUT', update_in_rule, data=data)
                            self.validate(response, 'PUT', rule, sgrule['id'])
                        elif (sgrule['port_range_min'] not in
                                  STATEFUL_ICMP_TYPES):
                            data = {
                                "ICMPType": sgrule['port_range_min'],
                                "ICMPCode": sgrule['port_range_max']
                            }
                            response = self.nuageclient.restproxy.rest_call(
                                'PUT', update_in_rule, data=data)
                            self.validate(response, 'PUT', rule, sgrule['id'])

                    for rule in delete_rule_list:
                        delete_eg_rule = ("/egressaclentrytemplates/"+rule+
                                          "?responseChoice=1")
                        if (not sgrule['port_range_min']):
                            continue
                        elif (sgrule['port_range_min'] in STATEFUL_ICMP_TYPES):
                            response = self.nuageclient.restproxy.rest_call(
                                'DELETE', delete_eg_rule, '')
                            self.validate(response, 'DELETE', rule,
                                          sgrule['id'])
                        elif (sgrule['port_range_min'] not in
                                  STATEFUL_ICMP_TYPES):
                            data = {
                                "ICMPType": sgrule['port_range_min'],
                                "ICMPCode": sgrule['port_range_max']
                            }
                            response = self.nuageclient.restproxy.rest_call(
                                'PUT', delete_eg_rule, data=data)
                            self.validate(response, 'PUT', rule, sgrule['id'])
                elif sgrule['direction'] == 'ingress':
                    if eg_response[3]:
                        acllist = eg_response[3]
                        for key, group in itertools.groupby(
                                acllist, lambda item: item["parentID"]):
                            for item in group:
                                update_rule_list.append(item['ID'])
                    if in_response[3]:
                        acllist = in_response[3]
                        for key, group in itertools.groupby(
                                acllist, lambda item: item["parentID"]):
                            for item in group:
                                delete_rule_list.append(item['ID'])
                    for rule in update_rule_list:
                        update_eg_rule =  ("/egressaclentrytemplates/"+rule+
                                           "?responseChoice=1")
                        if (not sgrule['port_range_min']):
                            continue
                        elif (sgrule['port_range_min'] in STATEFUL_ICMP_TYPES):
                            data = {
                                "stateful": True,
                                "ICMPType": sgrule['port_range_min'],
                                "ICMPCode": sgrule['port_range_max']
                            }
                            response = self.nuageclient.restproxy.rest_call(
                                'PUT', update_eg_rule, data=data)
                            self.validate(response, 'PUT', rule, sgrule['id'])
                        elif (sgrule['port_range_min'] not in
                                  STATEFUL_ICMP_TYPES):
                            data = {
                                "ICMPType": sgrule['port_range_min'],
                                "ICMPCode": sgrule['port_range_max']
                            }
                            response = self.nuageclient.restproxy.rest_call(
                                'PUT', update_eg_rule, data=data)
                            self.validate(response, 'PUT', rule, sgrule['id'])

                    for rule in delete_rule_list:
                        delete_in_rule = ("/ingressaclentrytemplates/"+rule+
                                          "?responseChoice=1")
                        if (not sgrule['port_range_min']):
                            continue
                        elif (sgrule['port_range_min'] in STATEFUL_ICMP_TYPES):
                            response = self.nuageclient.restproxy.rest_call(
                                'DELETE', delete_in_rule, '')
                            self.validate(response, 'DELETE', rule,
                                          sgrule['id'])
                        elif (sgrule['port_range_min'] not in
                                  STATEFUL_ICMP_TYPES):
                            data = {
                                "ICMPType": sgrule['port_range_min'],
                                "ICMPCode": sgrule['port_range_max']
                            }
                            response = self.nuageclient.restproxy.rest_call(
                                'PUT', delete_in_rule, data=data)
                            self.validate(response, 'PUT', rule, sgrule['id'])
            except Exception as e:
                LOG.error(str(e))


def main():
    parser = argparse.ArgumentParser()
    requiredNamed = parser.add_argument_group('mandatory arguments')
    requiredNamed.add_argument("--config-file",
                               nargs='+',
                               help='List of config files separated by space')
    args = parser.parse_args()

    if sys.argv[1:].count('--config-file') != 1:
        parser.print_help()
        return

    conffiles = args.config_file
    if conffiles is None:
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
    LOG.setLevel(logging.INFO)

    conf_list = []
    for conffile in conffiles:
        if not os.path.isfile(conffile):
            LOG.error('File "%s" cannot be found.' % conffile)
            return
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
    cms_id = cfg.CONF.RESTPROXY.cms_id
    if not cms_id:
        raise cfg.ConfigFileValueError(
            _('Missing cms_id in configuration.'))
    nuageclientinst = importutils.import_module('nuagenetlib.nuageclient')
    nuageclient = nuageclientinst.NuageClient(cms_id=cms_id,
                                              server=server,
                                              base_uri=base_uri,
                                              serverssl=serverssl,
                                              serverauth=serverauth,
                                              auth_resource=auth_resource,
                                              organization=organization)
    try:
        UpdatePGRules(nuageclient, cms_id).update_pg_rules()
    except Exception as e:
        LOG.error("Error in updating pg rules:%s", str(e))
        return

if __name__ == '__main__':
    main()
