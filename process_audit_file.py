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
import re
import logging
import logging.handlers
import os
import sys
import vsdclient_config
import yaml
from oslo_config import cfg

from restproxy import RESTProxyServer

LOG = logging.getLogger('Upgrade_Logger')
REST_SUCCESS_CODES = range(200, 207)
ENTITY_TYPE_TO_URL = {
    'ADDRESS_RANGE': 'addressranges',
    'CLOUD_MGMT_SYSTEMS': 'cms',
    'DHCP_OPTIONS': 'dhcpoptions',
    'DOMAIN': 'domains',
    'DOMAIN_TEMPLATE': 'domaintemplates',
    'EGRESS_ACLTEMPLATES': 'egressacltemplates',
    'EGRESS_ACLTEMPLATES_ENTRIES': 'egressaclentrytemplates',
    'EGRESS_FIP_ACLTEMPLATES': 'egressfloatingipacltemplates',
    'ENTERPRISE': 'enterprises',
    'ENTERPRISE_NTWK_MACRO': 'enterprisenetworks',
    'ENTERPRISE_PROFILE': 'enterpriseprofiles',
    'FIP_RATE_LIMITING_QOS': 'qos',
    'FLOATING_IP': 'floatingips',
    'GROUP': 'groups',
    'INGRESS_ACLTEMPLATES': 'ingressacltemplates',
    'INGRESS_ACLTEMPLATES_ENTRIES': 'ingressaclentrytemplates',
    'L2DOMAIN': 'l2domains',
    'L2DOMAIN_TEMPLATE': 'l2domaintemplates',
    'ME': 'me',
    'POLICY_GROUP': 'policygroups',
    'POLICY_GROUP_TEMPLATE': 'policygrouptemplates',
    'SHARED_NETWORK': 'sharednetworkresources',
    'STATICROUTE': 'staticroutes',
    'SUBNET': 'subnets',
    'USER': 'users',
    'VM': 'vms',
    'VM_INTERFACE': 'vminterfaces',
    'VPORT': 'vports',
    'ZONE': 'zones',
    'ZONE_TEMPLATE': 'zonetemplates',
}
CMS_DESCRIPTION = re.compile("\[cmsId\] expected: (.*), found: null")


class CmsUpdateExternalIDs(object):

    def __init__(self, restproxy, audit_file):
        super(CmsUpdateExternalIDs, self).__init__()
        self.restproxy = restproxy
        self.read_audit_file(audit_file)

    def upgrade_cms_id(self, discrepancy):
        put = self.restproxy.rest_call
        resource = ENTITY_TYPE_TO_URL.get(discrepancy.get('vsp_type'))
        id = discrepancy.get('vsp_id')
        description = discrepancy.get('description')
        match = CMS_DESCRIPTION.match(description)
        if not match:
            return
        cms_id = match.group(1)
        url = "/cms/%s/%s/%s" % (cms_id, resource, id)
        try:
            response = put('PUT', url, '')
            if response[0] not in REST_SUCCESS_CODES:
                msg = ("PUT %s did not return successfully. %s"
                       % (url, str(response[0]) + str(response[3])))
                LOG.error(msg)
            else:
                LOG.info("Successfully resolved discrepancy for the VSP ID:"
                         "%s " % id)
        except Exception:
            msg = "Error setting CMS ID for %s %s" % (resource, id)
            LOG.exception(msg)

    def convert(self, input):
        if isinstance(input, unicode):
            return input.encode('utf-8')
        else:
            return input

    def read_audit_file(self, file):
        with open(file, 'r') as in_stream:
            try:
                yaml_parse = yaml.parse(in_stream)
                for event in yaml_parse:
                    if isinstance(event, yaml.ScalarEvent):
                        if self.convert(event.value) == 'discrepancies':
                            if (isinstance(yaml_parse.next(),
                                           yaml.SequenceStartEvent)):
                                LOG.info("Processing CMS ID discrepancies"
                                         " in the audit file...")
                                while True:
                                    attribute = yaml_parse.next()
                                    if (isinstance(attribute,
                                                   yaml.SequenceEndEvent)):
                                        break
                                    if isinstance(attribute, yaml.ScalarEvent):
                                        resource = {}
                                        while not isinstance(
                                                attribute,
                                                yaml.MappingEndEvent):
                                            key = attribute.value
                                            value = yaml_parse.next().value
                                            resource[self.convert(key)] = (
                                                self.convert(value))
                                            attribute = yaml_parse.next()
                                        self.upgrade_cms_id(resource)
                LOG.info("Processed all the CMS ID discrepancies"
                         " in the audit file")
            except SyntaxError as se:
                LOG.error("Syntax Error in the audit file: %s", se)
            except Exception as e:
                LOG.error("Error processing the audit file: %s", e)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--audit-file", required=True,
                        help='An audit file generated from the CMS')
    parser.add_argument("--config-file", required=True,
                        help='Config file containing [restproxy] with vsd '
                             'connection data')
    args = parser.parse_args()
    cfg_file = args.config_file
    audit_file = args.audit_file

    if not audit_file:
        parser.print_help()
        return

    if cfg_file is None:
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

    if not os.path.isfile(cfg_file):
        LOG.error('File "%s" cannot be found.' % cfg_file)
        sys.exit(1)
    if not os.path.isfile(audit_file):
        LOG.error('File "%s" cannot be found.' % audit_file)
        sys.exit(1)
    conf_list = ['--config-file', cfg_file]

    cfg.CONF(conf_list)
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
        LOG.error("Error in connecting to VSD:%s", str(e))
        return

    CmsUpdateExternalIDs(restproxy, audit_file)
    LOG.debug("Setting CMS ID is now complete")


if __name__ == '__main__':
    main()
