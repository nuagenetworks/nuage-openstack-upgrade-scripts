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

from oslo.config import cfg

from restproxy import RESTProxyServer

LOG = logging.getLogger('Upgrade_Logger')
REST_SUCCESS_CODES = range(200, 207)
ENTITY_TYPE_TO_URL = {
    'ME': 'me',
    'ENTERPRISE': 'enterprise',
    'GROUP': 'groups',
    'USER': 'users',
    'L2DOMAIN_TEMPLATE': 'l2domaintemplates',
    'DOMAIN_TEMPLATE': 'domaintemplates',
    'ZONE_TEMPLATE': 'zonetemplates',
    'INGRESS_ACLTEMPLATES': 'ingressacltemplates',
    'INGRESS_ACLTEMPLATES_ENTRIES': 'ingressaclentrytemplates',
    'EGRESS_ACLTEMPLATES': 'egressacltemplates',
    'EGRESS_ACLTEMPLATES_ENTRIES': 'egressaclentrytemplates',
    'EGRESS_FIP_ACLTEMPLATES': 'egressfloatingipacltemplates',
    'FIP_RATE_LIMITING_QOS': 'qos',
    'DOMAIN': 'domains',
    'ZONE': 'zones',
    'SUBNET': 'subnets',
    'ADDRESS_RANGE': 'addressranges',
    'L2DOMAIN': 'l2domains',
    'VM': 'vm',
    'VM_INTERFACE': 'vminterfaces',
    'SHARED_NETWORK': 'sharednetworkresources',
    'FLOATING_IP': 'floatingips',
    'VPORT': 'vports',
    'ENTERPRISE_NTWK_MACRO': 'enterprisenetworks',
    'ENTERPRISE_PROFILE': 'enterpriseprofiles',
    'DHCP_OPTIONS': 'dhcpoptions',
    'CLOUD_MGMT_SYSTEMS': 'cms',
    'POLICY_GROUP_TEMPLATE': 'policygrouptemplates',
    'POLICY_GROUP': 'policygroups'
}
CMS_DESCRIPTION = re.compile("\[cmsId\] expected: (.*), found: null")


class CmsUpdateExternalIDs(object):

    def __init__(self, restproxy, audit_file):
        super(CmsUpdateExternalIDs, self).__init__()
        self.restproxy = restproxy
        self.discrepancies = []
        self.read_audit_file(audit_file)

    def upgrade_cms_id(self):
        put = self.restproxy.rest_call
        LOG.info("Processing %s updates..." % len(self.discrepancies))
        for idx, delta in enumerate(self.discrepancies):
            if (1 + idx) % 100 == 0:
                percent = (100 * (idx + 1) / len(self.discrepancies))
                LOG.info("Processing update #%s (%s%%)." % (idx + 1, percent))

            resource = ENTITY_TYPE_TO_URL.get(delta.get('vsp_type'))
            id = delta.get('vsp_id')
            description = delta.get('description')
            match = CMS_DESCRIPTION.match(description)
            if not match:
                continue
            cms_id = match.group(1)
            url = "/cms/%s/%s/%s" % (cms_id, resource, id)
            try:
                response = put('PUT', url, '')
                if response[0] not in REST_SUCCESS_CODES:
                    msg = ("PUT %s did not return successfully. %s"
                           % (url, str(response[0]) + str(response[3])))
                    LOG.error(msg)
            except Exception:
                msg = "Error setting cms ID for %s %s" % (resource, id)
                LOG.exception(msg)
        LOG.info("Processing finished")

    def read_audit_file(self, file):
        with open(file, 'r') as in_stream:
            yaml_input = yaml.load(in_stream)
        if yaml_input:
            self.discrepancies = yaml_input.get('discrepancies')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--audit-file", required=True,
                        help='A audit file from CloudStack sync or '
                             'generate_audit_file.py')
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

    updater = CmsUpdateExternalIDs(restproxy, audit_file)
    updater.upgrade_cms_id()
    LOG.debug("Setting CMS ID is now complete")


if __name__ == '__main__':
    main()
