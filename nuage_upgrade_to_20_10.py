# Copyright 2020 NOKIA
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
File: nuage_upgrade_to_20_10.py

Purpose:
    The Proprietary FIP QOS extension moves from a QOS object
    attached to the vPort to RateLimiter objects attached to
    the FIP itself.

Requirement:
    This script requires two configuration files.
    1. nuage_plugin.ini : which has details to connect to VSD
    2. neutron.conf : which has details to connect to neutron database.
Run:
    python nuage_upgrade_to_20_10.py --neutron-conf <neutron.conf>
      --nuage-conf <nuage_plugin.ini>
****************************************************************************"""
import argparse
import json
import logging
import os
import sys

from neutron.common import config
from neutron.db.models.l3 import FloatingIP
from neutron.db.models_v2 import Port
from nuage_neutron.plugins.common import config as nuage_config
from nuage_neutron.plugins.common import constants
from nuage_neutron.plugins.common.nuage_models import SubnetL2Domain
from nuage_neutron.vsdclient.common import constants as vsd_constants
from oslo_config import cfg

from utils import nuage_logging
from utils.restproxy import RESTProxyServer

try:
    from neutron import context as neutron_context
except ImportError:
    from neutron_lib import context as neutron_context

SCRIPT_NAME = 'nuage_upgrade_to_20_10.py'
REPORT_NAME = 'upgrade_report.json'

LOG = logging.getLogger(SCRIPT_NAME)

VIP_DEVICE_OWNERS = (
    [constants.DEVICE_OWNER_VIP_NUAGE,
     constants.DEVICE_OWNER_OCTAVIA,
     constants.DEVICE_OWNER_IRONIC] +
    cfg.CONF.PLUGIN.device_owner_prefix)


class UpgradeTo20Dot10(object):

    def __init__(self, restproxy):
        self.cms_id = cfg.CONF.RESTPROXY.cms_id
        if not self.cms_id:
            raise cfg.ConfigFileValueError('Missing cms_id in configuration.')
        self.restproxy = restproxy
        self.output = {}
        self.is_fatal_warn = False

    @staticmethod
    def has_vport_for_fip_association(device_owner):
        return device_owner not in VIP_DEVICE_OWNERS

    def bulk_post(self, resource, data, ignore_error_codes):
        self.output_store('BULK POST: ' + str(resource), 'INFO')
        return self.restproxy.bulk_post(resource, data,
                                        ignore_err_codes=ignore_error_codes)

    def bulk_put(self, resource, data):
        self.output_store('BULK PUT: ' + str(resource), 'INFO')
        self.restproxy.bulk_put(resource, data)

    def bulk_delete(self, resource, data):
        self.output_store('BULK DELETE: ' + str(resource), 'INFO')
        self.restproxy.bulk_delete(resource, data)

    def output_store(self, data, data_type):
        if self.output.get(data_type):
            self.output[data_type].append(data)
        else:
            self.output[data_type] = [data]

    def _get_external_id(self, neutron_id):
        return neutron_id + '@' + self.cms_id

    def _get_external_id_header(self, neutron_id):
        headers = {
            'X-NUAGE-FilterType': 'predicate',
            'X-Nuage-Filter': "externalID IS '{}'".format(
                self._get_external_id(neutron_id))
        }
        return headers

    @nuage_logging.step(description='updating object model for '
                                    'OpenStack 20.10 release')
    def upgrade(self):
        context = neutron_context.get_admin_context()
        session = context.session

        # Get all floating ips with attached port
        floatingips = session.query(FloatingIP).filter(
            FloatingIP.fixed_port_id.isnot(None)).all()
        # ratelimiters is a list of to be created ratelimiters
        ratelimiters = []
        qos_ids_to_be_deleted = []
        for fip in floatingips:
            fixed_port_id = fip['fixed_port_id']
            fixed_port = session.query(Port).get(fixed_port_id)
            if self.has_vport_for_fip_association(fixed_port['device_owner']):
                # calculate domain id
                subnet_id = fixed_port['fixed_ips'][0]['subnet_id']
                mapping = session.query(SubnetL2Domain).filter_by(
                    subnet_id=subnet_id).first()
                nuage_subnet_id = mapping['nuage_subnet_id']

                # GET vPort object
                headers = self._get_external_id_header(fixed_port['id'])
                response = self.restproxy.get(
                    '/subnets/%s/vports' % nuage_subnet_id,
                    extra_headers=headers)
                nuage_vport = response[0]
                # GEt QOS object
                headers = self._get_external_id_header(fip['id'])
                response = self.restproxy.get(
                    '/vports/%s/qos' % nuage_vport['ID'],
                    extra_headers=headers)
                if not response:
                    # No QOS to be transferred
                    continue
                qos = response[0]
                qos_ids_to_be_deleted.append(qos['ID'])
                # calculate relevant QOS attributes
                nuage_egress_rate_limit = qos['EgressFIPPeakInformationRate']
                nuage_ingress_rate_limit = qos['FIPPeakInformationRate']
                if nuage_egress_rate_limit != vsd_constants.INFINITY:
                    rl = self._get_ratelimiter_for_fip_rate_limit(
                        fip, nuage_egress_rate_limit, nuage_vport, 'egress')
                    ratelimiters.append(rl)
                if nuage_ingress_rate_limit != vsd_constants.INFINITY:
                    rl = self._get_ratelimiter_for_fip_rate_limit(
                        fip, nuage_ingress_rate_limit, nuage_vport, 'ingress')
                    ratelimiters.append(rl)

        # Create Ratelimiters
        bulk_rls = [{
            'peakInformationRate': rl['peakInformationRate'],
            'name': rl['name'],
            'description': rl['description'],
            'externalID': rl['externalID'],
            # Defaults
            'peakBurstSize': 100,
            'committedInformationRate': 0
        } for rl in ratelimiters]
        created_rls = self.bulk_post('/ratelimiters/?responseChoice=1',
                                     bulk_rls, ignore_error_codes=[9105])

        # Associate ratelimiters to floating ips
        fip_updates = {}
        for i in range(len(ratelimiters)):
            rl = ratelimiters[i]
            if not fip_updates.get(rl['nuage_floatingip_id']):
                fip_updates[rl['nuage_floatingip_id']] = {
                    'ID': rl['nuage_floatingip_id']}
            fip_updates[rl['nuage_floatingip_id']][
                rl['nuage_fip_attribute']] = created_rls[i]['data']['ID']
        self.bulk_put('/floatingips/?responseChoice=1',
                      list(fip_updates.values()))

        # Delete existing QOS objects
        self.bulk_delete('/qos/?responseChoice=1', qos_ids_to_be_deleted)

    def _get_ratelimiter_for_fip_rate_limit(self, fip, nuage_rate_limit,
                                            nuage_vport, direction):
        rl_name = '{}_{}'.format(direction, fip['id'])
        rl = {
            'nuage_floatingip_id':
                nuage_vport['associatedFloatingIPID'],
            'nuage_fip_attribute': '{}RateLimiterID'.format(direction),
            'peakInformationRate': nuage_rate_limit,
            'name': rl_name,
            'description': 'Openstack FIP Rate Limiter for '
                           'FIP {}, vsd direction: '
                           '{}.'.format(fip['id'], direction),
            'externalID': self._get_external_id(rl_name)
        }
        return rl


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--neutron-conf',
                        required=True,
                        help='File path to the neutron configuration file')
    parser.add_argument('--nuage-conf',
                        required=True,
                        help='File path to the nuage plugin configuration '
                             'file')
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
        LOG.user('Upgrading resources for 20.10 support\n')

        upgrade = UpgradeTo20Dot10(restproxy)

        with open(REPORT_NAME, 'w') as outfile:
            output = upgrade.upgrade()
            json.dump(output, outfile, indent=4, sort_keys=True)

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
