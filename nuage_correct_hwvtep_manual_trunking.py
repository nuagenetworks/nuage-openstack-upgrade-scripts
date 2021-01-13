# Copyright 2021 NOKIA
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
File: nuage_correct_hwvtep_manual_trunking.py

Purpose:
    For certain deployments manual provisioning of HWVTEP trunking bridgeports
    in VSP was executed.
    This correction script corrects the manually provisioned bridge ports by
    providing an external id. It also will populate the switch port binding
    table of nuage openstack neutron, to make sure future operations can be
    done correctly.

Requirement:
    This script requires two configuration files.
    1. nuage_plugin.ini : which has details to connect to VSD
    2. neutron.conf : which has details to connect to neutron database.
    The optional argument --dry-run is to run the correction script in
    dry-run mode and generate a correction report.

    This script can only be ran on request by Nuage support teams, and is not
    part of normal upgrade operations.

Run:
    python nuage_correct_hwvtep_manual_trunking.py
      --neutron-conf <neutron.conf>
      --neutron-ml2-conf <ml2.ini>
      --nuage-conf <nuage_plugin.ini> [--dry-run]
****************************************************************************"""
import argparse
import logging
import os
import sys

from neutron.common import config
from neutron.conf.plugins.ml2 import config as ml2_config
from neutron.services.trunk.models import Trunk
from neutron.db.models_v2 import Network

# Value of external key in network is a ExternalNetwork object
# which only appears when below import is added
# It also makes the networksegments table visible in Queens
from neutron.objects import network as network_object  # noqa

from nuage_neutron.plugins.common import config as nuage_config
from nuage_neutron.plugins.common.nuage_models import NuageSwitchportBinding
from nuage_neutron.plugins.common.nuage_models import SubnetL2Domain
from oslo_config import cfg

from utils import nuage_logging
from utils.restproxy import RESTProxyServer

try:
    from neutron import context as neutron_context
except ImportError:
    from neutron_lib import context as neutron_context

SCRIPT_NAME = 'nuage_correct_hwvtep_manual_trunking.py'

LOG = logging.getLogger(SCRIPT_NAME)


class CorrectHWVTEPTrunking(object):

    # dict vport ID -> vport external id
    vport_external_ids = {}
    # dict bridge interface ID -> bridge interface external id
    br_int_external_ids = {}
    # dict vlan ID -> vsd vlan external id
    vlan_external_ids = {}

    def __init__(self, restproxy, is_dry_run):
        self.cms_id = cfg.CONF.RESTPROXY.cms_id
        if not self.cms_id:
            raise cfg.ConfigFileValueError('Missing cms_id in configuration.')
        self.restproxy = restproxy
        self.is_dry_run = is_dry_run
        self.is_fatal_warn = False
        self.has_warnings = False

    def bulk_put(self, resource, data):
        if not self.is_dry_run:
            self.restproxy.bulk_put(resource, data)

    def warn(self, msg):
        self.has_warnings = True
        LOG.user('WARN: ' + msg)  # LOG.warn does not print to console

    def fatal_warn(self, msg):
        self.warn(msg)
        self.is_fatal_warn = True

    @staticmethod
    def _is_l2(subnet_mapping):
        return bool(subnet_mapping['nuage_l2dom_tmplt_id'])

    @staticmethod
    def _get_vlan_from_network(network):
        segment = network.segments[0]
        if segment['network_type'] != 'vlan':
            return None
        else:
            return segment['segmentation_id']

    @nuage_logging.step(description='Correcting manually deployed trunking '
                                    'infrastructure for HWVTEP')
    def correct(self):
        """Correct

        For all trunks which are bound:
            For all associated SwitchPortBindings for the parent port
                For all subports:
                    Retrieve appropriate vport/vminterface
                    Update external id (done through bulk put)
                    Insert SwitchPortBinding
        """
        context = neutron_context.get_admin_context()
        session = context.session
        trunks = session.query(Trunk).all()

        # Only consider trunks with a bound parent_port
        for trunk in trunks:
            if not trunk.port.device_id:
                continue
            parent_port = trunk.port
            parent_bindings = session.query(NuageSwitchportBinding).filter(
                NuageSwitchportBinding.neutron_port_id ==
                parent_port.id).all()
            # There can be multiple vports associated to parent_port,
            # as per Active/Standby Scenario's.
            for parent_binding in parent_bindings:
                parent_vports = self.restproxy.get(
                    '/vports/%s' % parent_binding.nuage_vport_id)
                if not parent_vports:
                    self.fatal_warn("VPORT not found for vport ID {}".format(
                        parent_binding.nuage_vport_id))
                    continue
                parent_vport = parent_vports[0]

                for sub_port in trunk.sub_ports:
                    subnet_id = sub_port.port.fixed_ips[0].subnet_id
                    subnet_mapping = session.query(SubnetL2Domain).filter_by(
                        subnet_id=subnet_id).first()

                    network = session.query(Network).get(
                        sub_port.port.network_id)
                    subport_network_vlan = self._get_vlan_from_network(network)
                    if subport_network_vlan is None:
                        self.warn("Subport {} not processed as network does "
                                  "not have vlan segment as first "
                                  "segment.".format(sub_port['port_id']))
                        continue

                    vport = self._get_sub_vport(parent_vport, subnet_mapping,
                                                subport_network_vlan)
                    if not vport:
                        self.fatal_warn("Vport not found for sub_port "
                                        "{}.".format(sub_port['port_id']))
                        continue

                    bridgeinterfaces = self.restproxy.get(
                        '/vports/%s/bridgeinterfaces' % vport['ID'])
                    if not bridgeinterfaces:
                        self.fatal_warn("Bridge Interface not found for "
                                        "sub_port {}.".format(
                                            sub_port['port_id']))
                        continue
                    bridgeinterface = bridgeinterfaces[0]

                    vsd_vlans = self.restproxy.get('/vlans/%s' %
                                                   vport['VLANID'])
                    if not vsd_vlans:
                        self.fatal_warn("VSD vlan not found for "
                                        "sub_port {}.".format(
                                            sub_port['port_id']))
                        continue
                    vsd_vlan = vsd_vlans[0]

                    # Correct external ID
                    self._update_ext_id_dicts(network, sub_port, vport,
                                              bridgeinterface, vsd_vlan)

                    # Insert switchport binding
                    self._insert_switchport_binding(session, parent_binding,
                                                    sub_port,
                                                    subport_network_vlan,
                                                    vport)
            # PUT external ID updates to VSD
            self._put_external_id_updates()

    def _insert_switchport_binding(self, session, parent_binding, sub_port,
                                   subport_network_vlan, vport):
        existing_binding = session.query(NuageSwitchportBinding).filter(
            NuageSwitchportBinding.neutron_port_id ==
            sub_port['port_id'],
            NuageSwitchportBinding.nuage_vport_id == vport['ID'],
            NuageSwitchportBinding.switchport_uuid ==
            parent_binding['switchport_uuid'],
            NuageSwitchportBinding.segmentation_id == subport_network_vlan,
            NuageSwitchportBinding.switchport_mapping_id ==
            parent_binding['switchport_mapping_id']).all()
        if existing_binding:
            LOG.user(
                'Found existing binding for subport '
                '%s.', sub_port['port_id'])
            return

        sub_binding = NuageSwitchportBinding(
            neutron_port_id=sub_port['port_id'],
            nuage_vport_id=vport['ID'],
            switchport_uuid=parent_binding['switchport_uuid'],
            segmentation_id=subport_network_vlan,
            switchport_mapping_id=parent_binding['switchport_mapping_id'])
        binding_log = ', '.join(["{}:{}".format(row[0], row[1]) for row in
                                 sub_binding])
        LOG.user(
            'Database insert NuageSwitchPortBinding: '
            '%s.', binding_log)
        if not self.is_dry_run:
            session.add(sub_binding)
            session.flush()

    def _update_ext_id_dicts(self, network, sub_port, vport, bridgeinterface,
                             vsd_vlan):
        """_update_ext_id_dicts

        Calculate appropriate external id for vport, bridge interface and vlan.
        Store this in vport_external_ids, br_int_external_ids
        and vlan_external_ids for future bulk PUT call to VSD.
        """
        vport_ext_id = br_int_ext_id = self._get_external_id(
            network['id'])
        vlan_ext_id = self._get_external_id(
            vsd_vlan['parentID'] + '.' + str(vsd_vlan['value']))
        if vport_ext_id != vport['externalID']:
            LOG.user("Adding external id %s for VPORT "
                     "for subport %s.", vport_ext_id,
                     sub_port['port_id'])
            self.vport_external_ids[vport['ID']] = vport_ext_id
        else:
            LOG.user("External id %s for VPORT "
                     "for subport %s already present.", vport_ext_id,
                     sub_port['port_id'])
        if br_int_ext_id != bridgeinterface['externalID']:
            LOG.user("Adding external id %s for bridge "
                     "interface for subport %s.",
                     br_int_ext_id, sub_port['port_id'])
            self.br_int_external_ids[bridgeinterface['ID']] = br_int_ext_id
        else:
            LOG.user("External id %s for bridge "
                     "interface for subport %s already present.",
                     br_int_ext_id, sub_port['port_id'])
        if vlan_ext_id != vsd_vlan['externalID']:
            LOG.user("Adding external id %s for vlan "
                     "for subport %s.",
                     vlan_ext_id, sub_port['port_id'])
            self.vlan_external_ids[vsd_vlan['ID']] = vlan_ext_id
        else:
            LOG.user("External id %s for vlan "
                     "for subport %s already present.",
                     vlan_ext_id, sub_port['port_id'])

    def _get_sub_vport(self, parent_vport, subnet_mapping,
                       subport_network_vlan):
        if self._is_l2(subnet_mapping):
            resource = 'l2domains'
            vsd_domain_id = subnet_mapping['nuage_subnet_id']
        else:
            resource = 'domains'
            vsd_domain_id = self.get_router_id_by_subnet(
                subnet_mapping['nuage_subnet_id'])
        nuage_filter = ("associatedGatewayID IS '{}' AND "
                        "gatewayPortName IS '{}'")
        headers = {
            'X-NUAGE-FilterType': 'predicate',
            'X-Nuage-Filter': nuage_filter.format(
                parent_vport['associatedGatewayID'],
                parent_vport['gatewayPortName'],
            )}
        vports = self.restproxy.get(
            '/%s/%s/vports' % (resource, vsd_domain_id),
            extra_headers=headers)
        # There is no possibility of filtering on VLAN in VSD api so we do it
        # manually
        vports = [vport for vport in vports if
                  vport['VLAN'] == subport_network_vlan]
        return vports[0] if vports else None

    def _put_external_id_updates(self):
        if not self.is_dry_run:
            vport_put_info = [{'ID': vport_id,
                               'externalID': self.vport_external_ids[vport_id]}
                              for vport_id in self.vport_external_ids]
            if vport_put_info:
                self.bulk_put('/vports/?responseChoice=1',
                              vport_put_info)
            br_int_put_info = [
                {'ID': br_int_id,
                 'externalID': self.br_int_external_ids[br_int_id]}
                for br_int_id in self.br_int_external_ids]
            if br_int_put_info:
                self.bulk_put('/bridgeinterfaces/?responseChoice=1',
                              br_int_put_info)
            vlan_put_info = [{'ID': vlan_id,
                              'externalID': self.vlan_external_ids[vlan_id]}
                             for vlan_id in self.vlan_external_ids]
            if vlan_put_info:
                self.bulk_put('/vlans/?responseChoice=1',
                              vlan_put_info)

    def _get_external_id(self, neutron_id):
        return neutron_id + '@' + self.cms_id

    def get_router_id_by_subnet(self, subnet_vsd_id):
        response = self.restproxy.get('/subnets/%s' % subnet_vsd_id)
        zone_response = self.restproxy.get('/zones/%s' %
                                           response[0]['parentID'])
        return zone_response[0]['parentID']


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--neutron-conf',
                        required=True,
                        help='File path to the neutron configuration file')
    parser.add_argument('--neutron-ml2-conf',
                        required=True,
                        help='File path to the neutron ml2 plugin '
                             'configuration file')
    parser.add_argument('--nuage-conf',
                        required=True,
                        help='File path to the nuage plugin configuration '
                             'file')
    parser.add_argument('--dry-run',
                        action='store_true',
                        help='Run the correction script in dry-run mode')
    args = parser.parse_args()

    if not nuage_logging.log_file:
        nuage_logging.init_logging(SCRIPT_NAME)

    conf_list = []
    for conffile in (args.neutron_conf, args.neutron_ml2_conf,
                     args.nuage_conf):
        if not os.path.isfile(conffile):
            LOG.user("File '%s' cannot be found." % conffile)
            sys.exit(1)
        conf_list.append('--config-file')
        conf_list.append(conffile)

    config.init(conf_list)
    ml2_config.register_ml2_plugin_opts()
    nuage_config.nuage_register_cfg_opts()

    server = cfg.CONF.RESTPROXY.server
    serverauth = cfg.CONF.RESTPROXY.serverauth
    serverssl = cfg.CONF.RESTPROXY.serverssl
    base_uri = cfg.CONF.RESTPROXY.base_uri
    auth_resource = cfg.CONF.RESTPROXY.auth_resource
    organization = cfg.CONF.RESTPROXY.organization
    verify_cert = cfg.CONF.RESTPROXY.verify_cert

    deployed_mech_drivers = cfg.CONF.ml2.mechanism_drivers
    deployed_mech_drivers = ''.join(deployed_mech_drivers).lower()
    if 'hwvtep' not in deployed_mech_drivers:
        LOG.user("Can't execute correction because ml2 is not configured "
                 "with HWVTEP. This correction script is only valid for "
                 "HWVTEP deployments. ".format(base_uri))
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
            LOG.user('Starting dry-run for HWVTEP trunk correction\n')
        else:
            LOG.user('Executing HWVTEP trunk correction\n')

        correction = CorrectHWVTEPTrunking(restproxy, args.dry_run)
        correction.correct()

        if args.dry_run:
            if correction.has_warnings:
                LOG.user('Dry-run finished with warnings/errors raised.\n'
                         'Please inspect the logs, as corrective '
                         'actions are needed before running in '
                         'production mode.')
            else:
                LOG.user('Dry-run finished without any warnings raised.\n'
                         'System is good to be corrected.')
        else:
            if correction.has_warnings:
                msg = ("The correction finished with warnings raised.\n"
                       "Please inspect the logs, as further corrective "
                       "actions are needed. ")
                if correction.is_fatal_warn:
                    LOG.user(msg + 'Please re-run after applying those.')
                else:
                    LOG.user(msg + 'No need to re-run the script.')
            else:
                LOG.user('The correction executed successfully.')

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
