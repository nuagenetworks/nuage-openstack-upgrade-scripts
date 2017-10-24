# Copyright 2017 Nokia
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
File: nuage_post_upgrade_to_5_0.py

Purpose:
    For ML2 VSD managed, plugin was not setting the nuage_l2dom_tmplt_id
    in the database. This script will take care in an upgrade
    scenario where the script will check all the VSD managed subnets
    annd have nuage_l2dom_tmplt_id value correctly set in database.
    Also the script will take care of partial ml2 to full ml2 deployment
    and update the DHCP ports accordingly in such upgrade path.
Requirement:
    This script require two configuration files.
    1. nuage_plugin.ini : which has details to connect to VSD
    2. neutron.conf : which has details to connect to neutron database.
Run:
    python nuage_post_upgrade_to_5_0.py --neutron-conf <neutron.conf>
      --nuage-conf <nuage_plugin.ini>
****************************************************************************"""
import argparse
import logging
import os
import subprocess
import sys
import tempfile

from neutron.api.v2 import attributes
from neutron.common import config
from neutron import context as neutron_context
from neutron.ipam.drivers.neutrondb_ipam import driver
from neutron.ipam import exceptions as ipam_exceptions
from neutron import manager
from nuage_neutron.plugins.common import config as nuage_config
from nuage_neutron.plugins.common import nuage_models
from nuage_neutron.plugins.common import nuagedb
from neutron.plugins.common import utils as plugin_utils
from nuage_neutron.plugins.common.nuage_models import SubnetL2Domain
from oslo_config import cfg

from utils import nuage_logging
from utils.restproxy import RESTProxyServer

script_name = 'nuage_post_upgrade_to_5_0.py'
LOG = logging.getLogger(script_name)
dhcp_device_owner = 'network:dhcp:nuage'

REST_SUCCESS_CODES = range(200, 207)


class UpgradePartialML2toFullML2(object):
    def __init__(self, restproxy):
        super(UpgradePartialML2toFullML2, self).__init__()
        self.restproxy = restproxy

    @nuage_logging.step(description="creating DHCP ports to reflect DHCP "
                                    "server IP of VSD L2domains")
    def upgrade(self):
        service_plugins = cfg.CONF.service_plugins
        core_plugin = cfg.CONF.core_plugin
        cfg.CONF.set_override('service_plugins', [])
        cfg.CONF.set_override('core_plugin', 'ml2')
        self.create_dhcp_ports(self.restproxy)
        cfg.CONF.set_override('service_plugins', service_plugins)
        cfg.CONF.set_override('core_plugin', core_plugin)

    def create_dhcp_ports(self, restproxy):
        created = 0
        plugin = manager.NeutronManager.get_plugin()
        context = neutron_context.get_admin_context()
        session = context.session

        l2_vsd_mngd_subnets = (
            session.query(SubnetL2Domain)
                .filter(
                SubnetL2Domain.nuage_managed_subnet.is_(True),
                SubnetL2Domain.nuage_l2dom_tmplt_id.isnot(None)
            )
        ).all()

        for mapping in nuage_logging.iterate(l2_vsd_mngd_subnets, 'subnets'):
            subnet = plugin.get_subnet(context, mapping['subnet_id'])

            dhcp_ip = self._get_vsd_dhcp_ip(restproxy, subnet, mapping)
            if not dhcp_ip:
                LOG.debug("Subnet %(subnet_id)s does not need dhcp port",
                          {'subnet_id': subnet['id']})
                continue

            already_migrated = self._check_existing_ports(context, dhcp_ip,
                                                          plugin, mapping)
            if not already_migrated:
                self._delete_existing_allocation(context, dhcp_ip, subnet)
                self._create_dhcp_port(plugin, context, subnet, dhcp_ip)
                created += 1
        LOG.user("\n  Created %(ports)s DHCP port(s).", {'ports': created})

    def _check_existing_ports(self, context, dhcp_ip, plugin, subnet_mapping):
        existing_ports = plugin.get_ports(
            context,
            filters={
                'fixed_ips': {'subnet_id': [subnet_mapping['subnet_id']],
                              'ip_address': [dhcp_ip]}})
        if len(existing_ports) > 0:
            return self._check_existing_port(existing_ports[0], dhcp_ip,
                                             subnet_mapping)
        return False

    @staticmethod
    def _check_existing_port(port, dhcp_ip, subnet_mapping):
        if port['device_owner'] != dhcp_device_owner:
            msg = ("Port %(id)s with IP %(ip)s already exists without "
                   "device owner %(device_owner)s.")
            raise Exception(msg % {'id': port['id'],
                                   'ip': dhcp_ip,
                                   'device_owner': dhcp_device_owner})
        else:
            LOG.debug("Found existing DHCP port %(port_id)s for subnet "
                      "%(subnet_id)s with ip %(ip)s"
                      % {'port_id': port['id'],
                         'subnet_id': subnet_mapping['subnet_id'],
                         'ip': dhcp_ip})
            return True

    def _get_vsd_dhcp_ip(self, restproxy, subnet, subnet_mapping):
        response = restproxy.get(
            '/l2domains/%s' % subnet_mapping['nuage_subnet_id'])
        if response[0] not in range(200, 207):
            LOG.user("WARNING: Can't find l2domain %(l2domain)s on VSD. The "
                     "neutron subnet %(subnet)s is supposed to be linked to "
                     "this. "
                     % {'l2domain': subnet_mapping['nuage_subnet_id'],
                        'subnet': subnet['id']})
            return None
        l2domain = response[3][0]
        if l2domain['associatedSharedNetworkResourceID']:
            response = restproxy.get(
                '/sharednetworkresources/%s'
                % l2domain['associatedSharedNetworkResourceID'])
            if response[0] not in range(200,207):
                LOG.user("WARNING: Can't find shared_subnet %(shared_subnet)s on VSD."
                         % {'shared_subnet': l2domain['associatedSharedNetworkResourceID']})
                return None
            shared_subnet = response[3][0]
        else:
            shared_subnet = None
        dhcp_ip = self._get_dhcp_ip(subnet, l2domain, shared_subnet)
        return dhcp_ip

    @staticmethod
    def _get_dhcp_ip(subnet, nuage_subnet, shared_subnet):
        nuage_subnet = shared_subnet or nuage_subnet
        if nuage_subnet.get('DHCPManaged', True) is False:
            # Nothing to reserve for L2 unmanaged or L3 subnets
            return
        if subnet['ip_version'] == 6:
            dhcp_ip = nuage_subnet.get('IPv6Gateway')
        else:
            dhcp_ip = nuage_subnet['gateway']
        return dhcp_ip

    @staticmethod
    def _delete_existing_allocation(context, dhcp_ip, subnet):
        LOG.debug("Deleting ip allocation %(ip)s for subnet %(subnet_id)s",
                  {'ip': dhcp_ip, 'subnet_id': subnet['id']})
        ipam_pool = driver.NeutronDbPool(None, context)
        ipam_subnet = ipam_pool.get_subnet(subnet['id'])
        try:
            ipam_subnet.deallocate(dhcp_ip)
        except ipam_exceptions.IpAddressAllocationNotFound:
            pass

    @staticmethod
    def _create_dhcp_port(plugin, context, subnet, ip):
        LOG.debug("Creating DHCP port with ip %(ip)s for subnet %(subnet_id)s",
                  {'ip': ip, 'subnet_id': subnet['id']})
        fixed_ip = [{'ip_address': ip, 'subnet_id': subnet['id']}]
        p_data = {
            'network_id': subnet['network_id'],
            'tenant_id': subnet['tenant_id'],
            'fixed_ips': fixed_ip,
            'device_owner': dhcp_device_owner
        }
        port = plugin_utils._fixup_res_dict(context,
                                            attributes.PORTS,
                                            p_data)
        plugin.create_port(context, {'port': port})


class UpgradeToMl2(object):
    def __init__(self, restproxy, neutron_conf):
        self.restproxy = restproxy
        self.neutron_conf = neutron_conf

    @nuage_logging.step(description="%s.py for upgrade to 5.0 full ML2 "
                                    "plugin" % script_name)
    def upgrade(self):
        UpgradePartialML2toFullML2(self.restproxy).upgrade()

        self._advice_next_steps()
        self._make_diff_files()

    @staticmethod
    def _advice_next_steps():
        LOG.user("Upgrades have finished. To proceed, change your neutron "
                 "configuration file to contain the following:\n")
        with nuage_logging.indentation():
            LOG.user("##################################")
            LOG.user("[DEFAULT]")
            LOG.user("service_plugins = NuagePortAttributes,NuageAPI,"
                     "NuageL3")
            LOG.user("##################################\n")

        LOG.user("Also edit your ml2 configuration file to contain the "
                 "following:\n")
        with nuage_logging.indentation():
            LOG.user("##################################")
            LOG.user("[ml2]")
            LOG.user("extension_drivers = nuage_subnet,nuage_port,"
                     "port_security")
            LOG.user("##################################\n")

        LOG.user("Restart neutron for package and configuration updates "
                 "to take effect.\n")

    def _make_diff_files(self):
        self._make_neutron_diff()
        self._make_ml2_diff()
        LOG.user("Please review the generated files and edit your neutron "
                 "configuration before restarting.")

    def _make_neutron_diff(self):
        _, temp_path = tempfile.mkstemp(text=True)
        try:
            self._make_temp_neutron_conf(self.neutron_conf, temp_path)
            self._generate_diff(self.neutron_conf,
                                temp_path,
                                'neutron.conf.diff')
        finally:
            os.remove(temp_path)

    def _make_ml2_diff(self):
        ml2_diff_file = 'ml2_conf.ini.diff'
        ml2_conf = (os.path.dirname(self.neutron_conf) +
                    '/plugins/ml2/ml2_conf.ini')
        if not os.path.isfile(ml2_conf):
            diff_path = (os.path.dirname(nuage_logging.log_file) +
                         '/' + ml2_diff_file)
            LOG.user("Could not find %s. Will write what ml2 configuration "
                     "file should minimally contain at %s",
                     ml2_conf, diff_path)
            with open(diff_path, 'w') as diff_file:
                diff_file.write("[ml2]\n")
                diff_file.write("extension_drivers = nuage_subnet,nuage_port,"
                                "port_security\n")
                diff_file.write("mechanism_drivers = nuage")
        else:
            _, temp_path = tempfile.mkstemp(text=True)
            try:
                self._make_temp_ml2_conf(ml2_conf, temp_path)
                self._generate_diff(ml2_conf, temp_path, ml2_diff_file)
            finally:
                os.remove(temp_path)

    @staticmethod
    def _make_temp_neutron_conf(neutron_conf, temp_path):
        with open(neutron_conf, 'r') as original, \
                open(temp_path, 'w') as temp_file:
            for line in original:
                if "core_plugin" in line and not line.startswith('#'):
                    temp_file.write("core_plugin = ml2\n")
                elif "service_plugins" in line and \
                        not line.startswith('#'):
                    temp_file.write(
                        "service_plugins = NuagePortAttributes,NuageAPI,"
                        "NuageL3\n")
                else:
                    temp_file.write(line)

    @staticmethod
    def _make_temp_ml2_conf(ml2_conf, temp_path):
        with open(ml2_conf, 'r') as original, \
                open(temp_path, 'w') as temp_file:
            for line in original:
                if "extension_drivers" in line and not line.startswith('#'):
                    temp_file.write("extension_drivers = nuage_subnet,"
                                    "nuage_port,port_security\n")
                elif "mechanism_drivers" in line and not line.startswith('#'):
                    temp_file.write(
                        "mechanism_drivers = nuage\n")
                else:
                    temp_file.write(line)

    @staticmethod
    def _generate_diff(original, new, output_path):
        diff_path = (os.path.dirname(nuage_logging.log_file) +
                     '/' + output_path)
        with open(diff_path, 'w') as diff_file:
            return_code = subprocess.call(
                ['diff', '-u', original, new],
                stdout=diff_file, stderr=diff_file)
        if return_code not in [0, 1]:  # 1 means files are same
            # In case of error read the diff_file to log, because it will
            # contain the diff command's output
            try:
                with open(diff_path, 'r') as content_file:
                    content = content_file.read()
                LOG.debug("Failed to generate diff file:\n'%s'", content)
            except Exception:
                LOG.exception("Failed at failing.")
            LOG.user("Failed to generate correct diff file at %s", diff_path)
            sys.exit(1)
        else:
            LOG.user("diff file generated at %s", diff_path)


class PopulateIDs(object):
    def __init__(self, restproxy):
        self.context = neutron_context.get_admin_context()
        self.rest_call = restproxy.rest_call

    @nuage_logging.step(description="Populating the database where needed")
    def populate_nuage_l2template_id(self):
        query = self.context.session.query(nuage_models.SubnetL2Domain)
        subnets = query.filter_by(nuage_managed_subnet=True)
        LOG.user("Got all VSD Managed Subnets from the database")
        for subnet in nuage_logging.iterate(subnets, 'subnets'):
            ns_id = subnet['nuage_subnet_id']
            try:
                response = self.rest_call(
                    'GET', "/l2domains/" + ns_id, '')
                if response[0] in REST_SUCCESS_CODES:
                    LOG.debug("Subnet exists Under L2 domain")
                    if ns_id is not subnet['nuage_l2dom_tmplt_id']:
                        with self.context.session.begin(subtransactions=True):
                            nuagedb.update_subnetl2dom_mapping(
                                subnet, {'nuage_l2dom_tmplt_id': ns_id})
                else:
                    # This will make sure that if L3 subnets
                    # should have template id as NULL
                    if subnet['nuage_l2dom_tmplt_id']:
                        with self.context.session.begin(subtransactions=True):
                            nuagedb.update_subnetl2dom_mapping(
                                subnet, {'nuage_l2dom_tmplt_id': None})
            except Exception:
                LOG.user("Error in setting nuage_l2dom_tmplt_id %s" % ns_id)
                sys.exit(1)


def main():
    if not nuage_logging.log_file:
        nuage_logging.init_logging(script_name)

    parser = argparse.ArgumentParser()
    parser.add_argument("--neutron-conf",
                        required=True,
                        help="File path to the neutron configuration file")
    parser.add_argument("--nuage-conf",
                        required=True,
                        help="File path to the nuage plugin configuration "
                             "file")
    args = parser.parse_args()

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
        PopulateIDs(restproxy).populate_nuage_l2template_id()
        LOG.user("Setting nuage_l2dom_tmplt_id is now complete")

        core_plugin = cfg.CONF.core_plugin
        if 'ml2' in (core_plugin or '').lower():
            LOG.user("ML2 deployment detected : upgrading to Full ML2 now")
            UpgradeToMl2(restproxy, args.neutron_conf).upgrade()

        LOG.user("Script executed successfully")
        LOG.user("Note that the nuagenetlib package can safely be removed in "
                 "this release.")

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
