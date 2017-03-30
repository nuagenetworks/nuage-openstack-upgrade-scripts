# Copyright 2017 NOKIA
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
File: nuage_core_to_ml2.py

Purpose:
    Bring the setup into a state that is suitable for full ML2.

    This script will update the neutron database and insert records into
    the following ml2 tables: ml2_port_bindings, networksegments,
    ml2_port_binding_levels, standardattributes.
    This is done to allow upstream ML2 plugin to work with existing
    networks and ports.
Since: 5.0
Requirements:
    The script should run with Newton packages installed, when moving to full
    ML2 plugin.

    This script requires two configuration files.
    1. neutron.conf : which has details to connect to neutron database.
    2. plugin.ini : which has details to connect to vsd.

Run: python nuage_core_to_ml2.py --neutron-conf <neutron.conf>
      --nuage-conf <nuage_plugin.ini>
****************************************************************************"""
import argparse
import logging
import os
import subprocess
import sys
import tempfile

from neutron.common import config
from neutron.db.models_v2 import Network
from neutron.db.models_v2 import Port
from neutron.db.portbindings_db import PortBindingPort
from neutron.db.segments_db import NetworkSegment
from neutron.db import standard_attr
from neutron.plugins.ml2.models import PortBinding
from neutron.plugins.ml2.models import PortBindingLevel
from oslo_config import cfg
from oslo_utils import uuidutils
from sqlalchemy import create_engine
from sqlalchemy import literal
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql.functions import now

from utils import nuage_logging

from utils.restproxy import RESTProxyServer
from utils.vsdclient_config import nuage_register_cfg_opts

from nuage_neutron.plugins.common.nuage_models import ProviderNetBinding

script_name = 'nuage_core_to_ml2'
LOG = logging.getLogger(script_name)
dhcp_device_owner = 'network:dhcp:nuage'


class UpgradeCoreToMl2(object):
    def __init__(self):
        super(UpgradeCoreToMl2, self).__init__()
        self.init_database()

    @nuage_logging.step(description="%s to update database to be Ml2 "
                                    "compliant" % script_name)
    def upgrade(self):
        self.execute_db_queries()

    @nuage_logging.step(description="connecting to database")
    def init_database(self):
        try:
            cfg.CONF.database._group._opts['connection']['default'] = ''
            self.engine = create_engine(cfg.CONF.database.connection,
                                        echo=True)
            # Must remove sqlalchemy logging handlers or it dumps to console
            sql_logger = logging.getLogger("sqlalchemy.engine.base.Engine")
            for handler in sql_logger.handlers:
                sql_logger.removeHandler(handler)

            self.engine.connect()
        except Exception:
            LOG.user("Can't create valid connection to neutron database")
            sys.exit(1)

    def _insert_network_segments(self, session, result):
        for row in result:
            with session.begin(subtransactions=True):
                new_attributes = standard_attr.StandardAttribute(
                    resource_type='networksegments',
                    created_at=now(),
                    updated_at=now())
                session.add(new_attributes)
                session.flush()  # We flush so 'new_attributes' will get an id.
                new_segment = NetworkSegment(
                    id=uuidutils.generate_uuid(),
                    network_id=row.network_id,
                    network_type=row.network_type,
                    standard_attr_id=new_attributes.id)
                session.add(new_segment)

    @nuage_logging.step(description="executing DB queries")
    def execute_db_queries(self):
        session_class = sessionmaker(bind=self.engine)
        session = session_class(autocommit=True)
        self._ml2_port_bindings_compute(session)
        self._ml2_port_bindings_non_compute(session)
        self._networksegments_non_provider(session)
        self._networksegments_provider(session)
        self._ml2_port_binding_levels(session)

    @nuage_logging.step(description="executing query to insert ml2_port_"
                                    "bindings for compute ports")
    def _ml2_port_bindings_compute(self, session):
        port_ids_subquery = session.query(PortBinding.port_id)
        values_subquery = (
            session.query(Port.id, literal('ovs'), literal('normal'),
                          PortBindingPort.host)
                .filter(
                PortBindingPort.port_id == Port.id,
                Port.id.notin_(port_ids_subquery),
                Port.device_id.isnot(None),
                Port.device_owner.like('compute:%')
            )
        )
        self.engine.execute(PortBinding.__table__.insert().from_select(
            [PortBinding.port_id, PortBinding.vif_type, PortBinding.vnic_type,
             PortBinding.host],
            values_subquery))

    @nuage_logging.step(description="executing query to insert ml2_port_"
                                    "bindings for non-compute ports")
    def _ml2_port_bindings_non_compute(self, session):
        port_ids_subquery = session.query(PortBinding.port_id)
        values_subquery = (
            session.query(Port.id, literal('unbound'), literal('normal'))
                .filter(
                Port.id.notin_(port_ids_subquery)
            )
        )
        self.engine.execute(PortBinding.__table__.insert().from_select(
            [PortBinding.port_id, PortBinding.vif_type, PortBinding.vnic_type],
            values_subquery))

    @nuage_logging.step(description="Executing queries to insert "
                                    "networksegments for non-provider "
                                    "networks")
    def _networksegments_non_provider(self, session):
        net_ids_in_networksegments_subquery = (
            session.query(NetworkSegment.network_id))
        net_ids_in_nuage_p_netbindings_subquery = (
            session.query(ProviderNetBinding.network_id))
        segments_to_create_query = (
            session.query(Network.id.label('network_id'),
                          literal('vxlan').label('network_type'))
                .filter(
                Network.id.notin_(net_ids_in_networksegments_subquery),
                Network.id.notin_(net_ids_in_nuage_p_netbindings_subquery))
        )
        self._insert_network_segments(
            session,
            segments_to_create_query)

    @nuage_logging.step(description="Executing queries to insert "
                                    "networksegments for provider networks")
    def _networksegments_provider(self, session):
        net_ids_in_networksegments_subquery = (
            session.query(NetworkSegment.network_id))
        segments_to_create_query = (
            session.query(
                Network.id.label('network_id'),
                literal('vlan').label('network_type'),
                ProviderNetBinding.vlan_id.label('segmentation_id'),
                ProviderNetBinding.physical_network.label('physical_network'))
                .filter(
                Network.id.notin_(net_ids_in_networksegments_subquery),
                Network.id == ProviderNetBinding.network_id)
        )
        self._insert_network_segments(
            session,
            segments_to_create_query)

    @nuage_logging.step(description="Executing query to insert "
                                    "ml2_port_binding_levels for compute "
                                    "ports")
    def _ml2_port_binding_levels(self, session):
        port_ids_subquery = session.query(PortBindingLevel.port_id)
        values_subquery = (
            session.query(Port.id, PortBindingPort.host, literal(0),
                          literal('nuage'), NetworkSegment.id)
                .filter(
                PortBindingPort.port_id == Port.id,
                Port.network_id == NetworkSegment.network_id,
                NetworkSegment.segment_index == 0,
                Port.id.notin_(port_ids_subquery),
                Port.device_id.isnot(None),
                Port.device_owner.like('compute:%')
            )
        )
        self.engine.execute(PortBindingLevel.__table__.insert().from_select(
            [PortBindingLevel.port_id, PortBindingLevel.host,
             PortBindingLevel.level, PortBindingLevel.driver,
             PortBindingLevel.segment_id],
            values_subquery))


class UpgradeToMl2(object):
    def __init__(self, restproxy, neutron_conf):
        self.restproxy = restproxy
        self.neutron_conf = neutron_conf

    @nuage_logging.step(description="%s.py for upgrade to 5.0 full ML2 "
                                    "plugin" % script_name)
    def upgrade(self):
        UpgradeCoreToMl2().upgrade()

        self._advice_next_steps()
        self._make_diff_files()

    def _advice_next_steps(self):
        LOG.user("Upgrades have finished. To proceed, change your neutron "
                 "configuration file to contain the following:\n")
        with nuage_logging.indentation():
            LOG.user("##################################")
            LOG.user("[DEFAULT]")
            LOG.user("core_plugin = ml2")
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
            LOG.user("mechanism_drivers = nuage")
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
                     "file should minimally contain to be a viable configuration at %s."
                     " Please refer to official documentation for a complete "
                     "overview of ml2 configuration options.",
                     ml2_conf, diff_path)
            with open(diff_path, 'w') as diff_file:
                diff_file.write("[ml2]\n"
                                "tenant_network_types = vxlan\n"
                                "extension_drivers = nuage_subnet,nuage_port,port_security\n"
                                "type_drivers = vxlan\n"
                                "mechanism_drivers = nuage\n"
                                "\n"
                                "[ml2_type_vxlan]\n"
                                "vni_ranges = 1:1000\n")
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
            original = list(original)
            #find lines to be changed
            core_line = None
            service_line = None
            for index in range(len(original)):
                line = str(original[index])
                if "".join(line.split()).startswith("core_plugin"):
                    core_line = index
                if not core_line and "".join(line.split()).startswith("#core_plugin"):
                    core_line = index
                if "".join(line.split()).startswith("service_plugins"):
                    service_line = index
                if not service_line and "".join(line.split()).startswith("#service_plugins"):
                    service_line = index
            original[core_line] = "core_plugin = ml2\n"
            original[service_line] = "service_plugins = NuagePortAttributes,NuageAPI," \
                                     "NuageL3\n"
            temp_file.write("".join(original))

    @staticmethod
    def _make_temp_ml2_conf(ml2_conf, temp_path):
        with open(ml2_conf, 'r') as original, \
                open(temp_path, 'w') as temp_file:
            original = list(original)

            #find lines to be changed
            extension_line = None
            mechanism_line = None
            for index in range(len(original)):
                line = str(original[index])
                if "".join(line.split()).startswith("extension_drivers"):
                    extension_line = index
                if not extension_line and "".join(line.split()).startswith("#extension_drivers"):
                    extension_line = index
                if "".join(line.split()).startswith("mechanism_drivers"):
                    mechanism_line = index
                if not mechanism_line and "".join(line.split()).startswith("#mechanism_drivers"):
                    mechanism_line = index
            original[extension_line] = "extension_drivers = nuage_subnet," \
                                       "nuage_port,port_security\n"
            original[mechanism_line] = "mechanism_drivers = nuage\n"
            temp_file.write("".join(original))

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


def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("--neutron-conf",
                        required=True,
                        help="File path to the neutron configuration file")
    parser.add_argument("--nuage-conf",
                        required=True,
                        help="File path to the nuage plugin configuration "
                             "file")
    return parser


def process_arguments(args):
    conf_list = []
    for conffile in (args.neutron_conf, args.nuage_conf):
        conf_list.append('--config-file')
        if not os.path.isfile(conffile):
            LOG.user('File "%s" cannot be found.' % conffile)
            sys.exit(1)
        conf_list.append(conffile)
    config.init(conf_list)


def _init_restproxy():
    nuage_register_cfg_opts()
    server = cfg.CONF.RESTPROXY.server
    serverauth = cfg.CONF.RESTPROXY.serverauth
    serverssl = cfg.CONF.RESTPROXY.serverssl
    base_uri = cfg.CONF.RESTPROXY.base_uri
    auth_resource = cfg.CONF.RESTPROXY.auth_resource
    organization = cfg.CONF.RESTPROXY.organization

    return RESTProxyServer(server=server,
                           base_uri=base_uri,
                           serverssl=serverssl,
                           serverauth=serverauth,
                           auth_resource=auth_resource,
                           organization=organization)


def main():
    if not nuage_logging.log_file:
        nuage_logging.init_logging(script_name)

    logging.getLogger('stevedore.extension').setLevel(logging.ERROR)
    logging.getLogger('neutron.callbacks.manager').setLevel(logging.ERROR)
    logging.getLogger('oslo_config.cfg').setLevel(logging.ERROR)
    parser = parse_arguments()
    args = parser.parse_args()

    try:
        process_arguments(args)
        restproxy = _init_restproxy()
        core_plugin = cfg.CONF.core_plugin

        if 'nuage' not in (core_plugin or '').lower():
            LOG.user("ERROR: Current core_plugin is not nuage. Exiting.")
            sys.exit(1)

        UpgradeToMl2(restproxy, args.neutron_conf).upgrade()
        LOG.user("Script executed successfully")

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
