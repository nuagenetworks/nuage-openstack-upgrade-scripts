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
"""**************************************************************************

File: pre_upgrade_lbaas.py

Purpose:
    Bring all the neutron ports owned by LBaasV2 to ovsdb.

    This script fetch all the neutron ports present in neutron
    database owned by lbaasv2 and then add entries in Nuage_VM_Table
    and Nuage_Port_Table so that they can be persistance accross ovs restart

Since: 4.0R10
Requirements:
    This script needs to run on only Lbaas configured node.

Run: python pre_upgrade_lbaas.py --neutrondb
         mysql+pymysql://neutron:tigris@10.100.100.20/neutron
     To fetch "mysql+pymysql://neutron:tigris@10.100.100.20/neutron",
     please follow the following steps.

     1.Open /etc/neutron/neutron.conf
     2. Under database section, fetch this value as show below:
         [database]
         connection = mysql+pymysql://neutron:tigris@10.100.100.20/neutron
****************************************************************************"""
import errno
import json
import logging
from neutron.db.models_v2 import Port
import re
import socket
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import subprocess
import sys
import time
from utils import nuage_logging

try:
    from neutron._i18n import _
except ImportError:
    from neutron.i18n import _

from argparse import ArgumentParser

script_name = 'pre_upgrade_lbaas'
LOG = logging.getLogger(script_name)


class NuageVMDriver(object):
    @classmethod
    def get_connected_socket(cls):
        OVSDB_IP = "localhost"
        OVSDB_PORT = 6640
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((OVSDB_IP, OVSDB_PORT))
            LOG.debug(("Connected to the ovsdb..."))
        except socket.error as error:
            msg = "Cannot connect to ovsdb. error: %s" % error
            LOG.exception(msg)

        return sock

    @classmethod
    def ovsdb_transaction(cls, msg, max_retries=5):
        LOG.debug(_("sending ovsdb-query as: %s"), msg)
        try:
            sock = cls.get_connected_socket()
            sock.sendall(msg)
            sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            ''' Retry 5 times every second '''
            if (socket.errno in [errno.EBUSY,
                                 errno.EAGAIN] and max_retries > 0):
                time.sleep(1)
                msg = "retrying as it was not able to complete " \
                      "the ovsdb_transaction"
                LOG.debug(msg)
                return cls.ovsdb_transaction(
                    msg, max_retries=(max_retries - 1))
            else:
                msg = "Unable to complete the ovsdb_transaction"
                LOG.debug(msg)
                LOG.user("Failed at ovsdb_transaction, Please contact "
                         "your vendor")
                sys.exit(1)

    @classmethod
    def formulate_query(cls, port_id=None, device_name=None,
                        mac_address=None, bridge=None):
        query = []
        LOG.debug(_("Args: %(port_id)s  %(device_name)s "
                    "%(mac_address) s"),
                  {'port_id': port_id,
                   'device_name': device_name,
                   'mac_address': mac_address})
        # Operation 1
        query1 = {"id": 1,
                  "method": "transact",
                  "params": [
                      "Open_vSwitch", {
                          "op": "insert",
                          "table": "Nuage_Port_Table",
                          "row": {
                              "name": device_name
                          }
                      }
                  ]
                  }
        # Operation 2
        query2 = {"id": 2,
                  "method": "transact",
                  "params": [
                      "Open_vSwitch", {
                          "op": "insert",
                          "table": "Nuage_VM_Table",
                          "row": {
                              "vm_uuid": port_id
                          }
                      }
                  ]
                  }
        # Operation 3
        query3 = {"id": 3,
                  "method": "transact",
                  "params": [
                      "Open_vSwitch", {
                          "op": "update",
                          "table": "Nuage_Port_Table",
                          "where": [["name", "==", device_name]],
                          "row": {
                              "mac": mac_address,
                              "bridge": bridge,
                              "vm_domain": 5
                          }
                      }, {
                          "op": "update",
                          "table": "Nuage_VM_Table",
                          "where": [["vm_uuid", "==", port_id]],
                          "row": {
                              "state": 1,
                              "reason": 1,
                              "domain": 5,
                              "vm_name": port_id,
                              "ports": ["set", [device_name]]
                          }
                      }
                  ]
                  }
        # stitch the queries into one single query
        query.append(json.dumps(query1))
        query.append(json.dumps(query2))
        query.append(json.dumps(query3))

        return query

    @classmethod
    def plug(cls, port_id, device_name, mac_address,
             bridge):
        LOG.debug(_("Nuage plugging port %(id)s:%(name)s on bridge %(bridge)s "
                    "in namespace %(namespace)s"),
                  {'id': port_id,
                   'name': device_name,
                   'bridge': bridge,
                   'namespace': None})

        # Formulate json object
        query = cls.formulate_query(
            port_id=port_id, device_name=device_name,
            mac_address=mac_address, bridge=bridge)
        # send the obj
        for q in query:
            cls.ovsdb_transaction(q)
        LOG.debug(_("NuageVMDriver plug: sent the query"))


@nuage_logging.step(description="fetching all the Loadbalancer Ports")
def get_all_loadbalancer_ports(neutrondb):
    list_of_ports = []
    try:
        engine = create_engine(neutrondb, echo=True)
        # Must remove sqlalchemy logging handlers or it dumps to console
        sql_logger = logging.getLogger("sqlalchemy.engine.base.Engine")
        for handler in sql_logger.handlers:
            sql_logger.removeHandler(handler)
        engine.connect()
    except Exception:
        LOG.user("Cannot create a valid connection to neutron database. "
                 "Please fetch the right connection details from "
                 "neutron.conf and retry.", exc_info=True)
        sys.exit(1)
    session_class = sessionmaker(bind=engine)
    session = session_class(autocommit=True)
    ports = session.query(Port).filter(
        Port.device_owner == "neutron:LOADBALANCERV2").all()
    for port in ports:
        list_of_ports.append(port.id)
    return list_of_ports


def main():
    if not nuage_logging.log_file:
        nuage_logging.init_logging(script_name)

    vid = NuageVMDriver()
    parser = ArgumentParser(
        usage="usage: --neutrondb "
              "mysql+pymysql://neutron:tigris@10.100.100.20/neutron")
    parser.add_argument("--neutrondb",
                        required=True,
                        help="fetch this string from neutron.conf")
    options = parser.parse_args()

    list_of_ports = get_all_loadbalancer_ports(options.neutrondb)
    if not list_of_ports:
        LOG.debug(_("No ports are found that we need to process"))
        return
    LOG.debug(_('List of LoadBalancer Ports: %s '), list_of_ports)
    for port_id in nuage_logging.iterate(list_of_ports, 'ports'):
        cmd = "sudo ovsdb-client  dump | grep %s" % port_id
        try:
            p = subprocess.Popen(
                cmd, shell=True,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            output, err = p.communicate()
        except Exception:
            LOG.debug("%r failed, status code %s stdout %r stderr %r" % (
                cmd, p.returncode, output, err))
            msg = 'Error Occurred while fetching for ovsdb.' \
                  ' Please look into log file for more details.'
            LOG.user(msg, exc_info=True)
            sys.exit(1)
        if len(output):
            msg = "Output fetched from ovsdb : %s" % output
            LOG.debug(msg)
            mac_address, tap_interface = None, None
            try:
                mac_address = re.search(r'([0-9A-F]{2}[:-]){5}([0-9A-F]{2})',
                                        output, re.I).group()
                tap_interface = re.search(
                    r'(tap\w+\-\w+)', output, re.I).group()
                msg = "mac_address : %s , tap_interface : %s" % \
                      (mac_address, tap_interface)
                LOG.debug(msg)
            except Exception:
                msg = "Unable to retrieve mac_address or tap_interface"
                LOG.user(msg)
            if mac_address and tap_interface:
                LOG.debug(_('Plugging in namespace %(port_id)s '
                            'with MAC Address %(mac_address)s to VRS'),
                          {'port_id': port_id, 'mac_address': mac_address})
                vid.plug(port_id=port_id, device_name=tap_interface,
                         mac_address=mac_address, bridge='alubr0')


if __name__ == '__main__':
    main()
