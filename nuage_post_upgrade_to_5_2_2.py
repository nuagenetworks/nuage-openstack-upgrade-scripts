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
File: nuage_post_upgrade_to_5_2_2.py

Purpose:
    Bring the setup into a consistent state for the new model for underlay.

    This script will update the neutron database and update the router table
    enable_snat values to be 0 (false). This is done to ensure compatibility
    with 5.2.2 where enable_snat value in router takes on a new meaning
    (snat to overlay).
    Additionally the nuage_underlay value is calculated for every current
    router, to ensure nuage_underlay reflects whether snat to underlay is
    configured on VSD.
Since: 5.2.2
Requirements:
    The script should run with Neutron packages installed, after upgrading to
    5.2.2 (or later).
    This script requires two configuration files.
    1. neutron.conf : which has details to connect to neutron database.
    2. plugin.ini : which has details to connect to vsd.

Run: python nuage_post_upgrade_to_5_2_2.py --neutron-conf <neutron.conf>
      --nuage-conf <nuage_plugin.ini>
****************************************************************************"""
import argparse
import logging
import os
import sys

from neutron.common import config
try:
    from neutron.db.models.l3 import Router
except Exception:
    from neutron.db.l3_db import Router
import neutron.db.l3_gwmode_db #noqa do not delete
from neutron_lib.db import model_base
from oslo_config import cfg
import sqlalchemy as sa
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from utils import nuage_logging
from utils.restproxy import RESTProxyServer
from utils.vsdclient_config import nuage_register_cfg_opts


script_name = 'nuage_post-upgrade_to_5_2_2'
LOG = logging.getLogger(script_name)


class NuageRouter(model_base.BASEV2):
    __tablename__ = 'nuage_router'
    router_id = sa.Column(sa.String(36),
                          sa.ForeignKey('routers.id', ondelete="CASCADE"),
                          primary_key=True,
                          nullable=False)
    router_parameter = sa.Column(sa.String(255),
                                 sa.ForeignKey('nuage_router_parameter.name',
                                               ondelete="CASCADE"),
                                 primary_key=True,
                                 nullable=False)
    parameter_value = sa.Column(sa.String(255),
                                nullable=False)


class NuageRouterParameter(model_base.BASEV2):
    __tablename__ = 'nuage_router_parameter'
    name = sa.Column(sa.String(255), primary_key=True, nullable=False)


class Upgrade_to_5_2_2(object):
    def __init__(self, restproxy):
        super(Upgrade_to_5_2_2, self).__init__()
        self.restproxy = restproxy
        self.init_database()

    @nuage_logging.step(description="%s to update database to be"
                                    " nuage_underlay  compliant" % script_name)
    def upgrade(self):
        session_class = sessionmaker(bind=self.engine)
        session = session_class(autocommit=True)
        with session.begin():
            self._disable_snat(session)
            self._calculate_nuage_pat(session)

    @nuage_logging.step(description="connecting to database")
    def init_database(self):
        try:
            if 'database' not in cfg.CONF:
                db_opts = [
                    cfg.StrOpt('connection',
                               default='',
                               secret=True,
                               help='URL to database')
                ]
                cfg.CONF.register_opts(db_opts, "database")
            cfg.CONF.database._group._opts['connection']['default'] = ''
            self.engine = create_engine(cfg.CONF.database.connection,
                                        echo=True)
            # Must remove sqlalchemy logging handlers or it dumps to console
            sql_logger = logging.getLogger("sqlalchemy.engine.base.Engine")
            for handler in sql_logger.handlers:
                sql_logger.removeHandler(handler)

            self.engine.connect()
        except Exception as e:
            LOG.user("Can't create valid connection to neutron database")
            LOG.user("Got exception: " + str(e))
            sys.exit(1)

    @nuage_logging.step(description="disabling enable_snat on"
                                    " existing routers.")
    def _disable_snat(self, session):
        session.query(Router).filter(Router.gw_port_id.isnot(None)).\
            update({"enable_snat": 0})

    @nuage_logging.step(description="calculating new values for"
                                    " nuage_underlay.")
    def _calculate_nuage_pat(self, session):
        routers = session.query(Router).filter(Router.gw_port_id.isnot(None))\
            .all()
        router_ids = [r['id'] for r in routers]
        routers_ids_pat = self._get_pat_enabled()
        for router_id in set(router_ids).intersection(routers_ids_pat):
            self._add_router_parameter(session, router_id,
                                       'nuage_underlay', 'snat')

    def _get_pat_enabled(self):
        cms_id = cfg.CONF.RESTPROXY.cms_id
        headers = {
            'X-NUAGE-FilterType': "predicate",
            'X-Nuage-Filter': "PATEnabled is 'ENABLED' and "
                              "externalID ENDSWITH '{}'".format(cms_id)
        }
        domains = self.restproxy.get(resource='/domains',
                                     extra_headers=headers)
        domain_ids = [d['externalID'].split("@")[0] for d in domains[3]]
        return domain_ids

    def _add_router_parameter(self, session, router_id, parameter, value):
        router_parameter = NuageRouter(router_id=router_id,
                                       router_parameter=parameter,
                                       parameter_value=value)
        session.merge(router_parameter)


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

        Upgrade_to_5_2_2(restproxy).upgrade()
        LOG.user("Script executed successfully")
        LOG.user("Please consult the Nuage documentation to determine "
                 "the most suitable configuration for nuage_pat and "
                 "nuage_underlay_default for your setup.")

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
