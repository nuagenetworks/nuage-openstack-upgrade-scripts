import argparse
import logging
import os
import sys
import time

from neutron.common import config
from oslo_config import cfg
from sqlalchemy import create_engine

cfg.LOG.setLevel(logging.ERROR)
CONSOLE_LOGGING_LEVEL = logging.INFO + 1
log_file = ""
interrupts = True
LOG = None

"""
This script should run when upgrading from a plugin without port-security
extension to a plugin with port-security extension.
This script is introduced in 4.0R3
"""


class SingleLevelFilter(logging.Filter):
    """
    Filters the logs so not everything goes to the console. Only using
    LOG.console(...) will log to the console.
    Everything will be logged to the logfile regardless of the log method or
    log level used.
    """
    def __init__(self, passlevel):
        super(SingleLevelFilter, self).__init__()
        self.passlevel = passlevel

    def filter(self, record):
        return record.levelno == self.passlevel


def init_logging():
    global log_file

    log_dir = os.path.expanduser('~') + '/nuageupgrade'
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    for handler in root_logger.handlers:
        root_logger.removeHandler(handler)
    formatter = logging.Formatter('%(message)s')
    stdout = logging.StreamHandler(sys.stdout)
    stdout.setFormatter(formatter)
    stdout.setLevel(CONSOLE_LOGGING_LEVEL)
    stdout.addFilter(SingleLevelFilter(CONSOLE_LOGGING_LEVEL))
    root_logger.addHandler(stdout)

    def console(self, message, *args, **kws):
        if self.isEnabledFor(CONSOLE_LOGGING_LEVEL):
            self._log(CONSOLE_LOGGING_LEVEL, message, args, **kws)

    logging.addLevelName(CONSOLE_LOGGING_LEVEL, "CONSOLE")
    logging.Logger.console = console

    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    log_file = log_dir + '/upgrade_%s.log' % time.strftime("%d-%m-%Y_%H:%M:%S")
    hdlr = logging.FileHandler(log_file)
    hdlr.setFormatter(formatter)
    hdlr.setLevel(logging.DEBUG)
    root_logger.setLevel(logging.DEBUG)
    root_logger.addHandler(hdlr)
    root_logger.console("Logfile created at %s" % log_file)


def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config-file", required=True,
                        help="Path to the configuration file containing a "
                             "[database] section with a 'connection' string. "
                             "This is typically the neutron.conf file")
    parser.add_argument("--interactive", default="True",
                        help="Set to 'False' to have the script work "
                             "without any interrupts asking for user "
                             "confirmations to continue.")
    return parser


def init_database():
    engine = create_engine(cfg.CONF.database.connection, echo=True)
    sql_logger = logging.getLogger("sqlalchemy.engine.base.Engine")
    for handler in sql_logger.handlers:
        sql_logger.removeHandler(handler)
    return engine


def execute_db_queries():
    LOG.console("Connecting to database...")
    engine = init_database()
    engine.connect()
    LOG.console("Connected.")
    if interrupts:
        raw_input("Press [ENTER] to begin database updates.")
    if engine.dialect.name == 'ibm_db_sa':
        engine.execute('INSERT INTO networksecuritybindings (network_id, '
                       'port_security_enabled) SELECT id, 1 FROM networks '
                       'WHERE id NOT IN (SELECT network_id FROM '
                       'networksecuritybindings);')

        engine.execute('INSERT INTO portsecuritybindings (port_id, '
                       'port_security_enabled) SELECT id, 1 FROM ports '
                       'WHERE id NOT IN (SELECT port_id FROM '
                       'portsecuritybindings);')
    else:
        engine.execute('INSERT INTO networksecuritybindings (network_id, '
                       'port_security_enabled) SELECT id, True FROM networks '
                       'WHERE id NOT IN (SELECT network_id FROM '
                       'networksecuritybindings);')

        engine.execute('INSERT INTO portsecuritybindings (port_id, '
                       'port_security_enabled) SELECT id, True FROM ports '
                       'WHERE id NOT IN (SELECT port_id FROM '
                       'portsecuritybindings);')
    LOG.console("Database updates executed.")


def main():
    global LOG, interrupts

    parser = parse_arguments()
    args = parser.parse_args()
    init_logging()
    LOG = logging.getLogger(__name__)
    LOG.console("Starting script to migrate existing networks and ports to be "
                "compliant with the port-security extension.")

    if args.interactive.lower() in ['false', '0']:
        interrupts = False
    elif args.interactive.lower() not in ['true', '1']:
        LOG.console("Invalid --interactive argument. Expected a boolean but "
                    "was '%s'." % args.interactive)
        sys.exit(1)

    cfg_file = args.config_file
    if not os.path.isfile(cfg_file):
        LOG.console('File "%s" cannot be found.' % cfg_file)
        sys.exit(1)
    config.init(['--config-file', cfg_file])

    try:
        execute_db_queries()
    except Exception:
        LOG.exception("execute_db_queries failed")
        LOG.console("port_security_introduction.py has finished "
                    "unsuccessfully. Please find logs at %s for more "
                    "information." % log_file)
        sys.exit(1)

    LOG.console("port_security_introduction.py has finished successfully.")


if __name__ == '__main__':
    main()
