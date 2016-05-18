import logging
import os
import sys
import time


USER_LOGGING_LEVEL = logging.INFO + 1
log_file = ""


class SingleLevelFilter(logging.Filter):
    def __init__(self, passlevel):
        super(SingleLevelFilter, self).__init__()
        self.passlevel = passlevel

    def filter(self, record):
        return record.levelno == self.passlevel


def init_logging(name):
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
    stdout.setLevel(USER_LOGGING_LEVEL)
    stdout.addFilter(SingleLevelFilter(USER_LOGGING_LEVEL))
    root_logger.addHandler(stdout)

    def user(self, message, *args, **kws):
        if self.isEnabledFor(USER_LOGGING_LEVEL):
            self._log(USER_LOGGING_LEVEL, message, args, **kws)

    logging.addLevelName(USER_LOGGING_LEVEL, "USER")
    logging.Logger.user = user

    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    log_file = log_dir + '/upgrade_%s_%s.log' % (
        name, time.strftime("%d-%m-%Y_%H:%M:%S"))
    hdlr = logging.FileHandler(log_file)
    hdlr.setFormatter(formatter)
    hdlr.setLevel(logging.DEBUG)
    root_logger.addHandler(hdlr)
    root_logger.user("Logfile created at %s" % log_file)
