# Copyright 2015 Alcatel-Lucent USA Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
import argparse
import logging
import os
import sys

from configobj import ConfigObj

from uuid import getnode


def dummy(msg):
    return msg

import __builtin__
__builtin__.__dict__['_'] = dummy


from restproxy import RESTProxyServer

REST_SUCCESS_CODES = range(200, 207)


def get_mac():
    mac = getnode()
    return ':'.join(("%012X" % mac)[i:i + 2] for i in range(0, 12, 2))


DEFAULT_CMS_NAME = 'OpenStack_' + get_mac()
LOG = logging.getLogger('generate_cms_id')


class NuagePluginConfig(object):
    def __init__(self, cfg_file_location):
        self.config = ConfigObj(cfg_file_location, encoding='UTF8')
        self.config.filename = cfg_file_location

    def get(self, section, key):
        try:
            return self.config[section].get(key)
        except KeyError:
            return self.config[section.upper()].get(key)

    def set(self, section, key, value):
        try:
            self.config[section][key] = value
        except KeyError:
            self.config[section.upper()][key] = value

    def write_file(self):
        self.config.write()


def init_logger():
    log_dir = os.path.expanduser('~') + '/nuageupgrade'
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    hdlr = logging.FileHandler(log_dir + '/generate_cms_id.log')
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    LOG.addHandler(hdlr)
    logging.basicConfig(level=logging.INFO)


def init_arg_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config-file', action='store', required=True,
                        help='The location of the nuage_plugin.ini file')
    parser.add_argument('--name', action='store',
                        default=DEFAULT_CMS_NAME,
                        help='The name of the CMS to create on VSD')
    return parser


def main():
    init_logger()
    parser = init_arg_parser()
    args = parser.parse_args()

    if not os.path.isfile(args.config_file):
        LOG.error('File "%s" cannot be found.' % args.config_file)
        sys.exit(1)
    plugin_config = NuagePluginConfig(args.config_file)

    server = plugin_config.get('restproxy', 'server')
    base_uri = plugin_config.get('restproxy', 'base_uri')
    serverssl = plugin_config.get('restproxy', 'serverssl')
    serverauth = plugin_config.get('restproxy', 'serverauth')
    auth_resource = plugin_config.get('restproxy', 'auth_resource')
    organization = plugin_config.get('restproxy', 'organization')

    try:
        restproxy = RESTProxyServer(server=server,
                                    base_uri=base_uri,
                                    serverssl=serverssl,
                                    serverauth=serverauth,
                                    auth_resource=auth_resource,
                                    organization=organization)
    except Exception as e:
        LOG.error('Error in connecting to VSD:%s' % str(e))
        sys.exit(1)

    cms_id = plugin_config.get('restproxy', 'cms_id')
    if cms_id:
        response = restproxy.rest_call('GET', '/cms/%s' % cms_id, '')
        if not response[0] in REST_SUCCESS_CODES:
            LOG.warn("Existing cms_id '%s' found in configuration. But CMS "
                     "could not be validated on the VSD. Please recheck the "
                     "configuration at '%s'" % (cms_id, args.config_file))
            sys.exit(1)
        else:
            LOG.info("Existing cms_id found in configuration and validated on "
                     "VSD. No new cms_id will be generated. '%s' is reused."
                     % cms_id)
            return

    response = restproxy.rest_call('POST', "/cms", {'name': args.name})
    if response[0] not in REST_SUCCESS_CODES:
        LOG.error('Failed to create CMS on VSD. http code: %s, response: %s'
                  % (response[0], response[3]))
        sys.exit(1)

    cms_id = response[3][0]['ID']
    plugin_config.set('restproxy', 'cms_id', cms_id)

    LOG.info('created CMS %s' % cms_id)
    plugin_config.write_file()

if __name__ == '__main__':
    main()
