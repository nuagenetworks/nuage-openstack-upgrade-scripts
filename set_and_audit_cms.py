import argparse
import generate_audit_file
import generate_cms_id
import process_audit_file
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--plugin-config-file', action='store', required=True,
                        help='The location of the nuage_plugin.ini file')
    parser.add_argument('--neutron-config-file', action='store', required=True,
                        help='The location of the neutron.conf file')
    parser.add_argument('--name', action='store',
                        default=generate_cms_id.DEFAULT_CMS_NAME,
                        help='The name of the CMS to create on VSD')
    args = parser.parse_args()
    sys.argv = [sys.argv[0], '--name', args.name, '--config-file',
                args.plugin_config_file]
    generate_cms_id.main()

    sys.argv = [sys.argv[0], '--config-file', args.plugin_config_file,
                args.neutron_config_file]
    generate_audit_file.main()

    sys.argv = [sys.argv[0], '--audit-file', 'audit.yaml', '--config-file',
                args.plugin_config_file]
    process_audit_file.main()


if __name__ == '__main__':
    main()
