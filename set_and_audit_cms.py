import argparse
import generate_audit_file
import generate_cms_id
import process_audit_file
import vport_sync
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

    try:
        sys.argv = [sys.argv[0], '--config-file', args.plugin_config_file,
                    args.neutron_config_file]
        vport_sync.main()
    except Exception as e:
        print e
        print ("Caution: An error occurred during synchronizing Vports on VSD"
               " according to OpenStack ports. Please contact your vendor.")
        sys.exit(1)

    sys.argv = [sys.argv[0], '--name', args.name, '--config-file',
                args.plugin_config_file]
    generate_cms_id.main()

    try:
        sys.argv = [sys.argv[0], '--config-file', args.plugin_config_file,
                    args.neutron_config_file]
        generate_audit_file.main()
    except Exception as e:
        print e
        print ("Caution: An error occurred after generating a cms ID. Please "
               "remove the cms_id entry in %s" % args.plugin_config_file)
        sys.exit(1)

    try:
        sys.argv = [sys.argv[0], '--audit-file', 'audit.yaml', '--config-file',
                    args.plugin_config_file]
        process_audit_file.main()
    except Exception as e:
        print e
        print ("Caution: An error occurred while updating cms values in VSD. "
               "Please contact your vendor.")
        sys.exit(1)


if __name__ == '__main__':
    main()
