The flow to follow should be as followed:

Starting state: 'old' neutron with existing objects

1) Shut down neutron server
2) update neutron and nuagenetlib
3) run the generate_cms_id.py script
	python generate_cms_id.py --help:
	optional arguments:
  -h, --help            show this help message and exit
  --config-file CONFIG_FILE
                        The location of the nuage_plugin.ini file
  --name NAME           The name of the CMS to create on VSD
  --overwrite           Overwrite existing cms_id configuration

  Unless overwrite is set to true, the script will cancel if the
  nuage_plugin.ini file already contains a cms_id, indicating the setup may
  already been upgraded.

4) run the generate_audit_file.py script
	python generate_audit_file.py --help:
	optional arguments:
  -h, --help            show this help message and exit
  --config-file CONFIG_FILE [CONFIG_FILE ...]
                        List of config files (nuage_plugin.ini + neutron.conf)
                        separated by space
	Need to specify both files. neutron.conf for database access,
	nuage_plugin.ini for vsd access

	A new file will be made in the current folder: audit.yaml
	It contains all info about which objects are missing a CMS id.

5) run the process_audit_file.py script
	python process_audit_file.py --help:
	optional arguments:
  -h, --help            show this help message and exit
  --audit-file AUDIT_FILE
                        A audit file from CloudStack sync or
                        generate_audit_file.py
  --config-file CONFIG_FILE
                        Config file containing [restproxy] with vsd connection
                        data

	The config-file is just nuage_plugin.ini for neutron systems. It's not
	mentioned explicitedly as this python script is supposed to run for
	Cloudstack as well.

6) Start neutron (the nuage_plugin.ini file it uses should contain the cms_id)