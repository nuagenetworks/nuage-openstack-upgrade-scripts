# Upgrade-scripts

## Warning

The scripts in this package should only be used by qualified technical support staff and according to the guidelines in 
the Nuage User Documentation. Unappropriate use may change data on both OpenStack Controller and VSD platform and result 
in inconsistent or failing system.

## Content
- set_external_id.py 	- script to update VSD objects with the OpenStack UUID for the related OpenStack resource
- set_rt_rd.py - script to update the OpenStack Neutron routers with Route Target and Route Distinghuisher values from VSD
- set_and_audit_cms.py - parent script to run underlying CMS ID scripts
  - generate_cms_id.py - script to allocated a unique CMS ID from the VSD 
  - generate_audit_file.py 	- script to create an audit file with VSD resources with undecorated External ID
	- process_audit_file.py - script to decorate all VSD resources from the audit file with the actual CMS ID
	
	- vsdclient_config.py - helper code for CMS ID scripts
	- restproxy.py - helper code for CMS ID scripts
