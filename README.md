# Upgrade-scripts

## Warning

The scripts in this package should only be used by qualified technical support staff and according to the guidelines in 
the Nuage User Documentation. Unappropriate use may change data on both OpenStack Controller and VSD platform and result 
in inconsistent or failing system.

## Content
- **_set_external_id.py_** - script to update VSD objects with the OpenStack UUID for the related OpenStack resource.
- **_set_rt_rd.py_** - script to update the OpenStack Neutron routers with Route Target and Route Distinghuisher values from VSD.
- **_set_and_audit_cms.py_** - parent script to run the following VportSync and CMS ID scripts.
	* **_vport_sync.py_** - script to create missing VPorts and set missing externalID of VPorts.
	* **_generate_cms_id.py_** - script to allocated a unique CMS ID from the VSD.
	* **_generate_audit_file.py_** - script to create an audit file with VSD resources with undecorated External ID.
	* **_process_audit_file.py_** - script to decorate all VSD resources from the audit file with the actual CMS ID.
	* **_vsdclient_config.py_** - helper code for CMS ID scripts.
	* **_restproxy.py_** - helper code for CMS ID scripts.
- **_uninstall_nuage_plugin.py_** - script to uninstall nuage plugin and remove nuage specific components from python path.
