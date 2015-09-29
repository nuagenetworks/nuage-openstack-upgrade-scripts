# Copyright 2015 OpenStack Foundation
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
#

import os
import fnmatch
import shutil
import sys


def main():
    try:
        import neutron
    except ImportError:
        print ("Openstack neutron is not installed.\n"
               " The uninstallation will stop.")
        sys.exit(1)
    else:
        neutron_path = neutron.__path__[0]
        nuage_path = os.path.join(neutron_path, 'plugins/nuage')
        if not os.access(neutron.__path__[0], os.W_OK):
            print ("The user does not have sufficient privileges to modify "
                   "%s.\n The uninstallation will stop." % (neutron_path))

            sys.exit(1)
        if os.path.exists(nuage_path):
            shutil.rmtree(nuage_path)

        for root, dirnames, filenames in os.walk('/usr'):
            for filename in fnmatch.filter(filenames, 'Nuage_Neutron-*.egg'):
                if os.access(os.path.join(root, filename), os.W_OK):
                    os.remove(os.path.join(root, filename))
                else:
                    print ("The user does not have sufficient privileges to delete "
                           "%s.\n The egg file will not be deleted." % (os.path.join(root, filename)))

if __name__ == '__main__':
    main()
