# Copyright 2016 Cisco Systems, Inc.  All rights reserved.
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


#from oslo_log import log as logging
#LOG = logging.getLogger(__name__)
#LOG.warn("*********** Printing traceback for test_setup_monkeypatch.py **********")
#import traceback
#traceback.print_stack()
from neutron.db import model_base
from neutron.plugins.cisco.db.l3 import l3_models as old_l3

# We can't import everyting first, otherwise we run into an exception
# with the Metadata class for multiple tables with the same name.
# First remove the upstream tables from the Metadata class
tables_to_drop = ['cisco_hosting_devices', 'cisco_port_mappings', 'cisco_router_mappings']
for tb in model_base.BASEV2.metadata.sorted_tables:
    if tb.name in tables_to_drop:
        model_base.BASEV2.metadata.remove(tb)

# Now it's safe to import the new tables. However we still
# need to re-map the old model classes to our new ones
from networking_cisco.plugins.cisco.db.device_manager import hd_models as hdm
from networking_cisco.plugins.cisco.db.l3 import l3_models as new_l3

old_l3.HostingDevice = hdm.HostingDevice
old_l3.HostedHostingPortBinding = hdm.HostedHostingPortBinding
old_l3.RouterHostingDeviceBinding = new_l3.RouterHostingDeviceBinding

from neutron.plugins.ml2.drivers.cisco.n1kv import n1kv_models as old_n1kv

tables_to_drop = ['cisco_ml2_n1kv_policy_profiles', 'cisco_ml2_n1kv_network_profiles', 'cisco_ml2_n1kv_port_bindings', 'cisco_ml2_n1kv_network_bindings','cisco_ml2_n1kv_vlan_allocations', 'cisco_ml2_n1kv_vxlan_allocations','cisco_ml2_n1kv_profile_bindings' ]
for tb in model_base.BASEV2.metadata.sorted_tables:
    if tb.name in tables_to_drop:
        model_base.BASEV2.metadata.remove(tb)

from networking_cisco.plugins.ml2.drivers.cisco.n1kv import n1kv_models as new_n1kv
old_n1kv.PolicyProfile = new_n1kv.PolicyProfile
old_n1kv.NetworkProfile = new_n1kv.NetworkProfile
old_n1kv.N1kvPortBinding = new_n1kv.N1kvPortBinding
old_n1kv.N1kvNetworkBinding = new_n1kv.N1kvNetworkBinding
old_n1kv.N1kvVlanAllocation = new_n1kv.N1kvVlanAllocation
old_n1kv.N1kvVxlanAllocation = new_n1kv.N1kvVxlanAllocation
old_n1kv.ProfileBinding = new_n1kv.ProfileBinding
