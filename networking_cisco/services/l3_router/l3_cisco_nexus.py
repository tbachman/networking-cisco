# Copyright (c) 2014 OpenStack Foundation.
# All Rights Reserved.
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

from oslo.config import cfg
from oslo_utils import importutils
from oslo_utils import excutils

from neutron.common import constants as q_const
from neutron.common import topics
from neutron.db import common_db_mixin
from neutron.db import db_base_plugin_v2
from neutron.db import extraroute_db
from neutron.db import l3_dvrscheduler_db
from neutron.db import l3_gwmode_db
from neutron.extensions import portbindings
from neutron.extensions import providernet as provider
from neutron.plugins.common import constants
from networking_cisco.plugins.ml2.drivers.cisco.nexus import config as conf
from networking_cisco.plugins.ml2.drivers.cisco.nexus import exceptions as cexc
from networking_cisco.plugins.ml2.drivers.cisco.nexus import nexus_db_v2 as nxdb
from networking_cisco.plugins.ml2.drivers.cisco.nexus import nexus_network_driver

class CiscoNexusL3ServicePlugin(db_base_plugin_v2.NeutronDbPluginV2,
                                extraroute_db.ExtraRoute_db_mixin,
                                l3_gwmode_db.L3_NAT_db_mixin):

    supported_extension_aliases = ["router", "ext-gw-mode",
                                   "extraroute"]

    def __init__(self):
        conf.ML2MechCiscoConfig()
        super(CiscoNexusL3ServicePlugin, self).__init__()
        self.driver = nexus_network_driver.CiscoNexusDriver()
        self._nexus_switches = conf.ML2MechCiscoConfig.nexus_dict
        self.vrf_enabled = cfg.CONF.ml2_cisco.vrf_enabled
        self.nat_enabled = cfg.CONF.ml2_cisco.nat_enabled

    def get_plugin_type(self):
        return constants.L3_ROUTER_NAT

    def get_plugin_description(self):
        """returns string description of the plugin."""
        return ("L3 Router Service Plugin for basic L3 forwarding"
                " between (L2) Neutron networks and access to external"
                " networks via a NAT gateway.")

    def _get_switch_info(self, host_id):
        host_connections = []
        for switch_ip, attr in self._nexus_switches:
            if str(attr) == str(host_id):
                for port_id in (
                    self._nexus_switches[switch_ip, attr].split(',')):
                    if ':' in port_id:
                        intf_type, port = port_id.split(':')
                    else:
                        intf_type, port = 'ethernet', port_id
                    host_connections.append((switch_ip, intf_type, port))

        if host_connections:
            return host_connections

    def _find_switch_for_svi(self, context):
        """Get a switch to create the SVI on."""
        nexus_switches = conf.ML2MechCiscoConfig.nexus_dict
        switch_ip = None
        if nexus_switches:
            switch_dict = (dict((switch_ip, 0)
                                for switch_ip, _ in nexus_switches))
        else:
            raise cexc.NoNexusSviSwitch()

        try:
            bindings = nxdb.get_nexussvi_bindings(context.session)
            # Build a switch dictionary with weights
            if bindings:
                for binding in bindings:
                    switch_ip = binding.switch_ip
                    if switch_ip not in switch_dict:
                        switch_dict[switch_ip] = 1
                    else:
                        switch_dict[switch_ip] += 1

                # Search for the lowest value in the dict
                if switch_dict:
                    switch_ip = min(switch_dict, key=switch_dict.get)
            else:
                switch_ip = switch_dict.keys()[0]

        except Exception:
            # First SVI binding, assign any switch IP configured.
            switch_ip = switch_dict.keys()[0]

        return switch_ip

    def _get_vlanid(self, context, subnet):
        return(self._core_plugin.get_network(context,
                            subnet['network_id'])[provider.SEGMENTATION_ID])

    def _add_nexus_svi_db(self, switch_ip, router_id, vlan_id,
                          subnet_id, vrf_id):
        """Create SVI database nexus switch entry."""
        binding = nxdb.get_nexussvi_bindings(None, vlan_id, router_id)
        if binding:
            raise cexc.SubnetInterfacePresent(subnet_id=subnet_id,
                                              router_id=router_id)
        else:
            nxdb.add_nexussvi_binding(None, switch_ip, vlan_id, subnet_id,
                                      router_id, vrf_id)

    def _add_nexus_svi_interface(self, switch_ip, router_id, vlan_id,
                                 subnet, vrf=None):
        """Create SVI nexus switch entries."""
        gateway_ip = subnet['gateway_ip']
        cidr = subnet['cidr']
        netmask = cidr.split('/', 1)[1]
        gateway_ip = gateway_ip + '/' + netmask
        vlan_name = cfg.CONF.ml2_cisco.vlan_name_prefix + str(vlan_id)
        # Create vlan interface on switch if it doesn't already exist.
        try:
            bindings = nxdb.get_nexusvlan_binding(vlan_id, switch_ip)
        except cexc.NexusPortBindingNotFound:
            self.driver.create_vlan(switch_ip, vlan_id, vlan_name, 0)

        # Create SVI interface entry.
        bindings = nxdb.get_nexussvi_bindings(None, vlan_id, switch_ip)
        if not bindings:
            if vrf:
                self.driver.create_vrf_svi(switch_ip, vlan_id, gateway_ip, vrf)
            else:
                self.driver.create_vlan_svi(switch_ip, vlan_id, gateway_ip)

            self._add_nexus_svi_db(switch_ip, router_id, vlan_id,
                                   subnet['id'], vrf)

    def _remove_nexus_svi_db(self, switch_ip, router_id, vlan_id):
        """Delete SVI database nexus switch entries."""
        nxdb.remove_nexusport_binding('router', str(vlan_id), 0,
                                         switch_ip, router_id, False)

    def _remove_nexus_svi_interface(self, switch_ip, vlan_id, vrf=None):
        """Delete SVI nexus switch entries."""

        # Delete the SVI interface from the nexus switch.
        if vrf:
            self.driver.delete_vrf_svi(switch_id, vlan_id, vrf)
        else:
            self.driver.delete_vlan_svi(switch_ip, vlan_id)

        # if there are no remaining db entries using this vlan on this
        # nexus switch then remove the vlan.
        try:
            nxdb.get_nexusvlan_binding(vlan_id, switch_ip)
        except cexc.NexusPortBindingNotFound:
            self.driver.delete_vlan(switch_ip, vlan_id)

    def create_router(self, context, router):
        db_router = super(CiscoNexusL3ServicePlugin, self).create_router(
            context, router)
        # Allocate VRF for router
        if self.vrf_enabled:
            nx_db_vrf = nxdb.add_nexus_vrf(context.session, db_router.get('id'))

        return db_router

    def update_router(self, context, id, router):
        if self.vrf_enabled:
            # Get the vrf corresponding to this router
            db_router = nxdb.get_nexus_vrf(context.session, id)
            vrf_id = db_router.vrf_id
            # Get all bindings for this VRF
            bindings = nxdb.get_nexus_vrf_bindings(context.session, vrf_id)
            gateways = self._get_router_gateways(context, router['router'])
            if gateways:
                for gateway in gateways:
                    for binding in bindings:
                        self.driver.add_vrf_gateway(binding.switch_ip,
                                                    vrf_id, gateway)
            else:
                for binding in bindings:
                    self.driver.del_vrf_gateway(binding.switch_ip, vrf_id,
                                                binding.gateway_ip)
                    nxdb.del_nexus_vrf_binding_gateway(
                        context.session, vrf_id, binding.switch_ip)
        return super(CiscoNexusL3ServicePlugin, self).update_router(
            context, id, router)

    def delete_router(self, context, id):
        if self.vrf_enabled:
            try:
                # Get VRF associated
                nx_db_vrf = nxdb.get_nexus_vrf(context.session, id)
                # Delete on switches
                nxdb.delete_nexus_vrf(context.session, nx_db_vrf['vrf_id'])
            except:
                pass

        return super(CiscoNexusL3ServicePlugin, self).delete_router(
            context, id)

    def add_router_interface(self, context, router_id, interface_info):
        result = super(CiscoNexusL3ServicePlugin, self).add_router_interface(
            context, router_id, interface_info)

        # Get interface subnet, network and ports
        subnet = self.get_subnet(context,
                                 interface_info['subnet_id'])
        vlan_id = self._get_vlanid(context, subnet)

        if self.vrf_enabled:
            port_filters = {'network_id': [subnet['network_id']]}
            ports = self.get_ports(context, port_filters)
            for port in ports:
                self._create_vrf(context, router_id, port)
        else:
            # Find a switch to create the SVI on.
            switch_ip = self._find_switch_for_svi(context)
            try:
                self._add_nexus_svi_interface(switch_ip, router_id, vlan_id,
                                              subnet)
            except Exception:
                with excutils.save_and_reraise_exception():
                    self._remove_nexus_svi_interface(switch_ip, vlan_id)

        return result

    def _get_router_gateways(self, context, router):
        ext_gw = router['external_gateway_info']
        gateways = []
        if ext_gw:
            net_id = ext_gw['network_id']
            net = self.get_network(context, net_id)
            for subnet in net['subnets']:
                subnet = self.get_subnet(context, subnet)
                gateways.append(subnet.get('gateway_ip'))
            return gateways
        else:
            return []

    def _create_vrf(self, context, router_id, port):
        db_router = nxdb.get_nexus_vrf(context.session, router_id)
        router = self.get_router(context, router_id)
        gateways = self._get_router_gateways(context, router)
        vrf_id = db_router.vrf_id
        host_id = port.get(portbindings.HOST_ID)
        owner = port.get('device_owner')
        router = self.get_router(context, router_id)
        network = self.get_network(context, port.get('network_id'))
        subnet = self.get_subnet(context, network.get('subnets')[0])
        vlan_id = self._get_vlanid(context, subnet)

        if host_id and owner=='compute:None':
            # Get switch connections for this host
            connections = self._get_switch_info(host_id)
            for connection in connections:
                # Check for a VRF binding
                if not nxdb.get_nexus_vrf_binding(context.session, vrf_id,
                                                  connection[0]):
                    self.driver.create_vrf(connection[0], vrf_id)
                    nxdb.add_nexus_vrf_binding(context.session, vrf_id,
                                               connection[0])
                # Check for a SVI binding
                bindings = nxdb.get_nexussvi_bindings(context.session, 
                                                      vlan_id, connection[0])
                if not bindings:
                    # Create SVI in this VRF
                    self._add_nexus_svi_interface(connection[0], router_id,
                                                  vlan_id, subnet, vrf_id)
                # add VRF gateways
                for gateway in gateways:
                    self.driver.add_vrf_gateway(connection[0],
                                                vrf_id, gateway)
                    nxdb.add_nexus_vrf_binding_gateway(
                        context.session, vrf_id, connection[0], gateway)

    def _create_floatingip(self, context, port, floating_ip):
        host_id = port.get(portbindings.HOST_ID)
        fixed_ips = port.get('fixed_ips')
        ips = []
        for ip in fixed_ips:
            ips.append(ip.get('ip_address'))

        # Get switch connections for this host
        connections = self._get_switch_info(host_id)
        for connection in connections:
            self.driver.create_floatingip_nat_rule(
                connection[0], floating_ip.get('floating_ip_address'), ips)

    def _delete_floatingip(self, context, floating_ip):
        port = self.get_port(context, floating_ip.get('port_id'))
        host_id = port.get(portbindings.HOST_ID)
        fixed_ips = port.get('fixed_ips')
        ips = []
        for ip in fixed_ips:
            ips.append(ip.get('ip_address'))

        # Get switch connections for this host
        connections = self._get_switch_info(host_id)
        for connection in connections:
            self.driver.delete_floatingip_nat_rule(
                connection[0], floating_ip.get('floating_ip_address'), ips)

    def remove_router_interface(self, context, router_id, interface_info):
        if self.vrf_enabled:
            # Get vrf_id for this router
            db_router = nxdb.get_nexus_vrf(context.session, router_id)
            # Get all bindings for this vrf
            bindings = nxdb.get_nexus_vrf_bindings(context.session,
                                                   db_router['vrf_id'])

            try:
                for binding in bindings:
                    self.driver.delete_vrf(binding['vrf_id'], binding['switch_ip'])
                    nxdb.delete_nexus_vrf_binding(context.session,
                                                  binding['vrf_id'],
                                                  binding['switch_ip'])
            except:
                pass
        else:
            subnet_id = interface_info['subnet_id']
            subnet = self.get_subnet(context, subnet_id)
            vlan_id = self._get_vlanid(context, subnet)
            bindings = nxdb.get_nexussvi_bindings(context.session, vlan_id)
            if bindings:
                switch_ip = bindings[0].switch_ip
                # Delete the entry from the databases.
                with context.session.begin(subtransactions=True):
                    nxdb.delete_nexussvi_binding(context.session, vlan_id)

                # Delete the entry from the nexus switch.
                try:
                    self._remove_nexus_svi_interface(switch_ip, vlan_id)
                except Exception:
                    with excutils.save_and_reraise_exception():
                        self._add_router_db(context, router_id, interface_info,
                                            switch_ip, vlan_id, subnet_id)

        return super(CiscoNexusL3ServicePlugin, self).remove_router_interface(
            context, router_id, interface_info)

    def update_floatingip(self, context, id, floatingip):
        port_id = floatingip.get('floatingip').get('port_id')
        floating_ip = self.get_floatingip(context, id)
        if self.nat_enabled:
            if port_id:
                port = self.get_port(context, port_id)
                self._create_floatingip(context, port, floating_ip)
            else:
               self._delete_floatingip(context, floating_ip)

        return super(CiscoNexusL3ServicePlugin, self).update_floatingip(
            context, id, floatingip)

    def create_floatingip(self, context, floatingip):
        return super(CiscoNexusL3ServicePlugin, self).create_floatingip(
            context, floatingip)

    def update_floatingip_status(self, context, floatingip_id, status):
        return super(CiscoNexusL3ServicePlugin, self).update_floatingip_status(
            context, floatingip_id, status)

    def delete_floatingip(self, context, id):
        return super(NexusL3ServicePlugin, self).delete_floatingip(
            context, id)

    def dissassociate_floatingips(self, context, port_id):
        return super(NexusL3ServicePlugin, self).disassociate_floatingips(
            context, port_id)
