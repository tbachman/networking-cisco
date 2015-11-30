# Copyright (c) 2015 OpenStack Foundation
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

from networking_odl.common import client
from networking_odl.common import constants as odl_const
from networking_odl.common import journal
from networking_odl.db import db
from networking_odl.ml2 import mech_driver_v2

import mock
from oslo_config import cfg
from oslo_serialization import jsonutils
import requests
import webob.exc

from neutron.extensions import portbindings
from neutron.plugins.common import constants
from neutron.plugins.ml2 import config as config
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2 import plugin
from neutron.tests import base
from neutron.tests.unit.plugins.ml2 import test_plugin
from neutron.tests.unit import testlib_api

cfg.CONF.import_group('ml2_odl', 'networking_odl.common.config')

HOST = 'fake-host'
PLUGIN_NAME = 'neutron.plugins.ml2.plugin.Ml2Plugin'
SECURITY_GROUP = '2f9244b4-9bee-4e81-bc4a-3f3c2045b3d7'
SG_FAKE_ID = "sg_fake_id"


class OpenDaylightTestCase(test_plugin.Ml2PluginV2TestCase):
    _mechanism_drivers = ['opendaylight']

    def setUp(self):
        # Set URL/user/pass so init doesn't throw a cfg required error.
        # They are not used in these tests since sendjson is overwritten.
        config.cfg.CONF.set_override('url', 'http://127.0.0.1:9999', 'ml2_odl')
        config.cfg.CONF.set_override('username', 'someuser', 'ml2_odl')
        config.cfg.CONF.set_override('password', 'somepass', 'ml2_odl')

        super(OpenDaylightTestCase, self).setUp()
        self.port_create_status = 'DOWN'
        self.mech = mech_driver_v2.OpenDaylightMechanismDriver()
        mock.patch.object(journal.OpendaylightJournalThread,
                          'start_odl_sync_thread').start()
        self.mock_sendjson = mock.patch.object(client.OpenDaylightRestClient,
                                               'sendjson').start()
        self.mock_sendjson.side_effect = self.check_sendjson

    def check_sendjson(self, method, urlpath, obj):
        self.assertFalse(urlpath.startswith("http://"))


class OpenDayLightMechanismConfigTests(testlib_api.SqlTestCase):

    def _set_config(self, url='http://127.0.0.1:9999', username='someuser',
                    password='somepass'):
        config.cfg.CONF.set_override('mechanism_drivers',
                                     ['logger', 'opendaylight'],
                                     'ml2')
        config.cfg.CONF.set_override('url', url, 'ml2_odl')
        config.cfg.CONF.set_override('username', username, 'ml2_odl')
        config.cfg.CONF.set_override('password', password, 'ml2_odl')

    def _test_missing_config(self, **kwargs):
        self._set_config(**kwargs)
        self.assertRaises(config.cfg.RequiredOptError,
                          plugin.Ml2Plugin)

    def test_valid_config(self):
        self._set_config()
        plugin.Ml2Plugin()

    def test_missing_url_raises_exception(self):
        self._test_missing_config(url=None)

    def test_missing_username_raises_exception(self):
        self._test_missing_config(username=None)

    def test_missing_password_raises_exception(self):
        self._test_missing_config(password=None)


class OpenDaylightMechanismTestBasicGet(test_plugin.TestMl2BasicGet,
                                        OpenDaylightTestCase):
    pass


class OpenDaylightMechanismTestNetworksV2(test_plugin.TestMl2NetworksV2,
                                          OpenDaylightTestCase):
    pass


class OpenDaylightMechanismTestSubnetsV2(test_plugin.TestMl2SubnetsV2,
                                         OpenDaylightTestCase):
    pass


class OpenDaylightMechanismTestPortsV2(test_plugin.TestMl2PortsV2,
                                       OpenDaylightTestCase):
    def test_update_port_mac(self):
        self.check_update_port_mac(
            host_arg={portbindings.HOST_ID: HOST},
            arg_list=(portbindings.HOST_ID,),
            expected_status=webob.exc.HTTPConflict.code,
            expected_error='PortBound')


class DataMatcher(object):

    def __init__(self, operation, object_type, context):
        self._data = context.current.copy()
        self._object_type = object_type
        filter_cls = (journal.OpendaylightJournalThread.
                      FILTER_MAP[object_type])
        attr_filter = getattr(filter_cls, 'filter_%s_attributes' % operation)
        attr_filter(self._data)

    def __eq__(self, s):
        data = jsonutils.loads(s)
        return self._data == data[self._object_type]


class OpenDaylightMechanismDriverTestCase(base.BaseTestCase):

    def setUp(self):
        super(OpenDaylightMechanismDriverTestCase, self).setUp()
        config.cfg.CONF.set_override('mechanism_drivers',
                                     ['logger', 'opendaylight'], 'ml2')
        config.cfg.CONF.set_override('url', 'http://127.0.0.1:9999', 'ml2_odl')
        config.cfg.CONF.set_override('username', 'someuser', 'ml2_odl')
        config.cfg.CONF.set_override('password', 'somepass', 'ml2_odl')
        self.mech = mech_driver_v2.OpenDaylightMechanismDriver()
        mock.patch.object(journal.OpendaylightJournalThread,
                          'start_odl_sync_thread').start()
        self.mech.initialize()
        self.thread = journal.OpendaylightJournalThread()

    @staticmethod
    def _get_mock_network_operation_context():
        current = {'status': 'ACTIVE',
                   'subnets': [],
                   'name': 'net1',
                   'provider:physical_network': None,
                   'admin_state_up': True,
                   'tenant_id': 'test-tenant',
                   'provider:network_type': 'local',
                   'router:external': False,
                   'shared': False,
                   'id': 'd897e21a-dfd6-4331-a5dd-7524fa421c3e',
                   'provider:segmentation_id': None}
        context = mock.Mock(current=current)
        return context

    @staticmethod
    def _get_mock_subnet_operation_context():
        current = {'ipv6_ra_mode': None,
                   'allocation_pools': [{'start': '10.0.0.2',
                                         'end': '10.0.1.254'}],
                   'host_routes': [],
                   'ipv6_address_mode': None,
                   'cidr': '10.0.0.0/23',
                   'id': '72c56c48-e9b8-4dcf-b3a7-0813bb3bd839',
                   'name': '',
                   'enable_dhcp': True,
                   'network_id': 'd897e21a-dfd6-4331-a5dd-7524fa421c3e',
                   'tenant_id': 'test-tenant',
                   'dns_nameservers': [],
                   'gateway_ip': '10.0.0.1',
                   'ip_version': 4,
                   'shared': False}
        context = mock.Mock(current=current)
        return context

    @staticmethod
    def _get_mock_port_operation_context():
        current = {'status': 'DOWN',
                   'binding:host_id': '',
                   'allowed_address_pairs': [],
                   'device_owner': 'fake_owner',
                   'binding:profile': {},
                   'fixed_ips': [],
                   'id': '72c56c48-e9b8-4dcf-b3a7-0813bb3bd839',
                   'security_groups': [SECURITY_GROUP],
                   'device_id': 'fake_device',
                   'name': '',
                   'admin_state_up': True,
                   'network_id': 'd897e21a-dfd6-4331-a5dd-7524fa421c3e',
                   'tenant_id': 'test-tenant',
                   'binding:vif_details': {},
                   'binding:vnic_type': 'normal',
                   'binding:vif_type': 'unbound',
                   'mac_address': '12:34:56:78:21:b6'}
        context = mock.Mock(current=current)
        context._plugin.get_security_group = mock.Mock(
            return_value=SECURITY_GROUP)
        context._plugin.get_port = mock.Mock(return_value=current)
        context._network_context = mock.Mock(
            _network=OpenDaylightMechanismDriverTestCase.
            _get_mock_network_operation_context().current)
        return context

    @staticmethod
    def _get_mock_security_group_operation_context():
        # Use 'id' to pass the sync_from_callback res_id's value to
        # the unit tests.
        current = {'context': {},
                   'security_group_id': SG_FAKE_ID,
                   'security_group': [SECURITY_GROUP],
                   'is_default': True,
                   'id': SG_FAKE_ID}
        context = mock.Mock(current=current)
        return context

    @staticmethod
    def _get_mock_security_group_rule_operation_context():
        # Use 'id' to pass the sync_from_callback res_id's value to
        # the unit tests.
        current = {'context': {},
                   'security_group_id': SG_FAKE_ID,
                   'security_group_rule': [SECURITY_GROUP],
                   'id': SG_FAKE_ID}
        context = mock.Mock(current=current)
        return context

    @classmethod
    def _get_mock_operation_context(cls, object_type):
        getter = getattr(cls, '_get_mock_%s_operation_context' % object_type)
        return getter()

    _status_code_msgs = {
        200: '',
        201: '',
        204: '',
        400: '400 Client Error: Bad Request',
        401: '401 Client Error: Unauthorized',
        403: '403 Client Error: Forbidden',
        404: '404 Client Error: Not Found',
        409: '409 Client Error: Conflict',
        501: '501 Server Error: Not Implemented',
        503: '503 Server Error: Service Unavailable',
    }

    def _db_cleanup(self):
        rows = db.get_all_db_rows()
        for row in rows:
            db.delete_row(None, row=row)

    @classmethod
    def _get_mock_request_response(cls, status_code):
        response = mock.Mock(status_code=status_code)
        response.raise_for_status = mock.Mock() if status_code < 400 else (
            mock.Mock(side_effect=requests.exceptions.HTTPError(
                cls._status_code_msgs[status_code])))
        return response

    def _test_operation(self, method, context, status_code, expected_calls,
                        *args, **kwargs):
        request_response = self._get_mock_request_response(status_code)
        with mock.patch('requests.request',
                        return_value=request_response) as mock_method:
            method()

        if expected_calls:
            mock_method.assert_called_with(
                headers={'Content-Type': 'application/json'},
                auth=(config.cfg.CONF.ml2_odl.username,
                      config.cfg.CONF.ml2_odl.password),
                timeout=config.cfg.CONF.ml2_odl.timeout, *args, **kwargs)
        self.assertEqual(expected_calls, mock_method.call_count)

    def _call_operation_object(self, operation, object_type):
        context = self._get_mock_operation_context(object_type)

        if object_type in [odl_const.ODL_SG, odl_const.ODL_SG_RULE]:
            self.mech.sync_from_callback(operation, object_type + 's',
                                         SG_FAKE_ID, context.current)
        else:
            method = getattr(self.mech, '%s_%s_precommit' % (operation,
                                                             object_type))
            method(context)

    def _test_operation_object(self, operation, object_type):
        self._call_operation_object(operation, object_type)

        context = self._get_mock_operation_context(object_type)
        row = db.get_oldest_pending_db_row_with_lock()

        self.assertEqual(operation, row['operation'])
        self.assertEqual(object_type, row['object_type'])
        self.assertEqual(context.current['id'], row['object_uuid'])

        self._db_cleanup()

    def _test_thread_processing(self, object_type, operation,
                                expected_calls=1):
        http_requests = {odl_const.ODL_CREATE: 'post',
                         odl_const.ODL_UPDATE: 'put',
                         odl_const.ODL_DELETE: 'delete'}
        status_codes = {odl_const.ODL_CREATE: requests.codes.created,
                        odl_const.ODL_UPDATE: requests.codes.ok,
                        odl_const.ODL_DELETE: requests.codes.no_content}

        http_request = http_requests[operation]
        status_code = status_codes[operation]

        self._call_operation_object(operation, object_type)

        context = self._get_mock_operation_context(object_type)
        if operation in [odl_const.ODL_UPDATE, odl_const.ODL_DELETE]:
            url = '%s/%ss/%s' % (config.cfg.CONF.ml2_odl.url,
                                 object_type, context.current['id'])
        else:
            url = '%s/%ss' % (config.cfg.CONF.ml2_odl.url, object_type)

        if operation in [odl_const.ODL_CREATE, odl_const.ODL_UPDATE]:
            kwargs = {
                'url': url,
                'data': DataMatcher(operation, object_type, context)}
        else:
            kwargs = {'url': url, 'data': None}
        self._test_operation(self.thread.sync_pending_row, context,
                             status_code, expected_calls, http_request,
                             **kwargs)

    def _test_object_type(self, object_type):
        # Add and process create request.
        self._test_thread_processing(object_type, odl_const.ODL_CREATE)
        rows = db.get_all_db_rows_by_state(None, 'completed')
        self.assertEqual(1, len(rows))

        # Add and process update request. Adds to database.
        self._test_thread_processing(object_type, odl_const.ODL_UPDATE)
        rows = db.get_all_db_rows_by_state(None, 'completed')
        self.assertEqual(2, len(rows))

        # Add and process update request. Adds to database.
        self._test_thread_processing(object_type, odl_const.ODL_DELETE)
        rows = db.get_all_db_rows_by_state(None, 'completed')
        self.assertEqual(3, len(rows))

        self._db_cleanup()

    def _test_object_type_pending_network(self, object_type):
        # Create a network (creates db row in pending state).
        self._call_operation_object(odl_const.ODL_CREATE,
                                    odl_const.ODL_NETWORK)

        # Create object_type database row and process. This results in both
        # the object_type and network rows being processed.
        self._test_thread_processing(object_type, odl_const.ODL_CREATE,
                                     expected_calls=2)

        # Verify both rows are now marked as completed.
        rows = db.get_all_db_rows_by_state(None, 'completed')
        self.assertEqual(2, len(rows))

        self._db_cleanup()

    def test_driver(self):
        for operation in [odl_const.ODL_CREATE, odl_const.ODL_UPDATE,
                          odl_const.ODL_DELETE]:
            for object_type in [odl_const.ODL_NETWORK, odl_const.ODL_SUBNET,
                                odl_const.ODL_PORT]:
                self._test_operation_object(operation, object_type)

    def test_network(self):
        self._test_object_type(odl_const.ODL_NETWORK)

    def test_subnet(self):
        self._test_object_type(odl_const.ODL_SUBNET)

    def test_subnet_pending_network(self):
        self._test_object_type_pending_network(odl_const.ODL_SUBNET)

    def test_port(self):
        self._test_object_type(odl_const.ODL_PORT)

    def test_port_pending_network(self):
        self._test_object_type_pending_network(odl_const.ODL_PORT)

    def test_sg(self):
        self._test_object_type(odl_const.ODL_SG)

    def test_sg_rule(self):
        self._test_object_type(odl_const.ODL_SG_RULE)

    # TODO(rcurran): Revisit this UT once db state of "processing" is
    # introduced into driver code. Perhaps include a UT with network_id
    # that does not belong to this port.
    def test_port_processing_network(self):
        # Create a network (creates db row in pending state).
        self._call_operation_object(odl_const.ODL_CREATE,
                                    odl_const.ODL_NETWORK)

        # Get network row and mark as processing.
        row = db.get_all_db_rows_by_state(None, 'pending')
        db.update_pending_db_row_processing(None, row[0])

        # Create port database row and process.
        # Verify that port create request is not processed (until we force
        # processing via mock).
        #
        # Mock out call in validate_operation to return twice with
        # "valid" data (this represents the "processing" network row).
        # Third call will return [] to have the port row processed.
        # (Just to get the test out of the infinite loop.)
        # expected_calls = 1 verifies that the port row was processed
        # but not the network row.
        return_values = [['valid_dummy1'], ['valid_dummy2'], []]
        with mock.patch.object(db, '_check_for_pending_or_processing_ops',
                               side_effect=return_values) as mock_method:
            self._test_thread_processing(odl_const.ODL_PORT,
                                         odl_const.ODL_CREATE)

        # Verify that network row is still in the database.
        rows = db.get_all_db_rows_by_state(None, 'processing')
        self.assertEqual(1, len(rows))

        # Verify calls to mocked method.
        self.assertEqual(len(return_values), mock_method.call_count)

        self._db_cleanup()

    def test_check_segment(self):
        """Validate the check_segment call."""
        segment = {'api.NETWORK_TYPE': ""}
        segment[api.NETWORK_TYPE] = constants.TYPE_LOCAL
        self.assertTrue(self.mech._check_segment(segment))
        segment[api.NETWORK_TYPE] = constants.TYPE_FLAT
        self.assertFalse(self.mech._check_segment(segment))
        segment[api.NETWORK_TYPE] = constants.TYPE_VLAN
        self.assertTrue(self.mech._check_segment(segment))
        segment[api.NETWORK_TYPE] = constants.TYPE_GRE
        self.assertTrue(self.mech._check_segment(segment))
        segment[api.NETWORK_TYPE] = constants.TYPE_VXLAN
        self.assertTrue(self.mech._check_segment(segment))
        # Validate a network type not currently supported
        segment[api.NETWORK_TYPE] = 'mpls'
        self.assertFalse(self.mech._check_segment(segment))
