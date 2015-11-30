# Copyright (c) 2013-2014 OpenStack Foundation
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

import threading

from copy import deepcopy

from oslo_config import cfg
from oslo_log import log as logging

# TODO(rcurran): Import configuration from networking_odl, not neutron.
# from networking_odl.common import config as odl_conf
from networking_odl.common import constants as odl_const
from networking_odl.common import filters
from networking_odl.db import db
from networking_odl.openstack.common._i18n import _LE
from networking_odl.openstack.common._i18n import _LI

from networking_odl.common.client import OpenDaylightRestClient

LOG = logging.getLogger(__name__)

# TODO(rcurran): Make configurable. (Config under /neutron today.)
ODL_SYNC_THREAD_TIMEOUT = 10


def call_thread_on_end(func):
    def new_func(obj, *args):
        func(obj, *args)
        OpendaylightJournalThread.start_odl_sync_thread()
    return new_func


class OpendaylightJournalThread(object):
    """Thread worker for the Opendaylight Journal Database."""
    FILTER_MAP = {
        odl_const.ODL_FLOATINGIP: filters.FloatingIPFilter,
        odl_const.ODL_NETWORK: filters.NetworkFilter,
        odl_const.ODL_ROUTER: filters.RouterFilter,
        odl_const.ODL_ROUTER_INTF: filters.RouterIntfFilter,
        odl_const.ODL_SUBNET: filters.SubnetFilter,
        odl_const.ODL_PORT: filters.PortFilter,
        odl_const.ODL_SG: filters.SecurityGroupFilter,
        odl_const.ODL_SG_RULE: filters.SecurityGroupRuleFilter,
    }

    def __init__(self):
        self.client = OpenDaylightRestClient(
            cfg.CONF.ml2_odl.url,
            cfg.CONF.ml2_odl.username,
            cfg.CONF.ml2_odl.password,
            cfg.CONF.ml2_odl.timeout
        )
        self._odl_sync_timeout = ODL_SYNC_THREAD_TIMEOUT
        self.start_odl_sync_thread()

    def start_odl_sync_thread(self):
        # Don't start a second thread if there is one alive already
        if (hasattr(self, '_odl_sync_thread') and
           self._odl_sync_thread.isAlive()):
            return

        self._odl_sync_thread = threading.Thread(
            name='sync',
            target=self.sync_pending_row)
        self._odl_sync_thread.start()

        if hasattr(self, 'timer'):
            LOG.debug("Resetting thread timer")
            self.timer.cancel()
            self.timer = None
        self.timer = threading.Timer(self._odl_sync_timeout,
                                     self.start_odl_sync_thread)
        self.timer.start()

    def stop_odl_sync_thread(self):
        if self.timer:
            self.timer.cancel()
            self.timer = None

    def _json_data(self, row):
        filter_cls = self.FILTER_MAP[row.object_type]

        if row.operation == odl_const.ODL_CREATE:
            method = 'post'
            attr_filter = filter_cls.filter_create_attributes
            data = deepcopy(row.data)
            urlpath = row.object_type + 's'
            attr_filter(data)
            to_send = {row.object_type: data}
        elif row.operation == odl_const.ODL_UPDATE:
            method = 'put'
            attr_filter = filter_cls.filter_update_attributes
            data = deepcopy(row.data)
            urlpath = row.object_type + 's/' + row.object_uuid
            attr_filter(data)
            to_send = {row.object_type: data}
        elif row.operation == odl_const.ODL_DELETE:
            method = 'delete'
            data = None
            urlpath = row.object_type + 's/' + row.object_uuid
            to_send = None
        elif row.operation == odl_const.ODL_ADD:
            method = 'put'
            attr_filter = filter_cls.filter_add_attributes
            data = deepcopy(row.data)
            attr_filter(data)
            urlpath = ('routers/' + row.object_uuid + '/add_router_interface')
            to_send = data
        elif row.operation == odl_const.ODL_REMOVE:
            method = 'put'
            attr_filter = filter_cls.filter_remove_attributes
            data = deepcopy(row.data)
            attr_filter(data)
            urlpath = ('routers/' + row.object_uuid +
                       '/remove_router_interface')
            to_send = data

        return method, urlpath, to_send

    def sync_pending_row(self):
        # Block until all pending rows are processed
        while True:
            LOG.debug("Thread walking database")
            row = db.get_oldest_pending_db_row_with_lock(None)
            if not row:
                break

            validate_object_operation = getattr(
                db, 'validate_%s_operation' % row.object_type)
            valid = validate_object_operation(None, row.object_uuid,
                                              row.operation, row.data)
            if not valid:
                LOG.info(_LI("%(operation)s %(type)s %(uuid)s is not a "
                             "valid operation yet, skipping for now"),
                         {'operation': row.operation,
                          'type': row.object_type,
                          'uuid': row.object_uuid})
                continue

            LOG.info(_LI("Syncing %(operation)s %(type)s %(uuid)s"),
                     {'operation': row.operation, 'type': row.object_type,
                      'uuid': row.object_uuid})

            # Add code to sync this to ODL
            method, urlpath, to_send = self._json_data(row)

            try:
                self.client.sendjson(method, urlpath, to_send)
                # NOTE: This will be marked 'processing' once we have
                # the asynchronous communication worked out with the ODL folks.
                db.update_processing_db_row_passed(None, row)
            except Exception as e:
                LOG.error(_LE("Error syncing %(type)s %(operation)s,"
                              " id %(uuid)s Error: %(error)s"),
                          {'type': row.object_type,
                           'uuid': row.object_uuid,
                           'operation': row.operation,
                           'error': e.message})
                db.update_pending_db_row_retry(None, row)
