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
from sqlalchemy import asc
from sqlalchemy import func
from sqlalchemy import or_

from networking_odl.db.models import OpendaylightJournal

import neutron.db.api as db


def _check_for_pending_or_processing_ops(session, object_uuid):
    return session.query(OpendaylightJournal).filter(
        or_(OpendaylightJournal.state == 'pending',
            OpendaylightJournal.state == 'processing'),
        OpendaylightJournal.object_uuid == object_uuid).all()


def get_untried_db_row_with_lock(session=None):
    if session is None:
        session = db.get_session()

    return session.query(OpendaylightJournal).filter_by(
        state='pending', retry_count=0).with_for_update().first()


def get_oldest_pending_db_row_with_lock(session=None):
    if session is None:
        session = db.get_session()

    return session.query(OpendaylightJournal).filter_by(
        state='pending').order_by(
        asc(OpendaylightJournal.last_retried)).with_for_update().first()


def get_all_db_rows(session=None):
    if session is None:
        session = db.get_session()

    return session.query(OpendaylightJournal).all()


def get_all_db_rows_by_state(session, state):
    if session is None:
        session = db.get_session()

    return session.query(OpendaylightJournal).filter_by(state=state).all()


def update_pending_db_row_processing(session, row):
    if session is None:
        session = db.get_session()

    row.state = 'processing'
    session.merge(row)
    session.flush()


def update_pending_db_row_retry(session, row):
    if session is None:
        session = db.get_session()
    # TODO(asomya): make this configurable
    if row.retry_count >= 5:
        row.state = 'failed'
    else:
        row.retry_count = row.retry_count + 1
        row.state = 'pending'
    session.merge(row)
    session.flush()


def update_processing_db_row_passed(session, row):
    if session is None:
        session = db.get_session()
    row.state = 'completed'
    session.merge(row)
    session.flush()


def update_pending_db_row_failed(row):
    row.update({'retry_count': row.retry_count + 1,
                'state': 'failed'})


def delete_row(session, row=None, row_id=None):
    if session is None:
        session = db.get_session()
    if row_id:
        row = session.query(OpendaylightJournal).filter_by(id=row_id).one()
    if row:
        session.delete(row)
        session.flush()


def create_pending_row(session, object_type, object_uuid,
                       operation, data):
    if session is None:
        session = db.get_session()
    row = OpendaylightJournal(object_type=object_type, object_uuid=object_uuid,
                              operation=operation, data=data,
                              created_at=func.now(), state='pending')
    session.add(row)
    session.flush()


def validate_network_operation(session, object_uuid, operation, data):
    """Validate the network operation based on dependencies.

    Validate network operation depending on whether it's dependencies
    are still in 'pending' or 'processing' state. e.g.
    """
    return True


def validate_subnet_operation(session, object_uuid, operation, data):
    """Validate the subnet operation based on dependencies.

    Validate subnet operation depending on whether it's dependencies
    are still in 'pending' or 'processing' state. e.g.
    """
    if session is None:
        session = db.get_session()

    if operation in ('create', 'update'):
        network_id = data['network_id']
        # Check for pending or processing network operations
        if _check_for_pending_or_processing_ops(session, network_id):
            return False
    elif operation == 'delete':
        # TODO(asomya):Check for pending port operations
        pass

    return True


def validate_port_operation(session, object_uuid, operation, data):
    """Validate port operation based on dependencies.

    Validate port operation depending on whether it's dependencies
    are still in 'pending' or 'processing' state. e.g.
    """
    if session is None:
        session = db.get_session()

    if operation in ('create', 'update'):
        network_id = data['network_id']
        # Check for pending or processing network operations
        ops = _check_for_pending_or_processing_ops(session, network_id)
        # Check for pending subnet operations.
        for fixed_ip in data['fixed_ips']:
            ops += _check_for_pending_or_processing_ops(session,
                                                        fixed_ip['subnet_id'])
        if ops:
            return False

    return True


def validate_router_operation(session, object_uuid, operation, data):
    """Validate router operation based on dependencies.

    Validate router operation depending on whether it's dependencies
    are still in 'pending' or 'processing' state. e.g.
    """
    if session is None:
        session = db.get_session()

    if operation in ('create', 'update'):
        if 'external_gateway_info' in data:
            network_id = data['external_gateway_info']['network_id']
            # Check for pending or processing network operations
            if _check_for_pending_or_processing_ops(session, network_id):
                return False
    else:
        # TODO(rcurran): Check for router interface operations.
        pass

    return True


def validate_floatingip_operation(session, object_uuid, operation, data):
    """Validate floatingip operation based on dependencies.

    Validate floating IP operation depending on whether it's dependencies
    are still in 'pending' or 'processing' state. e.g.
    """
    if session is None:
        session = db.get_session()

    if operation in ('create', 'update'):
        if 'port_id' in data:
            if _check_for_pending_or_processing_ops(session, data['port_id']):
                return False
        else:
            if _check_for_pending_or_processing_ops(
                    session, data['floating_network_id']):
                return False

    return True


def validate_router_interface_operation(session, object_uuid, operation, data):
    """Validate router_interface operation based on dependencies.

    Validate router_interface operation depending on whether it's dependencies
    are still in 'pending' or 'processing' state. e.g.
    """
    if session is None:
        session = db.get_session()

    if operation is 'add':
        # TODO(rcurran): Check for port_id?
        if _check_for_pending_or_processing_ops(session, data['subnet_id']):
            return False
    else:
        # TODO(rcurran)
        pass

    return True


def validate_security_group_operation(session, object_uuid, operation, data):
    """Validate security_group operation based on dependencies.

    Validate security_group operation depending on whether it's dependencies
    are still in 'pending' or 'processing' state. e.g.
    """
    if session is None:
        session = db.get_session()

    #TODO(rcurran) - add dependencies.

    return True


def validate_security_group_rule_operation(session, object_uuid, operation,
                                           data):
    """Validate security_group_rule operation based on dependencies.

    Validate security_group_rule operation depending on whether it's
    dependencies are still in 'pending' or 'processing' state. e.g.
    """
    if session is None:
        session = db.get_session()

    #TODO(rcurran) - add dependencies.

    return True
