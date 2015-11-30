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

import datetime

import sqlalchemy as sa

from neutron.db import model_base
from neutron.db.models_v2 import HasId

from networking_odl.common import constants as odl_const


class OpendaylightJournal(model_base.BASEV2, HasId):
    __tablename__ = 'opendaylightjournal'

    object_type = sa.Column(sa.Enum(odl_const.ODL_NETWORK,
                                    odl_const.ODL_SUBNET,
                                    odl_const.ODL_PORT,
                                    odl_const.ODL_ROUTER,
                                    odl_const.ODL_FLOATINGIP,
                                    odl_const.ODL_ROUTER_INTF,
                                    odl_const.ODL_SG,
                                    odl_const.ODL_SG_RULE),
                            nullable=False)
    object_uuid = sa.Column(sa.String(36), nullable=False)
    operation = sa.Column(sa.Enum(odl_const.ODL_CREATE,
                                  odl_const.ODL_UPDATE,
                                  odl_const.ODL_DELETE,
                                  odl_const.ODL_ADD,
                                  odl_const.ODL_REMOVE),
                          nullable=False)
    data = sa.Column(sa.PickleType, nullable=True)
    state = sa.Column(sa.Enum('pending', 'failed', 'processing', 'completed'))
    retry_count = sa.Column(sa.Integer, default=0)
    created_at = sa.Column(sa.DateTime)
    last_retried = sa.Column(sa.TIMESTAMP, nullable=False,
                             default=datetime.datetime.utcnow())
