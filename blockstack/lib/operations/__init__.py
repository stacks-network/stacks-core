#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstack
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016 by Blockstack.org

    This file is part of Blockstack

    Blockstack is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Blockstack is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with Blockstack. If not, see <http://www.gnu.org/licenses/>.
"""

import preorder
import register
import transfer
import update
import revoke
import nameimport
import namespacepreorder
import namespacereveal
import namespaceready
import announce
import binascii

SERIALIZE_FIELDS = {
    "NAME_PREORDER": preorder.FIELDS,
    "NAME_REGISTRATION": register.FIELDS,
    "NAME_UPDATE": update.FIELDS,
    "NAME_TRANSFER": transfer.FIELDS,
    "NAME_REVOKE": revoke.FIELDS,
    "NAME_IMPORT": nameimport.FIELDS,
    "NAMESPACE_PREORDER": namespacepreorder.FIELDS,
    "NAMESPACE_REVEAL": namespacereveal.FIELDS,
    "NAMESPACE_READY": namespaceready.FIELDS,
    "ANNOUNCE": announce.FIELDS
}

# NOTE: most operation logic lives in the client
from blockstack_client.operations import *

from .register import get_registration_recipient_from_outputs 
from .transfer import get_transfer_recipient_from_outputs
from .nameimport import get_import_update_hash_from_outputs



