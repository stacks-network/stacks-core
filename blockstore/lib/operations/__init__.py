#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstore
    ~~~~~
    copyright: (c) 2014 by Halfmoon Labs, Inc.
    copyright: (c) 2015 by Blockstack.org
    
    This file is part of Blockstore
    
    Blockstore is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    
    Blockstore is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with Blockstore.  If not, see <http://www.gnu.org/licenses/>.
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

from .preorder import build as build_preorder, \
    broadcast as preorder_name, parse as parse_preorder, \
    serialize as serialize_preorder
from .register import build as build_registration, \
    broadcast as register_name, parse as parse_registration, \
    serialize as serialize_registration
from .transfer import build as build_transfer, \
    broadcast as transfer_name, parse as parse_transfer, \
    serialize as serialize_transfer, \
    make_outputs as make_transfer_ouptuts
from .update import build as build_update, \
    broadcast as update_name, parse as parse_update, \
    serialize as serialize_update
from .revoke import build as build_revoke, \
    broadcast as revoke_name, parse as parse_revoke, \
    serialize as serialize_revoke
from .namespacepreorder import build as build_namespace_preorder, \
    broadcast as namespace_preorder, parse as parse_namespace_preorder, \
    serialize as serialize_namespace_preorder
from .nameimport import build as build_name_import, \
    broadcast as name_import, parse as parse_name_import, \
    serialize as serialize_name_import
from .namespacereveal import build as build_namespace_reveal, \
    broadcast as namespace_reveal, parse as parse_namespace_reveal, \
    serialize as serialize_namespace_reveal
from .namespaceready import build as build_namespace_ready, \
    broadcast as namespace_ready, parse as parse_namespace_ready, \
    serialize as serialize_namespace_ready

from .register import get_registration_recipient_from_outputs 

from .transfer import get_transfer_recipient_from_outputs

from .nameimport import get_import_update_hash_from_outputs