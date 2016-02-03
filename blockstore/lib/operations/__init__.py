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
import preorder_multi
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

from .preorder import build as build_preorder, \
    broadcast as preorder_name, tx_extract as extract_preorder, \
    get_fees as preorder_fees, restore_delta as restore_preorder
from .preorder_multi import build as build_preorder_multi, \
    broadcast as preorder_name_multi, tx_extract as extract_preorder_multi, \
    get_fees as preorder_multi_fees, hash_names as preorder_multi_hash_names, \
    decompose as preorder_decompose, restore_delta as restore_preorder_multi
from .register import build as build_registration, \
    broadcast as register_name, tx_extract as extract_registration, \
    get_fees as registration_fees, restore_delta as restore_register, \
    consensus_extras as register_consensus_extras
from .register_multi import build as build_registration_multi, \
    broadcast as register_name_multi, tx_extract as extract_registration_multi, \
    get_fees as registration_multi_fees, decompose as registration_decompose, \
    restore_delta as restore_register_multi
from .transfer import build as build_transfer, \
    broadcast as transfer_name, tx_extract as extract_transfer, \
    make_outputs as make_transfer_ouptuts, \
    get_fees as transfer_fees, restore_delta as restore_transfer, \
    consensus_extras as transfer_consensus_extras
from .update import build as build_update, \
    broadcast as update_name, tx_extract as extract_update, \
    get_fees as update_fees, restore_delta as restore_update, \
    consensus_extras as update_consensus_extras
from .revoke import build as build_revoke, \
    broadcast as revoke_name, tx_extract as extract_revoke, \
    get_fees as revoke_fees, restore_delta as restore_revoke
from .namespacepreorder import build as build_namespace_preorder, \
    broadcast as namespace_preorder, tx_extract as extract_namespace_preorder, \
    get_fees as namespace_preorder_fees, restore_delta as restore_namespace_preorder
from .nameimport import build as build_name_import, \
    broadcast as name_import, tx_extract as extract_name_import, \
    get_fees as name_import_fees, restore_delta as restore_name_import, \
    consensus_extras as name_import_consensus_extras
from .namespacereveal import build as build_namespace_reveal, \
    broadcast as namespace_reveal, tx_extract as extract_namespace_reveal, \
    get_fees as namespace_reveal_fees, restore_delta as restore_namespace_reveal
from .namespaceready import build as build_namespace_ready, \
    broadcast as namespace_ready, tx_extract as extract_namespace_ready, \
    get_fees as namespace_ready_fees, restore_delta as restore_namespace_ready
from .announce import build as build_announce, \
    broadcast as send_announce, tx_extract as extract_announce, \
    get_fees as announce_fees, restore_delta as restore_announce

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

# NOTE: these all have the same signatures
EXTRACT_METHODS = {
    "NAME_PREORDER": extract_preorder,
    "NAME_REGISTRATION": extract_registration,
    "NAME_UPDATE": extract_update,
    "NAME_TRANSFER": extract_transfer,
    "NAME_REVOKE": extract_revoke,
    "NAME_IMPORT": extract_name_import,
    "NAMESPACE_PREORDER": extract_namespace_preorder,
    "NAMESPACE_REVEAL": extract_namespace_reveal,
    "NAMESPACE_READY": extract_namespace_ready,
    "ANNOUNCE": extract_announce
}

# NOTE: these all have the same signatures 
RESTORE_METHODS = {
    "NAME_PREORDER": restore_preorder,
    "NAME_REGISTRATION": restore_register,
    "NAME_UPDATE": restore_update,
    "NAME_TRANSFER": restore_transfer,
    "NAME_REVOKE": restore_revoke,
    "NAME_IMPORT": restore_name_import,
    "NAMESPACE_PREORDER": restore_namespace_preorder,
    "NAMESPACE_REVEAL": restore_namespace_reveal,
    "NAMESPACE_READY": restore_namespace_ready,
    "ANNOUNCE": restore_announce 
}


# NOTE: these all have the same signatures 
CONSENSUS_EXTRA_METHODS = {
     "NAME_PREORDER": None,
     "NAME_REGISTRATION": register_consensus_extras,
     "NAME_UPDATE": update_consensus_extras,
     "NAME_TRANSFER": transfer_consensus_extras,
     "NAME_REVOKE": None,
     "NAME_IMPORT": name_import_consensus_extras,
     "NAMESPACE_PREORDER": None,
     "NAMESPACE_REVEAL": None,
     "NAMESPACE_READY": None,
     "ANNOUNCE": None
}


def op_extract( op_name, *args, **kw ):
    """
    Extract an operation from transaction data.
    Return the extracted fields as a dict.
    """

    global EXTRACT_METHODS

    if op_name not in EXTRACT_METHODS.keys():
        raise Exception("No such operation '%s'" % op_name)

    method = EXTRACT_METHODS[op_name]
    op_data = method( *args, **kw )
    return op_data


def op_restore_delta( op_name, *args, **kw ):
    """
    Get the values of fields in an name record
    needed to restore a prior operation.
    """

    global RESTORE_METHODS

    if op_name not in RESTORE_METHODS.keys():
        raise Exception("No such operation '%s'" % op_name)

    method = RESTORE_METHODS[op_name]
    delta = method( *args, **kw )
    return delta 


def op_consensus_extra( op_name, *args, **kw ):
    """
    Derive any missing consensus fields from the 
    fields of a name record (since some of them
    are dynamically generated when the operation
    is discovered).  This method is used for
    calculating prior operations from name records.

    Return the extra conesnsus fields on success.
    Return None on error.
    """

    global CONSENSUS_EXTRA_METHODS 

    if op_name not in CONSENSUS_EXTRA_METHODS.keys():
        raise Exception("No such operation '%s'" % op_name)

    method = CONSENSUS_EXTRA_METHODS[op_name]
    if method is None:
        return {}

    extras = method( *args, **kw )
    return extras 

