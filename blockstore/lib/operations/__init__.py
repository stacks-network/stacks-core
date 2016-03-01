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
import copy

from ..nameset import CONSENSUS_FIELDS_REQUIRED, NAMEREC_MUTATE_FIELDS, NAMEREC_BACKUP_FIELDS
from ..config import *

from .preorder import build as build_preorder, \
    broadcast as preorder_name, tx_extract as extract_preorder, \
    get_fees as preorder_fees, restore_delta as restore_preorder, \
    check as check_preorder, snv_consensus_extras as preorder_consensus_extras
from .preorder_multi import build as build_preorder_multi, \
    broadcast as preorder_name_multi, tx_extract as extract_preorder_multi, \
    get_fees as preorder_multi_fees, hash_names as preorder_multi_hash_names, \
    decompose as preorder_decompose, restore_delta as restore_preorder_multi
from .register import build as build_registration, \
    broadcast as register_name, tx_extract as extract_registration, \
    get_fees as registration_fees, restore_delta as restore_register, \
    snv_consensus_extras as register_consensus_extras, check_register as check_registration, check_renewal
from .register_multi import build as build_registration_multi, \
    broadcast as register_name_multi, tx_extract as extract_registration_multi, \
    get_fees as registration_multi_fees, decompose as registration_decompose, \
    restore_delta as restore_register_multi
from .transfer import build as build_transfer, \
    broadcast as transfer_name, tx_extract as extract_transfer, \
    make_outputs as make_transfer_ouptuts, \
    get_fees as transfer_fees, restore_delta as restore_transfer, \
    snv_consensus_extras as transfer_consensus_extras, check as check_transfer
from .update import build as build_update, \
    broadcast as update_name, tx_extract as extract_update, \
    get_fees as update_fees, restore_delta as restore_update, \
    snv_consensus_extras as update_consensus_extras, check as check_update
from .revoke import build as build_revoke, \
    broadcast as revoke_name, tx_extract as extract_revoke, \
    get_fees as revoke_fees, restore_delta as restore_revoke, \
    check as check_revoke, snv_consensus_extras as revoke_consensus_extras
from .namespacepreorder import build as build_namespace_preorder, \
    broadcast as namespace_preorder, tx_extract as extract_namespace_preorder, \
    get_fees as namespace_preorder_fees, restore_delta as restore_namespace_preorder, \
    check as check_namespace_preorder, snv_consensus_extras as namespace_preorder_consensus_extras
from .nameimport import build as build_name_import, \
    broadcast as name_import, tx_extract as extract_name_import, \
    get_fees as name_import_fees, restore_delta as restore_name_import, \
    snv_consensus_extras as name_import_consensus_extras, check as check_name_import
from .namespacereveal import build as build_namespace_reveal, \
    broadcast as namespace_reveal, tx_extract as extract_namespace_reveal, \
    get_fees as namespace_reveal_fees, restore_delta as restore_namespace_reveal, \
    check as check_namespace_reveal, snv_consensus_extras as namespace_reveal_consensus_extras
from .namespaceready import build as build_namespace_ready, \
    broadcast as namespace_ready, tx_extract as extract_namespace_ready, \
    get_fees as namespace_ready_fees, restore_delta as restore_namespace_ready, \
    check as check_namespace_ready, snv_consensus_extras as namespace_ready_consensus_extras
from .announce import build as build_announce, \
    broadcast as send_announce, tx_extract as extract_announce, \
    get_fees as announce_fees, restore_delta as restore_announce, \
    check as check_announce, snv_consensus_extras as announce_consensus_extras

SERIALIZE_FIELDS = {
    "NAME_PREORDER": preorder.FIELDS,
    "NAME_REGISTRATION": register.FIELDS,
    "NAME_RENEWAL": register.FIELDS,
    "NAME_UPDATE": update.FIELDS,
    "NAME_TRANSFER": transfer.FIELDS,
    "NAME_REVOKE": revoke.FIELDS,
    "NAME_IMPORT": nameimport.FIELDS,
    "NAMESPACE_PREORDER": namespacepreorder.FIELDS,
    "NAMESPACE_REVEAL": namespacereveal.FIELDS,
    "NAMESPACE_READY": namespaceready.FIELDS,
    "ANNOUNCE": announce.FIELDS
}

MUTATE_FIELDS = {
    "NAME_PREORDER": preorder.MUTATE_FIELDS,
    "NAME_REGISTRATION": register.REGISTER_MUTATE_FIELDS,
    "NAME_RENEWAL": register.RENEWAL_MUTATE_FIELDS,
    "NAME_UPDATE": update.MUTATE_FIELDS,
    "NAME_TRANSFER": transfer.MUTATE_FIELDS,
    "NAME_REVOKE": revoke.MUTATE_FIELDS,
    "NAME_IMPORT": nameimport.MUTATE_FIELDS,
    "NAMESPACE_PREORDER": namespacepreorder.MUTATE_FIELDS,
    "NAMESPACE_REVEAL": namespacereveal.MUTATE_FIELDS,
    "NAMESPACE_READY": namespaceready.MUTATE_FIELDS,
    "ANNOUNCE": announce.MUTATE_FIELDS
}

BACKUP_FIELDS = {
    "NAME_PREORDER": preorder.BACKUP_FIELDS,
    "NAME_REGISTRATION": register.REGISTER_BACKUP_FIELDS,
    "NAME_RENEWAL": register.RENEWAL_BACKUP_FIELDS,
    "NAME_UPDATE": update.BACKUP_FIELDS,
    "NAME_TRANSFER": transfer.BACKUP_FIELDS,
    "NAME_REVOKE": revoke.BACKUP_FIELDS,
    "NAME_IMPORT": nameimport.BACKUP_FIELDS,
    "NAMESPACE_PREORDER": namespacepreorder.BACKUP_FIELDS,
    "NAMESPACE_REVEAL": namespacereveal.BACKUP_FIELDS,
    "NAMESPACE_READY": namespaceready.BACKUP_FIELDS,
    "ANNOUNCE": announce.BACKUP_FIELDS
}

# NOTE: these all have the same signatures
EXTRACT_METHODS = {
    "NAME_PREORDER": extract_preorder,
    "NAME_REGISTRATION": extract_registration,
    "NAME_RENEWAL": extract_registration,
    "NAME_UPDATE": extract_update,
    "NAME_TRANSFER": extract_transfer,
    "NAME_REVOKE": extract_revoke,
    "NAME_IMPORT": extract_name_import,
    "NAMESPACE_PREORDER": extract_namespace_preorder,
    "NAMESPACE_REVEAL": extract_namespace_reveal,
    "NAMESPACE_READY": extract_namespace_ready,
    "ANNOUNCE": extract_announce
}

# NOTE: these all have the same signature
CHECK_METHODS = {
    "NAME_PREORDER": check_preorder,
    "NAME_REGISTRATION": check_registration,
    "NAME_RENEWAL": check_renewal,
    "NAME_UPDATE": check_update,
    "NAME_TRANSFER": check_transfer,
    "NAME_REVOKE": check_revoke,
    "NAME_IMPORT": check_name_import,
    "NAMESPACE_PREORDER": check_namespace_preorder,
    "NAMESPACE_REVEAL": check_namespace_reveal,
    "NAMESPACE_READY": check_namespace_ready,
    "ANNOUNCE": check_announce
}


# NOTE: these all have the same signatures 
RESTORE_METHODS = {
    "NAME_PREORDER": restore_preorder,
    "NAME_REGISTRATION": restore_register,
    "NAME_RENEWAL": restore_register,
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
SNV_CONSENSUS_EXTRA_METHODS = {
     "NAME_PREORDER": preorder_consensus_extras,
     "NAME_REGISTRATION": register_consensus_extras,
     "NAME_RENEWAL": register_consensus_extras,
     "NAME_UPDATE": update_consensus_extras,
     "NAME_TRANSFER": transfer_consensus_extras,
     "NAME_REVOKE": revoke_consensus_extras,
     "NAME_IMPORT": name_import_consensus_extras,
     "NAMESPACE_PREORDER": namespace_preorder_consensus_extras,
     "NAMESPACE_REVEAL": namespace_reveal_consensus_extras,
     "NAMESPACE_READY": namespace_ready_consensus_extras,
     "ANNOUNCE": announce_consensus_extras
}


# build-in sanity checks....
# required consensus fields are required!
for opcode, serialize_set in SERIALIZE_FIELDS.items():
    if len(serialize_set) == 0:
        continue

    for required_consensus_field in CONSENSUS_FIELDS_REQUIRED:
        if required_consensus_field not in serialize_set:
            # do not even allow this package to be imported 
            raise Exception("BUG: missing required consensus field '%s' in '%s' definition" % (required_consensus_field, opcode))

# required mutate fields must be present 
for opcode, mutate_set in MUTATE_FIELDS.items():
    if len(mutate_set) == 0:
        continue 

    for required_mutate_field in NAMEREC_MUTATE_FIELDS:
        if required_mutate_field not in mutate_set:
            # do not even allow this package to be imported 
            raise Exception("BUG: missing required mutate field '%s' of '%s' definition" % (required_mutate_field, opcode))


# required backup fields must be present 
for opcode, backup_set in BACKUP_FIELDS.items():
    if len(backup_set) == 0:
        continue

    if '__all__' in backup_set:
        # everything will be backed up
        continue

    for required_backup_field in NAMEREC_BACKUP_FIELDS:
        if required_backup_field not in backup_set:
            # do not even allow this package to be imported 
            raise Exception("BUG: missing required backup field '%s' of '%s' definition" % (required_backup_field, opcode))


# mutate fields must be a subset of backup fields 
for opcode, mutate_set in MUTATE_FIELDS.items():
    for mutate_field in mutate_set:

        if '__all__' in BACKUP_FIELDS[opcode]:
            # everything will be backed up
            continue 

        if mutate_field not in BACKUP_FIELDS[opcode]:
            # do not even allow this package to be imported 
            raise Exception("BUG: mutate field '%s' is not present in the backup fields for '%s'" % (mutate_field, opcode))

del opcode
del mutate_set
del backup_set
del serialize_set
del mutate_field
del required_backup_field
del required_mutate_field
del required_consensus_field


def op_extract( op_name, data, senders, inputs, outputs, block_id, vtxindex, txid ):
    """
    Extract an operation from transaction data.
    Return the extracted fields as a dict.
    """

    global EXTRACT_METHODS

    if op_name not in EXTRACT_METHODS.keys():
        raise Exception("No such operation '%s'" % op_name)

    method = EXTRACT_METHODS[op_name]
    op_data = method( data, senders, inputs, outputs, block_id, vtxindex, txid )
    return op_data


def op_check( state_engine, nameop, block_id, checked_ops ):
    """
    Given the state engine, the current block, the list of pending
    operations processed so far, and the current operation, determine
    whether or not it should be accepted.

    The operation is allowed to change once, as a result of a check
    """

    global CHECK_METHODS, MUTATE_FIELDS

    count = 0
    while count < 3:

        count += 1

        nameop_clone = copy.deepcopy( nameop )
        opcode = None

        if 'opcode' not in nameop_clone.keys():
            op = nameop_clone.get('op', None)
            try:
                assert op is not None, "BUG: no op defined"
                opcode = op_get_opcode_name( op )
                assert opcode is not None, "BUG: op '%s' undefined" % op
            except Exception, e:
                log.exception(e)
                log.error("FATAL: BUG: no 'op' defined")
                sys.exit(1)

        else:
            opcode = nameop_clone['opcode']
  
        check_method = CHECK_METHODS.get( opcode, None )
        try:
            assert check_method is not None, "BUG: no check-method for '%s'" % opcode
        except Exception, e:
            log.exception(e)
            log.error("FATAL: BUG: no check-method for '%s'" % opcode )
            sys.exit(1)

        rc = check_method( state_engine, nameop_clone, block_id, checked_ops )
        if not rc:
            # rejected
            break

        # did the opcode change?
        # i.e. did the nameop get transformed into a different opcode?
        new_opcode = nameop_clone.get( 'opcode', None )
        if new_opcode is None or new_opcode == opcode:
            # we're done
            nameop.clear()
            nameop.update( nameop_clone )
            break

        else:
            # try again 
            log.debug("Nameop re-interpreted from '%s' to '%s' (%s)" % (opcode, new_opcode, count))
            nameop['opcode'] = new_opcode 
            continue

    try:
        assert count < 3, "opcode flipflop loop detected"
    except Exception, e:
        log.exception(e)
        log.error("FATAL: BUG: flipflop loop")
        sys.exit(1)

    return rc


def op_make_restore_diff( op_name, cur_rec, prev_block_number, history_index, untrusted_db, testset=False ):
    """
    Given a current name record, an operation name, and a (block number, block history index) coordinate,
    calculate a diff that, when applied to the given name record, will restore it to the name
    record as it was when the operation at (block number, block history index) was applied.
    """

    global RESTORE_METHODS, MUTATE_FIELDS

    if op_name not in RESTORE_METHODS.keys():
        raise Exception("No such operation '%s'" % op_name)

    method = RESTORE_METHODS[op_name]
    delta = method( cur_rec, prev_block_number, history_index, untrusted_db, testset=testset )
    return delta 


def op_get_mutate_fields( op_name ):
    """
    Get the names of the fields that will change
    when this operation gets applied to a record.
    """

    global MUTATE_FIELDS

    if op_name not in MUTATE_FIELDS.keys():
        raise Exception("No such operation '%s'" % op_name)

    fields = MUTATE_FIELDS[op_name][:]
    return fields


def op_get_backup_fields( op_name ):
    """
    Get the set of fields to back up to a name's history
    when applying this operation.
    These fields should encompass sufficient
    information to calculate a diff that will restore
    a future version of a name record to the state it is in now.
    (NOTE this is different from the mutate fields--
    some operations need to back up fields even though
    they wont be changed, since the consensus hash
    is derived from them.
    """

    global BACKUP_FIELDS 

    if op_name not in BACKUP_FIELDS.keys():
        raise Exception("No such operation '%s'" % op_name )

    fields = BACKUP_FIELDS[op_name][:]
    return fields


def op_get_consensus_fields( op_name ):
    """
    Get the set of consensus-generating fields for an operation.
    """

    global SERIALIZE_FIELDS
    
    if op_name not in SERIALIZE_FIELDS.keys():
        raise Exception("No such operation '%s'" % op_name )

    fields = SERIALIZE_FIELDS[op_name][:]
    return fields


def op_snv_consensus_extra( op_name, prev_name_rec, prev_block_id, db ):
    """
    Derive any missing consensus-generating fields from the 
    fields of a name record (since some of them
    are dynamically generated when the operation
    is discovered).  This method is used for
    calculating prior operations from name records
    for SNV.

    The given name record is the name record as it was when
    prev_block_id was processed.  The 'vtxindex' field within
    the name record indicates which the transaction at which
    it existed.  I.e., the given name record is in the state
    it was in at (prev_block_id, prev_name_rec['vtxindex']).

    Return the extra conesnsus fields on success.
    Return None on error.
    """

    global SNV_CONSENSUS_EXTRA_METHODS 

    if op_name not in SNV_CONSENSUS_EXTRA_METHODS.keys():
        raise Exception("No such operation '%s'" % op_name)

    method = SNV_CONSENSUS_EXTRA_METHODS[op_name]
    if method is None:
        return {}

    extras = method( prev_name_rec, prev_block_id, False, db )
    return extras 


def op_commit_consensus_extra( op_name, name_rec, block_id, db ):
    """
    Like op_snv_consensus_extra, but will be called with the
    current name record and block number, in order to re-calculate
    any derived consensus-affecting fields.
    """

    global SNV_CONSENSUS_EXTRA_METHODS, SERIALIZE_FIELDS
 
    if op_name not in SNV_CONSENSUS_EXTRA_METHODS.keys():
        raise Exception("No such operation '%s'" % op_name)

    if op_name not in SERIALIZE_FIELDS.keys():
        raise Exception("No such operation '%s'" % op_name)

    method = SNV_CONSENSUS_EXTRA_METHODS[op_name]
    commit_fields = SERIALIZE_FIELDS[op_name]

    extras = method( name_rec, block_id, True, db )
    commit_extras = {}
    for cf in commit_fields + ['__override__']:
        if cf in extras:
            commit_extras[cf] = extras[cf]

    return commit_extras


def op_commit_consensus_override( consensus_extras, field ):
    """
    Force a consensus field to change on commit.
    This is used in the event that an operation encodes one value
    for this field, but we need to mix a different value for the 
    field into the operation we actually commit.

    This is used to stay compatible with bugs in previous implementations.
    """
    if not consensus_extras.has_key( '__override__' ):
        consensus_extras['__override__'] = [field]
    else:
        consensus_extras['__override__'].append( field )


def op_commit_consensus_has_override( consensus_extras, field ):
    """
    Is a consensus field overridden?
    """
    if consensus_extras.has_key( '__override__' ):
        if field in consensus_extras['__override__']:
            return True

    return False


def op_commit_consensus_sanitize( consensus_extras ):
    """
    Remove any non-commit metadata fields
    """
    for k in ['__override__']:
        if k in consensus_extras.keys():
            del consensus_extras[k]

    return consensus_extras


def op_commit_consensus_get_overrides( consensus_extras ):
    """
    get overridden field names
    """
    return consensus_extras.get("__override__", [])


