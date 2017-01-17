#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstack-client
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016 by Blockstack.org

    This file is part of Blockstack-client.

    Blockstack-client is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Blockstack-client is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with Blockstack-client. If not, see <http://www.gnu.org/licenses/>.
"""

import copy

from ..config import *
import copy

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

from .preorder import make_transaction as tx_preorder
from .register import make_transaction as tx_register
from .update import make_transaction as tx_update
from .transfer import make_transaction as tx_transfer
from .revoke import make_transaction as tx_revoke
from .namespacepreorder import make_transaction as tx_namespace_preorder
from .namespacereveal import make_transaction as tx_namespace_reveal
from .namespaceready import make_transaction as tx_namespace_ready
from .nameimport import make_transaction as tx_name_import
from .announce import make_transaction as tx_announce

from .preorder import get_fees as fees_preorder
from .register import get_fees as fees_registration
from .update import get_fees as fees_update
from .transfer import get_fees as fees_transfer
from .revoke import get_fees as fees_revoke
from .namespacepreorder import get_fees as fees_namespace_preorder
from .namespacereveal import get_fees as fees_namespace_reveal
from .namespaceready import get_fees as fees_namespace_ready
from .nameimport import get_fees as fees_name_import
from .announce import get_fees as fees_announce

from .preorder import build as build_preorder
from .register import build as build_registration
from .update import build as build_update
from .transfer import build as build_transfer
from .revoke import build as build_revoke
from .namespacepreorder import build as build_namespace_preorder
from .namespacereveal import build as build_namespace_reveal
from .namespaceready import build as build_namespace_ready
from .nameimport import build as build_name_import
from .announce import build as build_announce

from .preorder import snv_consensus_extras as preorder_consensus_extras
from .register import snv_consensus_extras as register_consensus_extras
from .update import snv_consensus_extras as update_consensus_extras
from .transfer import snv_consensus_extras as transfer_consensus_extras
from .revoke import snv_consensus_extras as revoke_consensus_extras
from .nameimport import snv_consensus_extras as name_import_consensus_extras
from .namespacepreorder import snv_consensus_extras as namespace_preorder_consensus_extras
from .namespacereveal import snv_consensus_extras as namespace_reveal_consensus_extras
from .namespaceready import snv_consensus_extras as namespace_ready_consensus_extras
from .announce import snv_consensus_extras as announce_consensus_extras

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

def nameop_is_history_snapshot( history_snapshot ):
    """
    Given a history entry, verify that it is a history snapshot.
    It must have all consensus fields.
    Return True if so.
    Raise an exception of it doesn't.
    """

    # sanity check:  each mutate field in the operation must be defined in op_data, even if it's null.
    missing = []

    assert 'op' in history_snapshot.keys(), "no op given"

    opcode = op_get_opcode_name(history_snapshot['op'])
    assert opcode is not None, "unrecognized op '%s'" % history_snapshot['op']

    op = history_snapshot['op']

    consensus_fields = OPFIELDS[op]
    for field in consensus_fields:
        if field not in history_snapshot.keys():
            missing.append( field )

    assert len(missing) == 0, ("operation '%s' is missing the following fields: %s" % (opcode, ",".join(missing)))
    return True


def nameop_history_extract( history_rows ):
    """
    Given the rows of history for a name, collapse
    them into a history dictionary.
    Return a dict of:
    {
        block_id: [
            { ... historical data ...
             txid:
             vtxindex:
             op:
             opcode:
            }, ...
        ],
        ...
    }

    Raise on failure to parse
    """

    history = {}
    for history_row in history_rows:

        block_id = history_row['block_id']
        data_json = history_row['history_data']
        hist = json.loads( data_json )

        hist['opcode'] = op_get_opcode_name(hist['op'])

        if history.has_key( block_id ):
            history[ block_id ].append( hist )
        else:
            history[ block_id ] = [ hist ]

    return history


def nameop_restore_from_history( name_rec, name_history, block_id ):
    """
    Given a name or a namespace record (`name_rec`), replay its
    history diffs (`name_history`) "back in time" to a particular block
    number (`block_id`).

    Return the sequence of states the name record went
    through at that block number, starting from the beginning
    of the block.

    Return None if the record does not exist at that point in time

    The returned records will *not* have a 'history' key.
    """

    block_history = list( reversed( sorted( name_history.keys() ) ) )

    historical_rec = copy.deepcopy( name_rec )
    if 'history' in historical_rec:
        del historical_rec['history']

    if len(block_history) == 0:
        # there is no history here...
        try:
            assert nameop_is_history_snapshot( historical_rec ), "No history for incomplete name"
            return [historical_rec]
        except Exception, e:
            log.exception(e)
            log.debug("\n%s" % (json.dumps(historical_rec, indent=4, sort_keys=True)))
            log.error("FATAL: tried to restore history for incomplete record")
            os.abort()

    if block_id > block_history[0]:
        # current record is valid
        return [historical_rec]

    if block_id < name_rec['block_number']:
        # doesn't yet exist
        return None

    # find the latest block prior to block_number
    last_block = len(block_history)
    for i in xrange( 0, len(block_history) ):
        if block_id >= block_history[i]:
            last_block = i
            break

    i = 0
    while i < last_block:

        try:
            diff_list = list( reversed( name_history[ block_history[i] ] ) )
        except:
            print json.dumps( name_history[block_history[i]], indent=4, sort_keys=True )
            raise

        for di in xrange(0, len(diff_list)):
            diff = diff_list[di]

            if diff.has_key('history_snapshot'):
                # wholly new state
                historical_rec = copy.deepcopy( diff )
                del historical_rec['history_snapshot']

            else:
                # delta in current state
                # no matter what, 'block_number' cannot be altered (unless it's a history snapshot)
                if diff.has_key('block_number'):
                    del diff['block_number']

                historical_rec.update( diff )

        i += 1

    # if this isn't the earliest history element, and the next-earliest
    # one (at last block) has multiple entries, then generate the sequence
    # of updates for all but the first one.  This is because all but the
    # first one were generated in the same block (i.e. the block requested).
    updates = [ copy.deepcopy( historical_rec ) ]

    if i < len(block_history):

        try:
            diff_list = list( reversed( name_history[ block_history[i] ] ) )
        except:
            print json.dumps( name_history[block_history[i]] )
            raise

        if len(diff_list) > 1:
            for diff in diff_list[:-1]:

                # no matter what, 'block_number' cannot be altered
                if diff.has_key('block_number'):
                    del diff['block_number']

                if diff.has_key('history_snapshot'):
                    # wholly new state
                    historical_rec = copy.deepcopy( diff )
                    del historical_rec['history_snapshot']

                else:
                    # delta in current state
                    historical_rec.update( diff )

                updates.append( copy.deepcopy(historical_rec) )

    return list( reversed( updates ) )


def nameop_snv_consensus_extra_quirks( extras, namerec, block_id ):
    """
    Given the set of arguments to snv_consensus_extras, apply any
    op-specific quirks that are needed to preserve backwards compatibility
    """

    last_creation_op = namerec.get('last_creation_op', None)
    last_creation_opcode = None

    if last_creation_op is not None:
        last_creation_opcode = op_get_opcode_name(last_creation_op)

    if last_creation_opcode is None:
        if namerec['op'] == NAME_IMPORT:
            # this is the first-ever import
            last_creation_opcode = 'NAME_IMPORT'

        elif namerec['op'] == NAME_PREORDER:
            # this is the first-ever preorder
            last_creation_opcode = 'NAME_PREORDER'

    log.debug("apply SNV QURIKS on %s at %s (created with %s)" % (namerec.get('name', "UNKNOWN"), block_id, last_creation_opcode))

    if namerec.has_key('name') and last_creation_opcode == 'NAME_IMPORT':
        log.debug("apply SNV QUIRK on %s: %s --> %s"  % (namerec.get('name', "UNKNOWN"), namerec['op_fee'], float(namerec['op_fee'])))
        extras['op_fee'] = float(namerec['op_fee'])

    return extras


def nameop_snv_consensus_extra( op_name, prev_name_rec, prev_block_id ):
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
    extras = method( prev_name_rec, prev_block_id, None )
    extras = nameop_snv_consensus_extra_quirks( extras, prev_name_rec, prev_block_id )
    return extras


def nameop_restore_snv_consensus_fields( name_rec, block_id ):
    """
    Given a name record at a given point in time, ensure
    that all of its consensus fields are present.
    Because they can be reconstructed directly from the record,
    but they are not always stored in the db, we have to do so here.
    """

    opcode_name = op_get_opcode_name( name_rec['op'] )
    assert opcode_name is not None, "Unrecognized opcode '%s'" % name_rec['op']

    ret_op = nameop_snv_consensus_extra( opcode_name, name_rec, block_id )

    if ret_op is None:
        raise Exception("Failed to derive extra consensus fields for '%s'" % opcode_name)

    ret_op['opcode'] = opcode_name

    merged_op = copy.deepcopy( name_rec )
    merged_op.update( ret_op )

    return merged_op
