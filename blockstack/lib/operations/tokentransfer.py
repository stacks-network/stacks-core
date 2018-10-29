#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
    Blockstack
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016-2018 by Blockstack.org

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

from ..config import *
from ..scripts import *
from ..hashing import *
from ..nameset import *

# consensus hash fields (ORDER MATTERS!)
FIELDS = [
    'sender',           # sender scriptpubkey
    'address',          # spending account address
    'recipient',            # recipient scriptpubkey
    'recipient_address',    # address that receives tokens
    'token_units',             # token type
    'token_fee',            # the amount to send
    'block_id',         # block height of this operation
    'op',               # opcode ($)
    'txid',             # txid on-chain
    'vtxindex',         # location in the block where this tx occurs
    'consensus_hash',       # consensus hash at time of send
    'scratch_area',     # metadata for the token transfer (useful for future extensions)
]

# fields this operation changes 
# (does nothing, since no UPDATEs occur; only INSERTs)
MUTATE_FIELDS = []

@token_operation("accounts")
def check( state_engine, token_op, block_id, checked_ops ):
    """
    Verify that a token transfer operation is permitted.
    * the token feature must exist
    * the sender must be unlocked---i.e. able to send at this point
    * the sender must have enough balance of the given token to send the amount requested
    * the token value must be positive
    * the consensus hash must be valid

    Return True if accepted
    Return False if not
    """

    epoch_features = get_epoch_features(block_id)
    if EPOCH_FEATURE_TOKEN_TRANSFER not in epoch_features:
        log.warning("Token transfers are not enabled in this epoch")
        return False

    consensus_hash = token_op['consensus_hash']
    address = token_op['address']
    recipient_address = token_op['recipient_address']
    token_type = token_op['token_units']
    token_value = token_op['token_fee']

    # token value must be positive
    if token_value <= 0:
        log.warning("Zero-value token transfer from {}".format(address))
        return False

    # can't send to ourselves 
    if address == recipient_address:
        log.warning('Cannot transfer token from the account to itself ({})'.format(address))
        return False

    # consensus hash must be valid
    if not state_engine.is_consensus_hash_valid(block_id, consensus_hash):
        log.warning('Invalid consensus hash {}'.format(consensus_hash))
        return False

    # sender account must exist
    account_info = state_engine.get_account(address, token_type)
    if account_info is None:
        log.warning("No account for {} ({})".format(address, token_type))
        return False

    # sender must not be transfer-locked
    if block_id < account_info['lock_transfer_block_id']:
        log.warning('Account {} is blocked from transferring tokens until block height {}'.format(address, account_info['lock_transfer_block_id']))
        return False

    # sender must have enough balance of the token  
    account_balance = state_engine.get_account_balance(account_info)
    if account_balance < token_value:
        log.warning('Account {} has {} {}; tried to send {}'.format(address, account_balance, token_type, token_value))
        return False
    
    receiver_account = state_engine.get_account(recipient_address, token_type)
    if receiver_account is not None:
        if not receiver_account['receive_whitelisted']:
            log.warning('Receiver account {} is not whitelisted'.format(recipient_address))
            return False

    log.debug("Account {} will pay {} {} to {}".format(address, token_value, token_type, recipient_address))

    # will execute a debit against the sender address
    token_operation_put_account_payment_info(token_op, address, token_type, token_value)

    # will execute a credit against the receiver address 
    token_operation_put_account_credit_info(token_op, recipient_address, token_type, token_value)

    # preserve token_fee as a string to prevent overflow
    token_op['token_fee'] = '{}'.format(token_op['token_fee'])
    return True
   

def get_token_transfer_recipient_from_outputs(outputs):
    """
    Get the token transfer recipient from the list of outputs.
    By design, this is the second output
    """
    if len(outputs) < 2:
        raise Exception("Malformed token transfer outputs: less than 2")
    
    return outputs[1]['script']


def tx_extract(payload, senders, inputs, outputs, block_id, vtxindex, txid):
    """
    Extract and return a dict of fields from the underlying blockchain transaction data
    that are useful to this operation.

    structure:
    inputs                                | outputs
    ------------------------------------------------------------------------------
    sender scriptsig + scriptPubkey       | OP_RETURN with token transfer payload
    ------------------------------------------------------------------------------
                                          | recipient script (DUST_MINIMUM)
                                          ----------------------------------------
                                          | sender's change address

    The recipient script identifies the recipient address.  This is its own output
    to ensure that the underlying blockchain can and will enforce signatures from
    the recipient on future spend transactions.  Also, it makes it straightforward
    to track blockstack transactions in existing block explorers.

    Any other inputs and outputs are allowed.
    """
  
    sender_script = None
    sender_address = None

    recipient_script = None
    recipient_address = None

    try:
        # first two outputs matter to us
        assert check_tx_output_types(outputs[:2], block_id)

        assert len(senders) > 0
        assert 'script_pubkey' in senders[0].keys()
        assert 'addresses' in senders[0].keys()

        sender_script = str(senders[0]['script_pubkey'])
        sender_address = str(senders[0]['addresses'][0])

        assert sender_script is not None
        assert sender_address is not None

        recipient_script = get_token_transfer_recipient_from_outputs(outputs)
        recipient_address = virtualchain.script_hex_to_address(recipient_script)

        assert recipient_script is not None
        assert recipient_address is not None

    except Exception, e:
        log.exception(e)
        raise Exception("Failed to extract")

    parsed_payload = parse(payload, block_id)
    assert parsed_payload is not None 
   
    ret = {}
    ret.update(parsed_payload)
    ret.update({
        'address': sender_address,
        'sender': sender_script,
        'recipient_address': recipient_address,
        'recipient': recipient_script,
        'op': TOKEN_TRANSFER,
        'block_id': block_id,
        'txid': txid,
        'vtxindex': vtxindex
    })

    return ret


def parse(bin_payload, block_height):
    """
    Parse a token transfer
    NOTE: bin_payload *excludes* the leading 3 bytes (magic + op) returned by build.

    Record format:
   
    0     2  3              19         38          46                        80
    |-----|--|--------------|----------|-----------|-------------------------|
    magic op  consensus_hash token_type amount (BE) scratch area
                             (ns_id)

    Returns a parsed payload on success
    Returns None on error
    """
    
    epoch_features = get_epoch_features(block_height)
    if EPOCH_FEATURE_TOKEN_TRANSFER not in epoch_features:
        log.warning("Token transfers are not enabled in this epoch")
        return None

    if len(bin_payload) < LENGTHS['consensus_hash'] + LENGTHS['namespace_id'] + LENGTHS['tokens_burnt']:
        log.warning('Invalid payload {}: expected at least {} bytes'.format(bin_payload.encode('hex'), LENGTHS['consensus_hash'] + LENGTHS['namespace_id'] + LENGTHS['tokens_burnt']))
        return None

    consensus_hash = bin_payload[0: LENGTHS['consensus_hash']].encode('hex')
    token_type = bin_payload[LENGTHS['consensus_hash']: LENGTHS['consensus_hash'] + LENGTHS['namespace_id']]
    amount_str = bin_payload[LENGTHS['consensus_hash'] + LENGTHS['namespace_id']: LENGTHS['consensus_hash'] + LENGTHS['namespace_id'] + LENGTHS['tokens_burnt']].encode('hex')
    scratch_area = bin_payload[LENGTHS['consensus_hash'] + LENGTHS['namespace_id'] + LENGTHS['tokens_burnt']: ].encode('hex')

    tokens_sent = int(amount_str, 16)
    token_units = token_type.strip('\x00')

    return {
        'opcode': 'TOKEN_TRANSFER',
        'consensus_hash': consensus_hash,
        'token_units': token_units,
        'token_fee': tokens_sent,
        'scratch_area': scratch_area
    }

