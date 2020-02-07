#!/usr/bin/env python2
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

from ..config import *
from ..scripts import *
from ..hashing import *
from ..nameset import *

import json

from binascii import hexlify, unhexlify

# consensus hash fields (ORDER MATTERS!) 
FIELDS = [
    'preorder_hash',        # hash(namespace_id,sender,reveal_addr)
    'consensus_hash',       # consensus hash at the time issued
    'op',                   # bytecode describing the operation (not necessarily 1 byte)
    'op_fee',               # fee paid for the namespace to the burn address
    'txid',                 # transaction ID
    'vtxindex',             # the index in the block where the tx occurs
    'block_number',         # block number at which this transaction occurred
    'sender',               # scriptPubKey hex from the principal that issued this preorder (identifies the preorderer)
    'sender_pubkey',        # if sender is a p2pkh script, this is the public key
    'address'               # address from the scriptPubKey
]

# save everything
MUTATE_FIELDS = FIELDS[:] + [
    'token_fee'
]

@state_preorder("check_preorder_collision")
def check( state_engine, nameop, block_id, checked_ops ):
    """
    Given a NAMESPACE_PREORDER nameop, see if we can preorder it.
    It must be unqiue.

    Return True if accepted.
    Return False if not.
    """

    namespace_id_hash = nameop['preorder_hash']
    consensus_hash = nameop['consensus_hash']
    token_fee = nameop['token_fee']

    # cannot be preordered already
    if not state_engine.is_new_namespace_preorder( namespace_id_hash ):
        log.warning("Namespace preorder '%s' already in use" % namespace_id_hash)
        return False

    # has to have a reasonable consensus hash
    if not state_engine.is_consensus_hash_valid( block_id, consensus_hash ):
        valid_consensus_hashes = state_engine.get_valid_consensus_hashes( block_id )
        log.warning("Invalid consensus hash '%s': expected any of %s" % (consensus_hash, ",".join( valid_consensus_hashes )) )
        return False

    # has to have paid a fee
    if not 'op_fee' in nameop:
        log.warning("Missing namespace preorder fee")
        return False

    # paid to the right burn address
    if nameop['burn_address'] != BLOCKSTACK_BURN_ADDRESS:
        log.warning("Invalid burn address: expected {}, got {}".format(BLOCKSTACK_BURN_ADDRESS, nameop['burn_address']))
        return False
    
    # token burn fee must be present, if we're in the right epoch for it
    epoch_features = get_epoch_features(block_id)
    if EPOCH_FEATURE_STACKS_BUY_NAMESPACES in epoch_features:
        # must pay in STACKs
        if 'token_fee' not in nameop:
            log.warning("Missing token fee")
            return False

        token_fee = nameop['token_fee']
        token_address = nameop['address']
        token_type = TOKEN_TYPE_STACKS

        # was a token fee paid?
        if token_fee is None:
            log.warning("No tokens paid by this NAMESPACE_PREORDER")
            return False

        # does this account have enough balance?
        account_info = state_engine.get_account(token_address, token_type)
        if account_info is None:
            log.warning("No account for {} ({})".format(token_address, token_type))
            return False

        account_balance = state_engine.get_account_balance(account_info)

        assert isinstance(account_balance, (int,long)), 'BUG: account_balance of {} is {} (type {})'.format(token_address, account_balance, type(account_balance))
        assert isinstance(token_fee, (int,long)), 'BUG: token_fee is {} (type {})'.format(token_fee, type(token_fee))

        if account_balance < token_fee:
            # can't afford 
            log.warning("Account {} has balance {} {}, but needs to pay {} {}".format(token_address, account_balance, token_type, token_fee, token_type))
            return False

        # debit this account when we commit
        state_preorder_put_account_payment_info(nameop, token_address, token_type, token_fee)
        
        # NOTE: must be a string, to avoid overflow
        nameop['token_fee'] = '{}'.format(token_fee)
        nameop['token_units'] = TOKEN_TYPE_STACKS

    else:
        # must pay in BTC
        # not paying in tokens, but say so!
        state_preorder_put_account_payment_info(nameop, None, None, None)
        nameop['token_fee'] = '0'
        nameop['token_units'] = 'BTC'

    return True


def get_namespace_preorder_burn_info( outputs ):
    """
    Given the set of outputs, find the fee sent 
    to our burn address.
    
    Return the fee and burn address on success as {'op_fee': ..., 'burn_address': ...}
    Return None if not found
    """
    if len(outputs) < 3:
        # not a well-formed preorder 
        return None 
   
    op_fee = outputs[2]['value']
    burn_address = None

    try:
        burn_address = virtualchain.script_hex_to_address(outputs[2]['script'])
        assert burn_address
    except:
        log.warning("Invalid burn script: {}".format(outputs[2]['script']))
        return None

    return {'op_fee': op_fee, 'burn_address': burn_address}


def tx_extract( payload, senders, inputs, outputs, block_id, vtxindex, txid ):
    """
    Extract and return a dict of fields from the underlying blockchain transaction data
    that are useful to this operation.

    Required (+ parse):
    sender:  the script_pubkey (as a hex string) of the principal that sent the name preorder transaction
    address:  the address from the sender script

    Optional:
    sender_pubkey_hex: the public key of the sender
    """
  
    sender_script = None 
    sender_address = None 
    sender_pubkey_hex = None
    burn_info = None

    try:
       # first three outputs matter to us
       assert check_tx_output_types(outputs[:3], block_id)

       # by construction, the first input comes from the principal
       # who sent the registration transaction...
       assert len(senders) > 0
       assert 'script_pubkey' in senders[0].keys()
       assert 'addresses' in senders[0].keys()

       sender_script = str(senders[0]['script_pubkey'])
       sender_address = str(senders[0]['addresses'][0])

       assert sender_script is not None 
       assert sender_address is not None

       if str(senders[0]['script_type']) == 'pubkeyhash':
          sender_pubkey_hex = get_public_key_hex_from_tx( inputs, sender_address )

       burn_info = get_namespace_preorder_burn_info(outputs)
       assert burn_info

    except Exception, e:
       log.exception(e)
       raise Exception("Failed to extract")

    parsed_payload = parse( payload, block_id )
    assert parsed_payload is not None 

    ret = {
       "sender": sender_script,
       "address": sender_address,
       "block_number": block_id,
       "vtxindex": vtxindex,
       "txid": txid,
       "op": NAMESPACE_PREORDER
    }

    # adds:
    # * opcode
    # * preorder_hash
    # * consensus_hash
    # * token_fee
    ret.update( parsed_payload )

    # adds:
    # * burn_address
    # * op_fee
    ret.update( burn_info )

    if sender_pubkey_hex is not None:
        ret['sender_pubkey'] = sender_pubkey_hex
    
    else:
        ret['sender_pubkey'] = None

    return ret


def parse( bin_payload, block_height ):
    """
    NOTE: the first three bytes will be missing


    wire format (Pre-STACKs Phase 1)

    0     2   3                                      23               39
    |-----|---|--------------------------------------|----------------|
    magic op  hash(ns_id,script_pubkey,reveal_addr)   consensus hash

    wire format (Post-STACKs phase 1)

    0     2   3                                      23               39                         47
    |-----|---|--------------------------------------|----------------|--------------------------|
    magic op  hash(ns_id,script_pubkey,reveal_addr)   consensus hash    token fee (big-endian)

    Returns {
        'opcode': ...
        'preorder_hash': ...
        'consensus_hash': ...
        'token_fee': ...
    }
    """
   
    if len(bin_payload) < LENGTHS['preorder_name_hash'] + LENGTHS['consensus_hash']:
        log.warning("Invalid namespace preorder payload length %s" % len(bin_payload))
        return None

    namespace_id_hash = bin_payload[ :LENGTHS['preorder_name_hash'] ]
    consensus_hash = bin_payload[ LENGTHS['preorder_name_hash']: LENGTHS['preorder_name_hash'] + LENGTHS['consensus_hash'] ]
    tokens_burned = None
    
    epoch_features = get_epoch_features(block_height)

    if len(bin_payload) > LENGTHS['preorder_name_hash'] + LENGTHS['consensus_hash']:
        if EPOCH_FEATURE_STACKS_BUY_NAMESPACES not in epoch_features:
            # not allowed--we can't use tokens in this epoch
            log.warning("Invalid payload {}: expected {} bytes".format(bin_payload.encode('hex'), LENGTHS['preorder_name_hash'] + LENGTHS['consensus_hash']))
            return None

        if len(bin_payload) != LENGTHS['preorder_name_hash'] + LENGTHS['consensus_hash'] + LENGTHS['tokens_burnt']:
            # not allowed--invalid length
            log.warning("Invalid payload {}: expected {} bytes".format(bin_payload.encode('hex'), LENGTHS['preorder_name_hash'] + LENGTHS['consensus_hash'] + LENGTHS['tokens_burnt']))
            return None
        
        bin_tokens_burned = bin_payload[LENGTHS['preorder_name_hash'] + LENGTHS['consensus_hash']: LENGTHS['preorder_name_hash'] + LENGTHS['consensus_hash'] + LENGTHS['tokens_burnt']]
        tokens_burned = int(bin_tokens_burned.encode('hex'), 16)
  
    else:
        # only allow the absence of the tokens field if we're in a pre-STACKs epoch 
        if EPOCH_FEATURE_STACKS_BUY_NAMESPACES in epoch_features:
            # not allowed---we need the stacks token field
            log.warning('Invalid payload {}: expected {} bytes'.format(bin_payload.encode('hex'), LENGTHS['preorder_name_hash'] + LENGTHS['consensus_hash'] + LENGTHS['tokens_burnt']))
            return None

    namespace_id_hash = hexlify( namespace_id_hash )
    consensus_hash = hexlify( consensus_hash )
   
    return {
       'opcode': 'NAMESPACE_PREORDER',
       'preorder_hash': namespace_id_hash,
       'consensus_hash': consensus_hash,
       'token_fee': tokens_burned
    }


def canonicalize(parsed_op):
    """
    Get the "canonical form" of this operation, putting it into a form where it can be serialized
    to form a consensus hash.  This method is meant to preserve compatibility across blockstackd releases.

    For all namespace operations, this means:
    * make the 'buckets' array into a string
    """
    if 'buckets' in parsed_op:
        parsed_op['buckets'] = str(parsed_op['buckets'])

    return parsed_op


def decanonicalize(canonical_op):
    """
    Get the "current form" of this operation, putting it into a form usable by the rest of the system.

    For namespace ops, this means:
    * make 'buckets' string into an array, if it is present
    """
    if 'buckets' in canonical_op:
        canonical_op['buckets'] = json.loads(canonical_op['buckets'])

    return canonical_op

