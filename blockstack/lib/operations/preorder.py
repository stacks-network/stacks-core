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
from ..hashing import *
from ..scripts import *
from ..nameset import *
from binascii import hexlify, unhexlify

# consensus hash fields (ORDER MATTERS!)
FIELDS = [
     'preorder_hash',       # hash(name,sender,register_addr) 
     'consensus_hash',      # consensus hash at time of send
     'sender',              # scriptPubKey hex that identifies the principal that issued the preorder
     'sender_pubkey',       # if sender is a pubkeyhash script, then this is the public key
     'address',             # address from the sender's scriptPubKey
     'block_number',        # block number at which this name was preordered for the first time

     'op',                  # blockstack bytestring describing the operation
     'txid',                # transaction ID
     'vtxindex',            # the index in the block where the tx occurs
     'op_fee',              # blockstack fee (sent to burn address)
]

# fields this operation changes
MUTATE_FIELDS = FIELDS[:] + [
    'token_fee',
    'token_units',
]


@state_preorder("check_preorder_collision")
def check( state_engine, nameop, block_id, checked_ops ):
    """
    Verify that a preorder of a name at a particular block number is well-formed

    NOTE: these *can't* be incorporated into namespace-imports,
    since we have no way of knowning which namespace the
    nameop belongs to (it is blinded until registration).
    But that's okay--we don't need to preorder names during
    a namespace import, because we will only accept names
    sent from the importer until the NAMESPACE_REVEAL operation
    is sent.

    Return True if accepted
    Return False if not.
    """

    from .register import get_num_names_owned

    preorder_name_hash = nameop['preorder_hash']
    consensus_hash = nameop['consensus_hash']
    sender = nameop['sender']

    token_fee = nameop['token_fee']
    token_type = nameop['token_units']
    token_address = nameop['address']

    # must be unique in this block
    # NOTE: now checked externally in the @state_preorder decorator

    # must be unique across all pending preorders
    if not state_engine.is_new_preorder( preorder_name_hash ):
        log.warning("Name hash '%s' is already preordered" % preorder_name_hash )
        return False

    # must have a valid consensus hash
    if not state_engine.is_consensus_hash_valid( block_id, consensus_hash ):
        log.warning("Invalid consensus hash '%s'" % consensus_hash )
        return False

    # sender must be beneath quota
    num_names = get_num_names_owned( state_engine, checked_ops, sender ) 
    if num_names >= MAX_NAMES_PER_SENDER:
        log.warning("Sender '%s' exceeded name quota of %s" % (sender, MAX_NAMES_PER_SENDER ))
        return False 

    # burn fee must be present
    if not 'op_fee' in nameop:
        log.warning("Missing preorder fee")
        return False

    epoch_features = get_epoch_features(block_id)
    if EPOCH_FEATURE_NAMEOPS_COST_TOKENS in epoch_features and token_type is not None and token_fee is not None:
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

        # must be the black hole address, regardless of namespace version (since we don't yet support pay-stacks-to-namespace-creator)
        if nameop['burn_address'] != BLOCKSTACK_BURN_ADDRESS:
            # not sent to the right address
            log.warning('Preorder burned to {}, but expected {}'.format(nameop['burn_address'], BLOCKSTACK_BURN_ADDRESS))
            return False

        # for now, this must be Stacks
        if nameop['token_units'] != TOKEN_TYPE_STACKS:
            # can't use any other token (yet)
            log.warning('Preorder burned unrecognized token unit "{}"'.format(nameop['token_units']))
            return False

        # debit this account when we commit
        state_preorder_put_account_payment_info(nameop, token_address, token_type, token_fee)
        
        # NOTE: must be a string, to avoid overflow
        nameop['token_fee'] = '{}'.format(token_fee)

    else:
        # not paying in tokens, but say so!
        state_preorder_put_account_payment_info(nameop, None, None, None)
        nameop['token_fee'] = '0'
        nameop['token_units'] = 'BTC'

    return True


def get_preorder_burn_info( outputs ):
    """
    Given the set of outputs, find the fee sent 
    to our burn address.  This is always the third output.
    
    Return the fee and burn address on success as {'op_fee': ..., 'burn_address': ...}
    Return None if not found
    """
    
    if len(outputs) != 3:
        # not a well-formed preorder 
        return None 
   
    op_fee = outputs[2]['value']
    burn_address = None

    try:
        burn_address = virtualchain.script_hex_to_address(outputs[2]['script'])
        assert burn_address
    except:
        log.error("Not a well-formed preorder burn: {}".format(outputs[2]['script']))
        return None

    return {'op_fee': op_fee, 'burn_address': burn_address}
   

def tx_extract( payload, senders, inputs, outputs, block_id, vtxindex, txid ):
    """
    Extract and return a dict of fields from the underlying blockchain transaction data
    that are useful to this operation.

    Required (+ parse):
    sender:  the script_pubkey (as a hex string) of the principal that sent the name preorder transaction
    address:  the address from the sender script
    sender_pubkey_hex: the public key of the sender
    """
  
    sender_script = None 
    sender_address = None 
    sender_pubkey_hex = None

    try:
       # first 3 outputs matter (op_return, payment addr, burn addr)
       assert check_tx_output_types(outputs[:3], block_id)

       # by construction, the first input comes from the principal
       # who sent the preorder transaction...
       assert len(senders) > 0
       assert 'script_pubkey' in senders[0].keys()
       assert 'addresses' in senders[0].keys()

       sender_script = str(senders[0]['script_pubkey'])
       sender_address = str(senders[0]['addresses'][0])

       assert sender_script is not None 
       assert sender_address is not None

       if str(senders[0]['script_type']) == 'pubkeyhash':
          sender_pubkey_hex = get_public_key_hex_from_tx( inputs, sender_address )

    except Exception, e:
       log.exception(e)
       raise Exception("Failed to extract")

    parsed_payload = parse( payload, block_id )
    assert parsed_payload is not None 

    burn_info = get_preorder_burn_info(outputs)
    if burn_info is None:
        # nope 
        raise Exception("No burn outputs")

    ret = {
       "sender": sender_script,
       "address": sender_address,
       "block_number": block_id,
       "vtxindex": vtxindex,
       "txid": txid,
       "op": NAME_PREORDER
    }

    ret.update( parsed_payload )
    ret.update( burn_info )

    if sender_pubkey_hex is not None:
        ret['sender_pubkey'] = sender_pubkey_hex
    else:
        ret['sender_pubkey'] = None

    return ret


def parse(bin_payload, block_height):
    """
    Parse a name preorder.
    NOTE: bin_payload *excludes* the leading 3 bytes (magic + op) returned by build.

    Record format:
    
    0     2  3                                              23             39
    |-----|--|----------------------------------------------|--------------|
    magic op  hash(name.ns_id,script_pubkey,register_addr)   consensus hash
    
    Record format when burning STACKs (STACKS Phase 1):
    0     2  3                                              23                 39                            47                      66
    |-----|--|----------------------------------------------|------------------|-----------------------------|-----------------------|
    magic op  hash(name.ns_id,script_pubkey,register_addr)   consensus hash     tokens to burn (big-endian)  token units (0-padded)

    Returns {
        opcode: NAME_PREORDER,
        preorder_hash: the hash of the name, scriptPubKey, and register address
        consensus_hash: the consensus hash
        token_fee: the amount of tokens to burn (will be None if not given)
        token_units: the type of tokens to burn (will be None if not given)
    }
    """
    
    epoch_features = get_epoch_features(block_height)

    if len(bin_payload) < LENGTHS['preorder_name_hash'] + LENGTHS['consensus_hash']:
        log.warning("Invalid payload {}: expected at least {} bytes".format(bin_payload.encode('hex'), LENGTHS['preorder_name_hash'] + LENGTHS['consensus_hash']))
        return None 

    name_hash = hexlify( bin_payload[0:LENGTHS['preorder_name_hash']] )
    consensus_hash = hexlify( bin_payload[LENGTHS['preorder_name_hash']: LENGTHS['preorder_name_hash'] + LENGTHS['consensus_hash']] )
    tokens_burned = None
    token_units = None

    if len(bin_payload) > LENGTHS['preorder_name_hash'] + LENGTHS['consensus_hash']:
        # only acceptable if there's a token burn
        if EPOCH_FEATURE_NAMEOPS_COST_TOKENS not in epoch_features:
            # not enabled yet
            log.warning("Invalid payload {}: expected {} bytes".format(bin_payload.encode('hex'), LENGTHS['preorder_name_hash'] + LENGTHS['consensus_hash']))
            return None

        if len(bin_payload) != LENGTHS['preorder_name_hash'] + LENGTHS['consensus_hash'] + LENGTHS['tokens_burnt'] + LENGTHS['namespace_id']:
            # invalid
            log.warning("Invalid payload {}: expected {} bytes".format(bin_payload.encode('hex'), LENGTHS['preorder_name_hash'] + LENGTHS['consensus_hash'] + LENGTHS['tokens_burnt']))
            return None

        at_tokens_burnt = LENGTHS['preorder_name_hash'] + LENGTHS['consensus_hash']
        at_token_units = LENGTHS['preorder_name_hash'] + LENGTHS['consensus_hash'] + LENGTHS['tokens_burnt']

        bin_tokens_burnt = bin_payload[at_tokens_burnt: at_tokens_burnt + LENGTHS['tokens_burnt']]
        bin_token_units = bin_payload[at_token_units: at_token_units + LENGTHS['namespace_id']]

        tokens_burned = int(bin_tokens_burnt.encode('hex'), 16)
        token_units = bin_token_units.strip('\x00')

    return {
        'opcode': 'NAME_PREORDER',
        'preorder_hash': name_hash,
        'consensus_hash': consensus_hash,
        'token_fee': tokens_burned,
        'token_units': token_units,
    }

