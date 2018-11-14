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
from ..hashing import *
from ..scripts import *
from ..nameset import *
import traceback
from binascii import hexlify, unhexlify 

import json

import virtualchain
log = virtualchain.get_logger("blockstack-server")

# consensus hash fields (ORDER MATTERS!)
FIELDS = [
    'namespace_id',         # human-readable namespace ID
    'preorder_hash',        # hash(namespace_id,sender,reveal_addr) from the preorder (binds this namespace to its preorder)
    'version',              # namespace rules version

    'sender',               # the scriptPubKey hex script that identifies the preorderer
    'sender_pubkey',        # if sender is a p2pkh script, this is the public key
    'address',              # address of the sender, from the scriptPubKey
    'recipient',            # the scriptPubKey hex script that identifies the revealer.
    'recipient_address',    # the address of the revealer
    'block_number',         # block number at which this namespace was preordered
    'reveal_block',         # block number at which this namespace was revealed

    'op',                   # byte code identifying this operation to Blockstack
    'txid',                 # transaction ID at which this namespace was revealed
    'vtxindex',             # the index in the block where the tx occurs

    'lifetime',             # how long names last in this namespace (in number of blocks)
    'coeff',                # constant multiplicative coefficient on a name's price
    'base',                 # exponential base of a name's price
    'buckets',              # array that maps name length to the exponent to which to raise 'base' to
    'nonalpha_discount',    # multiplicative coefficient that drops a name's price if it has non-alpha characters 
    'no_vowel_discount',    # multiplicative coefficient that drops a name's price if it has no vowels
]

# fields this operation changes
# everything but the block number
MUTATE_FIELDS = filter( lambda f: f not in ["block_number"], FIELDS ) + ['token_fee']

def namespacereveal_sanity_check( namespace_id, version, lifetime, coeff, base, bucket_exponents, nonalpha_discount, no_vowel_discount ):
   """
   Verify the validity of a namespace reveal.
   Return True if valid
   Raise an Exception if not valid.
   """
   # sanity check 
   if not is_b40( namespace_id ) or "+" in namespace_id or namespace_id.count(".") > 0:
      raise Exception("Namespace ID '%s' has non-base-38 characters" % namespace_id)
  
   if len(namespace_id) > LENGTHS['blockchain_id_namespace_id']:
      raise Exception("Invalid namespace ID length for '%s' (expected length between 1 and %s)" % (namespace_id, LENGTHS['blockchain_id_namespace_id']))
    
   if version not in [NAMESPACE_VERSION_PAY_TO_BURN, NAMESPACE_VERSION_PAY_TO_CREATOR, NAMESPACE_VERSION_PAY_WITH_STACKS]:
      raise Exception("Invalid namespace version bits {:x}".format(version))

   if lifetime < 0 or lifetime > (2**32 - 1):
      lifetime = NAMESPACE_LIFE_INFINITE 

   if coeff < 0 or coeff > 255:
      raise Exception("Invalid cost multiplier %s: must be in range [0, 256)" % coeff)
  
   if base < 0 or base > 255:
      raise Exception("Invalid base price %s: must be in range [0, 256)" % base)
 
   if type(bucket_exponents) != list:
        raise Exception("Bucket exponents must be a list")

   if len(bucket_exponents) != 16:
        raise Exception("Exactly 16 buckets required")

   for i in xrange(0, len(bucket_exponents)):
       if bucket_exponents[i] < 0 or bucket_exponents[i] > 15:
          raise Exception("Invalid bucket exponent %s (must be in range [0, 16)" % bucket_exponents[i])
   
   if nonalpha_discount <= 0 or nonalpha_discount > 15:
        raise Exception("Invalid non-alpha discount %s: must be in range [0, 16)" % nonalpha_discount)
    
   if no_vowel_discount <= 0 or no_vowel_discount > 15:
        raise Exception("Invalid no-vowel discount %s: must be in range [0, 16)" % no_vowel_discount)

   return True


@state_create( "namespace_id", "namespaces", "check_namespace_collision" )
def check( state_engine, nameop, block_id, checked_ops ):
    """
    Check a NAMESPACE_REVEAL operation to the name database.
    It is only valid if it is the first such operation
    for this namespace, and if it was sent by the same
    sender who sent the NAMESPACE_PREORDER.

    Return True if accepted
    Return False if not
    """

    epoch_features = get_epoch_features(block_id)

    namespace_id = nameop['namespace_id']
    namespace_id_hash = nameop['preorder_hash']
    sender = nameop['sender']
    namespace_preorder = None

    if not nameop.has_key('sender_pubkey'):
       log.warning("Namespace reveal requires a sender_pubkey (i.e. a p2pkh transaction)")
       return False

    if not nameop.has_key('recipient'):
       log.warning("No recipient script for namespace '%s'" % namespace_id)
       return False

    if not nameop.has_key('recipient_address'):
       log.warning("No recipient address for namespace '%s'" % namespace_id)
       return False

    # well-formed?
    if not is_b40( namespace_id ) or "+" in namespace_id or namespace_id.count(".") > 0:
       log.warning("Malformed namespace ID '%s': non-base-38 characters")
       return False

    # can't be revealed already
    if state_engine.is_namespace_revealed( namespace_id ):
       # this namespace was already revealed
       log.warning("Namespace '%s' is already revealed" % namespace_id )
       return False

    # can't be ready already
    if state_engine.is_namespace_ready( namespace_id ):
       # this namespace already exists (i.e. was already begun)
       log.warning("Namespace '%s' is already registered" % namespace_id )
       return False

    # must currently be preordered
    namespace_preorder = state_engine.get_namespace_preorder( namespace_id_hash )
    if namespace_preorder is None:
       # not preordered
       log.warning("Namespace '%s' is not preordered (no preorder %s)" % (namespace_id, namespace_id_hash) )
       return False

    # must be sent by the same principal who preordered it
    if namespace_preorder['sender'] != sender:
       # not sent by the preorderer
       log.warning("Namespace '%s' is not preordered by '%s'" % (namespace_id, sender))
       return False

    # must be a version we support
    # pre F-day 2017: only support names that send payment to the burn address
    # post F-day 2017: support both pay-to-burn and pay-to-creator
    # 2018 phase 1: support paying for names with STACKs tokens
    namespace_version_bits = int(nameop['version'])
    if namespace_version_bits == NAMESPACE_VERSION_PAY_TO_CREATOR:
        # need to be in post F-day 2017 or later
        if EPOCH_FEATURE_NAMESPACE_BURN_TO_CREATOR not in epoch_features:
            log.warning("pay-to-creator is not supported in this epoch")
            return False

    elif namespace_version_bits == NAMESPACE_VERSION_PAY_WITH_STACKS:
        # need to be in 2018 phase 1 or later
        if EPOCH_FEATURE_NAMESPACE_PAY_WITH_STACKS not in epoch_features:
            log.warning("pay-with-STACKs-tokens is not supported in this epoch")
            return False

    elif namespace_version_bits != NAMESPACE_VERSION_PAY_TO_BURN:
        # not supported at all
        log.warning("Unsupported namespace version {:x}".format(namespace_version_bits))
        return False

    # what units did the namespace preorderer pay?
    units = namespace_preorder['token_units']
    tokens_paid = 0

    if units == 'STACKS':
        # namespace creator paid in STACKs
        if EPOCH_FEATURE_STACKS_BUY_NAMESPACES not in epoch_features:
            traceback.print_stack()
            log.fatal("Namespaces must be bought in STACKs, but this epoch does not support it!")
            os.abort()

        # how much did the NAMESPACE_PREORDER pay?
        if 'token_fee' not in namespace_preorder:
            log.warning("Namespace {} did not pay the token fee".format(namespace_id))
            return False

        tokens_paid = namespace_preorder['token_fee']
        assert isinstance(tokens_paid, (int,long))

        token_namespace_fee = price_namespace(namespace_id, block_id, units)
        if token_namespace_fee is None:
            log.warning("Invalid namespace ID {}".format(namespace_id))
            return False

        if tokens_paid < token_namespace_fee:
            # not enough!
            log.warning("Namespace buyer paid {} tokens, but '{}' costs {} tokens".format(tokens_paid, namespace_id, token_namespace_fee))
            return False

    elif units == 'BTC':
        # namespace creator paid in BTC
        # check fee...
        if not 'op_fee' in namespace_preorder:
           log.warning("Namespace '%s' preorder did not pay the fee" % (namespace_id))
           return False

        namespace_fee = namespace_preorder['op_fee']

        # must have paid enough
        if namespace_fee < price_namespace(namespace_id, block_id, units):
           # not enough money
           log.warning("Namespace '%s' costs %s, but sender paid %s" % (namespace_id, price_namespace(namespace_id, block_id, units), namespace_fee))
           return False

    else:
        traceback.print_stack()
        log.fatal("Unknown payment unit {}".format(units))
        os.abort()

    # is this the first time this namespace has been revealed?
    old_namespace = state_engine.get_namespace_op_state( namespace_id, block_id, include_expired=True )
    namespace_block_number = None
    preorder_block_number = namespace_preorder['block_number']
    
    if old_namespace is None:
        # revealed for the first time
        log.warning("Revealing for the first time: '%s'" % namespace_id)
        namespace_block_number = namespace_preorder['block_number']
        
    else:
        # revealed for the 2nd or later time
        log.warning("Re-revealing namespace '%s'" % namespace_id )
        
        # push back preorder block number to the original preorder
        namespace_block_number = old_namespace['block_number']

    # record preorder
    nameop['block_number'] = namespace_block_number 
    nameop['reveal_block'] = block_id
    state_create_put_preorder( nameop, namespace_preorder )

    # NOTE: not fed into the consensus hash, but necessary for database constraints:
    nameop['ready_block'] = 0
    nameop['op_fee'] = namespace_preorder['op_fee']
    
    nameop['token_fee'] = '{}'.format(tokens_paid)      # NOTE: avoids overflow
    # can begin import
    return True


def get_reveal_recipient_from_outputs( outputs ):
    """
    There are between three outputs:
    * the OP_RETURN
    * the pay-to-address with the "reveal_addr", not the sender's address
    * the change address (i.e. from the namespace preorderer)
    
    Given the outputs from a namespace_reveal operation,
    find the revealer's address's script hex.
    
    By construction, it will be the first non-OP_RETURN 
    output (i.e. the second output).
    """
   
    if len(outputs) != 3:
        # invalid
        raise Exception("Outputs are not from a namespace reveal")

    return outputs[1]['script']


def tx_extract( payload, senders, inputs, outputs, block_id, vtxindex, txid ):
    """
    Extract and return a dict of fields from the underlying blockchain transaction data
    that are useful to this operation.
    """
  
    sender_script = None 
    sender_address = None 
    sender_pubkey_hex = None

    recipient_script = None 
    recipient_address = None 

    try:
       # first two outputs matter to us
       assert check_tx_output_types(outputs[:2], block_id)

       recipient_script = get_reveal_recipient_from_outputs( outputs )
       recipient_address = virtualchain.script_hex_to_address( recipient_script )

       assert recipient_script is not None 
       assert recipient_address is not None

       # by construction, the first input comes from the principal
       # who sent the reveal transaction...
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
       raise Exception("No reveal address")

    parsed_payload = parse( payload, sender_script, recipient_address )
    assert parsed_payload is not None 

    ret = {
       "sender": sender_script,
       "address": sender_address,
       "recipient": recipient_script,
       "recipient_address": recipient_address,
       "reveal_block": block_id,
       "vtxindex": vtxindex,
       "txid": txid,
       "op": NAMESPACE_REVEAL
    }

    ret.update( parsed_payload )

    if sender_pubkey_hex is not None:
        ret['sender_pubkey'] = sender_pubkey_hex
    else:
        ret['sender_pubkey'] = None

    return ret


def parse( bin_payload, sender_script, recipient_address ):
   """
   NOTE: the first three bytes will be missing
   """ 
   
   if len(bin_payload) < MIN_OP_LENGTHS['namespace_reveal']:
       raise AssertionError("Payload is too short to be a namespace reveal")

   off = 0
   life = None 
   coeff = None 
   base = None 
   bucket_hex = None
   buckets = []
   discount_hex = None
   nonalpha_discount = None 
   no_vowel_discount = None
   version = None
   namespace_id = None 
   namespace_id_hash = None
   
   life = int( hexlify(bin_payload[off:off+LENGTHS['blockchain_id_namespace_life']]), 16 )
   
   off += LENGTHS['blockchain_id_namespace_life']
   
   coeff = int( hexlify(bin_payload[off:off+LENGTHS['blockchain_id_namespace_coeff']]), 16 )
   
   off += LENGTHS['blockchain_id_namespace_coeff']
   
   base = int( hexlify(bin_payload[off:off+LENGTHS['blockchain_id_namespace_base']]), 16 )
   
   off += LENGTHS['blockchain_id_namespace_base']
   
   bucket_hex = hexlify(bin_payload[off:off+LENGTHS['blockchain_id_namespace_buckets']])
   
   off += LENGTHS['blockchain_id_namespace_buckets']
   
   discount_hex = hexlify(bin_payload[off:off+LENGTHS['blockchain_id_namespace_discounts']])
   
   off += LENGTHS['blockchain_id_namespace_discounts']
   
   version = int( hexlify(bin_payload[off:off+LENGTHS['blockchain_id_namespace_version']]), 16)
   
   off += LENGTHS['blockchain_id_namespace_version']
   
   namespace_id = bin_payload[off:]
   namespace_id_hash = None
   try:
       namespace_id_hash = hash_name( namespace_id, sender_script, register_addr=recipient_address )
   except:
       log.error("Invalid namespace ID and/or sender script")
       return None
   
   # extract buckets 
   buckets = [int(x, 16) for x in list(bucket_hex)]
   
   # extract discounts
   nonalpha_discount = int( list(discount_hex)[0], 16 )
   no_vowel_discount = int( list(discount_hex)[1], 16 )
  
   try:
       rc = namespacereveal_sanity_check( namespace_id, version, life, coeff, base, buckets, nonalpha_discount, no_vowel_discount )
       if not rc:
           raise Exception("Invalid namespace parameters")

   except Exception, e:
       if BLOCKSTACK_TEST:
           log.exception(e)

       log.error("Invalid namespace parameters")
       return None 

   return {
      'opcode': 'NAMESPACE_REVEAL',
      'lifetime': life,
      'coeff': coeff,
      'base': base,
      'buckets': buckets,
      'version': version,
      'nonalpha_discount': nonalpha_discount,
      'no_vowel_discount': no_vowel_discount,
      'namespace_id': namespace_id,
      'preorder_hash': namespace_id_hash
   }


def canonicalize(parsed_op):
    """
    Get the "canonical form" of this operation, putting it into a form where it can be serialized
    to form a consensus hash.  This method is meant to preserve compatibility across blockstackd releases.

    For NAMESPACE_REVEAL, this means:
    * make the 'buckets' array into a string
    """
    assert 'buckets' in parsed_op
    parsed_op['buckets'] = str(parsed_op['buckets'])
    return parsed_op


def decanonicalize(canonical_op):
    """
    Get the "current form" of this operation, putting it into a form usable by the rest of the system.

    For NAMESPACE_REVEAL, this means:
    * make 'buckets' string into an array
    """
    assert 'buckets' in canonical_op
    canonical_op['buckets'] = json.loads(canonical_op['buckets'])
    return canonical_op

