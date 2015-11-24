#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstore
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016 by Blockstack.org

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
    along with Blockstore. If not, see <http://www.gnu.org/licenses/>.
"""

from pybitcoin import embed_data_in_blockchain, serialize_transaction, \
    analyze_private_key, serialize_sign_and_broadcast, make_op_return_script, \
    make_pay_to_address_script, b58check_encode, b58check_decode, BlockchainInfoClient, hex_hash160

from pybitcoin.transactions.outputs import calculate_change_amount

from utilitybelt import is_hex
from binascii import hexlify, unhexlify
import types
import json

from ..b40 import b40_to_hex, bin_to_b40, is_b40
from ..config import *
from ..scripts import blockstore_script_to_hex, add_magic_bytes
from ..hashing import hash_name
   
import virtualchain

if not globals().has_key('log'):
    log = virtualchain.session.log

# consensus hash fields (ORDER MATTERS!)
FIELDS = [
    'namespace_id',         # human-readable namespace ID
    'namespace_id_hash',    # hash(namespace_id,sender,reveal_addr) from the preorder (binds this namespace to its preorder)
    'version',              # namespace rules version

    'sender',               # the scriptPubKey hex script that identifies the preorderer
    'sender_pubkey',        # if sender is a p2pkh script, this is the public key
    'address',              # address of the sender, from the scriptPubKey
    'recipient',            # the scriptPubKey hex script that identifies the revealer.
    'recipient_address',    # the address of the revealer
    'block_number',         # block number at which this namespace was preordered
    'reveal_block',         # block number at which this namespace was revealed

    'op',                   # byte code identifying this operation to Blockstore
    'txid',                 # transaction ID at which this namespace was revealed
    'vtxindex',             # the index in the block where the tx occurs

    'lifetime',             # how long names last in this namespace (in number of blocks)
    'coeff',                # constant multiplicative coefficient on a name's price
    'base',                 # exponential base of a name's price
    'buckets',              # array that maps name length to the exponent to which to raise 'base' to
    'nonalpha_discount',    # multiplicative coefficient that drops a name's price if it has non-alpha characters 
    'no_vowel_discount',    # multiplicative coefficient that drops a name's price if it has no vowels
]

def serialize_int( int_field, numbytes ):
   """
   Serialize an integer to a hex string that is padlen characters long.
   Raise an exception on overflow.
   """
   
   if int_field >= 2**(numbytes*8) or int_field < -(2**(numbytes*8)):
      raise Exception("Integer overflow (%s bytes)" % (numbytes) )
   
   format_str = "%%0.%sx" % (numbytes*2) 
   hex_str = format_str % int_field 
   
   if len(hex_str) % 2 != 0:
      # sometimes python cuts off the leading zero 
      hex_str = '0' + hex_str
   
   return hex_str
   

def serialize_buckets( bucket_exponents ):
    """
    Serialize the list of bucket exponents.
    There should be 16 buckets, and each one should have an integer between 0 and 15.
    """
    ret = ""
    for i in xrange(0, len(bucket_exponents)):
        ret += "%X" % bucket_exponents[i]
    
    return ret


def serialize_discounts( nonalpha_discount, no_vowel_discount ):
    """
    Serialize the non-alpha and no-vowel discounts.
    They must be between 0 and 15
    """
    return "%X%X" % (nonalpha_discount, no_vowel_discount)


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
   
   if lifetime < 0 or lifetime > (2**32 - 1):
      lifetime = NAMESPACE_LIFE_INFINITE 

   if coeff < 0 or coeff > 255:
      raise Exception("Invalid cost multiplier %s: must be in range [0, 256)" % coeff)
  
   if base < 0 or base > 255:
      raise Exception("Invalid base price %s: must be in range [0, 256)" % base)
  
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


# version: 2 bytes
# namespace ID: up to 19 bytes
def build( namespace_id, version, reveal_addr, lifetime, coeff, base, bucket_exponents, nonalpha_discount, no_vowel_discount, testset=False ):
   """
   Record to mark the beginning of a namespace import in the blockchain.
   This reveals the namespace ID, and encodes the preorder's namespace rules.
   
   The rules for a namespace are as follows:
   * a name can fall into one of 16 buckets, measured by length.  Bucket 16 incorporates all names at least 16 characters long.
   * the pricing structure applies a multiplicative penalty for having numeric characters, or punctuation characters.
   * the price of a name in a bucket is ((coeff) * (base) ^ (bucket exponent)) / ((numeric discount multiplier) * (punctuation discount multiplier))
   
   Example:
   base = 10
   coeff = 2
   nonalpha discount: 10
   no-vowel discount: 10
   buckets 1, 2: 9
   buckets 3, 4, 5, 6: 8
   buckets 7, 8, 9, 10, 11, 12, 13, 14: 7
   buckets 15, 16+:
   
   The price of "john" would be 2 * 10^8, since "john" falls into bucket 4 and has no punctuation or numerics.
   The price of "john1" would be 2 * 10^6, since "john1" falls into bucket 5 but has a number (and thus receives a 10x discount)
   The price of "john_1" would be 2 * 10^6, since "john_1" falls into bucket 6 but has a number and puncuation (and thus receives a 10x discount)
   The price of "j0hn_1" would be 2 * 10^5, since "j0hn_1" falls into bucket 6 but has a number and punctuation and lacks vowels (and thus receives a 100x discount)
   Namespace ID must be base38.
   
   Format:
   
   0     2   3        7     8     9    10   11   12   13   14    15    16    17       18        20                        39
   |-----|---|--------|-----|-----|----|----|----|----|----|-----|-----|-----|--------|----------|-------------------------|
   magic  op  life    coeff. base 1-2  3-4  5-6  7-8  9-10 11-12 13-14 15-16  nonalpha  version   namespace ID
                                                     bucket exponents         no-vowel
                                                                              discounts
   
   """
   
   rc = namespacereveal_sanity_check( namespace_id, version, lifetime, coeff, base, bucket_exponents, nonalpha_discount, no_vowel_discount )
   if not rc:
       raise Exception("Invalid namespace parameters")
    
   # good to go!
   life_hex = serialize_int( lifetime, 4 )
   coeff_hex = serialize_int( coeff, 1 )
   base_hex = serialize_int( base, 1 )
   bucket_hex = serialize_buckets( bucket_exponents )
   discount_hex = serialize_discounts( nonalpha_discount, no_vowel_discount )
   version_hex = serialize_int( version, 2 )
   namespace_id_hex = hexlify( namespace_id )
   
   readable_script = "NAMESPACE_REVEAL 0x%s 0x%s 0x%s 0x%s 0x%s 0x%s 0x%s" % (life_hex, coeff_hex, base_hex, bucket_hex, discount_hex, version_hex, namespace_id_hex)
   hex_script = blockstore_script_to_hex(readable_script)
   packaged_script = add_magic_bytes(hex_script, testset=testset)
   
   return packaged_script


def make_outputs( data, inputs, reveal_addr, change_addr, format='bin', testset=False ):
    """
    Make outputs for a register:
    [0] OP_RETURN with the name 
    [1] pay-to-address with the *reveal_addr*, not the sender's address.
    [2] change address with the NAMESPACE_PREORDER sender's address
    """
    
    total_to_send = DEFAULT_OP_RETURN_FEE + DEFAULT_DUST_FEE
    
    return [
        # main output
        {"script_hex": make_op_return_script(data, format=format),
         "value": 0},
    
        # register address
        {"script_hex": make_pay_to_address_script(reveal_addr),
         "value": DEFAULT_DUST_FEE},
        
        # change address
        {"script_hex": make_pay_to_address_script(change_addr),
         "value": calculate_change_amount(inputs, total_to_send, DEFAULT_DUST_FEE * (len(inputs) + 3))},
    ]
    
    

def broadcast( namespace_id, reveal_addr, lifetime, coeff, base_cost, bucket_exponents, nonalpha_discount, no_vowel_discount, private_key, blockchain_client, tx_only=False, blockchain_broadcaster=None, testset=False ):
   """
   Propagate a namespace.
   
   Arguments:
   namespace_id         human-readable (i.e. base-40) name of the namespace
   reveal_addr          address to own this namespace until it is ready
   lifetime:            the number of blocks for which names will be valid (pass a negative value for "infinite")
   coeff:               cost multipler
   base_cost:           the base cost (i.e. cost of a 1-character name), in satoshis 
   bucket_exponents:    bucket cost exponents to which to raise the base cost 
   nonalpha_discount:   discount multipler for non-alpha-character names 
   no_vowel_discount:   discount multipler for no-vowel names
   """
   
   if blockchain_broadcaster is None:
       blockchain_broadcaster = blockchain_client 
    
   nulldata = build( namespace_id, BLOCKSTORE_VERSION, reveal_addr, lifetime, coeff, base_cost, bucket_exponents, nonalpha_discount, no_vowel_discount, testset=testset )
   
   # get inputs and from address
   private_key_obj, from_address, inputs = analyze_private_key(private_key, blockchain_client)
    
   # build custom outputs here
   outputs = make_outputs(nulldata, inputs, reveal_addr, from_address, format='hex')
    
   if tx_only:
        unsigned_tx = serialize_transaction( inputs, outputs )
        return {"unsigned_tx": unsigned_tx}
   
   else:
        # serialize, sign, and broadcast the tx
        response = serialize_sign_and_broadcast(inputs, outputs, private_key_obj, blockchain_broadcaster)
            
        # response = {'success': True }
        response.update({'data': nulldata})
            
        return response
   

def parse( bin_payload, sender, recipient_address ):
   """
   NOTE: the first three bytes will be missing
   """
   
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
       namespace_id_hash = hash_name( namespace_id, sender, register_addr=recipient_address )
   except:
       log.error("Invalid namespace ID and/or sender")
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
      'namespace_id_hash': namespace_id_hash
   }


def get_fees( inputs, outputs ):
    """
    Blockstore currently does not allow 
    the subsidization of namespaces.
    """
    return (None, None)

