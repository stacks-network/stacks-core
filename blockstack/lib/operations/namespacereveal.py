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

from ..config import *
from ..hashing import *
from ..scripts import *
from ..nameset import *

from binascii import hexlify, unhexlify 

import blockstack_client
from blockstack_client.operations import *

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
MUTATE_FIELDS = filter( lambda f: f not in ["block_number"], FIELDS )

# fields that must be backed up when applying this operation (all of them)
BACKUP_FIELDS = ["__all__"]


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

    namespace_id = nameop['namespace_id']
    namespace_id_hash = nameop['preorder_hash']
    sender = nameop['sender']
    namespace_preorder = None

    if not nameop.has_key('sender_pubkey'):
       log.debug("Namespace reveal requires a sender_pubkey (i.e. a p2pkh transaction)")
       return False

    if not nameop.has_key('recipient'):
       log.debug("No recipient script for namespace '%s'" % namespace_id)
       return False

    if not nameop.has_key('recipient_address'):
       log.debug("No recipient address for namespace '%s'" % namespace_id)
       return False

    # well-formed?
    if not is_b40( namespace_id ) or "+" in namespace_id or namespace_id.count(".") > 0:
       log.debug("Malformed namespace ID '%s': non-base-38 characters")
       return False

    # can't be revealed already
    if state_engine.is_namespace_revealed( namespace_id ):
       # this namespace was already revealed
       log.debug("Namespace '%s' is already revealed" % namespace_id )
       return False

    # can't be ready already
    if state_engine.is_namespace_ready( namespace_id ):
       # this namespace already exists (i.e. was already begun)
       log.debug("Namespace '%s' is already registered" % namespace_id )
       return False

    # must currently be preordered
    namespace_preorder = state_engine.get_namespace_preorder( namespace_id_hash )
    if namespace_preorder is None:
       # not preordered
       log.debug("Namespace '%s' is not preordered (no preorder %s)" % (namespace_id, namespace_id_hash) )
       return False

    # must be sent by the same principal who preordered it
    if namespace_preorder['sender'] != sender:
       # not sent by the preorderer
       log.debug("Namespace '%s' is not preordered by '%s'" % (namespace_id, sender))

    # must be a version we support
    if int(nameop['version']) != BLOCKSTACK_VERSION:
       log.debug("Namespace '%s' requires version %s, but this blockstack is version %s" % (namespace_id, nameop['version'], BLOCKSTACK_VERSION))
       return False

    # check fee...
    if not 'op_fee' in namespace_preorder:
       log.debug("Namespace '%s' preorder did not pay the fee" % (namespace_id))
       return False

    namespace_fee = namespace_preorder['op_fee']

    # must have paid enough
    if namespace_fee < price_namespace( namespace_id, block_id ):
       # not enough money
       log.debug("Namespace '%s' costs %s, but sender paid %s" % (namespace_id, price_namespace(namespace_id, block_id), namespace_fee ))
       return False

    # is this the first time this namespace has been revealed?
    old_namespace = state_engine.get_namespace_op_state( namespace_id, block_id, include_expired=True )
    namespace_block_number = None
    preorder_block_number = namespace_preorder['block_number']
    
    if old_namespace is None:
        # revealed for the first time
        log.debug("Revealing for the first time: '%s'" % namespace_id)
        namespace_block_number = namespace_preorder['block_number']
        state_create_put_prior_history( nameop, None )
        
    else:
        # revealed for the 2nd or later time
        log.debug("Re-revealing namespace '%s'" % namespace_id )
        
        # push back preorder block number to the original preorder
        namespace_block_number = old_namespace['block_number']

        # re-revealing
        prior_hist = prior_history_create( nameop, old_namespace, preorder_block_number, state_engine, extra_backup_fields=['consensus_hash','preorder_hash'])
        state_create_put_prior_history( nameop, prior_hist )

    # record preorder
    nameop['block_number'] = namespace_block_number  # namespace_preorder['block_number']
    nameop['reveal_block'] = block_id
    state_create_put_preorder( nameop, namespace_preorder )

    # NOTE: not fed into the consensus hash, but necessary for database constraints:
    nameop['ready_block'] = 0
    nameop['op_fee'] = namespace_preorder['op_fee']

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
    
    ret = None
    if len(outputs) != 3:
        # invalid
        raise Exception("Outputs are not from a namespace reveal")

    reveal_output = outputs[1]
   
    output_script = reveal_output['scriptPubKey']
    output_asm = output_script.get('asm')
    output_hex = output_script.get('hex')
    output_addresses = output_script.get('addresses')
    
    if output_asm[0:9] != 'OP_RETURN' and output_hex is not None:
        
        # recipient's script hex
        ret = output_hex

    else:
       raise Exception("No namespace reveal script found")

    return ret


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


def restore_delta( name_rec, block_number, history_index, working_db, untrusted_db ):
    """
    Find the fields in a name record that were changed by an instance of this operation, at the 
    given (block_number, history_index) point in time in the past.  The history_index is the
    index into the list of changes for this name record in the given block.

    Return the fields that were modified on success.
    Return None on error.
    """

    buckets = name_rec['buckets']

    if type(buckets) in [str, unicode]:
        # serialized bucket list.
        # unserialize 
        reg = "[" + "[ ]*[0-9]+[ ]*," * 15 + "[ ]*[0-9]+[ ]*]"
        match = re.match( reg, buckets )
        if match is None:
            log.error("FATAL: bucket list '%s' is not parsable" % (buckets))
            os.abort()

        try:
            buckets = [int(b) for b in buckets.strip("[]").split(", ")]
        except Exception, e:
            log.exception(e)
            log.error("FATAL: failed to parse '%s' into a 16-elemenet list" % (buckets))
            os.abort()

    name_rec_script = build_namespace_reveal( str(name_rec['namespace_id']), name_rec['version'], str(name_rec['recipient_address']), \
                                              name_rec['lifetime'], name_rec['coeff'], name_rec['base'], buckets, 
                                              name_rec['nonalpha_discount'], name_rec['no_vowel_discount'] )

    name_rec_payload = unhexlify( name_rec_script )[3:]
    ret_op = parse( name_rec_payload, str(name_rec['sender']), str(name_rec['recipient_address']) )

    ret_op['op'] = NAMESPACE_REVEAL

    return ret_op


def snv_consensus_extras( name_rec, block_id, blockchain_name_data, db ):
    """
    Calculate any derived missing data that goes into the check() operation,
    given the block number, the name record at the block number, and the db.
    """
    return blockstack_client.operations.namespacereveal.snv_consensus_extras( name_rec, block_id, blockchain_name_data )
    '''
    return {}
    '''
