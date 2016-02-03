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
    make_pay_to_address_script, b58check_encode, b58check_decode, BlockchainInfoClient, \
    hex_hash160, bin_hash160, BitcoinPrivateKey, BitcoinPublicKey, script_hex_to_address, get_unspents, \
    make_op_return_outputs


from pybitcoin.transactions.outputs import calculate_change_amount
from utilitybelt import is_hex
from binascii import hexlify, unhexlify
import copy

from ..b40 import b40_to_hex, is_b40
from ..config import *
from ..scripts import *
from ..hashing import hash_name

# consensus hash fields (ORDER MATTERS!)
FIELDS = [
     'preorder_name_hashes',#  hash(sorted(name),sender,sorted(register_addr)) 
     'consensus_hash',      # consensus hash at time of send
     'sender',              # scriptPubKey hex that identifies the principal that issued the preorder
     'sender_pubkey',       # if sender is a pubkeyhash script, then this is the public key
     'address',             # address from the sender's scriptPubKey
     'block_number',        # block number at which these names were preordered for the first time

     'op',                  # blockstore bytestring describing the operation
     'txid',                # transaction ID
     'vtxindex',            # the index in the block where the tx occurs
     'op_fee',              # blockstore fee (sent to burn address)
]

def preorder_multi_valid( name_list, register_addrs ):
    """
    Verify that these names are all preorder-able:
    * preorder names in pairs
    * up to 3 pairs at once
    * must have matching address
    * must be unique
    * must be b40-encoded 
    * name[i] and name[i+1] cannot exceed 36 bytes (80 - 3 - 40 - 1) 
    """
    
    # sanity checks...
    if len(name_list) % 2 != 0:
        raise Exception("Name list must have 2, 4, or 6 names")

    if len(name_list) == 0 or len(name_list) > 6:
        raise Exception("Name list must have 2, 4, or 6 names")

    if len(name_list) != len(register_addrs):
        raise Exception("Name list and register addresses are not the same size")

    if len(name_list) != len(set(name_list)):
        raise Exception("Name list has duplicate names")

    for name in name_list:
        # expect inputs to the hash
        if not is_b40( name ) or "+" in name or name.count(".") > 1:
            raise Exception("Name '%s' has non-base-38 characters" % name)
            
        # name itself cannot exceed LENGTHS['blockchain_id_name']
        if len(NAME_SCHEME) + len(name) > LENGTHS['blockchain_id_name']:
            raise Exception("Name '%s' is too long; exceeds %s bytes" % (name, LENGTHS['blockchain_id_name'] - len(NAME_SCHEME)))


    # names must be sufficiently short that we can register them all
    for i in xrange(0, len(name_list), 2):
        if len(name_list[i]) + len(name_list[i+1]) > LENGTHS['max_op_length'] - 3 - LENGTHS['consensus_hash'] - 1:
            raise Exception("Names (%s, %s) cannot be paired" % (name_list[i], name_list[i+1]))

    return True


def hash_names( name_list, script_pubkey, register_addrs ):
    """
    Calculate the canonical hash of a set of names and their register addresses.
    """

    # sanity checks...
    if not preorder_multi_valid( name_list, register_addrs ):
        raise Exception("Invalid name/register lists")

    # names are sorted, but the addresses are put in the same order as the names
    name_addrs = zip( name_list, register_addrs )
    name_addrs.sort()
    
    name_addrs_str = ",".join( [ "%s:%s" % (n, a) for (n, a) in name_addrs ] )
    
    h = hex_hash160( name_addrs_str + script_pubkey )
    return h


def build(name_list, script_pubkey, register_addr_list, consensus_hash, name_hashes=None, testset=False):
    """
    Takes a name list where each name includes the namespace ID, a list of addresses to prove ownership
    of the subsequent NAME_REGISTER operation, and the current consensus hash for this block (to prove that the 
    caller is not on a shorter fork).

    The (name_list, register_addr_list) lists must pass the criteria defined by preorder_multi_valid() above.

    Returns a NAME_PREORDER_MULTI script.
    
    Record format:
    
    0     2  3             4                                                                          64             80
    |-----|--|-------------|--------------------------------------------------------------------------|--------------|
    magic op   #names       hash(sorted(list(names)),script_pubkey,sorted(list(register_addrs))) * 3  consensus hash
    
    """

    if name_hashes is None:

        if not preorder_multi_valid( name_list, register_addr_list ):
            raise Exception("Invalid name and address list")

        # force string, not unicode 
        for i in xrange(0, len(name_list)):
            name_list[i] = str(name_list[i])
  
        name_hashes = []
        for i in xrange(0, len(name_list), 2):
            name_hashes.append( hash_names( [name_list[i], name_list[i+1]], script_pubkey, [register_addr_list[i], register_addr_list[i+1]] ) )

        num_name_hashes = len(name_list) / 2

    else:
        num_name_hashes = len(name_hashes)

    count_hex = hexlify( chr(num_name_hashes) )
    name_hashes_hex = "".join( name_hashes )
    script = 'NAME_PREORDER_MULTI 0x%s 0x%s 0x%s' % (count_hex, name_hashes_hex, consensus_hash)
    hex_script = blockstore_script_to_hex(script)
    packaged_script = add_magic_bytes(hex_script, testset=testset)
    
    return packaged_script


def tx_extract( payload, senders, inputs, outputs ):
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

    try:
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

    except Exception, e:
       log.exception(e)
       raise Exception("Failed to extract")

    parsed_payload = parse( payload )
    assert parsed_payload is not None 

    ret = {
       "sender": sender_script,
       "address": sender_address
    }

    ret.update( parsed_payload )

    if sender_pubkey_hex is not None:
        ret['sender_pubkey'] = sender_pubkey_hex

    return ret


def make_outputs( data, inputs, sender_addr, op_fee, format='bin' ):
    """
    Make outputs for a name preorder:
    [0] OP_RETURN with the name 
    [1] address with the NAME_PREORDER sender's address
    [2] pay-to-address with the *burn address* with the fee
    
    NOTE: the fee must cover *all* the names
    """
    
    outputs = [
        # main output
        {"script_hex": make_op_return_script(data, format=format),
         "value": 0},
        
        # change address (can be subsidy key)
        {"script_hex": make_pay_to_address_script(sender_addr),
         "value": calculate_change_amount(inputs, 0, 0)},
        
        # burn address
        {"script_hex": make_pay_to_address_script(BLOCKSTORE_BURN_ADDRESS),
         "value": op_fee}
    ]

    dust_fee = tx_dust_fee_from_inputs_and_outputs( inputs, outputs )
    outputs[1]['value'] = calculate_change_amount( inputs, op_fee, dust_fee )
    return outputs


def broadcast(name_list, private_key, register_addr_list, consensus_hash, blockchain_client, fee, \
              blockchain_broadcaster=None, subsidy_public_key=None, tx_only=False, testset=False):
    """
    Builds and broadcasts a preorder transaction.

    @subsidy_public_key: if given, the public part of the subsidy key 
    """

    if subsidy_public_key is not None:
        # subsidizing, and only want the tx 
        tx_only = True
    
    # sanity check 
    if subsidy_public_key is None and private_key is None:
        raise Exception("Missing both client public and private key")
    
    if blockchain_broadcaster is None:
        blockchain_broadcaster = blockchain_client 

    from_address = None     # change address
    inputs = None
    private_key_obj = None
    script_pubkey = None    # to be mixed into preorder hash
    
    if subsidy_public_key is not None:
        # subsidizing
        pubk = BitcoinPublicKey( subsidy_public_key )
        
        from_address = BitcoinPublicKey( subsidy_public_key ).address()

        inputs = get_unspents( from_address, blockchain_client )
        script_pubkey = get_script_pubkey( subsidy_public_key )

    else:
        # ordering directly
        pubk = BitcoinPrivateKey( private_key ).public_key()
        public_key = pubk.to_hex()
        script_pubkey = get_script_pubkey( public_key )
        
        # get inputs and from address using private key
        private_key_obj, from_address, inputs = analyze_private_key(private_key, blockchain_client)
        
    nulldata = build( name_list, script_pubkey, register_addr_list, consensus_hash, testset=testset)
    outputs = make_outputs(nulldata, inputs, from_address, fee, format='hex')
    
    if tx_only:

        unsigned_tx = serialize_transaction( inputs, outputs )
        return {"unsigned_tx": unsigned_tx}
    
    else:
        # serialize, sign, and broadcast the tx
        response = serialize_sign_and_broadcast(inputs, outputs, private_key_obj, blockchain_client)
        response.update({'data': nulldata})
        return response


def parse(bin_payload):
    """
    Parse a name multi-preorder.
    NOTE: bin_payload *excludes* the leading 3 bytes (magic + count) returned by build.
    """
    
    if len(bin_payload) < 1 + LENGTHS['preorder_name_hash'] + LENGTHS['consensus_hash']:
        log.error("Not a NAME_PREORDER_MULTI")
        return None 

    num_hashes = ord(bin_payload[0])
    
    if len(bin_payload) != 1 + num_hashes * LENGTHS['preorder_name_hash'] + LENGTHS['consensus_hash']:
        log.error("Invalid NAME_PREORDER_MULTI")
        return None 

    name_hashes = []
    for i in xrange(0, num_hashes):
        nh = hexlify( bin_payload[ 1 + i*LENGTHS['preorder_name_hash'] : 1 + (i+1)*LENGTHS['preorder_name_hash'] ] )
        name_hashes.append( nh )

    consensus_hash = hexlify( bin_payload[ 1 + num_hashes*LENGTHS['preorder_name_hash'] : 1 + num_hashes*LENGTHS['preorder_name_hash'] + LENGTHS['consensus_hash']] )
    
    return {
        'opcode': 'NAME_PREORDER_MULTI',
        'preorder_name_hashes': name_hashes,
        'consensus_hash': consensus_hash
    }


def decompose( nameop, name_hash ):
    """
    Decompose a NAME_PREORDER_MULTI into a single NAME_PREORDER with the given name_hash.
    Used to simplify commits.
    """

    try:
        i = nameop['preorder_name_hashes'].index( name_hash )
    except:
        log.debug("No name hash '%s'" % name_hash)
        raise 

    ret = copy.deepcopy( nameop )

    ret['opcode'] = 'NAME_PREORDER'
    ret['op'] = NAME_PREORDER
    ret['preorder_name_hash'] = name_hash 
    
    del ret['preorder_name_hashes']
    return ret


def get_fees( inputs, outputs ):
    """
    Given a transaction's outputs, look up its fees:
    * the first output must be an OP_RETURN, and it must have a fee of 0.
    * the second must be the change address
    * the third must be a burn fee to the burn address.
    
    Return (dust fees, operation fees) on success 
    Return (None, None) on invalid output listing
    """
    if len(outputs) != 3:
        log.debug("Expected 3 outputs; got %s" % len(outputs))
        return (None, None)
    
    # 0: op_return
    if not tx_output_is_op_return( outputs[0] ):
        log.debug("outputs[0] is not an OP_RETURN")
        return (None, None) 
    
    if outputs[0]["value"] != 0:
        log.debug("outputs[0] has value %s'" % outputs[0]["value"])
        return (None, None) 
    
    # 1: change address 
    if script_hex_to_address( outputs[1]["script_hex"] ) is None:
        log.error("outputs[1] has no decipherable change address")
        return (None, None)
    
    # 2: burn address 
    addr_hash = script_hex_to_address( outputs[2]["script_hex"] )
    if addr_hash is None:
        log.error("outputs[2] has no decipherable burn address")
        return (None, None) 
    
    if addr_hash != BLOCKSTORE_BURN_ADDRESS:
        log.error("outputs[2] is not the burn address")
        return (None, None)
    
    dust_fee = (len(inputs) + 2) * DEFAULT_DUST_FEE + DEFAULT_OP_RETURN_FEE
    op_fee = outputs[2]["value"]
    
    return (dust_fee, op_fee)


def restore_delta( name_rec, block_number, history_index, untrusted_db, testset=False ):
    """
    Find the fields in a name record that were changed by an instance of this operation, at the 
    given (block_number, history_index) point in time in the past.  The history_index is the
    index into the list of changes for this name record in the given block.

    Return the fields that were modified on success.
    Return None on error.
    """

    # reconstruct the multi-preorder op 
    name_rec_script = build( None, None, None, str(name_rec['consensus_hash']), \
            name_hashes=name_rec['preorder_name_hashes'], testset=testset )

    name_rec_payload = unhexlify( name_rec_script )[3:]
    ret_delta = parse( name_rec_payload )

    return ret_delta
