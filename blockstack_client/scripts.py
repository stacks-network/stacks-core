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

from binascii import hexlify, unhexlify
import bitcoin
import pybitcoin
import simplejson
import virtualchain

from pybitcoin.transactions.outputs import calculate_change_amount
from .config import MAGIC_BYTES, NAME_OPCODES, LENGTH_MAX_NAME, LENGTH_MAX_NAMESPACE_ID, TX_MIN_CONFIRMATIONS
from .b40 import *
from .keys import *

from decimal import *

from virtualchain import tx_serialize, tx_deserialize, tx_script_to_asm, tx_output_parse_scriptPubKey

log = virtualchain.get_logger("blockstack-client")

class UTXOException(Exception):
    pass

def add_magic_bytes(hex_script):
    return hexlify(MAGIC_BYTES) + hex_script


def is_name_valid( fqn ):
    """
    Is a fully-qualified name acceptable?
    Return True if so
    Return False if not
    """

    if fqn.count( "." ) != 1:
        return False

    name, namespace_id = fqn.split(".")

    if len(name) == 0 or len(namespace_id) == 0:
        return False 

    if not is_b40( name ) or "+" in name or "." in name:
        return False 
    
    if not is_namespace_valid( namespace_id ):
        return False

    if len(fqn) > LENGTH_MAX_NAME:
       # too long
       return False 

    return True


def is_namespace_valid( namespace_id ):
    """
    Is a namespace ID valid?
    """
    if not is_b40( namespace_id ) or "+" in namespace_id or namespace_id.count(".") > 0:
        return False

    if len(namespace_id) == 0 or len(namespace_id) > LENGTH_MAX_NAMESPACE_ID:
        return False

    return True


def blockstack_script_to_hex(script):
    """ Parse the readable version of a script, return the hex version.
    """
    hex_script = ''
    parts = script.split(' ')
    for part in parts:
       
        if part in NAME_OPCODES.keys():
            try:
                hex_script += '%0.2x' % ord(NAME_OPCODES[part])
            except:
                raise Exception('Invalid opcode: %s' % part)
        
        elif part.startswith("0x"):
            # literal hex string
            hex_script += part[2:]
            
        elif is_valid_int(part):
            hex_part = '%0.2x' % int(part)
            if len(hex_part) % 2 != 0:
               hex_part = '0' + hex_part
               
            hex_script += hex_part
         
        elif is_hex(part) and len(part) % 2 == 0:
            hex_script += part
            
        else:
            raise ValueError('Invalid script (at %s), contains invalid characters: %s' % (part, script))
         
    if len(hex_script) % 2 != 0:
        raise ValueError('Invalid script: must have an even number of chars (got %s).' % hex_script)
     
    return hex_script


def hash_name(name, script_pubkey, register_addr=None):
   """
   Generate the hash over a name and hex-string script pubkey
   """
   bin_name = b40_to_bin(name)
   name_and_pubkey = bin_name + unhexlify(script_pubkey)
   
   if register_addr is not None:
       name_and_pubkey += str(register_addr)
   
   return pybitcoin.hex_hash160(name_and_pubkey)


def hash256_trunc128( data ):
   """
   Hash a string of data by taking its 256-bit sha256 and truncating it to 128 bits.
   """
   return hexlify( pybitcoin.hash.bin_sha256( data )[0:16] )
  
   
def tx_output_is_op_return( output ):
    """
    Is an output's script an OP_RETURN script?
    """
    return int( output["script_hex"][0:2], 16 ) == pybitcoin.opcodes.OP_RETURN


def tx_extend( partial_tx_hex, new_inputs, new_outputs ):
    """
    Given an unsigned serialized transaction, add more inputs and outputs to it.
    @new_inputs and @new_outputs will be pybitcoin-formatted:
    * new_inputs[i] will have {'output_index': ..., 'script_hex': ..., 'transaction_hash': ...}
    * new_outputs[i] will have {'script_hex': ..., 'value': ... (in satoshis!)}
    """
    
    # recover tx
    tx = tx_deserialize( partial_tx_hex )
    tx_inputs = tx['vin']
    tx_outputs = tx['vout']
    locktime = tx['locktime']
    version = tx['version']

    # format new inputs
    btc_new_inputs = []
    for inp in new_inputs:
        new_inp = {
            "vout": inp['output_index'],
            "txid": inp['transaction_hash'],
            "scriptSig": {
                "asm": tx_script_to_asm(inp['script_hex']),
                "hex": inp['script_hex']
            }
        }

        btc_new_inputs.append(new_inp)

    # format new outputs
    btc_new_outputs = []
    for i in xrange(0, len(new_outputs)):
        new_output = new_outputs[i]
        new_outp = {
            "n": i + len(tx_outputs),
            "value": Decimal(new_output['value']) / Decimal(10**8),
            "scriptPubKey": tx_output_parse_scriptPubKey(new_output['script_hex']),
            "script_hex": new_output['script_hex']
        }
        
        btc_new_outputs.append(new_outp)
    
    new_tx = {
        'vin': tx_inputs + btc_new_inputs,
        'vout': tx_outputs + btc_new_outputs,
        'locktime': locktime,
        'version': version
    }

    # new tx
    new_unsigned_tx = tx_serialize( new_tx )
     
    return new_unsigned_tx


def tx_make_subsidization_output( payer_utxo_inputs, payer_address, op_fee, dust_fee ):
    """
    Given the set of utxo inputs for both the client and payer, as well as the client's 
    desired tx outputs, generate the inputs and outputs that will cause the payer to pay 
    the operation's fees and dust fees.
    
    The client should send its own address as an input, with the same amount of BTC as the output.
    
    Return the payer output to include in the transaction on success, which should pay for the operation's
    fee and dust.

    Raise ValueError it here aren't enough inputs to subsidize
    """

    return {
        "script_hex": virtualchain.make_payment_script( payer_address ),
        "value": calculate_change_amount( payer_utxo_inputs, op_fee, int(round(dust_fee)) )
    }


def tx_sign_multisig( blockstack_tx, idx, redeem_script, private_keys, hashcode=bitcoin.SIGHASH_ALL ):
    """
    Sign a p2sh multisig input.
    Return the signed transaction
    """

    # sign in the right order
    privs = dict( [(virtualchain.BitcoinPrivateKey(str(pk_str)).public_key().to_hex(), str(pk_str)) for pk_str in private_keys] )
    m, public_keys = virtualchain.parse_multisig_redeemscript( str(redeem_script) )
   
    used_keys = []
    sigs = []

    for ki in xrange(0, len(public_keys)):
        if not privs.has_key(public_keys[ki]):
            continue

        if len(used_keys) == m:
            break

        assert public_keys[ki] not in used_keys, "Tried to reuse key %s" % public_keys[ki]

        pk_str = privs[public_keys[ki]]
        used_keys.append( public_keys[ki] )

        pk_hex = virtualchain.BitcoinPrivateKey(str(pk_str)).to_hex()
        sig = bitcoin.multisign( blockstack_tx, idx, str(redeem_script), pk_hex, hashcode=hashcode )
        sigs.append( sig )

    assert len(used_keys) == m, "Missing private keys"

    return bitcoin.apply_multisignatures( blockstack_tx, idx, str(redeem_script), sigs )


def tx_sign_input( blockstack_tx, idx, private_key_info, hashcode=bitcoin.SIGHASH_ALL ):
    """
    Sign a particular input in the given transaction.
    @private_key_info can either be a private key, or it can be a dict with 'redeem_script' and 'private_keys' defined
    """
    if type(private_key_info) in [str,unicode]:
        # single private key
        return bitcoin.sign( blockstack_tx, idx, virtualchain.BitcoinPrivateKey(str(private_key_info)).to_hex(), hashcode=hashcode )

    else:
        assert type(private_key_info) in [dict]
        assert "redeem_script" in private_key_info
        assert "private_keys" in private_key_info

        redeem_script = private_key_info['redeem_script']
        private_keys = private_key_info['private_keys']
        
        assert type(redeem_script) in [str, unicode]
        redeem_script = str(redeem_script)

        # multisig
        return tx_sign_multisig( blockstack_tx, idx, str(redeem_script), private_keys, hashcode=bitcoin.SIGHASH_ALL )


def tx_sign_all_unsigned_inputs( private_key_info, unsigned_tx_hex ):
    """
    Sign all unsigned inputs in the given transaction.

    @private_key_info: either a hex private key, or a dict with 'private_keys' and 'redeem_script'
    defined as keys.
    @unsigned_hex_tx: hex transaction with unsigned inputs

    Returns: signed hex transaction
    """
    inputs, outputs, locktime, version = pybitcoin.deserialize_transaction( unsigned_tx_hex )
    tx_hex = unsigned_tx_hex
    for index in xrange(0, len(inputs)):
        if len(inputs[index]['script_sig']) == 0:

            # tx with index i signed with privkey
            tx_hex = tx_sign_input( str(unsigned_tx_hex), index, private_key_info )
            unsigned_tx_hex = tx_hex

    return tx_hex


def tx_get_address_and_utxos( private_key_info, utxo_client ):
    """
    Get information about a private key (or a set of private keys used for multisig).
    Return (payer_address, payer_utxos) on success.
    UTXOs will be in BTC, not satoshis!
    """
    if type(private_key_info) in [str, unicode]:
        _, payer_address, payer_utxos = virtualchain.analyze_private_key( str(private_key_info), utxo_client )
        return (payer_address, payer_utxos )

    elif type(private_key_info) in [dict]:
        assert 'redeem_script' in private_key_info.keys()
        assert 'private_keys' in private_key_info.keys()

        redeem_script = str(private_key_info['redeem_script'])
        addr = virtualchain.make_multisig_address( redeem_script )
        unspents = pybitcoin.get_unspents( addr, utxo_client )

        return (addr, unspents)

    else:
        raise ValueError("Invalid private key info")


def tx_make_subsidizable( blockstack_tx, fee_cb, max_fee, subsidy_key_info, utxo_client, tx_fee=0 ):
    """
    Given an unsigned serialized transaction from Blockstack, make it into a subsidized transaction 
    for the client to go sign off on.
    * Add subsidization inputs/outputs
    * Make sure the subsidy does not exceed the maximum subsidy fee
    * Sign our inputs with SIGHASH_ANYONECANPAY

    @tx_fee should be in satoshis
    Raise ValueError if there are not enough inputs to subsidize
    """
   
    # get subsidizer key info
    # private_key_obj, payer_address, payer_utxo_inputs = virtualchain.analyze_private_key(subsidy_key, utxo_client)
    payer_address, payer_utxo_inputs = tx_get_address_and_utxos( subsidy_key_info, utxo_client )
   
    tx = tx_deserialize( blockstack_tx )
    tx_inputs = tx['vin']
    tx_outputs = tx['vout']     # NOTE: will be in BTC; convert to satoshis below
    locktime = tx['locktime']
    version = tx['version']

    for i in xrange(0, len(tx_outputs)):
        tx_outputs[i]['value'] = int(tx_outputs[i]['value'] * Decimal(10**8))

    # what's the fee?  does it exceed the subsidy?
    # NOTE: units are satoshis here
    dust_fee, op_fee = fee_cb( tx_inputs, tx_outputs )

    if dust_fee is None or op_fee is None:
        log.error("Invalid fee structure")
        return None 
    
    if dust_fee + op_fee + tx_fee > max_fee:
        log.error("Op fee (%s) + dust fee (%s) exceeds maximum subsidy %s" % (dust_fee, op_fee, max_fee))
        return None
    
    else:
        if tx_fee > 0:
            log.debug("%s will subsidize %s (ops+dust) + %s (txfee) satoshi" % (get_privkey_info_address(subsidy_key_info), dust_fee + op_fee, tx_fee ))
        else:
            log.debug("%s will subsidize %s (ops+dust) satoshi" % (get_privkey_info_address(subsidy_key_info), dust_fee + op_fee ))
  
    # NOTE: pybitcoin-formatted output; values are still in satoshis!
    subsidy_output = tx_make_subsidization_output( payer_utxo_inputs, payer_address, op_fee, dust_fee + tx_fee )

    # add our inputs and output (recall: pybitcoin-formatted; so values are satoshis)
    subsidized_tx = tx_extend( blockstack_tx, payer_utxo_inputs, [subsidy_output] )
   
    # sign each of our inputs with our key, but use SIGHASH_ANYONECANPAY so the client can sign its inputs
    for i in xrange( 0, len(payer_utxo_inputs)):
        idx = i + len(tx_inputs)
        # subsidized_tx = bitcoin.sign( subsidized_tx, idx, private_key_obj.to_hex(), hashcode=bitcoin.SIGHASH_ANYONECANPAY )
        subsidized_tx = tx_sign_input( subsidized_tx, idx, subsidy_key_info, hashcode=bitcoin.SIGHASH_ANYONECANPAY )
    
    return subsidized_tx
    

def tx_get_unspents(address, utxo_client, min_confirmations=TX_MIN_CONFIRMATIONS):
    """ 
    Given an address get unspent outputs (UTXOs)
    Return array of UTXOs on success
    Raise UTXOException on error
    """

    min_confirmations = 1
    data = pybitcoin.get_unspents(address, utxo_client)

    try:
        assert type(data) == list, "No UTXO list returned"
        for d in data:
            assert type(d) == dict, "Invalid UTXO information returned"
            assert d.has_key('value'), "Missing value in UTXOs from %s" % address
    except AssertionError, ae:
        log.exception(ae)
        raise UTXOException()

    # filter minimum confirmations 
    ret = []
    for d in data:
        if not d.has_key('confirmations') or d['confirmations'] >= min_confirmations:
            ret.append(d)

    return ret

