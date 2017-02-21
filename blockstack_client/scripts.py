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
from decimal import *

import bitcoin
import ecdsa
import hashlib
import pybitcoin
import virtualchain

from pybitcoin.transactions.outputs import calculate_change_amount
from virtualchain import tx_serialize, tx_deserialize, tx_script_to_asm, tx_output_parse_scriptPubKey

from .b40 import *
from .constants import MAGIC_BYTES, NAME_OPCODES, LENGTH_MAX_NAME, LENGTH_MAX_NAMESPACE_ID, TX_MIN_CONFIRMATIONS, BLOCKSTACK_TEST
from .keys import *

log = virtualchain.get_logger('blockstack-client')

class UTXOException(Exception):
    pass


def add_magic_bytes(hex_script):
    return '{}{}'.format(hexlify(MAGIC_BYTES), hex_script)


def common_checks(n):
    """
    Checks common to both name and namespace_id
    """
    if not n:
        return False

    if '+' in n or '.' in n:
        return False

    if len(n) > LENGTH_MAX_NAME:
       # too long
       return False 

    if not is_b40(n):
        return False

    return True


def is_namespace_valid(namespace_id):
    """
    Is a namespace ID valid?
    """
    if not common_checks(namespace_id):
        return False

    # validate max length
    return len(namespace_id) <= LENGTH_MAX_NAMESPACE_ID


def is_name_valid(fqn):
    """
    Is a fully-qualified name acceptable?
    Return True if so
    Return False if not
    """

    if fqn.count('.') != 1:
        return False

    name, namespace_id = fqn.split('.')

    if not common_checks(name):
        return False

    if not is_namespace_valid(namespace_id):
        return False

    # validate max length
    return len(fqn) < LENGTH_MAX_NAME


def is_valid_hash(value):
    """
    Is this string a valid 32-byte hash?
    """
    if not isinstance(value, (str, unicode)):
        return False

    strvalue = str(value)

    if re.match(r'^[a-fA-F0-9]+$', strvalue) is None:
        return False

    return len(strvalue) == 64


def blockstack_script_to_hex(script):
    """ Parse the readable version of a script, return the hex version.
    """
    hex_script = ''
    parts = script.split(' ')
    for part in parts:
        if part in NAME_OPCODES:
            try:
                hex_script += '{:02x}'.format(ord(NAME_OPCODES[part]))
            except:
                raise Exception('Invalid opcode: {}'.format(part))
        elif part.startswith('0x'):
            # literal hex string
            hex_script += part[2:]
        elif is_valid_int(part):
            hex_part = '{:02x}'.format(int(part))
            if len(hex_part) % 2 != 0:
                hex_part = '0' + hex_part
            hex_script += hex_part
        elif is_hex(part) and len(part) % 2 == 0:
            hex_script += part
        else:
            raise ValueError(
                'Invalid script (at {}), contains invalid characters: {}'.format(part, script))

    if len(hex_script) % 2 != 0:
        raise ValueError('Invalid script: must have an even number of chars (got {}).'.format(hex_script))

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


def hash256_trunc128(data):
    """
    Hash a string of data by taking its 256-bit sha256 and truncating it to 128 bits.
    """
    return hexlify(pybitcoin.hash.bin_sha256(data)[0:16])


def tx_output_is_op_return(output):
    """
    Is an output's script an OP_RETURN script?
    """
    return int(output['script_hex'][0:2], 16) == pybitcoin.opcodes.OP_RETURN


def tx_extend(partial_tx_hex, new_inputs, new_outputs):
    """
    Given an unsigned serialized transaction, add more inputs and outputs to it.
    @new_inputs and @new_outputs will be pybitcoin-formatted:
    * new_inputs[i] will have {'output_index': ..., 'script_hex': ..., 'transaction_hash': ...}
    * new_outputs[i] will have {'script_hex': ..., 'value': ... (in satoshis!)}
    """

    # recover tx
    tx = tx_deserialize(partial_tx_hex)

    tx_inputs, tx_outputs = tx['vin'], tx['vout']
    locktime, version = tx['locktime'], tx['version']

    # format new inputs
    btc_new_inputs = []
    for inp in new_inputs:
        new_inp = {
            'vout': inp['output_index'],
            'txid': inp['transaction_hash'],
            'scriptSig': {
                'asm': tx_script_to_asm(inp['script_hex']),
                'hex': inp['script_hex']
            }
        }

        btc_new_inputs.append(new_inp)

    # format new outputs
    btc_new_outputs = []
    for i, new_output in enumerate(new_outputs):
        new_outp = {
            'n': i + len(tx_outputs),
            'value': Decimal(new_output['value']) / Decimal(10 ** 8),
            'scriptPubKey': tx_output_parse_scriptPubKey(new_output['script_hex']),
            'script_hex': new_output['script_hex']
        }

        btc_new_outputs.append(new_outp)

    new_tx = {
        'vin': tx_inputs + btc_new_inputs,
        'vout': tx_outputs + btc_new_outputs,
        'locktime': locktime,
        'version': version
    }

    # new tx
    new_unsigned_tx = tx_serialize(new_tx)

    return new_unsigned_tx


def tx_make_subsidization_output(payer_utxo_inputs, payer_address, op_fee, dust_fee):
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
        'script_hex': virtualchain.make_payment_script(payer_address),
        'value': calculate_change_amount(payer_utxo_inputs, op_fee, int(round(dust_fee)))
    }


def tx_make_input_signature(tx, idx, script, privkey_str, hashcode):
    """
    Sign a single input of a transaction, given the serialized tx,
    the input index, the output's scriptPubkey, and the hashcode.

    privkey_str must be a hex-encoded private key

    TODO: move to virtualchain

    Return the hex signature.
    """
    pk = virtualchain.BitcoinPrivateKey(str(privkey_str))
    pubk = pk.public_key()
    
    priv = pk.to_hex()
    pub = pubk.to_hex()
    addr = pubk.address()

    signing_tx = bitcoin.signature_form(tx, idx, script, hashcode)
    txhash = bitcoin.bin_txhash(signing_tx, hashcode)

    # sign using uncompressed private key
    pk_uncompressed_hex, pubk_uncompressed_hex = get_uncompressed_private_and_public_keys(priv)
    sigb64 = sign_digest( txhash.encode('hex'), priv )

    # sanity check 
    assert verify_digest( txhash.encode('hex'), pubk_uncompressed_hex, sigb64 )

    sig_r, sig_s = decode_signature(sigb64)
    sig_bin = ecdsa.util.sigencode_der( sig_r, sig_s, ecdsa.SECP256k1.order )
    sig = sig_bin.encode('hex') + bitcoin.encode(hashcode, 16, 2)
    return sig


def tx_sign_multisig(tx, idx, redeem_script, private_keys, hashcode=bitcoin.SIGHASH_ALL):
    """
    Sign a p2sh multisig input.
    Return the signed transaction

    TODO: move to virtualchain
    """
    # sign in the right order.  map all possible public keys to their private key 
    privs = {}
    for pk in private_keys:
        pubk = keylib.ECPrivateKey(pk).public_key().to_hex()

        compressed_pubkey = keylib.key_formatting.compress(pubk)
        uncompressed_pubkey = keylib.key_formatting.decompress(pubk)

        privs[compressed_pubkey] = pk
        privs[uncompressed_pubkey] = pk

    m, public_keys = virtualchain.parse_multisig_redeemscript(str(redeem_script))

    used_keys, sigs = [], []
    for public_key in public_keys:
        if public_key not in privs:
            continue

        if len(used_keys) == m:
            break

        assert public_key not in used_keys, 'Tried to reuse key {}'.format(public_key)

        pk_str = privs[public_key]
        used_keys.append(public_key)

        sig = tx_make_input_signature(tx, idx, redeem_script, pk_str, hashcode)
        sigs.append(sig)

    assert len(used_keys) == m, 'Missing private keys (used {}, required {})'.format(len(used_keys), m)
    return bitcoin.apply_multisignatures(tx, idx, str(redeem_script), sigs)


def tx_sign_singlesig(tx, idx, private_key_info, hashcode=bitcoin.SIGHASH_ALL):
    """
    Sign a p2pkh input
    Return the signed transaction

    TODO: move to virtualchain

    NOTE: implemented here instead of bitcoin, since bitcoin.sign() can cause a stack overflow
    while converting the private key to a public key.
    """
    pk = virtualchain.BitcoinPrivateKey(str(private_key_info))
    pubk = pk.public_key()

    pub = pubk.to_hex()
    addr = pubk.address()

    script = virtualchain.make_payment_script(addr)
    sig = tx_make_input_signature(tx, idx, script, private_key_info, hashcode)

    txobj = bitcoin.deserialize(str(tx))
    txobj['ins'][idx]['script'] = bitcoin.serialize_script([sig, pub])
    return bitcoin.serialize(txobj)


def tx_sign_input(blockstack_tx, idx, private_key_info, hashcode=bitcoin.SIGHASH_ALL):
    """
    Sign a particular input in the given transaction.
    @private_key_info can either be a private key, or it can be a dict with 'redeem_script' and 'private_keys' defined
    """
    if is_singlesig(private_key_info):
        # single private key
        return tx_sign_singlesig(blockstack_tx, idx, private_key_info, hashcode=hashcode)

    elif is_multisig(private_key_info):

        redeem_script = private_key_info['redeem_script']
        private_keys = private_key_info['private_keys']

        redeem_script = str(redeem_script)

        # multisig
        return tx_sign_multisig(blockstack_tx, idx, redeem_script, private_keys, hashcode=bitcoin.SIGHASH_ALL)

    else:
        if BLOCKSTACK_TEST:
            log.debug("Invalid private key info: {}".format(private_key_info))

        raise ValueError("Invalid private key info")


def tx_sign_all_unsigned_inputs(private_key_info, unsigned_tx_hex):
    """
    Sign all unsigned inputs in the given transaction.

    @private_key_info: either a hex private key, or a dict with 'private_keys' and 'redeem_script'
    defined as keys.
    @unsigned_hex_tx: hex transaction with unsigned inputs

    Returns: signed hex transaction
    """
    inputs, outputs, locktime, version = pybitcoin.deserialize_transaction(unsigned_tx_hex)
    tx_hex = unsigned_tx_hex
    for i, input in enumerate(inputs):
        if input['script_sig']:
            continue

        # tx with index i signed with privkey
        tx_hex = tx_sign_input(str(unsigned_tx_hex), i, private_key_info)
        unsigned_tx_hex = tx_hex

    return tx_hex


def tx_get_address_and_utxos(private_key_info, utxo_client, address=None):
    """
    Get information about a private key (or a set of private keys used for multisig).
    Return (payer_address, payer_utxos) on success.
    UTXOs will be in BTC, not satoshis!
    """

    if private_key_info is None:
        # just go with the address 
        unspents = pybitcoin.get_unspents(address, utxo_client)
        return addr, unspents 

    if is_singlesig(private_key_info):
        _, payer_address, payer_utxos = virtualchain.analyze_private_key(
            str(private_key_info), utxo_client
        )
        return payer_address, payer_utxos

    if is_multisig(private_key_info):
        redeem_script = str(private_key_info['redeem_script'])
        addr = virtualchain.make_multisig_address(redeem_script)
        unspents = pybitcoin.get_unspents(addr, utxo_client)

        return addr, unspents

    raise ValueError('Invalid private key info')


def tx_get_subsidy_info(blockstack_tx, fee_cb, max_fee, subsidy_key_info, utxo_client, subsidy_address=None, tx_fee=0):
    """
    Get the requisite information to subsidize the given transaction:
    * parse the given transaction (tx)
    * calculate the operation-specific fee (op_fee)
    * calculate the dust fee (dust_fee)
    * calculate the transaction fee (tx_fee)
    * calculate the paying key's UTXOs (payer_utxos) 
    * calculate the paying key's address (payer_address)

    All fees will be in satoshis

    Return a dict with the above
    Return {'error': ...} on error
    """

    # get subsidizer key info
    payer_address, payer_utxo_inputs = tx_get_address_and_utxos(
        subsidy_key_info, utxo_client, address=subsidy_address 
    )

    tx = tx_deserialize(blockstack_tx)

    # NOTE: will be in BTC; convert to satoshis below
    tx_inputs, tx_outputs = tx['vin'], tx['vout']

    for tx_output in tx_outputs:
        tx_output['value'] = int(tx_output['value'] * Decimal(10 ** 8))

    # what's the fee?  does it exceed the subsidy?
    # NOTE: units are satoshis here
    dust_fee, op_fee = fee_cb(tx_inputs, tx_outputs)

    if dust_fee is None or op_fee is None:
        log.error('Invalid fee structure')
        return {'error': 'Invalid fee structure'}

    if dust_fee + op_fee + tx_fee > max_fee:
        log.error('Op fee ({}) + dust fee ({}) exceeds maximum subsidy {}'.format(dust_fee, op_fee, max_fee))
        return {'error': 'Fee exceeds maximum subsidy'}

    else:
        if tx_fee > 0:
            log.debug('{} will subsidize {} (ops+dust) + {} (txfee) satoshi'.format(payer_address, dust_fee + op_fee, tx_fee ))
        else:
            log.debug('{} will subsidize {} (ops+dust) satoshi'.format(payer_address, dust_fee + op_fee ))

    res = {
        'op_fee': op_fee,
        'dust_fee': dust_fee,
        'tx_fee': tx_fee, 
        'payer_address': payer_address,
        'payer_utxos': payer_utxo_inputs,
        'tx': tx
    }
    return res


def tx_make_subsidizable(blockstack_tx, fee_cb, max_fee, subsidy_key_info, utxo_client, tx_fee=0, subsidy_address=None):
    """
    Given an unsigned serialized transaction from Blockstack, make it into a subsidized transaction
    for the client to go sign off on.
    * Add subsidization inputs/outputs
    * Make sure the subsidy does not exceed the maximum subsidy fee
    * Sign our inputs with SIGHASH_ANYONECANPAY (if subsidy_key_info is not None)

    @tx_fee should be in satoshis

    Returns the transaction; signed if subsidy_key_info is given; unsigned otherwise
    Returns None if we can't get subsidy info
    Raise ValueError if there are not enough inputs to subsidize
    """
  
    subsidy_info = tx_get_subsidy_info(blockstack_tx, fee_cb, max_fee, subsidy_key_info, utxo_client, tx_fee=tx_fee, subsidy_address=subsidy_address)
    if 'error' in subsidy_info:
        log.error("Failed to get subsidy info: {}".format(subsidy_info['error']))
        return None

    payer_utxo_inputs = subsidy_info['payer_utxos']
    payer_address = subsidy_info['payer_address']
    op_fee = subsidy_info['op_fee']
    dust_fee = subsidy_info['dust_fee']
    tx_fee = subsidy_info['tx_fee']
    tx = subsidy_info['tx']
    tx_inputs = tx['vin']

    # NOTE: pybitcoin-formatted output; values are still in satoshis!
    subsidy_output = tx_make_subsidization_output(
        payer_utxo_inputs, payer_address, op_fee, dust_fee + tx_fee
    )

    # add our inputs and output (recall: pybitcoin-formatted; so values are satoshis)
    subsidized_tx = tx_extend(blockstack_tx, payer_utxo_inputs, [subsidy_output])

    # sign each of our inputs with our key, but use
    # SIGHASH_ANYONECANPAY so the client can sign its inputs
    if subsidy_key_info is not None:
        for i in range(len(payer_utxo_inputs)):
            idx = i + len(tx_inputs)
            subsidized_tx = tx_sign_input(
                subsidized_tx, idx, subsidy_key_info, hashcode=bitcoin.SIGHASH_ANYONECANPAY
            )
    
    else:
        log.debug("Warning: no subsidy key given; transaction will be subsidized but not signed")

    return subsidized_tx


def tx_get_unspents(address, utxo_client, min_confirmations=TX_MIN_CONFIRMATIONS):
    """
    Given an address get unspent outputs (UTXOs)
    Return array of UTXOs on success
    Raise UTXOException on error
    """

    if min_confirmations is None:
        min_confirmations = TX_MIN_CONFIRMATIONS

    if min_confirmations != TX_MIN_CONFIRMATIONS:
        log.warning("Using UTXOs with {} confirmations instead of the default {}".format(min_confirmations, TX_MIN_CONFIRMATIONS))

    data = pybitcoin.get_unspents(address, utxo_client)

    try:
        assert type(data) == list, "No UTXO list returned"
        for d in data:
            assert isinstance(d, dict), 'Invalid UTXO information returned'
            assert 'value' in d, 'Missing value in UTXOs from {}'.format(address)

    except AssertionError, ae:
        log.exception(ae)
        raise UTXOException()

    # filter minimum confirmations
    return [d for d in data if d.get('confirmations', 0) >= min_confirmations]
