#!/usr/bin/env python2
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
import json, re
from binascii import hexlify, unhexlify
import socket
import time

import virtualchain

from binascii import hexlify, unhexlify

from virtualchain.lib.hashing import is_hex, hex_hash160, bin_sha256
from virtualchain import tx_extend, tx_sign_input

from .b40 import is_b40, b40_to_bin
from .constants import MAGIC_BYTES, NAME_OPCODES, LENGTH_MAX_NAME, LENGTH_MAX_NAMESPACE_ID, TX_MIN_CONFIRMATIONS
from .utxo import get_unspents
from .logger import get_logger

log = get_logger('blockstack-client')

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
    return len(fqn) <= LENGTH_MAX_NAME


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


def is_valid_int(value):
    try:
        int(value)
        return True
    except ValueError:
        return False


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

    return hex_hash160(name_and_pubkey)


def hash256_trunc128(data):
    """
    Hash a string of data by taking its 256-bit sha256 and truncating it to 128 bits.
    """
    return hexlify(bin_sha256(data)[0:16])


def tx_get_address_and_utxos(private_key_info, utxo_client, address=None):
    """
    Get information about a private key (or a set of private keys used for multisig).
    Return (payer_address, payer_utxos) on success.
    UTXOs will be in BTC, not satoshis!
    """

    if private_key_info is None:
        # just go with the address
        unspents = get_unspents(address, utxo_client)
        return address, unspents

    addr = virtualchain.get_privkey_address(private_key_info)
    payer_utxos = get_unspents(addr, utxo_client)
    return addr, payer_utxos


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
    
    from .tx import deserialize_tx

    # get subsidizer key info
    payer_address, payer_utxo_inputs = tx_get_address_and_utxos(
        subsidy_key_info, utxo_client, address=subsidy_address 
    )

    # NOTE: units are in satoshis
    tx_inputs, tx_outputs = deserialize_tx(blockstack_tx)

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
            log.debug('{} will subsidize {} (ops) + {} (dust) ({}) + {} (txfee) satoshi'.format(payer_address, op_fee, dust_fee, dust_fee + op_fee, tx_fee ))
        else:
            log.debug('{} will subsidize {} (ops) + {} (dust) ({})  satoshi'.format(payer_address, op_fee, dust_fee, dust_fee + op_fee ))

    res = {
        'op_fee': op_fee,
        'dust_fee': dust_fee,
        'tx_fee': tx_fee, 
        'payer_address': payer_address,
        'payer_utxos': payer_utxo_inputs,
        'ins': tx_inputs,
        'outs': tx_outputs
    }
    return res


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
        'script': virtualchain.make_payment_script(payer_address),
        'value': virtualchain.calculate_change_amount(payer_utxo_inputs, op_fee, int(round(dust_fee)))
    }


def tx_make_subsidizable(blockstack_tx, fee_cb, max_fee, subsidy_key_info, utxo_client, tx_fee=0,
                         subsidy_address=None, add_dust_fee=True, simulated_sign = False):
    """
    Given an unsigned serialized transaction from Blockstack, make it into a subsidized transaction
    for the client to go sign off on.
    * Add subsidization inputs/outputs
    * Make sure the subsidy does not exceed the maximum subsidy fee
    * Sign our inputs with SIGHASH_ANYONECANPAY (if subsidy_key_info is not None)

    @tx_fee should be in fundamental units (i.e. satoshis)
    @simulated_sign tells us not to actually sign, but just compute expected sig lengths

    Returns the transaction; signed if subsidy_key_info is given; unsigned otherwise;
    if simulated_sign, returns a tuple (unsigned tx, expected length of encoded signatures in bytes)

    Returns None if we can't get subsidy info (or (None, None) if simulated_sign is True)
    Raise ValueError if there are not enough inputs to subsidize
    """

    from .backend.blockchain import select_utxos
  
    subsidy_info = tx_get_subsidy_info(blockstack_tx, fee_cb, max_fee, subsidy_key_info, utxo_client, tx_fee=tx_fee, subsidy_address=subsidy_address)
    if 'error' in subsidy_info:
        log.error("Failed to get subsidy info: {}".format(subsidy_info['error']))
        if simulated_sign:
            return (None, None)
        else:
            return None

    payer_utxo_inputs = subsidy_info['payer_utxos']
    payer_address = subsidy_info['payer_address']
    op_fee = subsidy_info['op_fee']
    if add_dust_fee:
        dust_fee = subsidy_info['dust_fee']
    else:
        dust_fee = 0 # NOTE: caller needed to include this in the passed tx_fee!

    tx_fee = subsidy_info['tx_fee']
    tx_inputs = subsidy_info['ins']

    def _make_subsidized_from(inputs, _tx_fee):
        # NOTE: virtualchain-formatted output; values are still in satoshis!
        subsidy_output = tx_make_subsidization_output(
            inputs, payer_address, op_fee, dust_fee + _tx_fee
        )

        # add our inputs and output (recall: virtualchain-formatted; so values are fundamental units (i.e. satoshis))
        subsidized_tx = tx_extend(blockstack_tx, inputs, [subsidy_output])
        return subsidized_tx

    subsidized_tx = None
    consumed_inputs = None

    # try to minimize the number of UTXOs we'll consume
    found = False
    log.debug("{} has {} UTXOs; will need to fund at least {} + {} + {} = {}".format(payer_address, len(payer_utxo_inputs), op_fee, dust_fee, tx_fee, op_fee + dust_fee + tx_fee))

    for i in xrange(0, len(payer_utxo_inputs)):
        consumed_inputs = payer_utxo_inputs[0:i+1]
        try:
            subsidized_tx = _make_subsidized_from(consumed_inputs, tx_fee)
            found = True
            log.debug("Consumed UTXOs 0-{}".format(i+1))
            break

        except ValueError:
            # nope
            log.debug("Not enough value in UTXOs 0-{} (tx fee so far: {})".format(i+1, tx_fee))
            continue

    if not found:
        # no solution found
        raise ValueError("Not enough value in all the UTXOs for {}".format(payer_address))

    # sign each of our inputs with our key, but use
    # SIGHASH_ANYONECANPAY so the client can sign its inputs
    log.debug("Length of unsigned subsidized = {}".format(len(subsidized_tx)))

    unsigned = subsidized_tx
    if subsidy_key_info is not None and not simulated_sign:
        for i in range(len(consumed_inputs)):
            idx = i + len(tx_inputs)
            amount = consumed_inputs[i]['value']
            out_script = consumed_inputs[i]['out_script']

            subsidized_tx = tx_sign_input(
                subsidized_tx, idx, out_script, amount, subsidy_key_info, hashcode=(virtualchain.SIGHASH_ALL | virtualchain.SIGHASH_ANYONECANPAY)
            )

    elif simulated_sign:
        return subsidized_tx, len(consumed_inputs) * virtualchain.tx_estimate_signature_len(subsidy_key_info)
    else:
        log.debug("Warning: no subsidy key given; transaction will be subsidized but not signed")

    return subsidized_tx


def tx_get_unspents(address, utxo_client, min_confirmations=None):
    """
    Given an address get unspent outputs (UTXOs)
    Return array of UTXOs on success
    Raise UTXOException on error
    """

    if utxo_client is not None:
        if min_confirmations is None:
            min_confirmations = utxo_client.min_confirmations

        if min_confirmations is None:
            min_confirmations = TX_MIN_CONFIRMATIONS
            log.debug("Defaulting to {} min confirmations".format(min_confirmations))

    if min_confirmations != TX_MIN_CONFIRMATIONS:
        log.warning("Using UTXOs with {} confirmations instead of the default {}".format(min_confirmations, TX_MIN_CONFIRMATIONS))

    data = None
    for i in xrange(0, 3):
        try:
            data = get_unspents(address, utxo_client)
            break
        except socket.error:
            log.warning("Failed to reach UTXO client; trying again...")
            time.sleep(1)

    if data is None:
        raise Exception("Failed to connect to UTXO provider")

    try:
        assert type(data) == list, "No UTXO list returned (got {})".format(type(data))
        for d in data:
            assert isinstance(d, dict), 'Invalid UTXO information returned'
            assert 'value' in d, 'Missing value in UTXOs from {}'.format(address)

    except AssertionError, ae:
        log.exception(ae)
        raise UTXOException()
    
    # filter minimum confirmations
    ret = [d for d in data if d.get('confirmations', 0) >= min_confirmations]
    
    # sort on value, largest first 
    ret.sort(lambda x, y: -1 if x['value'] > y['value'] else 0 if x['value'] == y['value'] else 1)
    return ret
