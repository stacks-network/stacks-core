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

import os
import sys
import json
import time
import random
import keylib

# Hack around absolute paths
current_dir = os.path.abspath(os.path.dirname(__file__))
parent_dir = os.path.abspath(current_dir + "/../")

from .queue import in_queue, queue_append, queue_findone, extract_entry

from .blockchain import get_tx_confirmations
from .blockchain import get_utxos 
from .blockchain import get_block_height

from ..config import DEFAULT_QUEUE_PATH, CONFIG_PATH, get_utxo_provider_client, get_tx_broadcaster
from ..constants import (
    BLOCKSTACK_TEST, BLOCKSTACK_DEBUG, TX_MIN_CONFIRMATIONS, BLOCKSTACK_DRY_RUN,
    PREORDER_CONFIRMATIONS, RPC_MAX_ZONEFILE_LEN, APPROX_TX_IN_P2SH_LEN, APPROX_TX_OUT_P2SH_LEN,
    APPROX_TX_IN_P2PKH_LEN, APPROX_TX_OUT_P2PKH_LEN, APPROX_TX_OVERHEAD_LEN, NAMESPACE_VERSION_PAY_TO_CREATOR,
    BLOCKSTACK_BURN_ADDRESS
)

from ..proxy import get_default_proxy
from ..proxy import getinfo as blockstack_getinfo
from ..proxy import get_name_cost as blockstack_get_name_cost
from ..proxy import get_namespace_blockchain_record as blockstack_get_namespace_blockchain_record

from ..tx import sign_tx, sign_and_broadcast_tx, deserialize_tx, preorder_tx, register_tx, update_tx, transfer_tx, revoke_tx, \
        namespace_preorder_tx, namespace_reveal_tx, namespace_ready_tx, announce_tx, name_import_tx

from ..scripts import tx_make_subsidizable, tx_get_unspents
from ..storage import get_blockchain_compat_hash, put_announcement, get_zonefile_data_hash

from ..operations import fees_update, fees_transfer, fees_revoke, fees_registration, fees_preorder, \
        fees_namespace_preorder, fees_namespace_reveal, fees_namespace_ready, fees_name_import, fees_announce

from .safety import (
    check_preorder, check_register, check_update, check_transfer, check_renewal,
    check_revoke, check_name_import, check_namespace_preorder, check_namespace_reveal, check_namespace_ready)

from ..logger import get_logger
from ..utxo import get_unspents

import virtualchain
from virtualchain.lib.ecdsalib import ecdsa_private_key

from ..constants import get_secret
from .crypto.utils import aes_decrypt
from binascii import hexlify

log = get_logger("blockstack-client")


class UTXOWrapper(object):
    """
    Override what a UTXO client sees as unspent outputs.
    Also, cache unspents we fetch upstream.
    """
    def __init__(self, utxo_client):
        assert not isinstance(utxo_client, UTXOWrapper)
        self.utxos = {}
        self.utxo_client = utxo_client


    def add_unspents( self, addr, unspents ):
        # sanity check...
        for unspent in unspents:
            assert unspent.has_key('outpoint')
            assert unspent['outpoint'].has_key('hash')
            assert unspent['outpoint'].has_key('index')

        self.utxos[addr] = unspents


    def get_unspents( self, addr ):
        if self.utxos.has_key(addr):
            return self.utxos[addr]

        unspents = get_unspents(addr, self.utxo_client)
        return unspents


    def __getattr__(self, name):
        if name == 'get_unspents':
            return self.get_unspents

        else:
            return getattr(self.utxo_client, name)


def estimate_dust_fee( tx, fee_estimator ):
    """
    Estimate the dust fee of an operation.
    fee_estimator is a callable, and is one of the operation's get_fees() methods.
    Return the number of satoshis on success
    Return None on error
    """
    tx_inputs, tx_outputs = deserialize_tx(tx)
    dust_fee, op_fee = fee_estimator( tx_inputs, tx_outputs )
    return dust_fee


def estimate_input_length( privkey_info ):
    """
    Estimate the length of a missing input
    of a transaction
    """
    siglen = virtualchain.tx_estimate_signature_len(privkey_info)
    outpoint_hash_len = 32  # length of sha256
    outpoint_index_len = 8  # 8-byte integer
    encoding_pad = 6        # number of bytes spent to encode fields
    return siglen + outpoint_hash_len + outpoint_index_len + encoding_pad


def make_cheapest_nameop( opcode, utxo_client, payment_address, payment_utxos, *tx_args, **tx_kw ):
    """
    Make the cheapest transaction possible.
    @payment_utxos should be sorted by decreasing value.

    Returns (unsigned tx hex string, number of UTXOs consumed)
    """
    unsigned_tx = None
    tx_builders = {
        'NAMESPACE_PREORDER': namespace_preorder_tx,
        'NAMESPACE_REVEAL': namespace_reveal_tx,
        'NAMESPACE_READY': namespace_ready_tx,
        'NAME_IMPORT': name_import_tx,
        'NAME_PREORDER': preorder_tx,
        'NAME_REGISTRATION': register_tx,
        'NAME_UPDATE': update_tx,
        'NAME_TRANSFER': transfer_tx,
        'NAME_RENEWAL': register_tx,
        'NAME_REVOKE': revoke_tx,
        'ANNOUNCE': announce_tx,
    }

    if opcode not in tx_builders.keys():
        raise ValueError("Invalid opcode {}".format(opcode))

    tx_builder = tx_builders[opcode]

    # estimate the cheapest transaction by selecting inputs in decreasing value
    # NOTE: payment_utxos should already be sorted in decreasing value

    if len(payment_utxos) < 1:
        raise ValueError("No UTXOs for address {}".format(payment_address))

    for i in xrange(1, len(payment_utxos)+1):
        try:
            log.debug("Try building a {} with inputs 0-{} of {}".format(opcode, i, payment_address))
            utxo_client = build_utxo_client(utxo_client, address=payment_address, utxos=payment_utxos[0:i])

            unsigned_tx = tx_builder(*tx_args, **tx_kw)
            assert unsigned_tx

            log.debug("Funded {} with inputs 0-{} of {}".format(opcode, i, payment_address))
            break
        except (AssertionError, ValueError) as e:
            if BLOCKSTACK_DEBUG:
                log.exception(e)

            pass

    return unsigned_tx, i


def make_cheapest_namespace_preorder( namespace_id, payment_address, reveal_address, cost, consensus_hash, utxo_client, payment_utxos, tx_fee=0):
    """
    Given namespace preorder info, make the cheapest possible namespace preorder transaction.
    @payment_utxos should be sorted by decreasing value
    Return the unsigned tx on success.
    Return None on error
    """
    return make_cheapest_nameop('NAMESPACE_PREORDER', utxo_client, payment_address, payment_utxos, namespace_id, reveal_address, cost, consensus_hash, payment_address, utxo_client, tx_fee=tx_fee )


def make_cheapest_namespace_reveal( namespace_id, version_bits, reveal_addr, lifetime, coeff, base_cost, bucket_exponents, nonalpha_discount, no_vowel_discount, preorder_addr, utxo_client, payment_utxos, tx_fee=0):
    """
    Given namespace reveal info, make the cheapest possible namespace reveal transaction.
    @payment_utxos should be sorted by decreasing value
    Return the unsigned tx on success
    Return None on error
    """
    return make_cheapest_nameop('NAMESPACE_REVEAL', utxo_client, preorder_addr, payment_utxos, namespace_id, version_bits, reveal_addr, lifetime, coeff, base_cost, bucket_exponents,
            nonalpha_discount, no_vowel_discount, preorder_addr, utxo_client, tx_fee=tx_fee)


def make_cheapest_namespace_ready( namespace_id, reveal_addr, utxo_client, payment_utxos, tx_fee=0):
    """
    Given namespace ready info, make the cheapest possible namespace ready transaction
    @payment_utxos should be sorted by decreasing value
    Return the unsigned tx on success
    Return None on error
    """
    return make_cheapest_nameop('NAMESPACE_READY', utxo_client, reveal_addr, payment_utxos, namespace_id, reveal_addr, utxo_client, tx_fee=tx_fee)


def make_cheapest_name_import( name, recipient_address, zonefile_hash, reveal_address, utxo_client, payment_utxos, tx_fee=0):
    """
    Given name import info, make the cheapest possible name import transaction
    @payment_utxos should be sorted by decreasing value
    Return the unsigned tx on success
    Return None on error
    """
    return make_cheapest_nameop("NAME_IMPORT", utxo_client, reveal_address, payment_utxos, name, recipient_address, zonefile_hash, reveal_address, utxo_client, tx_fee=tx_fee )


def make_cheapest_name_preorder( name, payment_address, owner_address, burn_address,
                                 cost, consensus_hash, utxo_client, payment_utxos, tx_fee=0,
                                 dust_included = False ):
    """
    Given name preorder info, make the cheapest possible name preorder transaction.
    @payment_utxos should be sorted by decreasing value
    Return the unsigned tx on success.
    Return None on error
    """
    return make_cheapest_nameop('NAME_PREORDER', utxo_client, payment_address, payment_utxos,
                                name, payment_address, owner_address, burn_address, cost,
                                consensus_hash, utxo_client, tx_fee=tx_fee, dust_included = dust_included )


def make_cheapest_name_registration( name, payment_address, owner_address, utxo_client,
                                     payment_utxos, zonefile_hash=None, tx_fee=0,
                                     subsidize=False, dust_included = False ):
    """
    Given name registration info, make the cheapest possible name register transaction
    @payment_utxos should be sorted by decreasing value
    Return the unsigned tx on success.
    Return None on error
    """
    return make_cheapest_nameop('NAME_REGISTRATION', utxo_client, payment_address,
                                payment_utxos, name, payment_address, owner_address, utxo_client,
                                zonefile_hash=zonefile_hash, subsidize=subsidize, tx_fee=tx_fee,
                                dust_included = dust_included)


def make_cheapest_name_renewal( name, owner_address, renewal_fee, utxo_client, payment_address,
                                payment_utxos, burn_address=None, recipient_addr=None,
                                zonefile_hash=None, tx_fee=0, subsidize=False, dust_included = False ):
    """
    Given name renewal info, make the cheapest possible name renewal transaction
    @payment_utxos should be sorted by decreasing value
    Return the unsigned tx on success
    Return None on error
    """
    # NOTE: for name renewal, the owner address is both the "preorder" and "register" address.
    # the payment address and UTXOs given here are for the address that will subsidize the operation.
    if recipient_addr is None:
        recipient_addr = owner_address

    return make_cheapest_nameop('NAME_RENEWAL', utxo_client, payment_address, payment_utxos,
                                name, owner_address, recipient_addr, utxo_client, burn_address=burn_address,
                                renewal_fee=renewal_fee, zonefile_hash=zonefile_hash, subsidize=subsidize,
                                tx_fee=tx_fee, dust_included = dust_included)


def make_cheapest_name_update( name, data_hash, consensus_hash, owner_address, utxo_client,
                               payment_address, payment_utxos, tx_fee=0, subsidize=False,
                               dust_included = False ):
    """
    Given name update info, make the cheapest possible name update transaction
    @payment_utxos should be sorted by decreasing value
    Return the unsigned tx on success
    Return None on error
    """
    return make_cheapest_nameop('NAME_UPDATE', utxo_client, payment_address, payment_utxos,
                                name, data_hash, consensus_hash, owner_address, utxo_client,
                                subsidize=subsidize, tx_fee=tx_fee, dust_included = dust_included )


def make_cheapest_name_transfer( name, recipient_address, keepdata, consensus_hash,
                                 owner_address, utxo_client, payment_address, payment_utxos,
                                 tx_fee=0, subsidize=False, dust_included = False):
    """
    Given name transfer info, make the cheapest possible name transfer transaction
    @payment_utxos should be sorted by decreasing value
    Return the unsigned tx on success
    Return None on error
    """
    return make_cheapest_nameop('NAME_TRANSFER', utxo_client, payment_address, payment_utxos,
                                name, recipient_address, keepdata, consensus_hash, owner_address,
                                utxo_client, subsidize=subsidize, tx_fee=tx_fee, dust_included = dust_included )


def make_cheapest_name_revoke( name, owner_address, utxo_client, payment_address, payment_utxos, tx_fee=0, subsidize=False):
    """
    Given name revoke info, make the cheapest possible name revoke transaction
    @payment_utxos should be sorted by decreasing value
    Return the unsigned tx on success
    Return None on error 
    """
    return make_cheapest_nameop('NAME_REVOKE', utxo_client, payment_address, payment_utxos, name, owner_address, utxo_client, subsidize=subsidize, tx_fee=tx_fee )


def make_cheapest_announce( announce_hash, sender_address, utxo_client, payment_utxos, tx_fee=0, subsidize=False):
    """
    Given announce info, make the cheapest possible announce transaction
    @payment_utxos should be sorted by decreasing value
    Return the unsigned tx on success
    Return None on error
    """
    return make_cheapest_nameop('ANNOUNCE', utxo_client, sender_address, payment_utxos, announce_hash, sender_address, utxo_client, subsidize=subsidize, tx_fee=tx_fee )


def get_estimated_signed_subsidized(unsigned_tx, op_fees, max_fee, payment_privkey_info,
                                    utxo_client, owner_privkey_info, tx_fee_per_byte):

    # This code tries to generate a subsidized transaction with enough payment inputs
    # to pay for the transaction *once* the transaction has been signed. Because it doesn't
    # sign the inputs before adding them, it loops to try to add more inputs if the signatures
    # change the tx_fee.
    # Ultimately, a faster implementation would figure out how much each signature adds to the
    # tx_fee without needing to continuously sign the tx, but for now, this is what we'll do.

    MAX_RETRIES = 10
    tx_fee_guess = 0
    owner_address = virtualchain.get_privkey_address(owner_privkey_info)

    try:
        owner_utxos = tx_get_unspents(owner_address, utxo_client)
    except Exception as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        log.error("Failed to get inputs for owner address {}".format(owner_address))
        raise

    for _ in range(MAX_RETRIES):
        subsidized_tx, sign_lens = tx_make_subsidizable(unsigned_tx, op_fees, max_fee, payment_privkey_info,
                                                        utxo_client, tx_fee = tx_fee_guess,
                                                        simulated_sign = True)
        assert subsidized_tx is not None
        pad_length = sign_lens + virtualchain.tx_estimate_signature_len(owner_privkey_info) * len(owner_utxos)
        padded_tx = subsidized_tx + ("00" * pad_length)

        tx_fee = (len(padded_tx) * tx_fee_per_byte)/2
        if tx_fee <= tx_fee_guess:
            log.debug("Estimated TX Length and fee per byte: {} + {}".format(len(padded_tx)/2, tx_fee_per_byte))
            return padded_tx

        tx_fee_guess = tx_fee

    raise Exception("Failed to cover the tx_fee in getting estimated subsidized tx")


def estimate_preorder_tx_fee( name, name_cost, payment_privkey_info, owner_privkey_info, tx_fee_per_byte, utxo_client, 
        owner_address=None, payment_utxos=None, payment_privkey_params=(None, None), config_path=CONFIG_PATH, include_dust=False ):

    """
    Estimate the transaction fee of a preorder.
    Optionally include the dust fees as well.
    Return the number of satoshis on success
    Return None on error
    """

    if not owner_privkey_info:
        assert owner_address, 'Need owner private key or address'
    else:
        owner_address = virtualchain.get_privkey_address(owner_privkey_info)

    payment_addr = virtualchain.get_privkey_address(payment_privkey_info)

    utxo_client = build_utxo_client(utxo_client, address=payment_addr, utxos=payment_utxos)

    try:
        payment_utxos = tx_get_unspents(payment_addr, utxo_client)
    except Exception as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        log.error("Failed to get inputs for {}".format(payment_addr))
        return None

    fake_consensus_hash = 'd4049672223f42aac2855d2fbf2f38f0'
    signed_tx = None

    try:
        try:
            unsigned_tx, n_inputs = make_cheapest_name_preorder(
                name, payment_addr, owner_address, BLOCKSTACK_BURN_ADDRESS, name_cost, fake_consensus_hash,
                utxo_client, payment_utxos)

            assert unsigned_tx

            pad_len = n_inputs * virtualchain.tx_estimate_signature_len(payment_privkey_info)
            signed_tx = unsigned_tx + ("00" * pad_len)

            assert signed_tx is not None

        except AssertionError as e:
            # unfunded payment addr
            log.warning("Insufficient funds in {} for NAME_PREORDER; estimating instead".format(payment_addr))
            unsigned_tx = preorder_tx( name, payment_addr, owner_address, BLOCKSTACK_BURN_ADDRESS, name_cost, fake_consensus_hash, utxo_client, safety=False, subsidize=True )
            assert unsigned_tx

            pad_len = estimate_input_length(payment_privkey_info)
            signed_tx = unsigned_tx + "00" * pad_len

    except ValueError as ve:
        if BLOCKSTACK_TEST:
            log.exception(ve)

        log.error("Failed to create preorder transaction (ValueError)")
        return None

    except Exception as e:
        log.exception(e)
        return None

    tx_fee = (len(signed_tx) * tx_fee_per_byte) / 2
    log.debug("preorder tx %s bytes, %s satoshis" % (len(signed_tx)/2, int(tx_fee)))
    log.debug("signed subsidized tx: {}".format(signed_tx))

    if include_dust:
        dust_fee = estimate_dust_fee( signed_tx, fees_preorder )
        assert dust_fee is not None
        log.debug("Additional preorder dust fee: %s" % dust_fee)
        tx_fee += dust_fee

    return tx_fee


def estimate_register_tx_fee( name, payment_privkey_info, owner_privkey_info, tx_fee_per_byte, utxo_client, owner_address=None, zonefile_hash=None, payment_utxos=None, config_path=CONFIG_PATH, include_dust=False ):
    """
    Estimate the transaction fee of a register.
    Optionally include the dust fees as well.
    Return the number of satoshis on success
    Return None on error
    """

    owner_addr = owner_address
    
    if not owner_privkey_info:
        assert owner_address, 'Need either owner address or owner privkey info'
    else:
        owner_addr = virtualchain.get_privkey_address(owner_privkey_info)

    payment_addr = virtualchain.get_privkey_address(payment_privkey_info)

    utxo_client = build_utxo_client(utxo_client, address=payment_addr, utxos=payment_utxos)

    try:
        payment_utxos = tx_get_unspents(payment_addr, utxo_client)
    except Exception as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        log.error("Failed to get inputs for {}".format(payment_addr))
        return None

    signed_tx = None
    try:
        try:
            unsigned_tx, n_inputs = make_cheapest_name_registration(
                name, payment_addr, owner_addr, utxo_client,
                payment_utxos, zonefile_hash=zonefile_hash)

            log.debug("Unsigned tx: {}".format(unsigned_tx))
            assert unsigned_tx

            pad_len = n_inputs * virtualchain.tx_estimate_signature_len(payment_privkey_info)
            signed_tx = unsigned_tx + ("00" * pad_len)

            assert signed_tx is not None

        except AssertionError as e:
            # no UTXOs for this owner address.  Try again and add padding for one
            log.warning("No UTXOs for {}; estimating...".format(payment_addr))
            unsigned_tx = register_tx( name, payment_addr, owner_addr, utxo_client, subsidize=True, safety=False )
            assert unsigned_tx

            pad_len = estimate_input_length(payment_privkey_info)
            signed_tx = unsigned_tx + "00" * pad_len

    except ValueError as ve:
        if BLOCKSTACK_TEST:
            log.exception(ve)

        log.error("Failed to create register transaction (ValueError)")
        return None

    except Exception as e:
        log.exception(e)
        return None 

    tx_fee = (len(signed_tx) * tx_fee_per_byte) / 2

    log.debug("register tx %s bytes, %s satoshis txfee" % (len(signed_tx)/2, int(tx_fee)))
    log.debug("signed subsidized tx: {}".format(signed_tx))

    if include_dust:
        dust_fee = estimate_dust_fee( signed_tx, fees_registration )
        assert dust_fee is not None
        log.debug("Additional register dust fee: %s" % dust_fee)
        tx_fee += dust_fee

    return tx_fee


def estimate_renewal_tx_fee( name, renewal_fee, payment_privkey_info, owner_privkey_info, tx_fee_per_byte, utxo_client, 
                             zonefile_hash=None, owner_utxos=None, payment_utxos=None, config_path=CONFIG_PATH, include_dust=False ):
    """
    Estimate the transaction fee of a renewal.
    Optionally include the dust fees as well.
    Return the number of satoshis on success
    Return None on error
    """

    payment_address = virtualchain.get_privkey_address( payment_privkey_info )
    owner_address = virtualchain.get_privkey_address( owner_privkey_info )

    utxo_client = build_utxo_client(utxo_client, address=owner_address, utxos=owner_utxos)
    utxo_client = build_utxo_client(utxo_client, address=payment_address, utxos=payment_utxos)

    try:
        payment_utxos = tx_get_unspents(payment_address, utxo_client)
        owner_utxos = tx_get_unspents(owner_address, utxo_client)
    except Exception as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        log.error("Failed to get inputs for {}".format(owner_address))
        return None

    signed_subsidized_tx = None

    try:
        try:
            unsigned_tx, num_utxos = make_cheapest_name_renewal(name, owner_address, renewal_fee, utxo_client, payment_address, payment_utxos, burn_address=BLOCKSTACK_BURN_ADDRESS, zonefile_hash=zonefile_hash)
            assert unsigned_tx

            signed_subsidized_tx = get_estimated_signed_subsidized(unsigned_tx, fees_registration, 21 * 10**14,
                                                                   payment_privkey_info, utxo_client,
                                                                   owner_privkey_info, tx_fee_per_byte)
            assert signed_subsidized_tx

        except AssertionError as ae:
            # no UTXOs for this owner address.  Try again and add padding for one
            log.warning("No UTXOs for {} and/or {}; estimating...".format(owner_address, payment_address))
            unsigned_tx = register_tx( name, owner_address, owner_address, utxo_client, renewal_fee=renewal_fee, subsidize=True, safety=False )
            assert unsigned_tx

            pad_len = estimate_input_length(payment_privkey_info) + estimate_input_length(owner_privkey_info)
            signed_subsidized_tx = unsigned_tx + "00" * pad_len

    except ValueError as ve:
        if BLOCKSTACK_TEST:
            log.exception(ve)
        
        log.error("Unable to create renewal transaction")
        return None

    except Exception as e:
        log.exception(e)
        return None

    tx_fee = (len(signed_subsidized_tx) * tx_fee_per_byte) / 2

    log.debug("renewal tx %s bytes, %s satoshis txfee" % (len(signed_subsidized_tx)/2, int(tx_fee)))
    log.debug("signed subsidized tx: {}".format(signed_subsidized_tx))
    if include_dust:
        dust_fee = estimate_dust_fee( unsigned_tx, fees_registration )   # must be unsigned_tx, without subsidy
        assert dust_fee is not None
        log.debug("Additional renewal dust fee: %s" % dust_fee)
        tx_fee += dust_fee

    return tx_fee


def estimate_update_tx_fee( name, payment_privkey_info, owner_privkey_info, tx_fee_per_byte, utxo_client,
                            owner_utxos=None, payment_utxos=None, config_path=CONFIG_PATH, include_dust=False ):
    """
    Estimate the transaction fee of an update.
    Optionally include the dust fees as well.
    Return the number of satoshis on success
    Return None on error
    """

    owner_address = virtualchain.get_privkey_address( owner_privkey_info )
    payment_address = virtualchain.get_privkey_address( payment_privkey_info )

    fake_consensus_hash = 'd4049672223f42aac2855d2fbf2f38f0'
    fake_zonefile_hash = '20b512149140494c0f7d565023973226908f6940'

    signed_subsidized_tx = None

    utxo_client = build_utxo_client(utxo_client, address=owner_address, utxos=owner_utxos)
    utxo_client = build_utxo_client(utxo_client, address=payment_address, utxos=payment_utxos)

    try:
        payment_utxos = tx_get_unspents(payment_address, utxo_client)
    except Exception as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        log.error("Failed to get inputs for {}".format(payment_address))
        return None

    signed_subsidized_tx = None

    try:
        unsigned_tx = None
        try:
            unsigned_tx, num_utxos = make_cheapest_name_update(name, fake_zonefile_hash, fake_consensus_hash, owner_address, utxo_client, payment_address, payment_utxos )
            assert unsigned_tx
            
            signed_subsidized_tx = get_estimated_signed_subsidized(
                unsigned_tx, fees_update, 21 * 10**14, payment_privkey_info, utxo_client, owner_privkey_info,
                tx_fee_per_byte)

            assert signed_subsidized_tx

        except AssertionError as ae:
            # no UTXOs for this owner address.  Try again and add padding for one
            log.warning("No UTXOs for {} and/or {}; estimating...".format(owner_address, payment_address))
            unsigned_tx = update_tx( name, fake_zonefile_hash, fake_consensus_hash, owner_address, utxo_client, subsidize=True, safety=False )
            assert unsigned_tx

            pad_len = estimate_input_length(owner_privkey_info) + estimate_input_length(payment_privkey_info)
            signed_subsidized_tx = unsigned_tx + "00" * pad_len

    except ValueError as ve:
        if BLOCKSTACK_TEST:
            log.exception(ve)

        log.error("Insufficient funds:  Not enough inputs to make an update transaction.")
        return None

    except AssertionError as ae:
        if BLOCKSTACK_DEBUG:
            log.exception(ae)

        log.error("Unable to create update transaction")
        return None

    except Exception as e:
        if os.environ.get("BLOCKSTACK_TEST") == "1":
            log.exception(e)

        return None

    tx_fee = (len(signed_subsidized_tx) * tx_fee_per_byte) / 2

    log.debug("update tx %s bytes, %s satoshis txfee" % (len(signed_subsidized_tx)/2, int(tx_fee)))
    log.debug("signed subsidized tx: {}".format(signed_subsidized_tx))

    if include_dust:
        dust_fee = estimate_dust_fee( unsigned_tx, fees_update )    # must be unsigned tx, without subsidy
        assert dust_fee is not None
        log.debug("Additional update dust fee: %s" % dust_fee)
        tx_fee += dust_fee

    return tx_fee


def estimate_transfer_tx_fee( name, payment_privkey_info, owner_privkey_info, tx_fee_per_byte, utxo_client,
                              owner_utxos=None, payment_utxos=None, config_path=CONFIG_PATH, include_dust=False ):
    """
    Estimate the transaction fee of a transfer.
    Optionally include the dust fees as well.
    Return the number of satoshis on success
    Return None on error
    """

    owner_address = virtualchain.get_privkey_address(owner_privkey_info)
    payment_address = virtualchain.get_privkey_address(payment_privkey_info)

    fake_recipient_address = virtualchain.address_reencode('1LL4X7wNUBCWoDhfVLA2cHE7xk1ZJMT98Q')
    fake_consensus_hash = 'd4049672223f42aac2855d2fbf2f38f0'

    utxo_client = build_utxo_client(utxo_client, address=owner_address, utxos=owner_utxos)
    utxo_client = build_utxo_client(utxo_client, address=payment_address, utxos=payment_utxos)

    try:
        payment_utxos = tx_get_unspents(payment_address, utxo_client)
    except Exception as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        log.error("Failed to get inputs for {}".format(payment_address))
        return None

    unsigned_tx = None
    signed_subsidized_tx = None

    try:
        try:
            unsigned_tx, num_utxos = make_cheapest_name_transfer(name, fake_recipient_address, True, fake_consensus_hash, owner_address, utxo_client, payment_address, payment_utxos )
            assert unsigned_tx

            signed_subsidized_tx = get_estimated_signed_subsidized(
                unsigned_tx, fees_transfer, 21 * 10**14, payment_privkey_info, utxo_client, owner_privkey_info,
                tx_fee_per_byte)

            assert signed_subsidized_tx

        except AssertionError as ae:
            # no UTXOs for this owner address.  Try again and add padding for one
            log.warning("No UTXOs for {} and/or {}; estimating...".format(owner_address, payment_address))
            unsigned_tx = transfer_tx( name, fake_recipient_address, True, fake_consensus_hash, owner_address, utxo_client, subsidize=True, safety=False )
            assert unsigned_tx

            pad_len = estimate_input_length(owner_privkey_info) + estimate_input_length(payment_privkey_info)
            signed_subsidized_tx = unsigned_tx + "00" * pad_len

    except ValueError, ve:
        if os.environ.get("BLOCKSTACK_TEST") == "1":
            log.exception(ve)

        log.error("Insufficient funds:  Not enough inputs to make a transfer transaction.")
        return None

    except AssertionError as ae:
        if BLOCKSTACK_DEBUG:
            log.exception(ae)

        log.error("Unable to make transfer transaction")
        return None

    except Exception as e:
        if os.environ.get("BLOCKSTACK_TEST") == "1":
            log.exception(e)

        return None

    tx_fee = (len(signed_subsidized_tx) * tx_fee_per_byte) / 2
    log.debug("transfer tx %s bytes, %s satoshis txfee" % (len(signed_subsidized_tx)/2, int(tx_fee)))
    log.debug("signed subsidized tx: {}".format(signed_subsidized_tx))

    if include_dust:
        dust_fee = estimate_dust_fee( unsigned_tx, fees_transfer )  # must be unsigned tx, without subsidy
        assert dust_fee is not None
        log.debug("Additional transfer dust fee: %s" % dust_fee)
        tx_fee += dust_fee

    return tx_fee


def estimate_revoke_tx_fee( name, payment_privkey_info, owner_privkey_info, tx_fee_per_byte, utxo_client, 
                            owner_utxos=None, payment_utxos=None, config_path=CONFIG_PATH, include_dust=False ):
    """
    Estimate the transaction fee of a revoke.
    Optionally include the dust fees as well.
    Return the number of satoshis on success
    Return None on error
    """

    owner_address = virtualchain.get_privkey_address(owner_privkey_info)
    payment_address = virtualchain.get_privkey_address(payment_privkey_info)

    unsigned_tx = None
    signed_subsidized_tx = None

    utxo_client = build_utxo_client(utxo_client, address=owner_address, utxos=owner_utxos)
    utxo_client = build_utxo_client(utxo_client, address=payment_address, utxos=payment_utxos)

    try:
        payment_utxos = tx_get_unspents(payment_address, utxo_client)
    except Exception as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        log.error("Failed to get inputs for {}".format(payment_address))
        return None

    unsigned_tx = None
    signed_subsidized_tx = None

    try:
        try:
            unsigned_tx, num_utxos = make_cheapest_name_revoke(name, owner_address, utxo_client, payment_address, payment_utxos)
            assert unsigned_tx

            signed_subsidized_tx = get_estimated_signed_subsidized(
                unsigned_tx, fees_revoke, 21 * 10**14, payment_privkey_info, utxo_client, owner_privkey_info,
                tx_fee_per_byte)

            assert signed_subsidized_tx

        except AssertionError as ae:
            # no UTXOs for this owner address.  Try again and add padding for one
            log.warning("No UTXOs for {} and/or {}; estimating...".format(owner_address, payment_address))
            unsigned_tx = revoke_tx( name, owner_address, utxo_client, subsidize=True, safety=False )
            assert unsigned_tx

            pad_len = estimate_input_length(owner_privkey_info) + estimate_input_length(payment_privkey_info)
            signed_subsidized_tx = unsigned_tx + '00' * pad_len

    except ValueError, ve:
        if os.environ.get("BLOCKSTACK_TEST") == "1":
            log.exception(ve)

        log.error("Insufficient funds:  Not enough inputs to make a revoke transaction.")
        return None

    except AssertionError as ae:
        if BLOCKSTACK_DEBUG:
            log.exception(ae)

        log.error("Unable to make revoke transaction")
        return None

    except Exception as e:
        if os.environ.get("BLOCKSTACK_TEST") == "1":
            log.exception(e)

        return None

    tx_fee = (len(signed_subsidized_tx) * tx_fee_per_byte) / 2

    log.debug("revoke tx %s bytes, %s satoshis txfee" % (len(signed_subsidized_tx)/2, int(tx_fee)))
    log.debug("signed subsidized tx: {}".format(signed_subsidized_tx))

    if include_dust:
        dust_fee = estimate_dust_fee( unsigned_tx, fees_revoke )    # must be unsigned tx, without subsidy
        assert dust_fee is not None
        log.debug("Additional revoke dust fee: %s" % dust_fee)
        tx_fee += dust_fee

    return tx_fee


def estimate_name_import_tx_fee( fqu, reveal_privkey_info, recipient_address, tx_fee_per_byte, utxo_client, 
                                 importer_utxos=None, config_path=CONFIG_PATH, include_dust=False ):
    """
    Estimate the transaction fee of a name import.
    Return the number of satoshis on success
    Return None on error
    """

    reveal_addr = virtualchain.get_privkey_address(reveal_privkey_info)

    utxo_client = build_utxo_client(utxo_client, address=reveal_addr, utxos=importer_utxos)

    fake_zonefile_hash = '20b512149140494c0f7d565023973226908f6940'

    try:
        importer_utxos = tx_get_unspents(reveal_addr, utxo_client)
    except Exception as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        log.error("Failed to get inputs for {}".format(reveal_addr))
        return None

    signed_tx = None
    unsigned_tx = None

    try:
        try:
            unsigned_tx, num_utxos = make_cheapest_name_import( fqu, recipient_address, fake_zonefile_hash, reveal_addr, utxo_client, importer_utxos)
            assert unsigned_tx
        
            signed_tx = sign_tx( unsigned_tx, importer_utxos[:num_utxos], reveal_privkey_info )
            assert signed_tx

        except AssertionError, ae:
            log.warning("No UTXOs for {}; estimating...".format(reveal_addr))
            unsigned_tx = name_import_tx( fqu, recipient_address, fake_zonefile_hash, reveal_addr, utxo_client, safety=False )
            assert unsigned_tx
            
            # fake owner UTXO
            pad_len = estimate_input_length(reveal_addr)
            signed_tx = unsigned_tx + "00" * pad_len

    except ValueError, ve:
        if os.environ.get("BLOCKSTACK_TEST") == "1":
            log.exception(ve)

        log.error("Insufficient funds:  Not enough inputs to make an import transaction")
        return None

    tx_fee = (len(signed_tx) * tx_fee_per_byte) / 2

    log.debug("name import tx %s bytes, %s satoshis txfee" % (len(signed_tx)/2, int(tx_fee)))
    log.debug("signed subsidized tx: {}".format(signed_tx))

    if include_dust:
        dust_fee = estimate_dust_fee( signed_tx, fees_name_import )
        assert dust_fee is not None
        log.debug("Additional name import dust fee: %s" % dust_fee)
        tx_fee += dust_fee

    return tx_fee


def estimate_namespace_preorder_tx_fee( namespace_id, cost, payment_privkey_info, tx_fee_per_byte, utxo_client, 
                                        payment_utxos=None, config_path=CONFIG_PATH, include_dust=False ):
    """
    Estimate the transaction fee of a namespace preorder
    Return the number of satoshis on success
    Return None on error
    """

    payment_address = virtualchain.get_privkey_address(payment_privkey_info)

    utxo_client = build_utxo_client(utxo_client, address=payment_address, utxos=payment_utxos)

    fake_reveal_address = virtualchain.address_reencode('1LL4X7wNUBCWoDhfVLA2cHE7xk1ZJMT98Q')
    fake_consensus_hash = 'd4049672223f42aac2855d2fbf2f38f0'

    try:
        payment_utxos = tx_get_unspents(payment_address, utxo_client)
    except Exception as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        log.error("Failed to get inputs for {}".format(payment_address))
        return None

    signed_tx = None
    unsigned_tx = None

    try:
        try:
            unsigned_tx, num_utxos = make_cheapest_namespace_preorder( namespace_id, payment_address, fake_reveal_address, cost, fake_consensus_hash, utxo_client, payment_utxos)
            assert unsigned_tx

            signed_tx = sign_tx( unsigned_tx, payment_utxos[:num_utxos], payment_privkey_info )
            assert signed_tx

        except AssertionError as ae:
            log.exception(ae)
            log.warning("Insufficient funds in {} for NAMESPACE_PREORDER; estimating instead".format(payment_address))
            unsigned_tx = namespace_preorder_tx( namespace_id, fake_reveal_address, cost, fake_consensus_hash, payment_address, utxo_client, safety=False )
            assert unsigned_tx
            
            # fake payer input
            pad_len = estimate_input_length(payment_address)
            signed_tx += unsigned_tx + "00" * pad_len

    except ValueError, ve:
        if os.environ.get("BLOCKSTACK_TEST") == "1":
            log.exception(ve)

        log.error("Insufficient funds:  Not enough inputs to make a namespace-preorder transaction.")
        return None

    tx_fee = (len(signed_tx) * tx_fee_per_byte) / 2
    
    log.debug("namespace preorder tx %s bytes, %s satoshis" % (len(signed_tx)/2, int(tx_fee)))
    log.debug("signed (fake) tx: {}".format(signed_tx))

    dust_fee = 0
    if include_dust:
        dust_fee = estimate_dust_fee( signed_tx, fees_namespace_preorder )
        assert dust_fee is not None
        log.debug("Additional namespace preorder dust fee: %s" % dust_fee)
        tx_fee += dust_fee

    return tx_fee


def estimate_namespace_reveal_tx_fee( namespace_id, payment_privkey_info, tx_fee_per_byte, utxo_client, 
                                      payment_utxos=None, config_path=CONFIG_PATH, include_dust=False ):
    """
    Estimate the transaction fee of a namespace reveal
    Return the number of satoshis on success
    Return None on error
    """

    payment_address = virtualchain.get_privkey_address(payment_privkey_info)

    utxo_client = build_utxo_client(utxo_client, address=payment_address, utxos=payment_utxos)

    fake_reveal_address = virtualchain.address_reencode('1LL4X7wNUBCWoDhfVLA2cHE7xk1ZJMT98Q')

    try:
        payment_utxos = tx_get_unspents(payment_address, utxo_client)
    except Exception as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        log.error("Failed to get inputs for {}".format(payment_address))
        return None

    unsigned_tx = None
    signed_tx = None

    try:
        try:
            unsigned_tx, num_utxos = make_cheapest_namespace_reveal( namespace_id, 1, fake_reveal_address, 1, 2, 3, [4,5,6,7,8,9,10,11,12,13,14,15,0,1,2,3], 4, 5, payment_address, utxo_client, payment_utxos)
            assert unsigned_tx

            signed_tx = sign_tx(unsigned_tx, payment_utxos[:num_utxos], payment_privkey_info)
            assert signed_tx

        except AssertionError as ae:
            log.warning("Insufficient funds in {} for NAMESPACE_REVEAL; estimating instead".format(payment_address))
            unsigned_tx = namespace_reveal_tx( namespace_id, 1, fake_reveal_address, 1, 2, 3, [4,5,6,7,8,9,10,11,12,13,14,15,0,1,2,3], 4, 5, payment_address, utxo_client, safety=False )
            assert unsigned_tx

            # fake payer input
            pad_len = estimate_input_length(payment_address)
            signed_tx = unsigned_tx + "00" * pad_len

    except ValueError, ve:
        if os.environ.get("BLOCKSTACK_TEST") == "1":
            log.exception(ve)

        log.error("Insufficient funds:  Not enough inputs to make a namespace-reveal transaction.")
        return None

    tx_fee = (len(signed_tx) * tx_fee_per_byte) / 2

    log.debug("namespace reveal tx %s bytes, %s satoshis txfee" % (len(signed_tx)/2, int(tx_fee)))
    log.debug("signed (fake) tx: {}".format(signed_tx))

    if include_dust:
        dust_fee = estimate_dust_fee( signed_tx, fees_namespace_reveal )
        assert dust_fee is not None
        log.debug("Additional namespace reveal dust fee: %s" % dust_fee)
        tx_fee += dust_fee

    return tx_fee


def estimate_namespace_ready_tx_fee( namespace_id, reveal_privkey_info, tx_fee_per_byte, utxo_client, 
                                     revealer_utxos=None, config_path=CONFIG_PATH, include_dust=False ):
    """
    Estimate the transaction fee of a namespace ready
    Return the number of satoshis on success
    Return None on error

    TODO: no dust estimation available for namespace ready
    """

    reveal_addr = virtualchain.get_privkey_address(reveal_privkey_info)

    utxo_client = build_utxo_client(utxo_client, address=reveal_addr, utxos=revealer_utxos)

    try:
        payment_utxos = tx_get_unspents(reveal_addr, utxo_client)
    except Exception as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        log.error("Failed to get inputs for {}".format(reveal_addr))
        return None

    try:
        try:
            unsigned_tx, num_utxos = make_cheapest_namespace_ready(namespace_id, reveal_addr, utxo_client, payment_utxos)
            assert unsigned_tx

            signed_tx = sign_tx(unsigned_tx, payment_utxos[:num_utxos], reveal_privkey_info)
            assert signed_tx

        except AssertionError as ae:
            log.warning("Insufficient funds in {} for NAMESPACE_READY; estimating instead".format(reveal_addr))
            unsigned_tx = namespace_ready_tx( namespace_id, reveal_addr, utxo_client, safety=False)
            assert unsigned_tx

            # fake payer input
            pad_len = estimate_input_length(payment_address)
            signed_tx = unsigned_tx + "00" * pad_len

    except ValueError, ve:
        if os.environ.get("BLOCKSTACK_TEST") == "1":
            log.exception(ve)

        log.error("Insufficient funds:  Not enough inputs to make a namespace-ready transaction.")
        return None
    
    tx_fee = (len(signed_tx) * tx_fee_per_byte) / 2

    log.debug("namespace ready tx %s bytes, %s satoshis txfee" % (len(signed_tx)/2, int(tx_fee)))
    log.debug("signed (fake) tx: {}".format(signed_tx))

    dust_fee = 0
    if include_dust:
        dust_fee = estimate_dust_fee( signed_tx, fees_namespace_ready )
        assert dust_fee is not None
        log.debug("Additional namespace ready dust fee: %s" % dust_fee)
        tx_fee += dust_fee

    return tx_fee


def estimate_announce_tx_fee( sender_privkey_info, tx_fee_per_byte, utxo_client, config_path=CONFIG_PATH, include_dust=False ):
    """
    Estimate the transaction fee of an announcement tx
    Return the number of satoshis on success
    Return None on error
    """

    sender_address = virtualchain.get_privkey_address(sender_privkey_info)
    fake_announce_hash = '20b512149140494c0f7d565023973226908f6940'

    try:
        payment_utxos = tx_get_unspents(sender_address, utxo_client)
    except Exception as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        log.error("Failed to get inputs for {}".format(sender_address))
        return None

    signed_tx = None
    unsigned_tx = None

    try:
        try:
            unsigned_tx, num_utxos = make_cheapest_announce(fake_announce_hash, sender_address, utxo_client, payment_utxos)
            assert unsigned_tx

            signed_tx = sign_tx(unsigned_tx, payment_utxos[:num_utxos], sender_privkey_info)
            assert signed_tx

        except AssertionError as ae:
            log.warning("Insufficient funds in {} for ANNOUNCE; estimating instead".format(sender_address))
            unsigned_tx = announce_tx( fake_announce_hash, sender_address, utxo_client, safety=False)
            assert unsigned_tx

            # fake payer input
            pad_len = estimate_input_length(sender_privkey_info)
            signed_tx = unsigned_tx + "00" * pad_len

    except ValueError, ve:
        if os.environ.get("BLOCKSTACK_TEST") == "1":
            log.exception(ve)

        log.error("Insufficient funds:  Not enough inputs to make an announce transaction.")
        return None

    tx_fee = (len(signed_tx) * tx_fee_per_byte) / 2

    log.debug("announce tx %s bytes, %s satoshis" % (len(signed_tx)/2, int(tx_fee)))
    log.debug("signed (fake) tx: {}".format(signed_tx))

    if include_dust:
        dust_fee = estimate_dust_fee( signed_tx, fees_announce )
        assert dust_fee is not None
        log.debug("Additional announce dust fee: %s" % dust_fee)
        tx_fee += dust_fee

    return tx_fee


def get_consensus_hash( proxy, config_path=CONFIG_PATH ):
    """
    Get the current consensus hash from the server.
    Also verify that the server has processed sufficiently
    many blocks (compared to what bitcoind tells us).
    Return {'status': True, 'consensus_hash': ...} on success
    Return {'error': ...} on failure
    """

    delay = 1.0
    while True:
        blockstack_info = blockstack_getinfo( proxy=proxy )
        if 'error' in blockstack_info:
            log.error("Blockstack server did not return consensus hash: {}".format(blockstack_info['error']))
            time.sleep(delay)
            delay = 2 * delay + random.randint(0, delay)
            continue

        # up-to-date?
        last_block_processed = None
        last_block_seen = None
        try:
            last_block_processed = int(blockstack_info['last_block_processed'])
            last_block_seen = int(blockstack_info['last_block_seen'])
            consensus_hash = blockstack_info['consensus']
        except Exception, e:
            log.exception(e)
            log.error("Invalid consensus hash from server")
            time.sleep(delay)
            delay = 2 * delay + random.randint(0, delay)
            continue

        # valid?
        height = get_block_height( config_path=config_path )
        if height is None:
            log.error("Failed to get blockchain height")
            delay = 2 * delay + random.randint(0, delay)
            continue

        if height > last_block_processed + 20 or (last_block_seen is not None and last_block_seen > last_block_processed + 20):
            # server is lagging
            log.error("Server is lagging behind: bitcoind height is %s, server is %s" % (height, last_block_processed))
            delay = 2 * delay + random.randint(0, delay)

        # success
        return {'status': True, 'consensus_hash': consensus_hash}


def address_privkey_match( address, privkey_params ):
    """
    Does an address correspond to the private key information?
    i.e. singlesig --> p2pkh address
    i.e. multisig --> p2sh address
    """
    if privkey_params == (1,1) and keylib.b58check.b58check_version_byte( str(address) ) != virtualchain.version_byte:
        # invalid address, given parameters
        log.error("Address %s does not correspond to a single private key" % address)
        return False

    elif (privkey_params[0] > 1 or privkey_params[1] > 1) and keylib.b58check.b58check_version_byte( str(address) ) != virtualchain.multisig_version_byte:
        # invalid address
        log.error("Address %s does not correspond to multisig private keys")
        return False

    return True


def build_utxo_client( utxo_client, utxos=None, address=None ):
    """
    Build a UTXO client.
    This can be called multiple times with different addresses and UTXO lists.

    Return the UTXO client instance on success.
    Return None on error
    """
    if not isinstance(utxo_client, UTXOWrapper):
        utxo_client = UTXOWrapper(utxo_client)

    # append to this client
    if utxos is not None and address is not None:
        utxo_client.add_unspents( address, utxos )

    return utxo_client


def do_blockchain_tx( unsigned_tx, prev_outputs, privkey_info=None, config_path=CONFIG_PATH, tx_broadcaster=None, dry_run=BLOCKSTACK_DRY_RUN ):
    """
    Sign and/or broadcast a subsidized transaction.
    If dry_run is True, then don't actually send the transaction (and don't bother signing it if no key is given).

    Return {'status': True, 'transaction_hash': ...} on successful signing and broadcasting
    Return {'status': True, 'tx': ...} otherwise.  'tx' will be signed if privkey_info is given.

    Return {'error': ...} on failure
    """

    assert privkey_info or dry_run, "Missing payment key"

    try:
        if dry_run:
            if privkey_info is not None:
                resp = sign_tx( unsigned_tx, prev_outputs, privkey_info )
            else:
                resp = unsigned_tx

            if resp is None:
                resp = {'error': 'Failed to generate signed register tx'}
            else:
                resp = {'status': True, 'tx': resp}

        else:
            resp = sign_and_broadcast_tx( unsigned_tx, prev_outputs, privkey_info, config_path=config_path, tx_broadcaster=tx_broadcaster )

        return resp

    except Exception, e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        return {'error': 'Failed to sign and broadcast transaction'}


def get_namespace_from_name( name ):
   """
   Get a fully-qualified name's namespace, if it has one.
   It's the sequence of characters after the last "." in the name.
   If there is no "." in the name, then it belongs to the null
   namespace (i.e. the empty string will be returned)
   """
   if "." not in name:
      # empty namespace
      return ""

   return name.split(".")[-1]


def get_namespace_burn_address(fqu, proxy):
    """
    Determine the right burn address to use
    """
    import blockstack
    burn_address = None
    
    indexer_info = blockstack_getinfo()
    if 'error' in indexer_info:
        return {'error': 'Failed to contact indexer'}

    # +1, so we consider the next block to be formed 
    block_height = indexer_info['last_block_seen'] + 1

    # look up burn address 
    namespace_id = get_namespace_from_name(fqu) 
    namespace_info = blockstack_get_namespace_blockchain_record(namespace_id, proxy=proxy)
    if 'error' in namespace_info:
        return namespace_info

    # does this namespace support burn-to-namespace-creator?
    if (namespace_info['version'] & NAMESPACE_VERSION_PAY_TO_CREATOR) != 0:
        # are we still in its fee capture period?
        receive_fees_period = blockstack.get_epoch_namespace_receive_fees_period(block_height, namespace_id)
        if namespace_info['reveal_block'] + receive_fees_period >= block_height:
            # use the namespace burn address
            burn_address = virtualchain.address_reencode(str(namespace_info['address']))
        else:
            # use the null burn address
            burn_address = blockstack.BLOCKSTACK_BURN_ADDRESS

    else:
        burn_address = BLOCKSTACK_BURN_ADDRESS

    return burn_address


def do_preorder( fqu, payment_privkey_info, owner_privkey_info, cost_satoshis, utxo_client, tx_broadcaster, owner_address=None, burn_address=None, tx_fee=None,
                 config_path=CONFIG_PATH, proxy=None, consensus_hash=None, dry_run=BLOCKSTACK_DRY_RUN, safety_checks=True ):
    """
    Preorder a name.

    Either payment_privkey_info or payment_address is necessary.
    Either payment_utxos or utxo_client is necessary.

    If payment_privkey_info is not given, then dry_run must be true.  An unsigned tx will be returned.

    Return {'status': True, 'transaction_hash': ...} on success (for dry_run = False)
    Return {'status': True, 'tx': ...} on success (for dry_run = True)
    Return {'error': ...} on failure
    """

    if proxy is None:
        proxy = get_default_proxy(config_path)

    if dry_run:
        assert tx_fee, "invalid argument: tx_fee is required on dry-run"
        assert cost_satoshis, 'invalid argument: cost_satoshis is required on dry-run'
        safety_checks = False

    fqu = str(fqu)

    # wrap UTXO client so we remember UTXOs
    utxo_client = build_utxo_client(utxo_client)

    if owner_privkey_info is None:
        assert owner_address, 'Need owner address or owner private key'
        owner_address = virtualchain.address_reencode(str(owner_address))
    else:
        owner_address = virtualchain.get_privkey_address( owner_privkey_info )

    payment_address = virtualchain.get_privkey_address( payment_privkey_info )

    min_confirmations = utxo_client.min_confirmations

    if burn_address is None:
        burn_address = get_namespace_burn_address(fqu, proxy)
    else:
        burn_address = virtualchain.address_reencode(str(burn_address))

    if not dry_run and (safety_checks or (cost_satoshis is None or tx_fee is None)):
        tx_fee = 0
        # find tx fee, and do sanity checks
        res = check_preorder(fqu, cost_satoshis, owner_privkey_info, payment_privkey_info, config_path=config_path,
                             proxy=proxy, min_payment_confs=min_confirmations, burn_address=burn_address)

        if 'error' in res and safety_checks:
            log.error("Failed to check preorder: {}".format(res['error']))
            return res

        tx_fee = res.get('tx_fee')

        if cost_satoshis is None:
            cost_satoshis = res['name_price']

    assert tx_fee, 'Missing tx fee'
    assert cost_satoshis, "Missing name cost"

    if consensus_hash is None:
        consensus_hash_res = get_consensus_hash( proxy, config_path=config_path )
        if 'error' in consensus_hash_res:
            return {'error': 'Failed to get consensus hash: %s' % consensus_hash_res['error']}

        consensus_hash = consensus_hash_res['consensus_hash']
    else:
        log.warn("Using user-supplied consensus hash %s" % consensus_hash)

    # get payment inputs
    try:
        payment_utxos = tx_get_unspents(payment_address, utxo_client)
        log.debug("Payment address {} has {} UTXOs".format(payment_address, len(payment_utxos)))
    except Exception as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        log.error("Failed to get inputs for {}".format(payment_address))
        return {'error': 'Failed to get payment inputs'}

    utxo_client = build_utxo_client( utxo_client, address=payment_address, utxos=payment_utxos )
    assert utxo_client, "Unable to build UTXO client"

    log.debug("Preordering (%s, %s, %s), for %s, tx_fee = %s, burn address = %s" % (fqu, payment_address, owner_address, cost_satoshis, tx_fee, burn_address))

    try:
        unsigned_tx, num_utxos = make_cheapest_name_preorder(
            fqu, payment_address, owner_address, burn_address, cost_satoshis, consensus_hash,
            utxo_client, payment_utxos, tx_fee=tx_fee, dust_included = True)

        assert unsigned_tx
    except (AssertionError, ValueError) as ve:
        if BLOCKSTACK_DEBUG:
            log.exception(ve)

        log.error("Failed to create preorder TX")
        return {'error': 'Insufficient funds'}

    resp = do_blockchain_tx( unsigned_tx, payment_utxos[:num_utxos], privkey_info=payment_privkey_info, tx_broadcaster=tx_broadcaster, config_path=config_path, dry_run=dry_run )
    return resp


def do_register( fqu, payment_privkey_info, owner_privkey_info, utxo_client, tx_broadcaster, zonefile_hash=None, tx_fee=None, 
                 config_path=CONFIG_PATH, proxy=None, dry_run=BLOCKSTACK_DRY_RUN, safety_checks=True,
                 force_register = False, owner_address=None ):

    """
    Register a name
    
    payment_privkey_info or payment_address is required.
    utxo_client or payment_utxos is required.
    force_register still performs SOME safety checks (payment)

    Return {'status': True, 'transaction_hash': ...} on success
    Return {'status': True, 'tx': ...} if no private key is given, or dry_run is True.
    Return {'error': ...} on failure
    """
    if proxy is None:
        proxy = get_default_proxy(config_path)

    fqu = str(fqu)
    resp = {}

    if dry_run:
        assert tx_fee, "Missing tx fee on dry-run"
        safety_checks = False

    # wrap UTXO client so we remember UTXOs 
    utxo_client = build_utxo_client(utxo_client)

    payment_address = virtualchain.get_privkey_address( payment_privkey_info )

    if owner_privkey_info is None:
        assert owner_address, "Need either owner address or owner private key"
        owner_address = virtualchain.address_reencode(str(owner_address))
    else:
        owner_address = virtualchain.get_privkey_address( owner_privkey_info )
    
    min_confirmations = utxo_client.min_confirmations

    if not dry_run and (safety_checks or tx_fee is None):
        tx_fee = 0
        # find tx fee, and do sanity checks
        res = check_register(fqu, owner_privkey_info, payment_privkey_info, zonefile_hash=zonefile_hash,
                             config_path=config_path, proxy=proxy, min_payment_confs=min_confirmations,
                             force_it = force_register, owner_address=owner_address)

        if 'error' in res and safety_checks:
            log.error("Failed to check register: {}".format(res['error']))

            return res

        tx_fee = res['tx_fee']

    assert tx_fee, "Missing tx fee"

    # get payment inputs
    try:
        payment_utxos = tx_get_unspents(payment_address, utxo_client)
        log.debug("Payment address {} has {} UTXOs".format(payment_address, len(payment_utxos)))
    except Exception as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        log.error("Failed to get inputs for {}".format(payment_address))
        return {'error': 'Failed to get payment inputs'}

    utxo_client = build_utxo_client( utxo_client, address=payment_address, utxos=payment_utxos )
    assert utxo_client, "Unable to build UTXO client"

    log.debug("Registering (%s, %s, %s), tx_fee = %s, zonefile_hash = %s" % (fqu, payment_address, owner_address, tx_fee, zonefile_hash))

    # make tx
    try:
        unsigned_tx, num_utxos = make_cheapest_name_registration(
            fqu, payment_address, owner_address, utxo_client, payment_utxos,
            zonefile_hash=zonefile_hash, tx_fee=tx_fee, dust_included = True)
        assert unsigned_tx
    except (AssertionError, ValueError) as ve:
        if BLOCKSTACK_TEST:
            log.exception(ve)

        log.error("Failed to create register TX")
        return {'error': 'Insufficient funds'}

    resp = do_blockchain_tx( unsigned_tx, payment_utxos[:num_utxos], privkey_info=payment_privkey_info, tx_broadcaster=tx_broadcaster, config_path=config_path, dry_run=dry_run )
    return resp


def do_update( fqu, zonefile_hash, owner_privkey_info, payment_privkey_info, utxo_client, tx_broadcaster,
               tx_fee=None, tx_fee_per_byte=None, config_path=CONFIG_PATH, proxy=None, consensus_hash=None,
               dry_run=BLOCKSTACK_DRY_RUN, safety_checks=True, force_update = False ):
    """
    Put a new zonefile hash for a name.

    utxo_client must be given, or UTXO lists for both owner and payment private keys must be given.
    If private key(s) are missing, then dry_run must be True.
    force_update skips only some safety checks (but still checks payment)

    Return {'status': True, 'transaction_hash': ..., 'value_hash': ...} on success (if dry_run is False)
    return {'status': True, 'tx': ..., 'value_hash': ...} on success (if dry_run is True)
    Return {'error': ...} on failure
    """

    if proxy is None:
        proxy = get_default_proxy(config_path)

    if dry_run:
        assert tx_fee, 'dry run needs tx fee'
        safety_checks = False

    fqu = str(fqu)

    # wrap UTXO client so we remember UTXOs
    utxo_client = build_utxo_client(utxo_client)

    owner_address = virtualchain.get_privkey_address( owner_privkey_info )
    payment_address = virtualchain.get_privkey_address( payment_privkey_info )

    min_confirmations = utxo_client.min_confirmations

    if not dry_run and (safety_checks or tx_fee is None):
        # find tx fee, and do sanity checks
        res = check_update(fqu, owner_privkey_info, payment_privkey_info,
                           config_path=config_path, proxy=proxy, min_payment_confs=min_confirmations,
                           force_it = force_update)
        if 'error' in res and safety_checks:
            log.error("Failed to check update: {}".format(res['error']))
            return res

        if not tx_fee_per_byte:
            tx_fee_per_byte = res['tx_fee_per_byte']

        if not tx_fee:
            tx_fee = res['tx_fee']

        assert tx_fee_per_byte, "Missing tx fee per byte"
        assert tx_fee, 'Missing tx fee'

    # get consensus hash
    if consensus_hash is None:
        consensus_hash_res = get_consensus_hash( proxy, config_path=config_path )
        if 'error' in consensus_hash_res:
            log.error("Failed to get consensus hash")
            return {'error': 'Failed to get consensus hash: %s' % consensus_hash_res['error']}

        consensus_hash = consensus_hash_res['consensus_hash']

    else:
        log.warn("Using caller-supplied consensus hash '%s'" % consensus_hash)

    # get inputs
    try:
        payment_utxos = tx_get_unspents(payment_address, utxo_client)
        owner_utxos = tx_get_unspents(owner_address, utxo_client)
        log.debug("Payment address {} has {} UTXOs".format(payment_address, len(payment_utxos)))
        log.debug("Owner address {} has {} UTXOs".format(owner_address, len(owner_utxos)))
    except Exception as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        log.error("Failed to get inputs for {} and/or {}".format(payment_address, owner_address))
        return {'error': 'Failed to get payment and/or owner inputs'}

    # build up UTXO client with the UTXOs preloaded
    utxo_client = build_utxo_client( utxo_client, address=payment_address, utxos=payment_utxos )
    assert utxo_client, "Unable to build UTXO client"

    utxo_client = build_utxo_client( utxo_client, address=owner_address, utxos=owner_utxos )
    assert utxo_client, "Unable to build UTXO client"

    # make and fund tx
    unsigned_tx = None
    subsidized_tx = None
    try:
        unsigned_tx, num_utxos = make_cheapest_name_update(fqu, zonefile_hash, consensus_hash, owner_address, utxo_client, payment_address, payment_utxos, subsidize=True )
        assert unsigned_tx

        subsidized_tx = tx_make_subsidizable( unsigned_tx, fees_update, 21 * (10**6) * (10**8),
                                              payment_privkey_info, utxo_client, tx_fee = tx_fee,
                                              add_dust_fee = False )
        assert subsidized_tx

    except (AssertionError, ValueError) as ve:
        if BLOCKSTACK_DEBUG:
            log.exception(ve)

        log.error("Failed to generate and subsidize update tx")
        return {'error': 'Failed to generate or subsidize tx'}

    # send tx
    resp = do_blockchain_tx( subsidized_tx, owner_utxos, privkey_info=owner_privkey_info, tx_broadcaster=tx_broadcaster, config_path=config_path, dry_run=dry_run )
    if 'error' in resp:
        return resp

    resp['value_hash'] = zonefile_hash
    return resp


def do_transfer( fqu, transfer_address, keep_data, owner_privkey_info, payment_privkey_info, utxo_client, tx_broadcaster, tx_fee=None, tx_fee_per_byte=None,
                 config_path=CONFIG_PATH, proxy=None, consensus_hash=None, dry_run=BLOCKSTACK_DRY_RUN, safety_checks=True ):
    """
    Transfer a name to a new address
    Return {'status': True, 'transaction_hash': ...} on success
    Return {'error': ...} on failure
    """

    if proxy is None:
        proxy = get_default_proxy(config_path)

    if dry_run:
        assert tx_fee is not None, 'Need tx fee for dry run'
        safety_checks = False

    # wrap UTXO client so we remember UTXOs 
    utxo_client = build_utxo_client(utxo_client)

    fqu = str(fqu)
    owner_address = virtualchain.get_privkey_address(owner_privkey_info)
    payment_address = virtualchain.get_privkey_address(payment_privkey_info)

    min_confirmations = utxo_client.min_confirmations

    if not dry_run and (safety_checks or tx_fee is None):
        # find tx fee, and do sanity checks
        res = check_transfer(fqu, transfer_address, owner_privkey_info, payment_privkey_info, config_path=config_path, proxy=proxy, min_payment_confs=min_confirmations)
        if 'error' in res and safety_checks:
            log.error("Failed to check transfer: {}".format(res['error']))
            return res

        if not tx_fee_per_byte:
            tx_fee_per_byte = res['tx_fee_per_byte']

        if not tx_fee:
            tx_fee = res['tx_fee']

        assert tx_fee_per_byte, "Missing tx fee-per-byte"
        assert tx_fee, 'Missing tx fee'

    # get consensus hash
    if consensus_hash is None:
        consensus_hash_res = get_consensus_hash( proxy, config_path=config_path )
        if 'error' in consensus_hash_res:
            return {'error': 'Failed to get consensus hash: %s' % consensus_hash_res['error']}

        consensus_hash = consensus_hash_res['consensus_hash']

    else:
        log.warn("Using caller-supplied consensus hash '%s'" % consensus_hash)

    # get inputs
    try:
        payment_utxos = tx_get_unspents(payment_address, utxo_client)
        owner_utxos = tx_get_unspents(owner_address, utxo_client)
        log.debug("Payment address {} has {} UTXOs".format(payment_address, len(payment_utxos)))
        log.debug("Owner address {} has {} UTXOs".format(owner_address, len(owner_utxos)))
    except Exception as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        log.error("Failed to get inputs for {} and/or {}".format(payment_address, owner_address))
        return {'error': 'Failed to get payment and/or owner inputs'}

    # build up UTXO client with the UTXOs preloaded
    utxo_client = build_utxo_client( utxo_client, address=payment_address, utxos=payment_utxos )
    assert utxo_client, "Unable to build UTXO client"

    utxo_client = build_utxo_client( utxo_client, address=owner_address, utxos=owner_utxos )
    assert utxo_client, "Unable to build UTXO client"

    # make and fund transaction
    subsidized_tx = None
    try:
        unsigned_tx, num_utxos = make_cheapest_name_transfer( fqu, transfer_address, keep_data, consensus_hash, owner_address, utxo_client, payment_address, payment_utxos, subsidize=True )
        assert unsigned_tx 

        subsidized_tx = tx_make_subsidizable( unsigned_tx, fees_transfer, 21 * (10**6) * (10**8),
                                              payment_privkey_info, utxo_client, tx_fee = tx_fee,
                                              add_dust_fee = False )
        assert subsidized_tx is not None
    except (AssertionError, ValueError) as ve:
        if BLOCKSTACK_DEBUG:
            log.exception(ve)

        log.error("Failed to generate and subsidize transfer tx")
        return {'error': 'Failed to generate or subsidize tx'}

    log.debug("Transferring (%s, %s)" % (fqu, transfer_address))
    log.debug("<owner, payment> (%s, %s) tx_fee_per_byte = %s" % (owner_address, payment_address, tx_fee_per_byte))

    resp = do_blockchain_tx( subsidized_tx, owner_utxos, privkey_info=owner_privkey_info, tx_broadcaster=tx_broadcaster, config_path=config_path, dry_run=dry_run )
    return resp


def do_renewal( fqu, owner_privkey_info, payment_privkey_info, renewal_fee, utxo_client, tx_broadcaster, burn_address=None, zonefile_hash=None, recipient_addr=None, tx_fee_per_byte=None, 
                tx_fee=None, config_path=CONFIG_PATH, proxy=None, dry_run=BLOCKSTACK_DRY_RUN, safety_checks=True ):
    """
    Renew a name
    Return {'status': True, 'transaction_hash': ...} on success
    Return {'error': ...} on failure
    """
    if proxy is None:
        proxy = get_default_proxy(config_path)

    if dry_run:
        assert tx_fee_per_byte, 'Need tx fee for dry run'
        assert renewal_fee, 'Need renewal fee for dry run'
        safety_checks = False

    # wrap UTXO client so we remember UTXOs 
    utxo_client = build_utxo_client(utxo_client)

    fqu = str(fqu)
    resp = {}
    owner_address = virtualchain.get_privkey_address( owner_privkey_info )
    payment_address = virtualchain.get_privkey_address( payment_privkey_info )

    if burn_address is None:
        burn_address = get_namespace_burn_address(fqu, proxy)
    else:
        burn_address = virtualchain.address_reencode(str(burn_address))

    if zonefile_hash is not None:
        zonefile_hash = str(zonefile_hash)
   
    min_confirmations = utxo_client.min_confirmations 

    if not dry_run and (safety_checks or (renewal_fee is None or tx_fee is None)):
        # find tx fee, and do sanity checks
        res = check_renewal(fqu, renewal_fee, owner_privkey_info, payment_privkey_info, new_owner_address=recipient_addr, zonefile_hash=zonefile_hash, burn_address=burn_address,
                            config_path=config_path, proxy=proxy, min_payment_confs=min_confirmations)

        if 'error' in res and safety_checks:
            log.error("Failed to check renewal: {}".format(res['error']))
            return res

        if not tx_fee_per_byte:
            tx_fee_per_byte = res['tx_fee_per_byte']

        if not renewal_fee:
            renewal_fee = res['name_price']

        if not tx_fee:
            tx_fee = res['tx_fee']

        assert tx_fee_per_byte, "Missing tx-per-byte fee"
    
    assert tx_fee, 'Missing tx fee'
    assert renewal_fee, "Missing renewal fee"

    # get inputs
    try:
        payment_utxos = tx_get_unspents(payment_address, utxo_client)
        owner_utxos = tx_get_unspents(owner_address, utxo_client)
        log.debug("Payment address {} has {} UTXOs".format(payment_address, len(payment_utxos)))
        log.debug("Owner address {} has {} UTXOs".format(owner_address, len(owner_utxos)))
    except Exception as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        log.error("Failed to get inputs for {} and/or {}".format(payment_address, owner_address))
        return {'error': 'Failed to get payment and/or owner inputs'}

    # build up UTXO client with the UTXOs preloaded
    utxo_client = build_utxo_client( utxo_client, address=payment_address, utxos=payment_utxos )
    assert utxo_client, "Unable to build UTXO client"

    utxo_client = build_utxo_client( utxo_client, address=owner_address, utxos=owner_utxos )
    assert utxo_client, "Unable to build UTXO client"

    log.debug("Renewing (%s, %s, %s), tx_fee_per_byte = %s, renewal_fee = %s, zonefile_hash = %s, recipient_addr = %s, burn_address = %s" % 
            (fqu, payment_address, owner_address, tx_fee_per_byte, renewal_fee, zonefile_hash, recipient_addr, burn_address))

    # now send it
    subsidized_tx = None
    try:
        unsigned_tx, num_utxos = make_cheapest_name_renewal(fqu, owner_address, renewal_fee, utxo_client, payment_address, payment_utxos,
                burn_address=burn_address, recipient_addr=recipient_addr, zonefile_hash=zonefile_hash, subsidize=True )

        assert unsigned_tx

        subsidized_tx = tx_make_subsidizable( unsigned_tx, fees_registration, 21 ** (10**6) * (10**8), 
                                              payment_privkey_info, utxo_client, tx_fee = tx_fee,
                                              add_dust_fee = False )
        assert subsidized_tx
    except (AssertionError, ValueError) as ve:
        if BLOCKSTACK_DEBUG:
            log.exception(ve)

        log.error("Failed to generate and subsidize renewal tx")
        return {'error': 'Failed to generate or subsidize tx'}

    resp = do_blockchain_tx( subsidized_tx, owner_utxos, privkey_info=owner_privkey_info, tx_broadcaster=tx_broadcaster, config_path=config_path, dry_run=dry_run )
    return resp


def do_revoke( fqu, owner_privkey_info, payment_privkey_info, utxo_client, tx_broadcaster, config_path=CONFIG_PATH,
               tx_fee=None, tx_fee_per_byte=None, proxy=None, dry_run=BLOCKSTACK_DRY_RUN, safety_checks=True):
    """
    Revoke a name
    Return {'status': True, 'transaction_hash': ...} on success
    Return {'error': ...} on failure
    """
    if proxy is None:
        proxy = get_default_proxy(config_path)

    if dry_run:
        assert tx_fee_per_byte, "need tx fee for dry run"
        safety_checks = False

    # wrap UTXO client so we remember UTXOs 
    utxo_client = build_utxo_client(utxo_client)

    fqu = str(fqu)
    owner_address = virtualchain.get_privkey_address(owner_privkey_info)
    payment_address = virtualchain.get_privkey_address(payment_privkey_info)
    min_confirmations = utxo_client.min_confirmations

    if not dry_run and (safety_checks or tx_fee is None):
        res = check_revoke(fqu, owner_privkey_info, payment_privkey_info, config_path=config_path, proxy=proxy, min_payment_confs=min_confirmations)
        if 'error' in res and safety_checks:
            log.error("Failed to check revoke: {}".format(res['error']))
            return res

        if not tx_fee_per_byte:
            tx_fee_per_byte = res['tx_fee_per_byte']

        if not tx_fee:
            tx_fee = res['tx_fee']

        assert tx_fee_per_byte, "Missing tx fee per byte"
        assert tx_fee, 'Missing tx fee'

    # get inputs
    try:
        payment_utxos = tx_get_unspents(payment_address, utxo_client)
        owner_utxos = tx_get_unspents(owner_address, utxo_client)
        log.debug("Payment address {} has {} UTXOs".format(payment_address, len(payment_utxos)))
        log.debug("Owner address {} has {} UTXOs".format(owner_address, len(owner_utxos)))
    except Exception as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        log.error("Failed to get inputs for {} and/or {}".format(payment_address, owner_address))
        return {'error': 'Failed to get payment and/or owner inputs'}

    # build up UTXO client with the UTXOs preloaded
    utxo_client = build_utxo_client( utxo_client, address=payment_address, utxos=payment_utxos )
    assert utxo_client, "Unable to build UTXO client"

    utxo_client = build_utxo_client( utxo_client, address=owner_address, utxos=owner_utxos )
    assert utxo_client, "Unable to build UTXO client"

    subsidized_tx = None
    try:
        unsigned_tx, num_utxos = make_cheapest_name_revoke( fqu, owner_address, utxo_client, payment_address, payment_utxos, subsidize=True )
        assert unsigned_tx

        subsidized_tx = tx_make_subsidizable( unsigned_tx, fees_revoke, 21 ** (10**6) * (10**8),
                                              payment_privkey_info, utxo_client, tx_fee = tx_fee,
                                              add_dust_fee = False )
        assert subsidized_tx is not None
    except (AssertionError, ValueError) as ve:
        if BLOCKSTACK_DEBUG:
            log.exception(ve)

        log.error("Failed to generate and subsidize revoke tx")
        return {'error': 'Failed to generate or subsidize tx'}

    log.debug("Revoking %s" % fqu)
    log.debug("<owner, payment> (%s, %s) tx_fee_per_byte = %s" % (owner_address, payment_address, tx_fee_per_byte))

    resp = do_blockchain_tx( subsidized_tx, owner_utxos, privkey_info=owner_privkey_info, tx_broadcaster=tx_broadcaster, config_path=config_path, dry_run=dry_run )
    return resp


def do_name_import( fqu, importer_privkey_info, recipient_address, zonefile_hash, utxo_client, tx_broadcaster, config_path=CONFIG_PATH, 
                    tx_fee=None, proxy=None, safety_checks=True, dry_run=BLOCKSTACK_DRY_RUN ):
    """
    Import a name
    Return {'status': True, 'transaction_hash': ..., 'value_hash': ...} on success
    Return {'error': ...} on failure
    """
    if proxy is None:
        proxy = get_default_proxy(config_path)

    fqu = str(fqu)
    
    # wrap UTXO client so we remember UTXOs 
    utxo_client = build_utxo_client(utxo_client)

    payment_address = virtualchain.get_privkey_address(importer_privkey_info)

    tx_fee = 0
    min_confirmations = utxo_client.min_confirmations

    if not dry_run and (safety_checks or tx_fee is None):
        res = check_name_import(fqu, importer_privkey_info, recipient_address, config_path=config_path, proxy=proxy, min_payment_confs=min_confirmations)
        if 'error' in res and safety_checks:
            log.error("Failed to check name import: {}".format(res['error']))
            return res

        tx_fee = res.get('tx_fee')
        assert tx_fee, 'Missing tx fee'

    # get payment inputs
    try:
        payment_utxos = tx_get_unspents(payment_address, utxo_client)
        log.debug("Payment address {} has {} UTXOs".format(payment_address, len(payment_utxos)))
    except Exception as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        log.error("Failed to get inputs for {}".format(payment_address))
        return {'error': 'Failed to get payment inputs'}

    # build up UTXO client with these UTXOs preloaded
    utxo_client = build_utxo_client( utxo_client, address=payment_address, utxos=payment_utxos )
    assert utxo_client, "Unable to build UTXO client"

    unsigned_tx = None
    num_utxos = None
    try:
        unsigned_tx, num_utxos = make_cheapest_name_import( fqu, recipient_address, zonefile_hash, payment_address, utxo_client, payment_utxos, tx_fee=tx_fee )
        assert unsigned_tx
    except (AssertionError, ValueError) as ve:
        if BLOCKSTACK_DEBUG:
            log.exception(ve)

        log.error("Failed to generate name-import tx")
        return {'error': 'Failed to generate tx'}

    log.debug("Import {} with {}".format(fqu, payment_address))
    log.debug("<payment, recipient> ({}, {}) tx_fee = {}".format(payment_address, recipient_address, tx_fee))

    resp = do_blockchain_tx( unsigned_tx, payment_utxos[:num_utxos], privkey_info=importer_privkey_info, tx_broadcaster=tx_broadcaster, config_path=config_path, dry_run=dry_run )
    if 'error' in resp:
        return resp

    resp['value_hash'] = zonefile_hash
    return resp


def do_namespace_preorder( namespace_id, cost, payment_privkey_info, reveal_address, utxo_client, tx_broadcaster,
                           consensus_hash=None, config_path=CONFIG_PATH, tx_fee=None, proxy=None, safety_checks=True, dry_run=BLOCKSTACK_DRY_RUN ):
    """
    Preorder a namespace
    Return {'status': True, 'transaction_hash': ...} on success
    Return {'error': ...} on failure
    """
    if proxy is None:
        proxy = get_default_proxy(config_path)

    # wrap UTXO client so we remember UTXOs 
    utxo_client = build_utxo_client(utxo_client)

    fqu = str(namespace_id)

    payment_address = virtualchain.get_privkey_address(payment_privkey_info)

    min_confirmations = utxo_client.min_confirmations
    tx_fee = 0

    if not dry_run and (safety_checks or tx_fee is None):
        res = check_namespace_preorder(namespace_id, payment_privkey_info, reveal_address, config_path=config_path, proxy=proxy, min_payment_confs=min_confirmations )
        if 'error' in res and safety_checks:
            log.error("Failed to check namespace preorder: {}".format(res['error']))
            return res

        tx_fee = res.get('tx_fee')
        assert tx_fee, 'Missing tx fee'

    # get consensus hash
    if consensus_hash is None:
        consensus_hash_res = get_consensus_hash( proxy, config_path=config_path )
        if 'error' in consensus_hash_res:
            return {'error': 'Failed to get consensus hash: %s' % consensus_hash_res['error']}

        consensus_hash = consensus_hash_res['consensus_hash']

    else:
        log.warn("Using caller-supplied consensus hash '%s'" % consensus_hash)

    try:
        payment_utxos = tx_get_unspents(payment_address, utxo_client)
        log.debug("Payment address {} has {} UTXOs".format(payment_address, len(payment_utxos)))
    except Exception as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        log.error("Failed to get inputs for {}".format(payment_address))
        return {'error': 'Failed to get payment inputs'}

    # build up UTXO client with these UTXOs preloaded
    utxo_client = build_utxo_client( utxo_client, address=payment_address, utxos=payment_utxos )
    assert utxo_client, "Unable to build UTXO client"

    log.debug("Preordering namespace (%s, %s, %s), tx_fee = %s" % (namespace_id, payment_address, reveal_address, tx_fee))

    unsigned_tx = None
    num_utxos = None
    try:
        unsigned_tx, num_utxos = make_cheapest_namespace_preorder(namespace_id, payment_address, reveal_address, cost, consensus_hash, utxo_client, payment_utxos, tx_fee=tx_fee)
        assert unsigned_tx
    except (AssertionError, ValueError) as ve:
        if BLOCKSTACK_DEBUG:
            log.exception(ve)

        log.error("Failed to create namespace preorder tx")
        return {'error': 'Insufficient funds'}

    resp = do_blockchain_tx( unsigned_tx, payment_utxos[:num_utxos], privkey_info=payment_privkey_info, tx_broadcaster=tx_broadcaster, config_path=config_path, dry_run=dry_run )
    return resp


def do_namespace_reveal( namespace_id, version_bits, reveal_address, lifetime, coeff, base_cost, bucket_exponents, nonalpha_discount, no_vowel_discount, payment_privkey_info, utxo_client, tx_broadcaster,
                         config_path=CONFIG_PATH, tx_fee=None, proxy=None, safety_checks=True, dry_run=BLOCKSTACK_DRY_RUN ):
    """
    Reveal a namespace
    Return {'status': True, 'transaction_hash': ...} on success
    Return {'error': ...} on failure
    """
    if proxy is None:
        proxy = get_default_proxy(config_path)

    # wrap UTXO client so we remember UTXOs 
    utxo_client = build_utxo_client(utxo_client)

    fqu = str(namespace_id)

    payment_address = virtualchain.get_privkey_address(payment_privkey_info)
    reveal_address = virtualchain.address_reencode( reveal_address )

    tx_fee = 0
    min_confirmations = utxo_client.min_confirmations

    if not dry_run and (safety_checks or tx_fee is None):
        res = check_namespace_reveal(namespace_id, payment_privkey_info, reveal_address, config_path=config_path, proxy=proxy, min_payment_confs=min_confirmations )
        if 'error' in res and safety_checks:
            log.error("Failed to check namespace preorder: {}".format(res['error']))
            return res

        tx_fee = res.get('tx_fee')
        assert tx_fee is not None, 'Missing tx fee'

    try:
        payment_utxos = tx_get_unspents(payment_address, utxo_client)
        log.debug("Payment address {} has {} UTXOs".format(payment_address, len(payment_utxos)))
    except Exception as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        log.error("Failed to get inputs for {}".format(payment_address))
        return {'error': 'Failed to get payment inputs'}

    # build up UTXO client with these UTXOs preloaded
    utxo_client = build_utxo_client( utxo_client, address=payment_address, utxos=payment_utxos )
    assert utxo_client, "Unable to build UTXO client"

    log.debug("Revealing namespace (%s, %s, %s), tx_fee = %s" % (namespace_id, payment_address, reveal_address, tx_fee))

    try:
        unsigned_tx, num_utxos = make_cheapest_namespace_reveal(namespace_id, version_bits, reveal_address, lifetime, coeff, base_cost, bucket_exponents,
                                                                nonalpha_discount, no_vowel_discount, payment_address, utxo_client, payment_utxos, tx_fee=tx_fee)
        assert unsigned_tx
    except (AssertionError, ValueError) as ve:
        if os.environ.get("BLOCKSTACK_TEST") == "1":
            log.exception(ve)

        return {'error': 'Insufficient funds'}

    resp = do_blockchain_tx( unsigned_tx, payment_utxos[:num_utxos], privkey_info=payment_privkey_info, tx_broadcaster=tx_broadcaster, config_path=config_path, dry_run=dry_run )
    return resp


def do_namespace_ready( namespace_id, reveal_privkey_info, utxo_client, tx_broadcaster, config_path=CONFIG_PATH, 
                        tx_fee=None, proxy=None, safety_checks=True, dry_run=BLOCKSTACK_DRY_RUN ):
    """
    Open a namespace for registration
    Return {'status': True, 'transaction_hash': ...} on success
    Return {'error': ...} on failure
    """

    if proxy is None:
        proxy = get_default_proxy(config_path)

    # wrap UTXO client so we remember UTXOs 
    utxo_client = build_utxo_client(utxo_client)

    fqu = str(namespace_id)

    reveal_address = virtualchain.get_privkey_address(reveal_privkey_info)

    tx_fee = 0
    min_confirmations = utxo_client.min_confirmations

    if not dry_run and (safety_checks or tx_fee is None):
        res = check_namespace_ready(namespace_id, reveal_privkey_info, config_path=config_path, proxy=proxy, min_payment_confs=min_confirmations )
        if 'error' in res and safety_checks:
            log.error("Failed to check namespace preorder: {}".format(res['error']))
            return res

        tx_fee = res.get('tx_fee')
        assert tx_fee, 'Missing tx fee'

    try:
        payment_utxos = tx_get_unspents(reveal_address, utxo_client)
        log.debug("Payment address {} has {} UTXOs".format(reveal_address, len(payment_utxos)))
    except Exception as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        log.error("Failed to get inputs for {}".format(reveal_address))
        return {'error': 'Failed to get payment inputs'}

    # build up UTXO client with these UTXOs preloaded
    utxo_client = build_utxo_client( utxo_client, address=reveal_address, utxos=payment_utxos )
    assert utxo_client, "Unable to build UTXO client"

    log.debug("Readying namespace (%s, %s), tx_fee = %s" % (namespace_id, reveal_address, tx_fee))

    try:
        unsigned_tx, num_utxos = make_cheapest_namespace_ready(namespace_id, reveal_address, utxo_client, payment_utxos, tx_fee=tx_fee)
        assert unsigned_tx
    except (AssertionError, ValueError) as ve:
        if BLOCKSTACK_DEBUG:
            log.exception(ve)

        log.error("Failed to create namespace-ready tx")
        return {'error': 'Insufficient funds'}

    resp = do_blockchain_tx( unsigned_tx, payment_utxos[:num_utxos], privkey_info=reveal_privkey_info, tx_broadcaster=tx_broadcaster, config_path=config_path, dry_run=dry_run )
    return resp


def do_announce( message_text, sender_privkey_info, utxo_client, tx_broadcaster, config_path=CONFIG_PATH, tx_fee_per_byte=None, proxy=None, safety_checks=True, dry_run=BLOCKSTACK_DRY_RUN ):
    """
    Send an announcement hash to the blockchain
    Return {'status': True, 'transaction_hash': ...} on success
    Return {'error': ...} on failure
    """

    if proxy is None:
        proxy = get_default_proxy(config_path)

    # wrap UTXO client so we remember UTXOs 
    utxo_client = build_utxo_client(utxo_client)

    message_text = str(message_text)
    message_hash = get_blockchain_compat_hash( message_text )

    sender_address = virtualchain.get_privkey_address( sender_privkey_info )
 
    # first things first: get fee per byte 
    if tx_fee_per_byte is None:
        tx_fee_per_byte = virtualchain.get_tx_fee_per_byte(config_path=config_path)
        if tx_fee_per_byte is None:
            log.error("Unable to calculate fee per byte")
            return {'error': 'Unable to get fee estimate'}

    tx_fee = estimate_announce_tx_fee( sender_privkey_info, tx_fee_per_byte, utxo_client, config_path=config_path )
    if tx_fee is None:
        log.error("Failed to estimate announce tx fee")
        return {'error': 'Failed to get fee estimate.  Please check your network settings and verify that you have sufficient funds.'}

    try:
        payment_utxos = tx_get_unspents(sender_address, utxo_client)
        log.debug("Payment address {} has {} UTXOs".format(sender_address, len(payment_utxos)))
    except Exception as e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        log.error("Failed to get inputs for {}".format(sender_address))
        return {'error': 'Failed to get payment inputs'}

    # build up UTXO client with these UTXOs preloaded
    utxo_client = build_utxo_client( utxo_client, address=sender_address, utxos=payment_utxos )
    assert utxo_client, "Unable to build UTXO client"

    log.debug("Announce (%s, %s) tx_fee = %s" % (message_hash, sender_address, tx_fee))

    try:
        unsigned_tx, num_utxos = make_cheapest_announce(message_hash, sender_address, utxo_client, payment_utxos, tx_fee=tx_fee)
        assert unsigned_tx
    except (AssertionError, ValueError) as ve:
        if BLOCKSTACK_DEBUG:
            log.exception(ve)

        log.error("Failed to create announce tx")
        return {'error': 'Insufficient funds'}

    resp = do_blockchain_tx( unsigned_tx, payment_utxos[:num_utxos], privkey_info=sender_privkey_info, tx_broadcaster=tx_broadcaster, config_path=config_path, dry_run=dry_run )
    if 'error' in resp:
        return resp

    # only tx?
    if dry_run:
        return resp

    # stash the announcement text
    res = put_announcement( message_text, resp['transaction_hash'] )
    if 'error' in res:
        log.error("Failed to store announcement text: %s" % res['error'])
        return {'error': 'Failed to store message text', 'transaction_hash': resp['transaction_hash'], 'message_hash': message_hash}

    else:
        resp['message_hash'] = message_hash
        return resp



def async_preorder(fqu, payment_privkey_info, owner_privkey_info, cost, name_data={}, min_payment_confs=TX_MIN_CONFIRMATIONS,
                   proxy=None, config_path=CONFIG_PATH, queue_path=DEFAULT_QUEUE_PATH,
                   safety_checks=True, tx_fee=None, consensus_hash=None, owner_address=None, burn_address=None ):
    """
        Preorder a fqu (step #1)

        @fqu: fully qualified name e.g., muneeb.id
        @payment_privkey_info: private key that will pay
        @owner_address: will own the name

        @transfer_address: will ultimately receive the name
        @zonefile_data: serialized zonefile for the name
        @profile: profile for the name

        Returns True/False and stores tx_hash in queue
    """

    if proxy is None:
        proxy = get_default_proxy(config_path=config_path)

    utxo_client = get_utxo_provider_client( config_path=config_path, min_confirmations=min_payment_confs )
    tx_broadcaster = get_tx_broadcaster( config_path=config_path )

    if not owner_privkey_info:
        assert owner_address, "need owner private key or address"
        owner_address = virtualchain.address_reencode(str(owner_address))
    else:
        owner_address = virtualchain.get_privkey_address( owner_privkey_info )

    payment_address = virtualchain.get_privkey_address( payment_privkey_info )

    # stale preorder will get removed from preorder_queue
    if in_queue("register", fqu, path=queue_path):
        log.error("Already in register queue: %s" % fqu)
        return {'error': 'Already in register queue'}

    if in_queue("preorder", fqu, path=queue_path):
        log.error("Already in preorder queue: %s" % fqu)
        return {'error': 'Already in preorder queue'}

    try:
        resp = do_preorder( fqu, payment_privkey_info, owner_privkey_info, cost, utxo_client, tx_broadcaster, config_path=CONFIG_PATH,
                safety_checks=safety_checks, tx_fee=tx_fee, consensus_hash=consensus_hash, owner_address=owner_address, burn_address=burn_address )

    except Exception, e:
        log.exception(e)
        return {'error': 'Failed to sign and broadcast preorder transaction'}

    additionals = {}
    if 'unsafe_reg' in name_data:
        additionals['unsafe_reg'] = name_data['unsafe_reg']
        additionals['confirmations_needed'] = name_data.get('confirmations_needed', 4)
        log.debug("Adding an *aggressive* preorder for {}; only waiting {} confirmations".format(fqu, additionals['confirmations_needed']))

    if 'min_payment_confs' in name_data:
        additionals['min_payment_confs'] = name_data['min_payment_confs']

    if 'owner_privkey' in name_data:
        additionals['owner_privkey'] = name_data['owner_privkey']

    if 'payment_privkey' in name_data:
        additionals['payment_privkey'] = name_data['payment_privkey']

    if 'transaction_hash' in resp:
        if not BLOCKSTACK_DRY_RUN:
            # watch this preorder, and register it when it gets queued
            queue_append("preorder", fqu, resp['transaction_hash'],
                         payment_address=payment_address,
                         owner_address=owner_address,
                         transfer_address=name_data.get('transfer_address'),
                         zonefile_data=name_data.get('zonefile'),
                         zonefile_hash=name_data.get('zonefile_hash'),
                         profile=name_data.get('profile'),
                         config_path=config_path,
                         path=queue_path, **additionals)
    else:
        assert 'error' in resp
        log.error("Error preordering: %s with %s for %s" % (fqu, payment_address, owner_address))
        log.error("Error below\n%s" % json.dumps(resp, indent=4, sort_keys=True))
        return {'error': 'Failed to preorder: %s' % resp['error']}

    return resp


def check_owner_privkey_info(owner_privkey_info, name_data):
    """
    Get the right owner private key and address, given the caller-given owner private key
    and the name data.  The name data may stipulate that the registrar should use an encrypted
    owner private key instead.  Determine if this is the case and return the owner private key
    and address that we should use.

    Return (owner_address, owner_privkey_info)
    """
    
    owner_address = None

    if owner_privkey_info is not None:
        owner_address = virtualchain.get_privkey_address(owner_privkey_info)

    if 'owner_address' in name_data and owner_address != name_data['owner_address'] and 'owner_privkey' in name_data:

       if owner_address is not None:
           log.debug("Registrar owner address changed since beginning registration : from {} to {}".format(name_data['owner_address'], owner_address))

       passwd = get_secret('BLOCKSTACK_CLIENT_WALLET_PASSWORD')
       owner_privkey_info = aes_decrypt(str(name_data['owner_privkey']), hexlify( passwd ))
       possible_addresses = []
       if owner_privkey_info is not None:
           try:
               owner_privkey_info = json.loads(owner_privkey_info)
               possible_addresses = [virtualchain.get_privkey_address(owner_privkey_info)]
           except Exception as e:
               possible_addresses = [
                    virtualchain.address_reencode(keylib.ECPrivateKey(owner_privkey_info, compressed=True).public_key().address()), 
                    virtualchain.address_reencode(keylib.ECPrivateKey(owner_privkey_info, compressed=False).public_key().address()),
               ]

       if name_data['owner_address'] not in possible_addresses:
           raise Exception("Attempting to correct registrar owner address to {}, but failed! Got {}".format(owner_address, ','.join(possible_addresses)))
       
       if owner_privkey_info is not None:
           owner_address = virtualchain.get_privkey_address(owner_privkey_info)
       else:
           owner_address = name_data['owner_address']

    return virtualchain.address_reencode(str(owner_address)), owner_privkey_info


def check_payment_privkey_info(payment_privkey_info, name_data):
    """
    Get the right payment private key and address, given the caller-given payment private key
    and the name data.  The name data may stipulate that the registrar should use an encrypted
    payment private key instead.  Determine if this is the case and return the payment private key
    and address that we should use.

    Return (payment_address, payment_privkey_info)
    """

    payment_address = None

    if payment_privkey_info is not None:
        payment_address = virtualchain.get_privkey_address(payment_privkey_info)

    if 'payment_address' in name_data and payment_address != name_data['payment_address']:

       if payment_address is not None:
           log.debug("Registrar payment address changed since beginning registration : from {} to {}".format(
               name_data['payment_address'], payment_address))

       passwd = get_secret('BLOCKSTACK_CLIENT_WALLET_PASSWORD')
       payment_privkey_info = aes_decrypt(str(name_data['payment_privkey']), hexlify(passwd))
       possible_addresses = []
       if payment_privkey_info is not None:
           try:
               payment_privkey_info = json.loads(payment_privkey_info)
               possible_addresses = [virtualchain.get_privkey_address(payment_privkey_info)]
           except Exception as e:
               possible_addresses = [
                    virtualchain.address_reencode(keylib.ECPrivateKey(payment_privkey_info, compressed=True).public_key().address()), 
                    virtualchain.address_reencode(keylib.ECPrivateKey(payment_privkey_info, compressed=False).public_key().address()),
               ]

       if name_data['payment_address'] not in possible_addresses:
           raise Exception("Attempting to correct registrar payment address to {}, but failed! Got {}".format(payment_address, ','.join(possible_addresses)))
        
       if payment_privkey_info is not None:
           payment_address = virtualchain.get_privkey_address(payment_privkey_info)
       else:
           payment_address = name_data['payment_address']

    return virtualchain.address_reencode(str(payment_address)), payment_privkey_info


def async_register(fqu, payment_privkey_info, owner_privkey_info, name_data={}, owner_address=None,
                   proxy=None, config_path=CONFIG_PATH, queue_path=DEFAULT_QUEUE_PATH, safety_checks=True):
    """
        Register a previously preordered fqu (step #2)

        @fqu: fully qualified name e.g., muneeb.id

        Uses from preorder queue:
        @payment_address: used for making the payment
        @owner_address: will own the fqu (must be same as preorder owner_address)

        Return {'status': True, ...} on success
        Return {'error': ...} on error
    """
    
    import blockstack

    if proxy is None:
        proxy = get_default_proxy(config_path=config_path)

    if 'min_payment_confs' in name_data:
        utxo_client = get_utxo_provider_client( config_path=config_path,
                                                min_confirmations=name_data['min_payment_confs'] )
    else:
        utxo_client = get_utxo_provider_client(config_path=config_path)

    tx_broadcaster = get_tx_broadcaster( config_path=config_path )
   
    zonefile_hash = name_data.get('zonefile_hash')
    zonefile_data = name_data.get('zonefile')

    if zonefile_data is not None:
        if zonefile_hash is None:
            zonefile_hash = get_zonefile_data_hash(zonefile_data)
        
        else:
            assert get_zonefile_data_hash(zonefile_data) == zonefile_hash, "Conflicting zone file hash given"

        if len(zonefile_data) > RPC_MAX_ZONEFILE_LEN:
            return {'error': 'Zonefile is too big (%s bytes)' % len(zonefile_data)}

    if owner_address is None:
        owner_address, owner_privkey_info = check_owner_privkey_info( owner_privkey_info, name_data )

        # only owner address is strictly needed
        assert owner_address

    payment_address, payment_privkey_info = check_payment_privkey_info( payment_privkey_info, name_data )

    assert payment_address
    assert payment_privkey_info

    owner_address = virtualchain.address_reencode(str(owner_address))
    payment_address = virtualchain.address_reencode(str(payment_address))

    # check register_queue first
    # stale preorder will get removed from preorder_queue
    if in_queue("register", fqu, path=queue_path):
        log.error("Already in register queue: %s" % fqu)
        return {'error': 'Already in register queue'}

    if not in_queue("preorder", fqu, path=queue_path):
        log.error("No preorder sent yet: %s" % fqu)
        return {'error': 'No preorder sent yet'}

    preorder_entry = queue_findone( "preorder", fqu, path=queue_path )
    if len(preorder_entry) == 0:
        log.error("No preorder for '%s'" % fqu)
        return {'error': 'No preorder found'}

    preorder_tx = preorder_entry[0]['tx_hash']
    tx_confirmations = get_tx_confirmations(preorder_tx, config_path=config_path)

    if tx_confirmations < PREORDER_CONFIRMATIONS:
        log.error("Waiting on preorder confirmations: (%s, %s)"
                  % (preorder_tx, tx_confirmations))

        return {'error': 'Waiting on preorder confirmations'}

    # configure registrar with information from the preorder
    additionals = {}
    force_register = False
    if 'unsafe_reg' in name_data:
        log.debug("Adding an *aggressive* register for {}".format(fqu))
        additionals['unsafe_reg'] = name_data['unsafe_reg']
        additionals['confirmations_needed'] = 1
        force_register = True

    if 'min_payment_confs' in name_data:
        additionals['min_payment_confs'] = name_data['min_payment_confs']

    if 'owner_privkey' in name_data:
        additionals['owner_privkey'] = name_data['owner_privkey']

    if 'payment_privkey' in name_data:
        additionals['payment_privkey'] = name_data['payment_privkey']

    # F-day 2017
    is_regup = False
    regup_zonefile_hash = None
    block_height = get_block_height(config_path=config_path)
    if block_height is None:
        return {'error': 'Failed to get blockchain height'}

    if blockstack.EPOCH_FEATURE_OP_REGISTER_UPDATE in blockstack.get_epoch_features(block_height):
        # can set zonefile hash in this epoch 
        regup_zonefile_hash = zonefile_hash
        is_regup = True

    try:
        resp = do_register( fqu, payment_privkey_info, owner_privkey_info, utxo_client, tx_broadcaster, owner_address=owner_address,
                            zonefile_hash=regup_zonefile_hash, config_path=config_path, proxy=proxy, force_register = force_register )
    except Exception, e:
        log.exception(e)
        return {'error': 'Failed to sign and broadcast registration transaction'}

    if 'transaction_hash' in resp:
        if not BLOCKSTACK_DRY_RUN:
            queue_append("register", fqu, resp['transaction_hash'],
                         payment_address=payment_address,
                         owner_address=owner_address,
                         transfer_address=name_data.get('transfer_address'),
                         zonefile_data=name_data.get('zonefile'),
                         profile=name_data.get('profile'),
                         is_regup=is_regup,
                         config_path=config_path,
                         path=queue_path, **additionals)

        return resp

    else:
        assert 'error' in resp
        log.error("Error registering: %s" % fqu)
        log.error(resp)
        return {'error': 'Failed to send registration: {}'.format(resp['error'])}


def async_update(fqu, zonefile_data, profile, owner_privkey_info, payment_privkey_info,
                 name_data={}, config_path=CONFIG_PATH,
                 zonefile_hash=None, proxy=None, queue_path=DEFAULT_QUEUE_PATH ):
    """
        Update a previously registered fqu, using a different payment address

        @fqu: fully qualified name e.g., muneeb.id
        @zonefile_data: new zonefile text, hash(zonefile) goes to blockchain.  If not given, it will be extracted from name_data
        @profile: the name's profile.  If not given, it will be extracted from name_data
        @owner_privkey_info: privkey of owner address, to sign update
        @payment_privkey_info: the privkey which is paying for the cost

        @zonefile_hash: the hash of the zonefile.  Must match the zonefile_data (or name_data['zonefile'])

        return {'status': True} on success
        Return {'error': ...} on error
    """

    if zonefile_data is None:
        zonefile_data = name_data.get('zonefile')
    elif name_data.get('zonefile') is not None and zonefile_data != name_data.get('zonefile'):
        assert name_data['zonefile'] == zonefile_data, "Conflicting zone file data given"

    if profile is None:
        profile = name_data.get('profile')
    elif name_data.get('profile') is not None and profile != name_data.get('profile'):
        assert name_data['profile'] == profile, "Conflicting profile data given"

    assert zonefile_hash is not None or zonefile_data is not None, "No zone file or zone file hash given"

    if zonefile_hash is None and zonefile_data is not None:
        zonefile_hash = get_zonefile_data_hash( zonefile_data )

    if name_data.get('zonefile_hash') is not None:
        assert name_data['zonefile_hash'] == zonefile_hash, "Conflicting zone file hash given"

    if zonefile_data is not None and len(zonefile_data) > RPC_MAX_ZONEFILE_LEN:
        return {'error': 'Zonefile is too big (%s bytes)' % len(zonefile_data)}

    if proxy is None:
        proxy = get_default_proxy(config_path=config_path)

    # Are we the result of a register? If so, use it to configure our transaction
    register_entry = queue_findone( "register", fqu, path=queue_path )
    if len(register_entry) == 0:
        register_data = {}
    else:
        register_data = extract_entry( register_entry[0] )

    if 'min_payment_confs' in register_data:
        utxo_client = get_utxo_provider_client( config_path=config_path,
                                                min_confirmations=register_data['min_payment_confs'] )
    else:
        utxo_client = get_utxo_provider_client(config_path=config_path)

    tx_broadcaster = get_tx_broadcaster(config_path=config_path)

    owner_address, owner_privkey_info = check_owner_privkey_info( owner_privkey_info, name_data )
    payment_address, payment_privkey_info = check_payment_privkey_info( payment_privkey_info, name_data )
    
    assert owner_address
    assert owner_privkey_info
    assert payment_address
    assert payment_privkey_info

    owner_address = virtualchain.address_reencode(str(owner_address))
    payment_address = virtualchain.address_reencode(str(payment_address))

    if in_queue("update", fqu, path=queue_path):
        log.error("Already in update queue: %s" % fqu)
        return {'error': 'Already in update queue'}

    # configure any additional information about the registrar entry.
    additionals = {}
    force_update = True

    if 'unsafe_reg' in register_data:
        log.debug("Adding an *aggressive* update for {}".format(fqu))
        additionals['unsafe_reg'] = register_data['unsafe_reg']
        additionals['confirmations_needed'] = 1
        force_update = True

    if 'owner_privkey' in name_data:
        additionals['owner_privkey'] = name_data['owner_privkey']

    if 'payment_privkey' in name_data:
        additionals['payment_privkey'] = name_data['payment_privkey']

    resp = {}
    try:
        resp = do_update( fqu, zonefile_hash, owner_privkey_info, payment_privkey_info, utxo_client, tx_broadcaster,
                          config_path=config_path, proxy=proxy, force_update=force_update )
    except Exception, e:
        log.exception(e)
        return { 'error':
                 'Failed to sign and broadcast update transaction. Exception: {}'.format(e) }

    if 'transaction_hash' in resp:
        if not BLOCKSTACK_DRY_RUN:
            queue_append("update", fqu, resp['transaction_hash'],
                         payment_address = payment_address,
                         zonefile_data=zonefile_data,
                         profile=profile,
                         zonefile_hash=zonefile_hash,
                         owner_address=owner_address,
                         transfer_address=name_data.get('transfer_address'),
                         config_path=config_path,
                         path=queue_path, **additionals)

        resp['zonefile_hash'] = zonefile_hash
        return resp

    else:
        assert 'error' in resp
        log.error("Error updating: %s" % fqu)
        log.error(resp)
        return {'error': 'Failed to broadcast update transaction: {}'.format(resp['error'])}


def async_transfer(fqu, transfer_address, owner_privkey_info, payment_privkey_info,
                   config_path=CONFIG_PATH, proxy=None, queue_path=DEFAULT_QUEUE_PATH, name_data = {}):
    """
        Transfer a previously registered fqu, using a different payment address.
        Preserves the zonefile.

        @fqu: fully qualified name e.g., muneeb.id
        @transfer_address: new owner address
        @owner_privkey_info: privkey of current owner address, to sign tx
        @payment_privkey_info: the key which is paying for the cost

        Return {'status': True, 'transaction_hash': ...} on success
        Return {'error': ...} on failure
    """

    if proxy is None:
        proxy = get_default_proxy(config_path=config_path)

    utxo_client = get_utxo_provider_client(config_path=config_path)
    tx_broadcaster = get_tx_broadcaster(config_path=config_path)

    owner_address, owner_privkey_info = check_owner_privkey_info( owner_privkey_info, name_data )
    payment_address, payment_privkey_info = check_payment_privkey_info( payment_privkey_info, name_data )

    assert owner_address
    assert owner_privkey_info
    assert payment_address
    assert payment_privkey_info

    owner_address = virtualchain.address_reencode(str(owner_address))
    payment_address = virtualchain.address_reencode(str(payment_address))

    if in_queue("transfer", fqu, path=queue_path):
        log.error("Already in transfer queue: %s" % fqu)
        return {'error': 'Already in transfer queue'}

    try:
        resp = do_transfer( fqu, transfer_address, True, owner_privkey_info, payment_privkey_info, utxo_client, tx_broadcaster,
                            config_path=config_path, proxy=proxy )
    except Exception, e:
        log.exception(e)
        return {'error': 'Failed to sign and broadcast transfer transaction'}

    additionals = {}
    if 'owner_privkey' in name_data:
        additionals['owner_privkey'] = name_data['owner_privkey']
    if 'payment_privkey' in name_data:
        additionals['payment_privkey'] = name_data['payment_privkey']

    if 'transaction_hash' in resp:
        if not BLOCKSTACK_DRY_RUN:
            queue_append("transfer", fqu, resp['transaction_hash'],
                         owner_address=owner_address,
                         transfer_address=transfer_address,
                         config_path=config_path,
                         path=queue_path, **additionals)
    else:
        assert 'error' in resp
        log.error("Error transferring: %s" % fqu)
        log.error(resp)
        return {'error': 'Failed to broadcast transfer transaction: {}'.format(resp['error'])}

    return resp


def async_renew(fqu, owner_privkey_info, payment_privkey_info, renewal_fee, new_owner_address=None, zonefile_txt=None, profile=None,
                proxy=None, config_path=CONFIG_PATH, queue_path=DEFAULT_QUEUE_PATH):
    """
        Renew an already-registered name.

        @fqu: fully qualified name e.g., muneeb.id

        Return {'status': True, ...} on success
        Return {'error': ...} on error
    """

    if proxy is None:
        proxy = get_default_proxy(config_path=config_path)

    owner_address = virtualchain.get_privkey_address( owner_privkey_info )
    utxo_client = get_utxo_provider_client(config_path=config_path)
    tx_broadcaster = get_tx_broadcaster( config_path=config_path )

    zonefile_hash = None
    if zonefile_txt:
        zonefile_hash = get_zonefile_data_hash(zonefile_txt)

    # check renew queue first
    if in_queue("renew", fqu, path=queue_path):
        log.error("Already in renew queue: %s" % fqu)
        return {'error': 'Already in renew queue'}

    try:
        resp = do_renewal( fqu, owner_privkey_info, payment_privkey_info, renewal_fee, utxo_client, tx_broadcaster,
                           config_path=config_path, proxy=proxy, zonefile_hash=zonefile_hash, recipient_addr=new_owner_address )
    except Exception, e:
        log.exception(e)
        return {'error': 'Failed to sign and broadcast renewal transaction'}

    if 'error' in resp or 'transaction_hash' not in resp:
        log.error("Error renewing: %s" % fqu)
        log.error(resp)
        return {'error': 'Failed to send renewal: {}'.format(resp['error'])}

    else:
        if 'transaction_hash' in resp:
            if not BLOCKSTACK_DRY_RUN:
                queue_append("renew", fqu, resp['transaction_hash'],
                             owner_address=owner_address,
                             transfer_address=new_owner_address,
                             zonefile_data = zonefile_txt,
                             zonefile_hash = zonefile_hash,
                             profile = profile,
                             config_path=config_path,
                             path=queue_path)
        return resp


def async_revoke(fqu, owner_privkey_info, payment_privkey_info, 
                 proxy=None, config_path=CONFIG_PATH, queue_path=DEFAULT_QUEUE_PATH):
    """
        Revoke a name.

        @fqu: fully qualified name e.g., muneeb.id

        Return {'status': True, ...} on success
        Return {'error': ...} on error
    """

    if proxy is None:
        proxy = get_default_proxy(config_path=config_path)

    owner_address = virtualchain.get_privkey_address( owner_privkey_info )
    utxo_client = get_utxo_provider_client(config_path=config_path)
    tx_broadcaster = get_tx_broadcaster( config_path=config_path )

    # check revoke queue first
    if in_queue("revoke", fqu, path=queue_path):
        log.error("Already in revoke queue: %s" % fqu)
        return {'error': 'Already in revoke queue'}

    try:
        resp = do_revoke( fqu, owner_privkey_info, payment_privkey_info, utxo_client, tx_broadcaster,
                          config_path=config_path, proxy=proxy )

    except Exception, e:
        log.exception(e)
        return {'error': 'Failed to sign and broadcast revoke transaction'}

    if 'error' in resp or 'transaction_hash' not in resp:
        log.error("Error revoking: %s" % fqu)
        log.error(resp)
        return {'error': 'Failed to send revoke: {}'.format(resp['error'])}

    else:
        if 'transaction_hash' in resp:
            if not BLOCKSTACK_DRY_RUN:
                queue_append("revoke", fqu, resp['transaction_hash'],
                             owner_address=owner_address,
                             config_path=config_path,
                             path=queue_path)

        return resp
