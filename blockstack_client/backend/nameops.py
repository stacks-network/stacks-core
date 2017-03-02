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
import simplejson
import pybitcoin
import traceback
import time

# Hack around absolute paths
current_dir = os.path.abspath(os.path.dirname(__file__))
parent_dir = os.path.abspath(current_dir + "/../")

from .queue import in_queue, queue_append, queue_findone

from .blockchain import get_tx_confirmations
from .blockchain import is_address_usable
from .blockchain import can_receive_name, get_balance, get_tx_fee, get_utxos
from .blockchain import get_block_height

from crypto.utils import get_address_from_privkey, get_pubkey_from_privkey

from ..utils import pretty_print as pprint
from ..utils import pretty_dump

from ..config import PREORDER_CONFIRMATIONS, DEFAULT_QUEUE_PATH, CONFIG_PATH, get_utxo_provider_client, get_tx_broadcaster, RPC_MAX_ZONEFILE_LEN, RPC_MAX_PROFILE_LEN
from ..config import get_logger, APPROX_TX_IN_P2PKH_LEN, APPROX_TX_OUT_P2PKH_LEN, APPROX_TX_OVERHEAD_LEN, APPROX_TX_IN_P2SH_LEN, APPROX_TX_OUT_P2SH_LEN
from ..constants import BLOCKSTACK_TEST, BLOCKSTACK_DEBUG, TX_MIN_CONFIRMATIONS

from ..proxy import get_default_proxy
from ..proxy import getinfo as blockstack_getinfo
from ..proxy import get_name_cost as blockstack_get_name_cost
from ..proxy import get_name_blockchain_record as blockstack_get_name_blockchain_record
from ..proxy import get_namespace_blockchain_record as blockstack_get_namespace_blockchain_record
from ..proxy import is_name_registered, is_name_owner

from ..tx import sign_tx, sign_and_broadcast_tx, preorder_tx, register_tx, update_tx, transfer_tx, revoke_tx, \
        namespace_preorder_tx, namespace_reveal_tx, namespace_ready_tx, announce_tx, name_import_tx, sign_tx

from ..scripts import tx_make_subsidizable
from ..storage import get_blockchain_compat_hash, hash_zonefile, put_announcement, get_zonefile_data_hash

from ..operations import fees_update, fees_transfer, fees_revoke, fees_registration, fees_preorder, \
        fees_namespace_preorder, fees_namespace_reveal, fees_namespace_ready, fees_announce

from ..keys import get_privkey_info_address, get_privkey_info_params

from .safety import *

import virtualchain

log = get_logger("blockstack-client")


class UTXOWrapper(object):
    """
    Class for wrapping a known list of UTXOs for a set of addresses.
    Compatible with pybitcoin's UTXO service class.
    Requires get_unspents()
    """
    def __init__(self):
        self.utxos = {}

    def add_unspents( self, addr, unspents ):
        # sanity check...
        for unspent in unspents:
            assert unspent.has_key('transaction_hash')
            assert unspent.has_key('output_index')

        if not self.utxos.has_key(addr):
            self.utxos[addr] = []

        self.utxos[addr] += unspents

    def get_unspents( self, addr ):
        if addr not in self.utxos:
            raise ValueError("No unspents for address {}".format(addr))

        return self.utxos[addr]


def estimate_dust_fee( tx, fee_estimator ):
    """
    Estimate the dust fee of an operation.
    fee_estimator is a callable, and is one of the operation's get_fees() methods.
    Return the number of satoshis on success
    Return None on error
    """
    tx = virtualchain.tx_deserialize( tx )
    tx_inputs = tx['vin']
    tx_outputs = tx['vout']
    dust_fee, op_fee = fee_estimator( tx_inputs, tx_outputs )
    log.debug("dust_fee is %s" % dust_fee)
    return dust_fee


def make_fake_privkey_info( privkey_params ):
    """
    Make fake private key information, given parameters.
    Used for generating fake transactions and estimating fees.
    @privkey_params is a 2-tuple, with m and n (m of n signatures).
        (1, 1) means "use a single private key"
        (m, n) means "use multiple signatures and a redeem script"
    """
    if privkey_params is None or privkey_params[0] < 1 or privkey_params[1] < 1:
        raise Exception("Invalid private key parameters %s" % str(privkey_params))

    if privkey_params == (1, 1):
        # fake private key
        return "5512612ed6ef10ea8c5f9839c63f62107c73db7306b98588a46d0cd2c3d15ea5"

    else:
        m, n = privkey_params
        return virtualchain.make_multisig_wallet( m, n )


def estimate_payment_bytes( payment_address, utxo_client, num_payment_sigs=None, config_path=CONFIG_PATH ):
    """
    Given the payment address and number of owner signatures, estimate how many
    extra bytes will be needed to include the payment inputs and outputs

    Return the number of bytes on success
    Raise ValueError if there are no UTXOs
    Raise Exception if we can't query UTXOs
    """

    payment_utxos = get_utxos( payment_address, config_path=config_path, utxo_client=utxo_client )
    if payment_utxos is None:
        log.error("No UTXOs returned")
        raise ValueError()

    if 'error' in payment_utxos:
        log.error("Failed to query UTXOs for %s: %s" % payment_address, payment_utxos['error'])
        raise Exception("Failed to query UTXO provider: %s" % payment_utxos['error'])

    num_payment_inputs = len(payment_utxos)
    if num_payment_inputs == 0:
        # assume at least one payment UTXO
        num_payment_inputs = 1

    if num_payment_sigs is None:
        # try to guess from the address
        if virtualchain.is_p2sh_address(payment_address):
            log.warning("Assuming 2 signatures required from p2sh payment address")
            num_payment_sigs = 2

        else:
            num_payment_sigs = 1

    payment_input_len = 0
    payment_output_len = 0

    if virtualchain.is_p2sh_address(payment_address):
        payment_input_len = APPROX_TX_IN_P2SH_LEN
        payment_output_len = APPROX_TX_OUT_P2SH_LEN
    else:
        payment_input_len = APPROX_TX_IN_P2PKH_LEN
        payment_output_len = APPROX_TX_IN_P2PKH_LEN

    # assuming they're p2pkh outputs...
    subsidy_byte_count = APPROX_TX_OVERHEAD_LEN + (num_payment_inputs * (71 + payment_input_len)) + payment_output_len # ~71 bytes for signature
    return subsidy_byte_count


def estimate_owner_output_length( owner_address, owner_num_sigs=None ):
    """
    Estimate the length of the owner input/output
    of a transaction
    """
    assert owner_address
    owner_address = str(owner_address)

    if virtualchain.is_p2sh_address( owner_address ):
        if owner_num_sigs is None:
            log.warning("Guessing that owner address {} requires 2 signatures".format(owner_address))
            owner_num_sigs = 2

        return APPROX_TX_OVERHEAD_LEN + APPROX_TX_IN_P2SH_LEN + APPROX_TX_OUT_P2SH_LEN

    else:
        return APPROX_TX_OVERHEAD_LEN + APPROX_TX_IN_P2PKH_LEN + APPROX_TX_OUT_P2PKH_LEN


def subsidize_or_pad_transaction( unsigned_tx, owner_address, owner_privkey_params, payment_privkey_info, fees_func, utxo_client, payment_address=None, config_path=CONFIG_PATH ):
    """
    Subsidize an unsigned transaction, or append the equivalent
    number of bytes (as 0's).

    The point is to get a byte string that is long enough.

    Return the new transaction on success
    Raise Exception if payment_address is None and private key info is None
    """

    fake_privkey = make_fake_privkey_info( owner_privkey_params )
    signed_subsidized_tx = None

    if payment_privkey_info is not None:
        # actually try to subsidize this tx
        subsidized_tx = tx_make_subsidizable( unsigned_tx, fees_func, 21 * 10**14, payment_privkey_info, utxo_client )
        assert subsidized_tx is not None

        signed_subsidized_tx = sign_tx( subsidized_tx, fake_privkey )

        # there will be at least one more output here (the registration output), so append that too
        pad_len = estimate_owner_output_length(owner_address)
        signed_subsidized_tx += "00" * pad_len

    else:
        # do a rough size estimation
        if payment_address is None:
            log.error("BUG: missing payment private key and address")
            raise Exception("Need either payment_privkey_info or payment_address")

        num_extra_bytes = estimate_payment_bytes( payment_address, utxo_client, config_path=config_path )
        signed_subsidized_tx = unsigned_tx + '00' * num_extra_bytes

    return signed_subsidized_tx


def estimate_preorder_tx_fee( name, name_cost, owner_address, payment_addr, utxo_client, min_payment_confs=TX_MIN_CONFIRMATIONS, owner_privkey_params=(None, None), config_path=CONFIG_PATH, include_dust=False ):
    """
    Estimate the transaction fee of a preorder.
    Optionally include the dust fees as well.
    Return the number of satoshis on success
    Return None on error
    """

    assert owner_address
    assert payment_addr

    owner_address = str(owner_address)
    payment_addr = str(payment_addr)

    fake_consensus_hash = 'd4049672223f42aac2855d2fbf2f38f0'

    try:
        unsigned_tx = preorder_tx( name, payment_addr, owner_address, name_cost, fake_consensus_hash, utxo_client, min_payment_confs=min_payment_confs )
        assert unsigned_tx
    except (ValueError, AssertionError) as e:
        # unfunded payment addr
        unsigned_tx = preorder_tx( name, payment_addr, owner_address, name_cost, fake_consensus_hash, utxo_client, safety=False, subsidize=True, min_payment_confs=min_payment_confs )
        assert unsigned_tx

        pad_len = estimate_owner_output_length(owner_address)
        unsigned_tx += "00" * pad_len

    signed_subsidized_tx = subsidize_or_pad_transaction(unsigned_tx, owner_address, owner_privkey_params, None, fees_preorder, utxo_client, payment_address=payment_addr, config_path=config_path )

    tx_fee = get_tx_fee( signed_subsidized_tx, config_path=config_path )
    if tx_fee is None:
        log.error("Failed to get tx fee")
        return None

    log.debug("preorder tx %s bytes, %s satoshis" % (len(signed_subsidized_tx)/2, int(tx_fee)))

    if include_dust:
        dust_fee = estimate_dust_fee( signed_subsidized_tx, fees_preorder )
        assert dust_fee is not None
        log.debug("Additional dust fee: %s" % dust_fee)
        tx_fee += dust_fee

    return tx_fee


def estimate_register_tx_fee( name, owner_addr, payment_addr, utxo_client, owner_privkey_params=(None, None), config_path=CONFIG_PATH, include_dust=False ):
    """
    Estimate the transaction fee of a register.
    Optionally include the dust fees as well.
    Return the number of satoshis on success
    Return None on error
    """

    assert owner_addr
    assert payment_addr

    owner_addr = str(owner_addr)
    payment_addr = str(payment_addr)

    fake_privkey = make_fake_privkey_info( owner_privkey_params )

    try:
        unsigned_tx = register_tx( name, payment_addr, owner_addr, utxo_client, subsidized=True )
        assert unsigned_tx
    except (ValueError, AssertionError) as e:
        # no UTXOs for this owner address.  Try again and add padding for one
        unsigned_tx = register_tx( name, payment_addr, owner_addr, utxo_client, subsidized=True, safety=False )
        assert unsigned_tx

        pad_len = estimate_owner_output_length(owner_addr)
        unsigned_tx += "00" * pad_len

    signed_subsidized_tx = subsidize_or_pad_transaction(unsigned_tx, owner_addr, owner_privkey_params, None, fees_registration, utxo_client, payment_address=payment_addr, config_path=config_path )

    tx_fee = get_tx_fee( signed_subsidized_tx, config_path=config_path )
    if tx_fee is None:
        log.error("Failed to get tx fee")
        return None

    log.debug("register tx %s bytes, %s satoshis txfee" % (len(signed_subsidized_tx)/2, int(tx_fee)))

    if include_dust:
        dust_fee = estimate_dust_fee( signed_subsidized_tx, fees_registration )
        assert dust_fee is not None
        log.debug("Additional dust fee: %s" % dust_fee)
        tx_fee += dust_fee

    return tx_fee


def estimate_renewal_tx_fee( name, renewal_fee, payment_privkey_info, owner_privkey_info, utxo_client, config_path=CONFIG_PATH, include_dust=False ):
    """
    Estimate the transaction fee of a renewal.
    Optionally include the dust fees as well.
    Return the number of satoshis on success
    Return None on error
    """

    payment_address = get_privkey_info_address( payment_privkey_info )
    owner_address = get_privkey_info_address( owner_privkey_info )
    owner_privkey_params = get_privkey_info_params(owner_privkey_info)

    try:
        unsigned_tx = register_tx( name, owner_address, owner_address, utxo_client, renewal_fee=renewal_fee )
    except (AssertionError, ValueError), ve:
        # no UTXOs for this owner address.  Try again and add padding for one
        unsigned_tx = register_tx( name, owner_address, owner_address, utxo_client, renewal_fee=renewal_fee, subsidized=True, safety=False )
        assert unsigned_tx

        pad_len = estimate_owner_output_length(owner_address)
        unsigned_tx += "00" * pad_len

    signed_subsidized_tx = subsidize_or_pad_transaction(unsigned_tx, owner_address, owner_privkey_params, payment_privkey_info, fees_registration, utxo_client, payment_address=payment_address, config_path=config_path )

    tx_fee = get_tx_fee( signed_subsidized_tx, config_path=config_path )
    if tx_fee is None:
        log.error("Failed to get tx fee")
        return None

    log.debug("renewal tx %s bytes, %s satoshis txfee" % (len(signed_subsidized_tx)/2, int(tx_fee)))

    if include_dust:
        dust_fee = estimate_dust_fee( unsigned_tx, fees_registration )   # must be unsigned_tx, without subsidy
        assert dust_fee is not None
        log.debug("Additional dust fee: %s" % dust_fee)
        tx_fee += dust_fee

    return tx_fee


def estimate_update_tx_fee( name, payment_privkey_info, owner_address, utxo_client, owner_privkey_params=(None, None), config_path=CONFIG_PATH, payment_address=None, include_dust=False ):
    """
    Estimate the transaction fee of an update.
    Optionally include the dust fees as well.
    Return the number of satoshis on success
    Return None on error
    """

    assert owner_address
    owner_address = str(owner_address)

    fake_consensus_hash = 'd4049672223f42aac2855d2fbf2f38f0'
    fake_zonefile_hash = '20b512149140494c0f7d565023973226908f6940'

    fake_privkey = make_fake_privkey_info( owner_privkey_params )

    signed_subsidized_tx = None
    if payment_privkey_info is not None:
        # consistency
        payment_address = get_privkey_info_address( payment_privkey_info )

    try:
        unsigned_tx = None
        try:
            unsigned_tx = update_tx( name, fake_zonefile_hash, fake_consensus_hash, owner_address, utxo_client, subsidize=True )
        except AssertionError as ae:
            # no UTXOs for this owner address.  Try again and add padding for one
            unsigned_tx = update_tx( name, fake_zonefile_hash, fake_consensus_hash, owner_address, utxo_client, subsidize=True, safety=False )
            assert unsigned_tx

            pad_len = estimate_owner_output_length(owner_address)
            unsigned_tx += "00" * pad_len

        signed_subsidized_tx = subsidize_or_pad_transaction(unsigned_tx, owner_address, owner_privkey_params, payment_privkey_info, fees_update, utxo_client, payment_address=payment_address, config_path=config_path )

    except ValueError as ve:
        if BLOCKSTACK_TEST:
            log.exception(ve)
            print >> sys.stderr, "payment key info: %s" % str(payment_privkey_info)

        log.error("Insufficient funds:  Not enough inputs to make an update transaction.")
        return None

    except AssertionError as ae:
        if BLOCKSTACK_DEBUG:
            log.exception(ae)

        log.error("Unable to create transaction")
        return None

    except Exception as e:
        if os.environ.get("BLOCKSTACK_TEST") == "1":
            log.exception(e)

        return None

    tx_fee = get_tx_fee( signed_subsidized_tx, config_path=config_path )
    if tx_fee is None:
        log.error("Failed to get tx fee")
        return None

    log.debug("update tx %s bytes, %s satoshis txfee" % (len(signed_subsidized_tx)/2, int(tx_fee)))

    if include_dust:
        dust_fee = estimate_dust_fee( unsigned_tx, fees_update )    # must be unsigned tx, without subsidy
        assert dust_fee is not None
        log.debug("Additional dust fee: %s" % dust_fee)
        tx_fee += dust_fee

    return tx_fee


def estimate_transfer_tx_fee( name, payment_privkey_info, owner_address, utxo_client, owner_privkey_params=(None, None), payment_address=None, config_path=CONFIG_PATH, include_dust=False ):
    """
    Estimate the transaction fee of a transfer.
    Optionally include the dust fees as well.
    Return the number of satoshis on success
    Return None on error
    """

    assert owner_address
    owner_address = str(owner_address)

    fake_recipient_address = virtualchain.address_reencode('1LL4X7wNUBCWoDhfVLA2cHE7xk1ZJMT98Q')
    fake_consensus_hash = 'd4049672223f42aac2855d2fbf2f38f0'

    fake_privkey = make_fake_privkey_info( owner_privkey_params )

    unsigned_tx = None
    try:
        try:
            unsigned_tx = transfer_tx( name, fake_recipient_address, True, fake_consensus_hash, owner_address, utxo_client, subsidize=True )
        except AssertionError as ae:
            # no UTXOs for this owner address.  Try again and add padding for one
            unsigned_tx = transfer_tx( name, fake_recipient_address, True, fake_consensus_hash, owner_address, utxo_client, subsidize=True, safety=False )
            assert unsigned_tx

            pad_len = estimate_owner_output_length(owner_address)
            unsigned_tx += "00" * pad_len

        signed_subsidized_tx = subsidize_or_pad_transaction(unsigned_tx, owner_address, owner_privkey_params, payment_privkey_info, fees_transfer, utxo_client, payment_address=payment_address, config_path=config_path )

    except ValueError, ve:
        if os.environ.get("BLOCKSTACK_TEST") == "1":
            log.exception(ve)

        log.error("Insufficient funds:  Not enough inputs to make a transfer transaction.")
        return None

    except AssertionError as ae:
        if BLOCKSTACK_DEBUG:
            log.exception(ae)

        log.error("Unable to make transaction")
        return None

    except Exception as e:
        if os.environ.get("BLOCKSTACK_TEST") == "1":
            log.exception(e)

        return None

    tx_fee = get_tx_fee( signed_subsidized_tx, config_path=config_path )
    if tx_fee is None:
        log.error("Failed to get tx fee")
        return None

    log.debug("transfer tx %s bytes, %s satoshis txfee" % (len(signed_subsidized_tx)/2, int(tx_fee)))

    if include_dust:
        dust_fee = estimate_dust_fee( unsigned_tx, fees_transfer )  # must be unsigned tx, without subsidy
        assert dust_fee is not None
        log.debug("Additional dust fee: %s" % dust_fee)
        tx_fee += dust_fee

    return tx_fee


def estimate_revoke_tx_fee( name, payment_privkey_info, owner_address, utxo_client, owner_privkey_params=(None, None), config_path=CONFIG_PATH, include_dust=False ):
    """
    Estimate the transaction fee of a revoke.
    Optionally include the dust fees as well.
    Return the number of satoshis on success
    Return None on error
    """

    assert owner_address
    owner_address = str(owner_address)

    fake_privkey = make_fake_privkey_info( owner_privkey_params )
    unsigned_tx = None

    try:
        try:
            unsigned_tx = revoke_tx( name, owner_address, utxo_client, subsidize=True )
        except AssertionError as ae:
            # no UTXOs for this owner address.  Try again and add padding for one
            unsigned_tx = revoke_tx( name, owner_address, utxo_client, subsidize=True, safety=False )
            assert unsigned_tx

            pad_len = estimate_owner_output_length(owner_address)
            unsigned_tx += "00" * pad_len

        signed_subsidized_tx = subsidize_or_pad_transaction(unsigned_tx, owner_address, owner_privkey_params, payment_privkey_info, fees_revoke, utxo_client, config_path=config_path )

    except ValueError, ve:
        if os.environ.get("BLOCKSTACK_TEST") == "1":
            log.exception(ve)

        log.error("Insufficient funds:  Not enough inputs to make a revoke transaction.")
        return None

    except AssertionError as ae:
        if BLOCKSTACK_DEBUG:
            log.exception(ae)

        log.error("Unable to make transaction")
        return None

    except Exception as e:
        if os.environ.get("BLOCKSTACK_TEST") == "1":
            log.exception(e)

        return None

    tx_fee = get_tx_fee( signed_subsidized_tx, config_path=config_path )
    if tx_fee is None:
        log.error("Failed to get tx fee")
        return None

    log.debug("revoke tx %s bytes, %s satoshis txfee" % (len(signed_subsidized_tx)/2, int(tx_fee)))

    if include_dust:
        dust_fee = estimate_dust_fee( unsigned_tx, fees_revoke )    # must be unsigned tx, without subsidy
        assert dust_fee is not None
        log.debug("Additional dust fee: %s" % dust_fee)
        tx_fee += dust_fee

    return tx_fee


def estimate_name_import_tx_fee( fqu, payment_addr, utxo_client, config_path=CONFIG_PATH, include_dust=False ):
    """
    Estimate the transaction fee of a name import.
    Return the number of satoshis on success
    Return None on error

    TODO: no dust fee estimation available for imports
    """

    assert payment_addr
    payment_addr = str(payment_addr)

    fake_privkey = '5J8V3QacBzCwh6J9NJGZJHQ5NoJtMzmyUgiYFkBEgUzKdbFo7GX'   # fake private key (NOTE: NAME_IMPORT only supports p2pkh)
    fake_zonefile_hash = '20b512149140494c0f7d565023973226908f6940'
    fake_recipient_address = virtualchain.address_reencode('1LL4X7wNUBCWoDhfVLA2cHE7xk1ZJMT98Q')

    try:
        unsigned_tx = name_import_tx( fqu, fake_recipient_address, fake_zonefile_hash, payment_addr, utxo_client )
        signed_tx = sign_tx( unsigned_tx, fake_privkey )
    except ValueError, ve:
        if os.environ.get("BLOCKSTACK_TEST") == "1":
            log.exception(ve)

        log.error("Insufficient funds:  Not enough inputs to make an import transaction")
        return None

    tx_fee = get_tx_fee( signed_tx, config_path=config_path )
    if tx_fee is None:
        log.error("Failed to get tx fee")
        return None

    log.debug("name import tx %s bytes, %s satoshis txfee" % (len(signed_tx)/2, int(tx_fee)))
    return tx_fee


def estimate_namespace_preorder_tx_fee( namespace_id, cost, payment_address, utxo_client, config_path=CONFIG_PATH, include_dust=False ):
    """
    Estimate the transaction fee of a namespace preorder
    Return the number of satoshis on success
    Return None on error

    TODO: no dust fee estimation available for namespace preorder
    """

    assert payment_address
    payment_address = str(payment_address)

    fake_privkey = virtualchain.BitcoinPrivateKey('5J8V3QacBzCwh6J9NJGZJHQ5NoJtMzmyUgiYFkBEgUzKdbFo7GX').to_hex()   # fake private key (NOTE: NAMESPACE_PREORDER only supports p2pkh)
    fake_reveal_address = virtualchain.address_reencode('1LL4X7wNUBCWoDhfVLA2cHE7xk1ZJMT98Q')
    fake_consensus_hash = 'd4049672223f42aac2855d2fbf2f38f0'

    try:
        unsigned_tx = namespace_preorder_tx( namespace_id, fake_reveal_address, cost, fake_consensus_hash, payment_address, utxo_client )
        signed_tx = sign_tx( unsigned_tx, fake_privkey )
    except ValueError, ve:
        if os.environ.get("BLOCKSTACK_TEST") == "1":
            log.exception(ve)

        log.error("Insufficient funds:  Not enough inputs to make a namespace-preorder transaction.")
        return None

    tx_fee = get_tx_fee( signed_tx, config_path=config_path )
    if tx_fee is None:
        log.error("Failed to get tx fee")
        return None

    log.debug("namespace preorder tx %s bytes, %s satoshis" % (len(signed_tx)/2, int(tx_fee)))
    return tx_fee


def estimate_namespace_reveal_tx_fee( namespace_id, payment_address, utxo_client, config_path=CONFIG_PATH, include_dust=False ):
    """
    Estimate the transaction fee of a namespace reveal
    Return the number of satoshis on success
    Return None on error

    TODO: no dust estimation available for namespace reveal
    """

    assert payment_address
    payment_address = str(payment_address)

    fake_privkey = virtualchain.BitcoinPrivateKey('5J8V3QacBzCwh6J9NJGZJHQ5NoJtMzmyUgiYFkBEgUzKdbFo7GX').to_hex()   # fake private key (NOTE: NAMESPACE_REVEAL only supports p2pkh)
    fake_reveal_address = virtualchain.address_reencode('1LL4X7wNUBCWoDhfVLA2cHE7xk1ZJMT98Q')

    try:
        unsigned_tx = namespace_reveal_tx( namespace_id, fake_reveal_address, 1, 2, 3, [4,5,6,7,8,9,10,11,12,13,14,15,0,1,2,3], 4, 5, payment_address, utxo_client )
        signed_tx = sign_tx( unsigned_tx, fake_privkey )
    except ValueError, ve:
        if os.environ.get("BLOCKSTACK_TEST") == "1":
            log.exception(ve)

        log.error("Insufficient funds:  Not enough inputs to make a namespace-reveal transaction.")
        return None

    tx_fee = get_tx_fee( signed_tx, config_path=config_path )
    if tx_fee is None:
        log.error("Failed to get tx fee")
        return None

    log.debug("namespace reveal tx %s bytes, %s satoshis txfee" % (len(signed_tx)/2, int(tx_fee)))

    if include_dust:
        dust_fee = estimate_dust_fee( signed_tx, fees_namespace_reveal )
        assert dust_fee is not None
        log.debug("Additional dust fee: %s" % dust_fee)
        tx_fee += dust_fee

    return tx_fee


def estimate_namespace_ready_tx_fee( namespace_id, reveal_addr, utxo_client, config_path=CONFIG_PATH, include_dust=False ):
    """
    Estimate the transaction fee of a namespace ready
    Return the number of satoshis on success
    Return None on error

    TODO: no dust estimation available for namespace ready
    """

    assert reveal_addr
    reveal_addr = str(reveal_addr)

    fake_privkey = virtualchain.BitcoinPrivateKey('5J8V3QacBzCwh6J9NJGZJHQ5NoJtMzmyUgiYFkBEgUzKdbFo7GX').to_hex()   # fake private key (NOTE: NAMESPACE_READY only supports p2pkh)

    try:
        unsigned_tx = namespace_ready_tx( namespace_id, reveal_addr, utxo_client )
        signed_tx = sign_tx( unsigned_tx, fake_privkey )
    except ValueError, ve:
        if os.environ.get("BLOCKSTACK_TEST") == "1":
            log.exception(ve)

        log.error("Insufficient funds:  Not enough inputs to make a namespace-ready transaction.")
        return None

    tx_fee = get_tx_fee( signed_tx, config_path=config_path )
    if tx_fee is None:
        log.error("Failed to get tx fee")
        return None

    log.debug("namespace ready tx %s bytes, %s satoshis txfee" % (len(signed_tx)/2, int(tx_fee)))

    return tx_fee


def estimate_announce_tx_fee( sender_address, utxo_client, sender_privkey_params=(1, 1), config_path=CONFIG_PATH, include_dust=False ):
    """
    Estimate the transaction fee of an announcement tx
    Return the number of satoshis on success
    Return None on error
    """

    assert sender_address
    sender_address = str(sender_address)

    fake_privkey = make_fake_privkey_info( sender_privkey_params )
    fake_announce_hash = '20b512149140494c0f7d565023973226908f6940'

    try:
        unsigned_tx = announce_tx( fake_announce_hash, sender_address, utxo_client )
        signed_tx = sign_tx( unsigned_tx, fake_privkey )
    except ValueError, ve:
        if os.environ.get("BLOCKSTACK_TEST") == "1":
            log.exception(ve)

        log.error("Insufficient funds:  Not enough inputs to make an announce transaction.")
        return None

    tx_fee = get_tx_fee( signed_tx, config_path=config_path )
    if tx_fee is None:
        log.error("Failed to get tx fee")
        return None

    log.debug("announce tx %s bytes, %s satoshis" % (len(signed_tx)/2, int(tx_fee)))

    if include_dust:
        dust_fee = estimate_dust_fee( signed_tx, fees_announce )
        assert dust_fee is not None
        log.debug("Additional dust fee: %s" % dust_fee)
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
    if privkey_params == (1,1) and pybitcoin.b58check_version_byte( str(address) ) != virtualchain.version_byte:
        # invalid address, given parameters
        log.error("Address %s does not correspond to a single private key" % address)
        return False

    elif (privkey_params[0] > 1 or privkey_params[1] > 1) and pybitcoin.b58check_version_byte( str(address) ) != virtualchain.multisig_version_byte:
        # invalid address
        log.error("Address %s does not correspond to multisig private keys")
        return False

    return True


def build_utxo_client( utxo_client=None, utxos=None, address=None ):
    """
    Build a UTXO client.
    This can be called multiple times with different addresses and UTXO lists.

    Return the UTXO client instance on success.
    Return None on error
    """
    if utxo_client:
        if isinstance(utxo_client, UTXOWrapper):
            # append to this client
            if utxos is not None and address is not None:
                utxo_client.add_unspents( address, utxos )

        return utxo_client

    if utxos is None or address is None:
        log.error("No payment address or payment UTXO list")
        return None

    utxo_client = UTXOWrapper()
    utxo_client.add_unspents( address, utxos )
    return utxo_client


def deduce_privkey_params( address=None, privkey_info=None, privkey_params=(None, None) ):
    """
    Try to figure out what the private key parameters (m, n) are.
    Return (m, n) on success
    Raise AssertionError on failure
    """
    if privkey_params[0] and privkey_params[1]:

        if address is not None:
            assert address_privkey_match(address, privkey_params), "Address does not match private key params"

        if privkey_info is not None:
            assert privkey_params == get_privkey_info_params( privkey_info ), "Params do not match private key"

        return privkey_params

    assert address is not None and privkey_info is not None, "Missing both address and private key info"

    if privkey_info is not None:
        privkey_params = get_privkey_info_params( privkey_info )

        msg = "Either key or key parameters are required"
        assert privkey_params, msg
        assert privkey_params[0] is not None, msg
        assert privkey_params[1] is not None, msg
        return privkey_params

    if address is not None:
        assert not virtualchain.is_p2sh_address(address), "Cannot deduce private key params from multisig address"
        return (1, 1)

    raise AssertionError("Unable to deduce private key params")


def do_blockchain_tx( unsigned_tx, privkey_info=None, config_path=CONFIG_PATH, tx_broadcaster=None, dry_run=False ):
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
            if payment_privkey_info is not None:
                resp = sign_tx( unsigned_tx, privkey_info )
            else:
                resp = unsigned_tx

            if resp is None:
                resp = {'error': 'Failed to generate signed register tx'}
            else:
                resp = {'status': True, 'tx': resp}

        else:
            resp = sign_and_broadcast_tx( unsigned_tx, privkey_info, config_path=config_path, tx_broadcaster=tx_broadcaster )

        return resp

    except Exception, e:
        if BLOCKSTACK_DEBUG:
            log.exception(e)

        return {'error': 'Failed to sign and broadcast transaction'}


def do_preorder( fqu, payment_privkey_info, owner_privkey_info, cost_satoshis, utxo_client, tx_broadcaster, tx_fee=None,
                 config_path=CONFIG_PATH, owner_address=None, payment_address=None, payment_utxos=None,
                 min_payment_confs=TX_MIN_CONFIRMATIONS, proxy=None, consensus_hash=None, dry_run=False, safety_checks=True ):
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
        proxy = get_default_proxy()

    if dry_run:
        assert tx_fee, "invalid argument: tx_fee is required on dry-run"
        assert cost_satoshis, 'invalid argument: cost_satoshis is required on dry-run'
        safety_checks = False

    fqu = str(fqu)

    assert payment_privkey_info or dry_run, "Missing payment private keys"
    assert payment_privkey_info or payment_address, "Missing payment address or keys"
    assert owner_privkey_info or owner_address, "Missing owner address or keys"

    if owner_address is None:
        owner_address = get_privkey_info_address( owner_privkey_info )

    if payment_address is None:
        payment_address = get_privkey_info_address( payment_privkey_info )

    utxo_client = build_utxo_client( utxo_client=utxo_client, address=payment_address, utxos=payment_utxos )
    assert utxo_client, "Unable to build UTXO client"

    if not dry_run and (safety_checks or (cost_satoshis is None or tx_fee is None)):
        # find tx fee, and do sanity checks
        res = check_preorder(fqu, cost_satoshis, owner_privkey_info, payment_privkey_info, config_path=config_path, proxy=proxy)
        if 'error' in res and safety_checks:
            log.error("Failed to check preorder: {}".format(res['error']))
            return res

        if tx_fee is None:
            tx_fee = res['tx_fee']

        if cost_satoshis is None:
            cost_satoshis = res['name_price']
        
        assert tx_fee, "Missing tx fee"
        assert cost_satoshis, "Missing name cost"

    if consensus_hash is None:
        consensus_hash_res = get_consensus_hash( proxy, config_path=config_path )
        if 'error' in consensus_hash_res:
            return {'error': 'Failed to get consensus hash: %s' % consensus_hash_res['error']}

        consensus_hash = consensus_hash_res['consensus_hash']
    else:
        log.warn("Using user-supplied consensus hash %s" % consensus_hash)

    log.debug("Preordering (%s, %s, %s), for %s, tx_fee = %s" % (fqu, payment_address, owner_address, cost_satoshis, tx_fee))

    try:
        unsigned_tx = preorder_tx( fqu, payment_address, owner_address, cost_satoshis, consensus_hash, utxo_client, tx_fee=tx_fee, min_payment_confs=min_payment_confs )
    except ValueError as ve:
        if BLOCKSTACK_DEBUG:
            log.exception(ve)
            
        log.error("Failed to create preorder TX")
        return {'error': 'Insufficient funds'}

    resp = do_blockchain_tx( unsigned_tx, privkey_info=payment_privkey_info, tx_broadcaster=tx_broadcaster, config_path=config_path, dry_run=dry_run )
    return resp


def do_register( fqu, payment_privkey_info, owner_privkey_info, utxo_client, tx_broadcaster, tx_fee=None,
                 config_path=CONFIG_PATH, owner_address=None, payment_address=None, payment_utxos=None,
                 proxy=None, dry_run=False, safety_checks=True ):

    """
    Register a name

    payment_privkey_info or payment_address is required.
    utxo_client or payment_utxos is required.

    Return {'status': True, 'transaction_hash': ...} on success
    Return {'status': True, 'tx': ...} if no private key is given, or dry_run is True.
    Return {'error': ...} on failure
    """
    if proxy is None:
        proxy = get_default_proxy()

    fqu = str(fqu)
    resp = {}

    if dry_run:
        assert tx_fee, "Missing tx fee on dry-run"
        safety_checks = False

    assert payment_privkey_info or dry_run, "Missing payment private keys"
    assert payment_privkey_info or payment_address, "Missing payment address or keys"

    if payment_address is None:
        payment_address = get_privkey_info_address( payment_privkey_info )

    if owner_address is None:
        owner_address = get_privkey_info_address( owner_privkey_info )

    assert payment_privkey_info or (payment_address and payment_utxos), "Missing payment keys or payment UTXOs and address"

    utxo_client = build_utxo_client( utxo_client=utxo_client, address=payment_address, utxos=payment_utxos )
    assert utxo_client, "Unable to build UTXO client"
       
    if not dry_run and (safety_checks or tx_fee is None):
        # find tx fee, and do sanity checks
        res = check_register(fqu, owner_privkey_info, payment_privkey_info, config_path=config_path, proxy=proxy)
        if 'error' in res and safety_checks:
            log.error("Failed to check register: {}".format(res['error']))
            return res

        if tx_fee is None:
            tx_fee = res['tx_fee']

        assert tx_fee, "Missing tx fee"

    log.debug("Registering (%s, %s, %s), tx_fee = %s" % (fqu, payment_address, owner_address, tx_fee))

    # now send it
    try:
        unsigned_tx = register_tx( fqu, payment_address, owner_address, utxo_client, tx_fee=tx_fee )
    except ValueError as ve:
        if BLOCKSTACK_TEST:
            log.exception(ve)

        log.error("Failed to create register TX")
        return {'error': 'Insufficient funds'}

    resp = do_blockchain_tx( unsigned_tx, privkey_info=payment_privkey_info, tx_broadcaster=tx_broadcaster, config_path=config_path, dry_run=dry_run )
    return resp


def do_update( fqu, zonefile_hash, owner_privkey_info, payment_privkey_info, utxo_client, tx_broadcaster, tx_fee=None,
               owner_address=None, owner_utxos=None, payment_address=None, payment_utxos=None,
               config_path=CONFIG_PATH, proxy=None, consensus_hash=None, dry_run=False, safety_checks=True ):
    """
    Put a new zonefile hash for a name.

    utxo_client must be given, or UTXO lists for both owner and payment private keys must be given.
    If private key(s) are missing, then dry_run must be True.

    Return {'status': True, 'transaction_hash': ..., 'value_hash': ...} on success (if dry_run is False)
    return {'status': True, 'tx': ..., 'value_hash': ...} on success (if dry_run is True)
    Return {'error': ...} on failure
    """

    if proxy is None:
        proxy = get_default_proxy()

    if dry_run:
        assert tx_fee, 'dry run needs tx fee'
        safety_checks = False

    fqu = str(fqu)

    assert payment_privkey_info or dry_run, "Missing payment private keys"
    assert owner_privkey_info or dry_run, "Missing owner private keys"
    assert payment_privkey_info or payment_address, "Missing payment address or keys"
    assert owner_privkey_info or owner_address, "Missing owner address or keys"

    if owner_address is None:
        owner_address = get_privkey_info_address( owner_privkey_info )

    if payment_address is None:
        payment_address = get_privkey_info_address( payment_privkey_info )

    assert payment_privkey_info or (payment_address and payment_utxos), "Missing payment keys or payment UTXOs and address"

    # build up UTXO client
    utxo_client = build_utxo_client( utxo_client=utxo_client, address=payment_address, utxos=payment_utxos )
    assert utxo_client, "Unable to build UTXO client"

    utxo_client = build_utxo_client( utxo_client=utxo_client, address=owner_address, utxos=owner_utxos )
    assert utxo_client, "Unable to build UTXO client"

    if not dry_run and (safety_checks or tx_fee is None):
        # find tx fee, and do sanity checks
        res = check_update(fqu, owner_privkey_info, payment_privkey_info, config_path=config_path, proxy=proxy)
        if 'error' in res and safety_checks:
            log.error("Failed to check update: {}".format(res['error']))
            return res

        if tx_fee is None:
            tx_fee = res['tx_fee']

        assert tx_fee, "Missing tx fee"

    # get consensus hash
    if consensus_hash is None:
        consensus_hash_res = get_consensus_hash( proxy, config_path=config_path )
        if 'error' in consensus_hash_res:
            log.error("Failed to get consensus hash")
            return {'error': 'Failed to get consensus hash: %s' % consensus_hash_res['error']}

        consensus_hash = consensus_hash_res['consensus_hash']

    else:
        log.warn("Using caller-supplied consensus hash '%s'" % consensus_hash)

    log.debug("Updating (%s, %s)" % (fqu, zonefile_hash))
    log.debug("<owner, payment> (%s, %s) tx_fee = %s" % (owner_address, payment_address, tx_fee))

    unsigned_tx = None
    try:
        unsigned_tx = update_tx( fqu, zonefile_hash, consensus_hash, owner_address, utxo_client, subsidize=True, tx_fee=tx_fee )
    except ValueError, ve:
        log.exception(ve)
        log.error("Failed to generate update TX")
        return {'error': 'Insufficient funds'}
    except Exception, e:
        log.exception(e)
        return {'error': 'Failed to generate update transaction'}

    if payment_privkey_info is not None:
        # will subsidize
        try:
            subsidized_tx = tx_make_subsidizable( unsigned_tx, fees_update, 21 * (10**6) * (10**8), payment_privkey_info, utxo_client, tx_fee=tx_fee )
            assert subsidized_tx is not None

            unsigned_tx = subsidized_tx
        except ValueError, ve:
            if BLOCKSTACK_DEBUG:
                log.exception(ve)

            log.error("Failed to subsidize update TX")
            return {'error': 'Insufficient funds'}
        except AssertionError as ae:
            if BLOCKSTACK_DEBUG:
                log.exception(ae)

            log.error("Failed to create subsidized tx")
            return {'error': 'Unable to create transaction'}

    resp = do_blockchain_tx( unsigned_tx, privkey_info=owner_privkey_info, tx_broadcaster=tx_broadcaster, config_path=config_path, dry_run=dry_run )
    if 'error' in resp:
        return resp

    resp['value_hash'] = zonefile_hash
    return resp


def do_transfer( fqu, transfer_address, keep_data, owner_privkey_info, payment_privkey_info, utxo_client, tx_broadcaster, tx_fee=None,
                 config_path=CONFIG_PATH, proxy=None, consensus_hash=None, dry_run=False, safety_checks=True ):
    """
    Transfer a name to a new address
    Return {'status': True, 'transaction_hash': ...} on success
    Return {'error': ...} on failure
    """

    if proxy is None:
        proxy = get_default_proxy()

    if dry_run:
        assert tx_fee is not None, 'Need tx fee for dry run'
        safety_checks = False

    fqu = str(fqu)
    owner_address = get_privkey_info_address(owner_privkey_info)
    payment_address = get_privkey_info_address(payment_privkey_info)

    if not dry_run and (safety_checks or tx_fee is None):
        # find tx fee, and do sanity checks
        res = check_transfer(fqu, transfer_address, owner_privkey_info, payment_privkey_info, config_path=config_path, proxy=proxy)
        if 'error' in res and safety_checks:
            log.error("Failed to check transfer: {}".format(res['error']))
            return res

        if tx_fee is None:
            tx_fee = res['tx_fee']

        assert tx_fee, "Missing tx fee"

    # get consensus hash
    if consensus_hash is None:
        consensus_hash_res = get_consensus_hash( proxy, config_path=config_path )
        if 'error' in consensus_hash_res:
            return {'error': 'Failed to get consensus hash: %s' % consensus_hash_res['error']}

        consensus_hash = consensus_hash_res['consensus_hash']

    else:
        log.warn("Using caller-supplied consensus hash '%s'" % consensus_hash)

    subsidized_tx = None
    try:
        unsigned_tx = transfer_tx( fqu, transfer_address, keep_data, consensus_hash, owner_address, utxo_client, subsidize=True, tx_fee=tx_fee )
        subsidized_tx = tx_make_subsidizable( unsigned_tx, fees_transfer, 21 * (10**6) * (10**8), payment_privkey_info, utxo_client, tx_fee=tx_fee )
        assert subsidized_tx is not None
    except ValueError as ve:
        if BLOCKSTACK_DEBUG:
            log.exception(ve)

        log.error("Failed to generate transfer tx")
        return {'error': 'Insufficient funds'}
    except AssertionError as ae:
        if BLOCKSTACK_DEBUG:
            log.exception(ae)

        log.error("Failed to subsidize transfer tx")
        return {'error': 'Unable to create transaction'}

    log.debug("Transferring (%s, %s)" % (fqu, transfer_address))
    log.debug("<owner, payment> (%s, %s) tx_fee = %s" % (owner_address, payment_address, tx_fee))

    resp = do_blockchain_tx( subsidized_tx, privkey_info=owner_privkey_info, tx_broadcaster=tx_broadcaster, config_path=config_path, dry_run=dry_run )
    return resp


def do_renewal( fqu, owner_privkey_info, payment_privkey_info, renewal_fee, utxo_client, tx_broadcaster, tx_fee=None, config_path=CONFIG_PATH, proxy=None, dry_run=False, safety_checks=True ):
    """
    Renew a name
    Return {'status': True, 'transaction_hash': ...} on success
    Return {'error': ...} on failure
    """
    if proxy is None:
        proxy = get_default_proxy()

    if dry_run:
        assert tx_fee, 'Need tx fee for dry run'
        assert renewal_fee, 'Need renewal fee for dry run'
        safety_checks = False

    fqu = str(fqu)
    resp = {}
    owner_address = get_privkey_info_address( owner_privkey_info )
    payment_address = get_privkey_info_address( payment_privkey_info )

    if not dry_run and (safety_checks or (renewal_fee is None or tx_fee is None)):
        # find tx fee, and do sanity checks
        res = check_renewal(fqu, renewal_fee, owner_privkey_info, payment_privkey_info, config_path=config_path, proxy=proxy)
        if 'error' in res and safety_checks:
            log.error("Failed to check renewal: {}".format(res['error']))
            return res

        if tx_fee is None:
            tx_fee = res['tx_fee']

        if renewal_fee is None:
            renewal_fee = res['name_price']

        assert tx_fee, "Missing tx fee"
        assert renewal_fee, "Missing renewal fee"

    log.debug("Renewing (%s, %s, %s), tx_fee = %s, renewal_fee = %s" % (fqu, payment_address, owner_address, tx_fee, renewal_fee))

    # now send it
    subsidized_tx = None
    try:
        unsigned_tx = register_tx( fqu, owner_address, owner_address, utxo_client, renewal_fee=renewal_fee, tx_fee=tx_fee )
        subsidized_tx = tx_make_subsidizable( unsigned_tx, fees_registration, 21 ** (10**6) * (10**8), payment_privkey_info, utxo_client, tx_fee=tx_fee )
        assert subsidized_tx is not None
    except ValueError as ve:
        if BLOCKSTACK_DEBUG:
            log.exception(ve)

        log.error("Failed to generate renewal tx")
        return {'error': 'Insufficient funds'}
    except AssertionError as ae:
        if BLOCKSTACK_DEBUG:
            log.exception(ae)

        log.error("Failed to subsidize renewal tx")
        return {'error': 'Unable to create transaction'}

    resp = do_blockchain_tx( subsidized_tx, privkey_info=owner_privkey_info, tx_broadcaster=tx_broadcaster, config_path=config_path, dry_run=dry_run )
    return resp


def do_revoke( fqu, owner_privkey_info, payment_privkey_info, utxo_client, tx_broadcaster, config_path=CONFIG_PATH, tx_fee=None, proxy=None, dry_run=False, safety_checks=True):
    """
    Revoke a name
    Return {'status': True, 'transaction_hash': ...} on success
    Return {'error': ...} on failure
    """
    if proxy is None:
        proxy = get_default_proxy()

    if dry_run:
        assert tx_fee, "need tx fee for dry run"
        safety_checks = False

    fqu = str(fqu)
    owner_address = get_privkey_info_address(owner_privkey_info)
    payment_address = get_privkey_info_address(payment_privkey_info)

    if not dry_run and (safety_checks or tx_fee is None):
        res = check_revoke(fqu, owner_privkey_info, payment_privkey_info, config_path=config_path, proxy=proxy)
        if 'error' in res and safety_checks:
            log.error("Failed to check revoke: {}".format(res['error']))
            return res

        if tx_fee is None:
            tx_fee = res['tx_fee']

        assert tx_fee, "Missing tx fee"

    subsidized_tx = None
    try:
        unsigned_tx = revoke_tx( fqu, owner_address, utxo_client, subsidize=True, tx_fee=tx_fee )
        subsidized_tx = tx_make_subsidizable( unsigned_tx, fees_revoke, 21 ** (10**6) * (10**8), payment_privkey_info, utxo_client, tx_fee=tx_fee )
        assert subsidized_tx is not None
    except ValueError as ve:
        if BLOCKSTACK_DEBUG:
            log.exception(ve)

        log.error("Failed to generate revoke tx")
        return {'error': 'Insufficient funds'}
    except AssertionError as ae:
        if BLOCKSTACK_DEBUG:
            log.exception(ae)

        log.error("Failed to subsidize revoke tx")
        return {'error': 'Unable to create transaction'}

    log.debug("Revoking %s" % fqu)
    log.debug("<owner, payment> (%s, %s) tx_fee = %s" % (owner_address, payment_address, tx_fee))

    resp = do_blockchain_tx( subsidized_tx, privkey_info=owner_privkey_info, tx_broadcaster=tx_broadcaster, config_path=config_path, dry_run=dry_run )
    return resp


def do_name_import( fqu, importer_privkey_info, recipient_address, zonefile_hash, utxo_client, tx_broadcaster, config_path=CONFIG_PATH, proxy=None, safety_checks=True, dry_run=False ):
    """
    Import a name
    Return {'status': True, 'transaction_hash': ..., 'value_hash': ...} on success
    Return {'error': ...} on failure
    """
    if proxy is None:
        proxy = get_default_proxy()

    fqu = str(fqu)
    payment_address = None

    try:
        payment_address = virtualchain.BitcoinPrivateKey( importer_privkey_info ).public_key().address()
    except Exception, e:
        log.exception(e)
        return {'error': 'Import can only use a single private key with a P2PKH script'}

    log.debug("Import {} with {}".format(fqu, payment_address))

    tx_fee = estimate_name_import_tx_fee( fqu, payment_address, utxo_client, config_path=config_path )
    if tx_fee is None:
        log.error("Failed to estimate name import tx fee")
        return {'error': 'Failed to get fee estimate.  Please check your network settings and verify that you have sufficient funds.'}

    unsigned_tx = None
    try:
        unsigned_tx = name_import_tx( fqu, recipient_address, zonefile_hash, payment_address, utxo_client, tx_fee=tx_fee )
    except ValueError, ve:
        if BLOCKSTACK_DEBUG:
            log.exception(ve)
        log.error("Failed to generate name import tx")
        return {'error': 'Insufficient funds'}

    resp = do_blockchain_tx( unsigned_tx, privkey_info=importer_privkey_info, tx_broadcaster=tx_broadcaster, config_path=config_path, dry_run=dry_run )
    if 'error' in resp:
        return resp

    resp['value_hash'] = zonefile_hash
    return resp


def do_namespace_preorder( namespace_id, cost, payment_privkey_info, reveal_address, utxo_client, tx_broadcaster, consensus_hash=None, config_path=CONFIG_PATH, proxy=None, safety_checks=True, dry_run=False ):
    """
    Preorder a namespace
    Return {'status': True, 'transaction_hash': ...} on success
    Return {'error': ...} on failure
    """
    if proxy is None:
        proxy = get_default_proxy()

    fqu = str(namespace_id)
    payment_address = None

    try:
        payment_address = virtualchain.BitcoinPrivateKey( payment_privkey_info ).public_key().address()
    except Exception, e:
        log.error("Invalid private key info")
        return {'error': 'Namespace preorder can only use a single private key with a P2PKH script'}

    # get consensus hash
    if consensus_hash is None:
        consensus_hash_res = get_consensus_hash( proxy, config_path=config_path )
        if 'error' in consensus_hash_res:
            return {'error': 'Failed to get consensus hash: %s' % consensus_hash_res['error']}

        consensus_hash = consensus_hash_res['consensus_hash']

    else:
        log.warn("Using caller-supplied consensus hash '%s'" % consensus_hash)

    if safety_checks:
        # namespace must not exist
        blockchain_record = blockstack_get_namespace_blockchain_record( namespace_id, proxy=proxy )
        if blockchain_record is None or 'error' in blockchain_record:
            if blockchain_record is None:
                log.error("Failed to read blockchain record for %s" % namespace_id)
                return {'error': 'Failed to read blockchain record for namespace'}

            if blockchain_record['error'] != 'No such namespace':
                log.error("Failed to read blockchain record for %s" % namespace_id)
                return {'error': 'Failed to read blockchain record for namespace'}

        else:
            # exists
            return {'error': 'Namespace already exists'}

    tx_fee = estimate_namespace_preorder_tx_fee( namespace_id, cost, payment_address, utxo_client, config_path=config_path )
    if tx_fee is None:
        log.error("Failed to estimate namespace preorder tx fee")
        return {'error': 'Failed to get fee estimate.  Please check your network settings and verify that you have sufficient funds.'}

    log.debug("Preordering namespace (%s, %s, %s), tx_fee = %s" % (namespace_id, payment_address, reveal_address, tx_fee))

    unsigned_tx = None
    try:
        unsigned_tx = namespace_preorder_tx( namespace_id, reveal_address, cost, consensus_hash, payment_address, utxo_client, tx_fee=tx_fee )
    except ValueError, ve:
        if os.environ.get("BLOCKSTACK_DEBUG") == "1":
            log.exception(ve)

        log.error("Failed to create namespace preorder tx")
        return {'error': 'Insufficient funds'}

    resp = do_blockchain_tx( unsigned_tx, privkey_info=payment_privkey_info, tx_broadcaster=tx_broadcaster, config_path=config_path, dry_run=dry_run )
    return resp


def do_namespace_reveal( namespace_id, reveal_address, lifetime, coeff, base_cost, bucket_exponents, nonalpha_discount, no_vowel_discount, payment_privkey_info, utxo_client, tx_broadcaster, config_path=CONFIG_PATH, proxy=None, safety_checks=True, dry_run=False ):
    """
    Reveal a namespace
    Return {'status': True, 'transaction_hash': ...} on success
    Return {'error': ...} on failure
    """
    if proxy is None:
        proxy = get_default_proxy()

    fqu = str(namespace_id)
    payment_address = None

    try:
        payment_address = virtualchain.BitcoinPrivateKey( payment_privkey_info ).public_key().address()
    except:
        log.error("Invalid private key info")
        return {'error': 'Namespace reveal can only use a single private key with a P2PKH script'}

    if safety_checks:
        # namespace must not exist
        blockchain_record = blockstack_get_namespace_blockchain_record( namespace_id, proxy=proxy )
        if blockchain_record is None or 'error' in blockchain_record:
            if blockchain_record['error'] != 'No such namespace':
                log.error("Failed to read blockchain record for %s" % namespace_id)
                return {'error': 'Failed to read blockchain record for namespace'}

        else:
            # exists
            log.error("Namespace already exists")
            return {'error': 'Namespace already exists'}

    tx_fee = estimate_namespace_reveal_tx_fee( namespace_id, payment_address, utxo_client, config_path=config_path )
    if tx_fee is None:
        log.error("Failed to estimate namespace reveal tx fee")
        return {'error': 'Failed to get fee estimate.  Please check your network settings and verify that you have sufficient funds.'}

    log.debug("Revealing namespace (%s, %s, %s), tx_fee = %s" % (namespace_id, payment_address, reveal_address, tx_fee))

    try:
        unsigned_tx = namespace_reveal_tx( namespace_id, reveal_address, lifetime, coeff, base_cost, bucket_exponents, nonalpha_discount, no_vowel_discount, payment_address, utxo_client, tx_fee=tx_fee )
    except ValueError, ve:
        if os.environ.get("BLOCKSTACK_TEST") == "1":
            log.exception(ve)

        return {'error': 'Insufficient funds'}

    resp = do_blockchain_tx( unsigned_tx, privkey_info=payment_privkey_info, tx_broadcaster=tx_broadcaster, config_path=config_path, dry_run=dry_run )
    return resp


def do_namespace_ready( namespace_id, reveal_privkey_info, utxo_client, tx_broadcaster, config_path=CONFIG_PATH, proxy=None, safety_checks=True, dry_run=False ):
    """
    Open a namespace for registration
    Return {'status': True, 'transaction_hash': ...} on success
    Return {'error': ...} on failure
    """

    if proxy is None:
        proxy = get_default_proxy()

    fqu = str(namespace_id)
    reveal_address = None

    try:
        reveal_address = virtualchain.BitcoinPrivateKey( reveal_privkey_info ).public_key().address()
    except:
        log.error("Invalid private key info")
        return {'error': 'Namespace ready can only use a single private key with a P2PKH script'}

    if safety_checks:
        # namespace must exist, but not be ready
        blockchain_record = blockstack_get_namespace_blockchain_record( namespace_id, proxy=proxy )
        if blockchain_record is None or 'error' in blockchain_record:
            log.error("Failed to read blockchain record for %s" % namespace_id)
            return {'error': 'Failed to read blockchain record for namespace'}

        if blockchain_record['ready']:
            # exists
            log.error("Namespace already made ready")
            return {'error': 'Namespace already made ready'}

    tx_fee = estimate_namespace_ready_tx_fee( namespace_id, reveal_address, utxo_client, config_path=config_path )
    if tx_fee is None:
        log.error("Failed to estimate namespace-ready tx fee")
        return {'error': 'Failed to get fee estimate.  Please check your network settings and verify that you have sufficient funds.'}

    log.debug("Readying namespace (%s, %s), tx_fee = %s" % (namespace_id, reveal_address, tx_fee) )

    try:
        unsigned_tx = namespace_ready_tx( namespace_id, reveal_address, utxo_client, tx_fee=tx_fee )
    except ValueError, ve:
        if os.environ.get("BLOCKSTACK_DEBUG") == "1":
            log.exception(ve)

        log.error("Failed to create namespace-ready tx")
        return {'error': 'Insufficient funds'}

    resp = do_blockchain_tx( unsigned_tx, privkey_info=reveal_privkey_info, tx_broadcaster=tx_broadcaster, config_path=config_path, dry_run=dry_run )
    return resp


def do_announce( message_text, sender_privkey_info, utxo_client, tx_broadcaster, config_path=CONFIG_PATH, proxy=None, safety_checks=True, dry_run=False ):
    """
    Send an announcement hash to the blockchain
    Return {'status': True, 'transaction_hash': ...} on success
    Return {'error': ...} on failure
    """

    if proxy is None:
        proxy = get_default_proxy()

    message_text = str(message_text)
    message_hash = get_blockchain_compat_hash( message_text )

    sender_address = get_privkey_info_address( sender_privkey_info )
    sender_privkey_params = get_privkey_info_params( sender_privkey_info )
    if sender_privkey_params == (None, None):
        log.error("Invalid owner private key info")
        return {'error': 'Invalid owner private key'}

    tx_fee = estimate_announce_tx_fee( sender_address, utxo_client, config_path=config_path )
    if tx_fee is None:
        log.error("Failed to estimate announce tx fee")
        return {'error': 'Failed to get fee estimate.  Please check your network settings and verify that you have sufficient funds.'}

    log.debug("Announce (%s, %s) tx_fee = %s" % (message_hash, sender_address, tx_fee))

    try:
        unsigned_tx = announce_tx( message_hash, sender_address, utxo_client, tx_fee=tx_fee )
    except ValueError, ve:
        if os.environ.get("BLOCKSTACK_DEBUG") == "1":
            log.exception(ve)

        log.error("Failed to create announce tx")
        return {'error': 'Insufficient funds'}

    resp = do_blockchain_tx( unsigned_tx, privkey_info=sender_privkey_info, tx_broadcaster=tx_broadcaster, config_path=config_path, dry_run=dry_run )
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



def async_preorder(fqu, payment_privkey_info, owner_privkey_info, cost, tx_fee=None, name_data={}, min_payment_confs=TX_MIN_CONFIRMATIONS,
                   proxy=None, config_path=CONFIG_PATH, queue_path=DEFAULT_QUEUE_PATH ):
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

    utxo_client = get_utxo_provider_client( config_path=config_path )
    tx_broadcaster = get_tx_broadcaster( config_path=config_path )

    owner_address = get_privkey_info_address( owner_privkey_info )
    payment_address = get_privkey_info_address( payment_privkey_info )

    # stale preorder will get removed from preorder_queue
    if in_queue("register", fqu, path=queue_path):
        log.error("Already in register queue: %s" % fqu)
        return {'error': 'Already in register queue'}

    if in_queue("preorder", fqu, path=queue_path):
        log.error("Already in preorder queue: %s" % fqu)
        return {'error': 'Already in preorder queue'}

    try:
        resp = do_preorder( fqu, payment_privkey_info, owner_privkey_info, cost, utxo_client, tx_broadcaster,
                            tx_fee=tx_fee, min_payment_confs=min_payment_confs, config_path=CONFIG_PATH )

    except Exception, e:
        log.exception(e)
        return {'error': 'Failed to sign and broadcast preorder transaction'}

    if 'transaction_hash' in resp:
        if not BLOCKSTACK_DRY_RUN:
            # watch this preorder, and register it when it gets queued
            queue_append("preorder", fqu, resp['transaction_hash'],
                         payment_address=payment_address,
                         owner_address=owner_address,
                         transfer_address=name_data.get('transfer_address'),
                         zonefile_data=name_data.get('zonefile'),
                         profile=name_data.get('profile'),
                         config_path=config_path,
                         path=queue_path)
    else:
        assert 'error' in resp
        log.error("Error preordering: %s with %s for %s" % (fqu, payment_address, owner_address))
        log.error("Error below\n%s" % json.dumps(resp, indent=4, sort_keys=True))
        return {'error': 'Failed to preorder: %s' % resp['error']}

    return resp


def async_register(fqu, payment_privkey_info, owner_privkey_info, tx_fee=None, name_data={},
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

    if proxy is None:
        proxy = get_default_proxy(config_path=config_path)

    utxo_client = get_utxo_provider_client(config_path=config_path)
    tx_broadcaster = get_tx_broadcaster( config_path=config_path )

    owner_address = get_privkey_info_address( owner_privkey_info )
    payment_address = get_privkey_info_address( payment_privkey_info )

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

    try:
        resp = do_register( fqu, payment_privkey_info, owner_privkey_info, utxo_client, tx_broadcaster,
                            tx_fee=tx_fee, config_path=config_path, proxy=proxy )
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
                         config_path=config_path,
                         path=queue_path)

        return resp

    else:
        assert 'error' in resp
        log.error("Error registering: %s" % fqu)
        log.error(resp)
        return {'error': 'Failed to send registration: {}'.format(resp['error'])}


def async_update(fqu, zonefile_data, profile, owner_privkey_info, payment_privkey_info,
                 tx_fee=None, name_data={}, config_path=CONFIG_PATH,
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

    utxo_client = get_utxo_provider_client(config_path=config_path)
    tx_broadcaster = get_tx_broadcaster(config_path=config_path)

    owner_address = get_privkey_info_address( owner_privkey_info )

    if in_queue("update", fqu, path=queue_path):
        log.error("Already in update queue: %s" % fqu)
        return {'error': 'Already in update queue'}

    resp = {}
    try:
        resp = do_update( fqu, zonefile_hash, owner_privkey_info, payment_privkey_info, utxo_client, tx_broadcaster,
                          tx_fee=tx_fee, config_path=config_path, proxy=proxy )
    except Exception, e:
        log.exception(e)
        return {'error': 'Failed to sign and broadcast update transaction'}

    if 'transaction_hash' in resp:
        if not BLOCKSTACK_DRY_RUN:
            queue_append("update", fqu, resp['transaction_hash'],
                         zonefile_data=zonefile_data,
                         profile=profile,
                         zonefile_hash=zonefile_hash,
                         owner_address=owner_address,
                         transfer_address=name_data.get('transfer_address'),
                         config_path=config_path,
                         path=queue_path)

        resp['zonefile_hash'] = zonefile_hash
        return resp

    else:
        assert 'error' in resp
        log.error("Error updating: %s" % fqu)
        log.error(resp)
        return {'error': 'Failed to broadcast update transaction: {}'.format(resp['error'])}


def async_transfer(fqu, transfer_address, owner_privkey_info, payment_privkey_info, 
                   tx_fee=None, config_path=CONFIG_PATH, proxy=None, queue_path=DEFAULT_QUEUE_PATH):
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

    owner_address = get_privkey_info_address( owner_privkey_info )

    if in_queue("transfer", fqu, path=queue_path):
        log.error("Already in transfer queue: %s" % fqu)
        return {'error': 'Already in transfer queue'}

    try:
        resp = do_transfer( fqu, transfer_address, True, owner_privkey_info, payment_privkey_info, utxo_client, tx_broadcaster,
                            tx_fee=tx_fee, config_path=config_path, proxy=proxy )
    except Exception, e:
        log.exception(e)
        return {'error': 'Failed to sign and broadcast transfer transaction'}

    if 'transaction_hash' in resp:
        if not BLOCKSTACK_DRY_RUN:
            queue_append("transfer", fqu, resp['transaction_hash'],
                         owner_address=owner_address,
                         transfer_address=transfer_address,
                         config_path=config_path,
                         path=queue_path)
    else:
        assert 'error' in resp
        log.error("Error transferring: %s" % fqu)
        log.error(resp)
        return {'error': 'Failed to broadcast transfer transaction: {}'.format(resp['error'])}

    return resp


def async_renew(fqu, owner_privkey_info, payment_privkey_info, renewal_fee,
                tx_fee=None, proxy=None, config_path=CONFIG_PATH, queue_path=DEFAULT_QUEUE_PATH):
    """
        Renew an already-registered name.

        @fqu: fully qualified name e.g., muneeb.id

        Return {'status': True, ...} on success
        Return {'error': ...} on error
    """

    if proxy is None:
        proxy = get_default_proxy(config_path=config_path)

    owner_address = get_privkey_info_address( owner_privkey_info )
    utxo_client = get_utxo_provider_client(config_path=config_path)
    tx_broadcaster = get_tx_broadcaster( config_path=config_path )

    # check renew queue first
    if in_queue("renew", fqu, path=queue_path):
        log.error("Already in renew queue: %s" % fqu)
        return {'error': 'Already in renew queue'}

    try:
        resp = do_renewal( fqu, owner_privkey_info, payment_privkey_info, renewal_fee, utxo_client, tx_broadcaster,
                           tx_fee=tx_fee, config_path=config_path, proxy=proxy )
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
                             config_path=config_path,
                             path=queue_path)
        return resp


def async_revoke(fqu, owner_privkey_info, payment_privkey_info, 
                 tx_fee=None, proxy=None, config_path=CONFIG_PATH, queue_path=DEFAULT_QUEUE_PATH):
    """
        Revoke a name.

        @fqu: fully qualified name e.g., muneeb.id

        Return {'status': True, ...} on success
        Return {'error': ...} on error
    """

    if proxy is None:
        proxy = get_default_proxy(config_path=config_path)

    owner_address = get_privkey_info_address( owner_privkey_info )
    utxo_client = get_utxo_provider_client(config_path=config_path)
    tx_broadcaster = get_tx_broadcaster( config_path=config_path )

    # check revoke queue first
    if in_queue("revoke", fqu, path=queue_path):
        log.error("Already in revoke queue: %s" % fqu)
        return {'error': 'Already in revoke queue'}

    try:
        resp = do_revoke( fqu, owner_privkey_info, payment_privkey_info, utxo_client, tx_broadcaster,
                          tx_fee=tx_fee, config_path=config_path, proxy=proxy )

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
