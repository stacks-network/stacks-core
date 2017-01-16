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
from ..config import get_logger, APPROX_TX_IN_P2PKH_LEN, APPROX_TX_OUT_P2PKH_LEN, APPROX_TX_OVERHEAD_LEN

from ..proxy import get_default_proxy
from ..proxy import getinfo as blockstack_getinfo
from ..proxy import get_name_cost as blockstack_get_name_cost
from ..proxy import get_name_blockchain_record as blockstack_get_name_blockchain_record
from ..proxy import get_namespace_blockchain_record as blockstack_get_namespace_blockchain_record
from ..proxy import is_name_registered, is_name_owner

from ..tx import sign_and_broadcast_tx, preorder_tx, register_tx, update_tx, transfer_tx, revoke_tx, \
        namespace_preorder_tx, namespace_reveal_tx, namespace_ready_tx, announce_tx, name_import_tx, sign_tx

from ..scripts import tx_make_subsidizable
from ..storage import get_blockchain_compat_hash, hash_zonefile, put_announcement, get_zonefile_data_hash

from ..operations import fees_update, fees_transfer, fees_revoke, fees_registration, fees_preorder, \
        fees_namespace_preorder, fees_namespace_reveal, fees_namespace_ready, fees_announce

from ..keys import get_privkey_info_address, get_privkey_info_params

import virtualchain

log = get_logger("blockstack-client")


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
    

def estimate_preorder_tx_fee( name, name_cost, payment_addr, utxo_client, owner_privkey_params=(1, 1), config_path=CONFIG_PATH, include_dust=False ):
    """
    Estimate the transaction fee of a preorder.
    Optionally include the dust fees as well.
    Return the number of satoshis on success
    Return None on error
    """
    fake_owner_address = virtualchain.address_reencode('1PJeKxYXfTjE26FGFXmSuYpfnP2oRBu9kp')  # fake address
    fake_consensus_hash = 'd4049672223f42aac2855d2fbf2f38f0'

    fake_privkey = make_fake_privkey_info( owner_privkey_params )

    try:
        unsigned_tx = preorder_tx( name, payment_addr, fake_owner_address, name_cost, fake_consensus_hash, utxo_client )
    except ValueError, ve:
        if os.environ.get("BLOCKSTACK_TEST") == "1":
            log.exception(ve)

        log.error("Insufficient funds:  Not enough inputs to make a preorder transaction")
        return None

    signed_tx = sign_tx( unsigned_tx, fake_privkey )
    tx_fee = get_tx_fee( signed_tx, config_path=config_path )
    if tx_fee is None:
        log.error("Failed to get tx fee")
        return None

    log.debug("preorder tx %s bytes, %s satoshis" % (len(signed_tx), int(tx_fee)))

    if include_dust:
        dust_fee = estimate_dust_fee( signed_tx, fees_preorder )
        assert dust_fee is not None
        log.debug("Additional dust fee: %s" % dust_fee)
        tx_fee += dust_fee

    return tx_fee


def estimate_register_tx_fee( name, payment_addr, utxo_client, owner_privkey_params=(1, 1), config_path=CONFIG_PATH, include_dust=False ):
    """
    Estimate the transaction fee of a register.
    Optionally include the dust fees as well.
    Return the number of satoshis on success
    Return None on error
    """
    fake_owner_address = virtualchain.address_reencode('1PJeKxYXfTjE26FGFXmSuYpfnP2oRBu9kp')  # fake address
    fake_privkey = make_fake_privkey_info( owner_privkey_params )

    try:
        unsigned_tx = register_tx( name, payment_addr, fake_owner_address, utxo_client )
    except ValueError, ve:
        if os.environ.get("BLOCKSTACK_TEST") == "1":
            log.exception(ve)

        log.error("Insufficient funds:  Not enough inputs to make a register transaction")
        return None

    signed_tx = sign_tx( unsigned_tx, fake_privkey )
    tx_fee = get_tx_fee( signed_tx, config_path=config_path )
    if tx_fee is None:
        log.error("Failed to get tx fee")
        return None

    log.debug("register tx %s bytes, %s satoshis txfee" % (len(signed_tx), int(tx_fee)))

    if include_dust:
        dust_fee = estimate_dust_fee( signed_tx, fees_registration )
        assert dust_fee is not None
        log.debug("Additional dust fee: %s" % dust_fee)
        tx_fee += dust_fee

    return tx_fee


def estimate_renewal_tx_fee( name, renewal_fee, payment_privkey_info, owner_address, utxo_client, owner_privkey_params=(1, 1), config_path=CONFIG_PATH, include_dust=False ):
    """
    Estimate the transaction fee of a renewal.
    Optionally include the dust fees as well.
    Return the number of satoshis on success
    Return None on error
    """
    
    fake_privkey = make_fake_privkey_info( owner_privkey_params )
    address = get_privkey_info_address( payment_privkey_info )

    try:
        unsigned_tx = register_tx( name, address, address, utxo_client, renewal_fee=renewal_fee )
        subsidized_tx = tx_make_subsidizable( unsigned_tx, fees_registration, 21 * 10**14, payment_privkey_info, utxo_client )
        assert subsidized_tx is not None
    except ValueError, ve:
        if os.environ.get("BLOCKSTACK_TEST") == "1":
            log.exception(ve)
            print >> sys.stderr, "payment key info: %s" % str(payment_privkey_info)

        log.error("Insufficient funds:  Not enough inputs to make a renewal transaction.")
        return None
    except AssertionError, ae:
        if BLOCKSTACK_DEBUG:
            log.exception(ae)

        log.error("Unable to create transaction")
        return None
        
    signed_tx = sign_tx( subsidized_tx, fake_privkey )
    tx_fee = get_tx_fee( signed_tx, config_path=config_path )
    if tx_fee is None:
        log.error("Failed to get tx fee")
        return None

    log.debug("renewal tx %s bytes, %s satoshis txfee" % (len(signed_tx), int(tx_fee)))

    if include_dust:
        dust_fee = estimate_dust_fee( signed_tx, fees_registration )
        assert dust_fee is not None
        log.debug("Additional dust fee: %s" % dust_fee)
        tx_fee += dust_fee

    return tx_fee


def estimate_update_tx_fee( name, payment_privkey_info, owner_address, utxo_client, owner_privkey_params=(1, 1), config_path=CONFIG_PATH, payment_address=None, include_dust=False ):
    """
    Estimate the transaction fee of an update.
    Optionally include the dust fees as well.
    Return the number of satoshis on success
    Return None on error
    """
    fake_consensus_hash = 'd4049672223f42aac2855d2fbf2f38f0'
    fake_zonefile_hash = '20b512149140494c0f7d565023973226908f6940'

    fake_privkey = make_fake_privkey_info( owner_privkey_params )

    signed_subsidized_tx = None
    payment_address = get_privkey_info_address( payment_privkey_info )

    try:
        unsigned_tx = update_tx( name, fake_zonefile_hash, fake_consensus_hash, owner_address, utxo_client, subsidize=True )
        if payment_privkey_info is not None:
            # actually try to subsidize this tx
            subsidized_tx = tx_make_subsidizable( unsigned_tx, fees_update, 21 * 10**14, payment_privkey_info, utxo_client )
            assert subsidized_tx is not None

            signed_subsidized_tx = sign_tx( subsidized_tx, fake_privkey )

            # there will be at least one more output here (the registration output), so append that too 
            signed_subsidized_tx += "00" * (APPROX_TX_OVERHEAD_LEN + APPROX_TX_IN_P2PKH_LEN + APPROX_TX_OUT_P2PKH_LEN)

        else:
            # do a rough size estimation 
            if payment_address is not None:
                log.debug("Payment private key not given; estimating the subsidization fee from UTXOs")
                payment_utxos = get_utxos( payment_address, config_path=config_path, utxo_client=utxo_client ) 
                if payment_utxos is None:
                    log.error("No UTXOs returned")
                    raise ValueError()

                if 'error' in payment_utxos:
                    log.error("Failed to query UTXOs for %s: %s" % payment_address, payment_utxos['error'])
                    raise Exception("Failed to query UTXO provider: %s" % payment_utxos['error'])
                
                # assuming they're p2pkh outputs...
                subsidy_byte_count = APPROX_TX_OVERHEAD_LEN + ((len(payment_utxos) + 3) * APPROX_TX_IN_P2PKH_LEN) + APPROX_TX_OUT_P2PKH_LEN
                signed_subsidized_tx = unsigned_tx + "00" * (71 + subsidy_byte_count)    # ~71 bytes for signature

            else:
                log.error("BUG: missing both payment private key and address")
                raise Exception("Need either payment_privkey or payment_address")

    except ValueError, ve:
        if os.environ.get("BLOCKSTACK_TEST") == "1":
            log.exception(ve)
            print >> sys.stderr, "payment key info: %s" % str(payment_privkey_info)

        log.error("Insufficient funds:  Not enough inputs to make an update transaction.")
        return None 

    except AssertionError, ae:
        if BLOCKSTACK_DEBUG:
            log.exception(ae)

        log.error("Unable to create transaction")
        return None

    except Exception, e: 
        if os.environ.get("BLOCKSTACK_TEST") == "1":
            log.exception(e)

        return None

    tx_fee = get_tx_fee( signed_subsidized_tx, config_path=config_path )
    if tx_fee is None:
        log.error("Failed to get tx fee")
        return None
    
    log.debug("update tx %s bytes, %s satoshis txfee" % (len(signed_subsidized_tx), int(tx_fee)))

    if include_dust:
        dust_fee = estimate_dust_fee( unsigned_tx, fees_update )
        assert dust_fee is not None
        log.debug("Additional dust fee: %s" % dust_fee)
        tx_fee += dust_fee

    return tx_fee


def estimate_transfer_tx_fee( name, payment_privkey_info, owner_address, utxo_client, owner_privkey_params=(1, 1), config_path=CONFIG_PATH, include_dust=False ):
    """
    Estimate the transaction fee of a transfer.
    Optionally include the dust fees as well.
    Return the number of satoshis on success
    Return None on error
    """
    fake_recipient_address = virtualchain.address_reencode('1LL4X7wNUBCWoDhfVLA2cHE7xk1ZJMT98Q')
    fake_consensus_hash = 'd4049672223f42aac2855d2fbf2f38f0'
    
    fake_privkey = make_fake_privkey_info( owner_privkey_params )

    try:
        unsigned_tx = transfer_tx( name, fake_recipient_address, True, fake_consensus_hash, owner_address, utxo_client, subsidize=True )
        subsidized_tx = tx_make_subsidizable( unsigned_tx, fees_transfer, 21 * 10**14, payment_privkey_info, utxo_client )
        assert subsidized_tx is not None
    except ValueError, ve:
        if os.environ.get("BLOCKSTACK_TEST") == "1":
            log.exception(ve)

        log.error("Insufficient funds:  Not enough inputs to make a transfer transaction.")
        return None
    except AssertionError as ae:
        if BLOCKSTACK_DEBUG:
            log.exception(ve)

        log.error("Unable to make transaction")
        return None

    signed_subsidized_tx = sign_tx( subsidized_tx, fake_privkey )

    tx_fee = get_tx_fee( signed_subsidized_tx, config_path=config_path )
    if tx_fee is None:
        log.error("Failed to get tx fee")
        return None
    
    log.debug("transfer tx %s bytes, %s satoshis txfee" % (len(signed_subsidized_tx), int(tx_fee)))

    if include_dust:
        dust_fee = estimate_dust_fee( unsigned_tx, fees_transfer )
        assert dust_fee is not None
        log.debug("Additional dust fee: %s" % dust_fee)
        tx_fee += dust_fee

    return tx_fee


def estimate_revoke_tx_fee( name, payment_privkey_info, owner_address, utxo_client, owner_privkey_params=(1, 1), config_path=CONFIG_PATH, include_dust=False ):
    """
    Estimate the transaction fee of a revoke.
    Optionally include the dust fees as well.
    Return the number of satoshis on success
    Return None on error
    """
    fake_privkey = make_fake_privkey_info( owner_privkey_params )

    try:
        unsigned_tx = revoke_tx( name, owner_address, utxo_client, subsidize=True )
        subsidized_tx = tx_make_subsidizable( unsigned_tx, fees_revoke, 21 * 10**14, payment_privkey_info, utxo_client )
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

    signed_subsidized_tx = sign_tx( subsidized_tx, fake_privkey )

    tx_fee = get_tx_fee( signed_subsidized_tx, config_path=config_path )
    if tx_fee is None:
        log.error("Failed to get tx fee")
        return None

    log.debug("revoke tx %s bytes, %s satoshis txfee" % (len(signed_subsidized_tx), int(tx_fee)))

    if include_dust:
        dust_fee = estimate_dust_fee( signed_tx, fees_revoke )
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

    log.debug("name import tx %s bytes, %s satoshis txfee" % (len(signed_tx), int(tx_fee)))
    return tx_fee


def estimate_namespace_preorder_tx_fee( namespace_id, cost, payment_address, utxo_client, config_path=CONFIG_PATH, include_dust=False ):
    """
    Estimate the transaction fee of a namespace preorder
    Return the number of satoshis on success
    Return None on error

    TODO: no dust fee estimation available for namespace preorder
    """
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
  
    log.debug("namespace preorder tx %s bytes, %s satoshis" % (len(signed_tx), int(tx_fee)))
    return tx_fee


def estimate_namespace_reveal_tx_fee( namespace_id, payment_address, utxo_client, config_path=CONFIG_PATH, include_dust=False ):
    """
    Estimate the transaction fee of a namespace reveal
    Return the number of satoshis on success
    Return None on error

    TODO: no dust estimation available for namespace reveal
    """
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

    log.debug("namespace reveal tx %s bytes, %s satoshis txfee" % (len(signed_tx), int(tx_fee)))
    
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

    log.debug("namespace ready tx %s bytes, %s satoshis txfee" % (len(signed_tx), int(tx_fee)))
   
    return tx_fee


def estimate_announce_tx_fee( sender_address, utxo_client, sender_privkey_params=(1, 1), config_path=CONFIG_PATH, include_dust=False ):
    """
    Estimate the transaction fee of an announcement tx
    Return the number of satoshis on success
    Return None on error
    """
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

    log.debug("announce tx %s bytes, %s satoshis" % (len(signed_tx), int(tx_fee)))
    
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

    blockstack_info = blockstack_getinfo( proxy=proxy )
    if 'error' in blockstack_info:
        return {'error': 'Blockstack server did not return consensus hash: %s' % blockstack_info['error']}

    # up-to-date?
    last_block_processed = None
    last_block_seen = None
    try:
        last_block_processed = int(blockstack_info['last_block_processed'])
        last_block_seen = int(blockstack_info['last_block_seen'])
        consensus_hash = blockstack_info['consensus']
    except Exception, e:
        log.exception(e) 
        return {'error': 'Invalid consensus hash from server'}

    # valid?
    height = get_block_height( config_path=config_path )
    if height is None:
        return {'error': 'Failed to get blockchain height'}

    if height > last_block_processed + 20 or (last_block_seen is not None and last_block_seen > last_block_processed + 20):
        # server is lagging
        log.error("Server is lagging behind: bitcoind height is %s, server is %s" % (height, last_block_processed))
        return {'error': 'Server is lagging behind'}

    return {'status': True, 'consensus_hash': consensus_hash}


def address_privkey_match( address, privkey_params ):
    """
    Does an address correspond to the private key information?
    i.e. singlesig --> p2pkh address
    i.e. multisig --> p2sh address
    """
    if privkey_params == (1,1) and pybitcoin.b58check_version_byte( str(address) ) != virtualchain.version_byte:
        # invalid address, given parameters
        log.error("Address %s does not correspond to a single private key" % owner_address)
        return False

    elif (privkey_params[0] > 1 or privkey_params[1] > 1) and pybitcoin.b58check_version_byte( str(address) ) != virtualchain.multisig_version_byte:
        # invalid address
        log.error("Address %s does not correspond to multisig private keys")
        return False

    return True


def do_preorder( fqu, payment_privkey_info, owner_address, cost, utxo_client, tx_broadcaster, owner_privkey_params=(1,1), config_path=CONFIG_PATH, proxy=None, consensus_hash=None, safety_checks=True ):
    """
    Preorder a name
    Return {'status': True, 'transaction_hash': ...} on success
    Return {'error': ...} on failure
    """

    if proxy is None:
        proxy = get_default_proxy()

    fqu = str(fqu)

    if not can_receive_name(owner_address, proxy=proxy):
        log.error("Address %s owns too many names already." % owner_address)
        return {'error': 'Address owns too many names'}

    payment_address = get_privkey_info_address( payment_privkey_info )

    # sanity check
    if not address_privkey_match( owner_address, owner_privkey_params ):
        return {'error': 'Owner address does not match private key'}

    if not is_address_usable(payment_address, config_path=config_path):
        log.error("Payment address not ready: %s" % payment_address)
        return {'error': 'Payment address is not ready'}

    if consensus_hash is None:
        consensus_hash_res = get_consensus_hash( proxy, config_path=config_path )
        if 'error' in consensus_hash_res:
            return {'error': 'Failed to get consensus hash: %s' % consensus_hash_res['error']}

        consensus_hash = consensus_hash_res['consensus_hash']
    else:
        log.warn("Using user-supplied consensus hash %s" % consensus_hash)

    tx_fee = estimate_preorder_tx_fee( fqu, cost, payment_address, utxo_client, owner_privkey_params=owner_privkey_params, config_path=config_path )
    if tx_fee is None:
        log.error("Failed to estimate preorder TX fee")
        return {'error': 'Failed to get fee estimate.  Please check your network settings and verify that you have sufficient funds.'}

    log.debug("Preordering (%s, %s, %s), tx_fee = %s" % (fqu, payment_address, owner_address, tx_fee))

    try:
        unsigned_tx = preorder_tx( fqu, payment_address, owner_address, cost, consensus_hash, utxo_client, tx_fee=tx_fee )
    except ValueError:
        log.error("Failed to create preorder TX")
        return {'error': 'Insufficient funds'}

    try:
        resp = sign_and_broadcast_tx( unsigned_tx, payment_privkey_info, tx_broadcaster=tx_broadcaster )
    except Exception, e:
        log.exception(e)
        return {'error': 'Failed to create and broadcast preorder transaction'}

    return resp


def do_register( fqu, payment_privkey_info, owner_address, utxo_client, tx_broadcaster, owner_privkey_params=(1,1), config_path=CONFIG_PATH, proxy=None, safety_checks=True ):
    """
    Register a name
    Return {'status': True, 'transaction_hash': ...} on success
    Return {'error': ...} on failure
    """
    if proxy is None:
        proxy = get_default_proxy()

    fqu = str(fqu)
    resp = {}
    payment_address = get_privkey_info_address( payment_privkey_info )

    # sanity check
    if not address_privkey_match( owner_address, owner_privkey_params ):
        return {'error': 'Owner address does not match private key'}

    if safety_checks:
        # name must not be registered yet
        if is_name_registered(fqu, proxy=proxy):
            log.error("Already registered %s" % fqu)
            return {'error': 'Already registered'}

    # check address usability
    if not is_address_usable(payment_address, config_path=config_path, utxo_client=utxo_client):
        log.error("Payment address not ready: %s" % payment_address)
        return {'error': 'Payment address has unconfirmed transactions'}

    tx_fee = estimate_register_tx_fee( fqu, payment_address, utxo_client, owner_privkey_params=owner_privkey_params, config_path=config_path )
    if tx_fee is None:
        log.error("Failed to estimate register TX fee")
        return {'error': 'Failed to get fee estimate.  Please check your network settings and verify that you have sufficient funds.'}

    log.debug("Registering (%s, %s, %s), tx_fee = %s" % (fqu, payment_address, owner_address, tx_fee))

    # now send it
    try:
        unsigned_tx = register_tx( fqu, payment_address, owner_address, utxo_client, tx_fee=tx_fee )
    except ValueError:
        log.error("Failed to create register TX")
        return {'error': 'Insufficient funds'}

    try:
        resp = sign_and_broadcast_tx( unsigned_tx, payment_privkey_info, config_path=config_path, tx_broadcaster=tx_broadcaster )
    except Exception, e:
        log.exception(e)
        return {'error': 'Failed to sign and broadcast transaction'}

    return resp


def do_update( fqu, zonefile_hash, owner_privkey_info, payment_privkey_info, utxo_client, tx_broadcaster, config_path=CONFIG_PATH, proxy=None, consensus_hash=None, safety_checks=True ):
    """
    Put a new zonefile hash for a name
    Return {'status': True, 'transaction_hash': ..., 'value_hash': ...} on success
    Return {'error': ...} on failure
    """

    if proxy is None:
        proxy = get_default_proxy()
    
    fqu = str(fqu)
    owner_address = get_privkey_info_address( owner_privkey_info )
    payment_address = get_privkey_info_address( payment_privkey_info )
    owner_privkey_params = get_privkey_info_params( owner_privkey_info )
    if owner_privkey_params == (None, None):
        return {'error': 'Invalid owner private key'}

    # get consensus hash
    if consensus_hash is None:
        consensus_hash_res = get_consensus_hash( proxy, config_path=config_path )
        if 'error' in consensus_hash_res:
            return {'error': 'Failed to get consensus hash: %s' % consensus_hash_res['error']}

        consensus_hash = consensus_hash_res['consensus_hash']

    else:
        log.warn("Using caller-supplied consensus hash '%s'" % consensus_hash)

    if safety_checks:
        # check ownership
        blockchain_record = blockstack_get_name_blockchain_record( fqu, proxy=proxy )
        if blockchain_record is None or 'error' in blockchain_record:
            log.error("Failed to read blockchain record for %s" % fqu)
            return {'error': 'Failed to read blockchain record for name'}

        if owner_address != blockchain_record['address']:
            log.error("Given privkey/address doesn't own this name.")
            return {'error': 'Not name owner'}

    # check address usability
    if not is_address_usable(payment_address, config_path=config_path):
        log.error("Payment address not ready: %s" % payment_address)
        return {'error': 'Payment address has unconfirmed transactions'}

    tx_fee = estimate_update_tx_fee( fqu, payment_privkey_info, owner_address, utxo_client, owner_privkey_params=owner_privkey_params, config_path=config_path ) 
    if tx_fee is None:
        log.error("Failed to estimate update TX fee")
        return {'error': 'Failed to get fee estimate.  Please check your network settings and verify that you have sufficient funds.'}

    log.debug("Updating (%s, %s)" % (fqu, zonefile_hash))
    log.debug("<owner, payment> (%s, %s) tx_fee = %s" % (owner_address, payment_address, tx_fee))

    try:
        unsigned_tx = update_tx( fqu, zonefile_hash, consensus_hash, owner_address, utxo_client, subsidize=True, tx_fee=tx_fee )
    except ValueError, ve:
        log.exception(ve)
        log.error("Failed to generate update TX")
        return {'error': 'Insufficient funds'}
    except Exception, e:
        log.exception(e)
        return {'error': 'Failed to generate update transaction'}

    try:
        subsidized_tx = tx_make_subsidizable( unsigned_tx, fees_update, 21 * (10**6) * (10**8), payment_privkey_info, utxo_client, tx_fee=tx_fee )
        assert subsidized_tx is not None
    except ValueError, ve:
        log.exception(ve)
        log.error("Failed to subsidize update TX")
        return {'error': 'Insufficient funds'}
    except AssertionError as ae:
        if BLOCKSTACK_DEBUG:
            log.exception(ae)

        log.error("Failed to create subsidized tx")
        return {'error': 'Unable to create transaction'}

    resp = {}

    try:
        resp = sign_and_broadcast_tx( subsidized_tx, owner_privkey_info, config_path=config_path, tx_broadcaster=tx_broadcaster )
    except Exception, e:
        log.exception(e)
        return {'error': 'Failed to sign and broadcast transaction'}

    if 'error' in resp:
        return resp

    else:
        resp['value_hash'] = zonefile_hash
        return resp


def do_transfer( fqu, transfer_address, keep_data, owner_privkey_info, payment_privkey_info, utxo_client, tx_broadcaster, config_path=CONFIG_PATH, proxy=None, consensus_hash=None, safety_checks=True ):
    """
    Transfer a name to a new address
    Return {'status': True, 'transaction_hash': ...} on success
    Return {'error': ...} on failure
    """
    
    if proxy is None:
        proxy = get_default_proxy()

    fqu = str(fqu)
    owner_address = get_privkey_info_address(owner_privkey_info)
    payment_address = get_privkey_info_address(payment_privkey_info)
    owner_privkey_params = get_privkey_info_params(owner_privkey_info)
    if owner_privkey_params == (None, None):
        return {'error': 'Invalid owner private key'}

    # get consensus hash
    if consensus_hash is None:
        consensus_hash_res = get_consensus_hash( proxy, config_path=config_path )
        if 'error' in consensus_hash_res:
            return {'error': 'Failed to get consensus hash: %s' % consensus_hash_res['error']}

        consensus_hash = consensus_hash_res['consensus_hash']

    else:
        log.warn("Using caller-supplied consensus hash '%s'" % consensus_hash)

    if safety_checks:
        # name must exist
        blockchain_record = blockstack_get_name_blockchain_record( fqu, proxy=proxy )
        if blockchain_record is None or 'error' in blockchain_record:
            log.error("Failed to read blockchain record for %s" % fqu)
            return {'error': 'Failed to read blockchain record for name'}

        # must be owner
        if blockchain_record['address'] != owner_address:
            log.error("Given privkey/address doesn't own this name.")
            return {'error': 'Given keypair does not own this name'}

        # recipient must have space
        if not can_receive_name(transfer_address, proxy=proxy):
            log.error("Address %s owns too many names already." % transfer_address)
            return {'error': 'Recipient owns too many names'}
    
    # payment address must be usable
    if not is_address_usable(payment_address, config_path=config_path):
        log.error("Payment address not ready: %s" % payment_address)
        return {'error': 'Payment address has unconfirmed transactions'}

    tx_fee = estimate_transfer_tx_fee( fqu, payment_privkey_info, owner_address, utxo_client, owner_privkey_params=owner_privkey_params, config_path=config_path )
    if tx_fee is None:
        log.error("Failed to estimate tx fee")
        return {'error': 'Failed to get fee estimate.  Please check your network settings and verify that you have sufficient funds.'}

    try:
        unsigned_tx = transfer_tx( fqu, transfer_address, keep_data, consensus_hash, owner_address, utxo_client, subsidize=True, tx_fee=tx_fee )
        subsidized_tx = tx_make_subsidizable( unsigned_tx, fees_transfer, 21 * (10**6) * (10**8), payment_privkey_info, utxo_client, tx_fee=tx_fee )
        assert subsidized_tx is not None
    except ValueError:
        log.error("Failed to generate transfer tx")
        return {'error': 'Insufficient funds'}
    except AssertionError as ae:
        if BLOCKSTACK_DEBUG:
            log.exception(ae)

        log.error("Failed to subsidize transfer tx")
        return {'error': 'Unable to create transaction'}

    log.debug("Transferring (%s, %s)" % (fqu, transfer_address))
    log.debug("<owner, payment> (%s, %s) tx_fee = %s" % (owner_address, payment_address, tx_fee))

    resp = {}
    try:
        resp = sign_and_broadcast_tx( subsidized_tx, owner_privkey_info, config_path=config_path, tx_broadcaster=tx_broadcaster )
    except Exception, e:
        log.exception(e)
        return {'error': 'Failed to sign and broadcast transaction'}

    return resp


def do_renewal( fqu, owner_privkey_info, payment_privkey_info, renewal_fee, utxo_client, tx_broadcaster, config_path=CONFIG_PATH, proxy=None, safety_checks=True ):
    """
    Renew a name
    Return {'status': True, 'transaction_hash': ...} on success
    Return {'error': ...} on failure
    """
    if proxy is None:
        proxy = get_default_proxy()
    
    fqu = str(fqu)
    resp = {}
    owner_address = get_privkey_info_address( owner_privkey_info )
    payment_address = get_privkey_info_address( payment_privkey_info )
    owner_privkey_params = get_privkey_info_params( owner_privkey_info )
    if owner_privkey_params == (None, None):
        return {'error': 'Invalid owner private key'}

    if safety_checks:
        if not is_name_registered(fqu, proxy=proxy):
            log.error("Already registered %s" % fqu)
            return {'error': 'Already registered'}
            
        blockchain_record = blockstack_get_name_blockchain_record( fqu, proxy=proxy )
        if blockchain_record is None or 'error' in blockchain_record:
            log.error("Failed to read blockchain record for %s" % fqu)
            return {'error': 'Failed to read blockchain record for name'}

        if owner_address != blockchain_record['address']:
            log.error("Given privkey/address doesn't own this name.")
            return {'error': 'Not name owner'}

    # check address usability
    if not is_address_usable(payment_address, config_path=config_path, utxo_client=utxo_client):
        log.error("Payment address not ready: %s" % payment_address)
        return {'error': 'Payment address has unconfirmed transactions'}

    tx_fee = estimate_renewal_tx_fee( fqu, renewal_fee, payment_privkey_info, owner_address, utxo_client, owner_privkey_params=owner_privkey_params, config_path=config_path ) 
    if tx_fee is None:
        log.error("Failed to estimate renewal tx fee")
        return {'error': 'Failed to get fee estimate.  Please check your network settings and verify that you have sufficient funds.'}

    log.debug("Renewing (%s, %s, %s), tx_fee = %s, renewal_fee = %s" % (fqu, payment_address, owner_address, tx_fee, renewal_fee))

    # now send it
    try:
        unsigned_tx = register_tx( fqu, owner_address, owner_address, utxo_client, renewal_fee=renewal_fee, tx_fee=tx_fee )
        subsidized_tx = tx_make_subsidizable( unsigned_tx, fees_registration, 21 ** (10**6) * (10**8), payment_privkey_info, utxo_client, tx_fee=tx_fee )
        assert subsidized_tx is not None
    except ValueError:
        log.error("Failed to generate renewal tx")
        return {'error': 'Insufficient funds'}
    except AssertionError as ae:
        if BLOCKSTACK_DEBUG:
            log.exception(ae)

        log.error("Failed to subsidize renewal tx")
        return {'error': 'Unable to create transaction'}

    try:
        resp = sign_and_broadcast_tx( subsidized_tx, owner_privkey_info, config_path=config_path, tx_broadcaster=tx_broadcaster )
    except Exception, e:
        if os.environ.get("BLOCKSTACK_DEBUG") == "1":
            log.exception(e)

        log.error("Failed to sign and broadcast tx")
        return {'error': 'Failed to sign and broadcast transaction'}

    return resp


def do_revoke( fqu, owner_privkey_info, payment_privkey_info, utxo_client, tx_broadcaster, config_path=CONFIG_PATH, proxy=None, safety_checks=True ):
    """
    Revoke a name
    Return {'status': True, 'transaction_hash': ...} on success
    Return {'error': ...} on failure
    """
    if proxy is None:
        proxy = get_default_proxy()

    fqu = str(fqu)
    owner_address = get_privkey_info_address(owner_privkey_info)
    payment_address = get_privkey_info_address(payment_privkey_info)
    owner_privkey_params = get_privkey_info_params(owner_privkey_info)
    if owner_privkey_params == (None, None):
        log.error("Invalid owner private key")
        return {'error': 'Invalid owner private key'}

    tx_fee = estimate_revoke_tx_fee( fqu, payment_privkey_info, owner_address, utxo_client, owner_privkey_params=owner_privkey_params, config_path=config_path )
    if tx_fee is None:
        log.error("Failed to estimate revoke tx fee")
        return {'error': 'Failed to get fee estimate.  Please check your network settings and verify that you have sufficient funds.'}

    if safety_checks:
        # name must exist
        blockchain_record = blockstack_get_name_blockchain_record( fqu, proxy=proxy )
        if blockchain_record is None or 'error' in blockchain_record:
            log.error("Failed to read blockchain record for %s" % fqu)
            return {'error': 'Failed to read blockchain record for name'}

        # must be owner
        if blockchain_record['address'] != owner_address:
            log.error("Given privkey/address doesn't own this name.")
            return {'error': 'Given keypair does not own this name'}

    try:
        unsigned_tx = revoke_tx( fqu, owner_address, utxo_client, subsidize=True, tx_fee=tx_fee )
        subsidized_tx = tx_make_subsidizable( unsigned_tx, fees_revoke, 21 ** (10**6) * (10**8), payment_privkey_info, utxo_client, tx_fee=tx_fee )
        assert subsidized_tx is not None
    except ValueError:
        log.error("Failed to generate revoke tx")
        return {'error': 'Insufficient funds'}
    except AssertionError as ae:
        if BLOCKSTACK_DEBUG:
            log.exception(ae)

        log.error("Failed to subsidize revoke tx")
        return {'error': 'Unable to create transaction'}

    log.debug("Revoking %s" % fqu)
    log.debug("<owner, payment> (%s, %s) tx_fee = %s" % (owner_address, payment_address, tx_fee))

    resp = {}
    try:
        resp = sign_and_broadcast_tx( subsidized_tx, owner_privkey_info, config_path=config_path, tx_broadcaster=tx_broadcaster )
    except Exception, e:
        if os.environ.get("BLOCKSTACK_DEBUG") == "1":
            log.exception(e)

        log.error("Failed to sign and broadcast tx")
        return {'error': 'Failed to sign and broadcast revoke transaction'}

    return resp


def do_name_import( fqu, importer_privkey_info, recipient_address, zonefile_hash, utxo_client, tx_broadcaster, config_path=CONFIG_PATH, proxy=None, safety_checks=True ):
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

    tx_fee = estimate_name_import_tx_fee( fqu, payment_address, utxo_client, config_path=config_path )
    if tx_fee is None:
        log.error("Failed to estimate name import tx fee")
        return {'error': 'Failed to get fee estimate.  Please check your network settings and verify that you have sufficient funds.'}

    try:
        unsigned_tx = name_import_tx( fqu, recipient_address, zonefile_hash, payment_address, utxo_client, tx_fee=tx_fee )
    except ValueError, ve:
        log.exception(ve)
        log.error("Failed to generate name import tx")
        return {'error': 'Insufficient funds'}

    log.debug("Import (%s, %s, %s)" % (fqu, recipient_address, zonefile_hash))
    resp = {}
    try:
        resp = sign_and_broadcast_tx( unsigned_tx, importer_privkey_info, config_path=config_path, tx_broadcaster=tx_broadcaster )
    except Exception, e:
        if os.environ.get("BLOCKSTACK_DEBUG") == "1":
            log.exception(e)

        log.error("Failed to sign and broadcast tx")
        return {'error': 'Failed to sign and broadcast import transaction'}

    if 'error' in resp:
        return resp

    else:
        resp['value_hash'] = zonefile_hash
        return resp


def do_namespace_preorder( namespace_id, cost, payment_privkey_info, reveal_address, utxo_client, tx_broadcaster, consensus_hash=None, config_path=CONFIG_PATH, proxy=None, safety_checks=True ):
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

    try:
        unsigned_tx = namespace_preorder_tx( namespace_id, reveal_address, cost, consensus_hash, payment_address, utxo_client, tx_fee=tx_fee )
    except ValueError, ve:
        if os.environ.get("BLOCKSTACK_DEBUG") == "1":
            log.exception(ve)

        log.error("Failed to create namespace preorder tx")
        return {'error': 'Insufficient funds'}

    resp = {}

    try:
        resp = sign_and_broadcast_tx( unsigned_tx, payment_privkey_info, tx_broadcaster=tx_broadcaster)
    except Exception, e:
        if os.environ.get("BLOCKSTACK_DEBUG") == "1":
            log.exception(e)

        log.error("Failed to sign and broadcast tx")
        return {'error': 'Failed to sign and broadcast namespace preorder transaction'}

    return resp


def do_namespace_reveal( namespace_id, reveal_address, lifetime, coeff, base_cost, bucket_exponents, nonalpha_discount, no_vowel_discount, payment_privkey_info, utxo_client, tx_broadcaster, config_path=CONFIG_PATH, proxy=None, safety_checks=True ):
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

    resp = {}

    try:
        resp = sign_and_broadcast_tx( unsigned_tx, payment_privkey_info, tx_broadcaster=tx_broadcaster )
    except Exception, e:
        if os.environ.get("BLOCKSTACK_DEBUG") == "1":
            log.exception(e)

        log.error("Failed to sign and broadcast tx")
        return {'error': 'Failed to sign and broadcast namespace reveal transaction'}

    return resp


def do_namespace_ready( namespace_id, reveal_privkey_info, utxo_client, tx_broadcaster, config_path=CONFIG_PATH, proxy=None, safety_checks=True ):
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

    resp = {}

    try:
        resp = sign_and_broadcast_tx( unsigned_tx, reveal_privkey_info, tx_broadcaster=tx_broadcaster )
    except Exception, e:
        if os.environ.get("BLOCKSTACK_DEBUG") == "1":
            log.exception(e)

        log.error("Failed to sign and broadcast tx")
        return {'error': 'Failed to sign and broadcast namespace ready transaction'}

    return resp


def do_announce( message_text, sender_privkey_info, utxo_client, tx_broadcaster, config_path=CONFIG_PATH, proxy=None, safety_checks=True ):
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

    resp = {}

    try:
        resp = sign_and_broadcast_tx( unsigned_tx, sender_privkey_info, tx_broadcaster=tx_broadcaster )
    except Exception, e:
        log.exception(e)
        log.error("Failed to sign and broadcast transaction")
        return {'error': 'Failed to sign and broadcast announce transaction'}
    
    # stash the announcement text 
    res = put_announcement( message_text, resp['transaction_hash'] )
    if 'error' in res:
        log.error("Failed to store announcement text: %s" % res['error'])
        return {'error': 'Failed to store message text', 'transaction_hash': resp['transaction_hash'], 'message_hash': message_hash}

    else:
        resp['message_hash'] = message_hash
        return resp


def async_preorder(fqu, payment_privkey_info, owner_address, cost, owner_privkey_params=(1,1), proxy=None, config_path=CONFIG_PATH, queue_path=DEFAULT_QUEUE_PATH):
    """
        Preorder a fqu (step #1)

        @fqu: fully qualified name e.g., muneeb.id
        @payment_privkey_info: private key that will pay
        @owner_address: will own the name

        Returns True/False and stores tx_hash in queue
    """

    if proxy is None:
        proxy = get_default_proxy(config_path=config_path)

    utxo_client = get_utxo_provider_client( config_path=config_path )
    tx_broadcaster = get_tx_broadcaster( config_path=config_path )

    payment_address = get_privkey_info_address( payment_privkey_info )
    
    # stale preorder will get removed from preorder_queue
    if in_queue("register", fqu, path=queue_path):
        log.error("Already in register queue: %s" % fqu)
        return {'error': 'Already in register queue'}

    if in_queue("preorder", fqu, path=queue_path):
        log.error("Already in preorder queue: %s" % fqu)
        return {'error': 'Already in preorder queue'}

    try:
        resp = do_preorder( fqu, payment_privkey_info, owner_address, cost, utxo_client, tx_broadcaster, owner_privkey_params=owner_privkey_params, config_path=CONFIG_PATH )
    except Exception, e:
        log.exception(e)
        return {'error': 'Failed to sign and broadcast preorder transaction'}

    if 'transaction_hash' in resp:
        # watch this preorder, and register it when it gets queued
        queue_append("preorder", fqu, resp['transaction_hash'],
                     payment_address=payment_address,
                     owner_address=owner_address,
                     config_path=config_path,
                     path=queue_path)
    else:
        log.error("Error preordering: %s with %s for %s" % (fqu, payment_address, owner_address))
        log.error("Error below\n%s" % json.dumps(resp, indent=4, sort_keys=True))
        return {'error': 'Failed to preorder: %s' % resp['error']}

    return resp


def async_register(fqu, payment_privkey_info, owner_address, owner_privkey_params=(1,1), proxy=None, config_path=CONFIG_PATH, queue_path=DEFAULT_QUEUE_PATH):
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
        resp = do_register( fqu, payment_privkey_info, owner_address, utxo_client, tx_broadcaster, owner_privkey_params=owner_privkey_params, config_path=config_path, proxy=proxy )
    except Exception, e:
        log.exception(e)
        return {'error': 'Failed to sign and broadcast registration transaction'}

    if 'transaction_hash' in resp:
        queue_append("register", fqu, resp['transaction_hash'],
                     payment_address=payment_address,
                     owner_address=owner_address,
                     config_path=config_path,
                     path=queue_path)

        return resp

    else:
        log.error("Error registering: %s" % fqu)
        log.error(pprint(resp))
        return {'error': 'Failed to send registration'}


def async_update(fqu, zonefile_data, profile, owner_privkey_info, payment_privkey_info, config_path=CONFIG_PATH,
                 zonefile_hash=None, proxy=None, queue_path=DEFAULT_QUEUE_PATH):
    """
        Update a previously registered fqu, using a different payment address

        @fqu: fully qualified name e.g., muneeb.id
        @zonefile_data: new zonefile text, hash(zonefile) goes to blockchain
        @owner_privkey_info: privkey of owner address, to sign update
        @payment_privkey_info: the privkey which is paying for the cost

        Returns True/False and stores tx_hash in queue
    """

    if zonefile_hash is None and zonefile_data is None:
        raise Exception("No zonefile or zonefile hash given")

    if proxy is None:
        proxy = get_default_proxy(config_path=config_path)

    if zonefile_data is not None and len(zonefile_data) > RPC_MAX_ZONEFILE_LEN:
        return {'error': 'Zonefile is too big (%s bytes)' % len(zonefile_data)}
    
    utxo_client = get_utxo_provider_client(config_path=config_path)
    tx_broadcaster = get_tx_broadcaster(config_path=config_path)

    owner_address = get_privkey_info_address( owner_privkey_info )

    if in_queue("update", fqu, path=queue_path):
        log.error("Already in update queue: %s" % fqu)
        return {'error': 'Already in update queue'}

    if zonefile_hash is None:
        zonefile_hash = get_zonefile_data_hash( zonefile_data )

    resp = {}
    try:
        resp = do_update( fqu, zonefile_hash, owner_privkey_info, payment_privkey_info, utxo_client, tx_broadcaster, config_path=config_path, proxy=proxy )
    except Exception, e:
        log.exception(e)
        return {'error': 'Failed to sign and broadcast update transaction'}

    if 'transaction_hash' in resp:
        queue_append("update", fqu, resp['transaction_hash'],
                     zonefile_data=zonefile_data,
                     profile=profile,
                     zonefile_hash=zonefile_hash,
                     owner_address=owner_address,
                     config_path=config_path,
                     path=queue_path)

        resp['zonefile_hash'] = zonefile_hash
        return resp

    else:
        log.error("Error updating: %s" % fqu)
        log.error("Full response: %s" % json.dumps(resp))
        return {'error': 'Failed to broadcast update transaction'}


def async_transfer(fqu, transfer_address, owner_privkey_info, payment_privkey_info, config_path=CONFIG_PATH, proxy=None, queue_path=DEFAULT_QUEUE_PATH):
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
        resp = do_transfer( fqu, transfer_address, True, owner_privkey_info, payment_privkey_info, utxo_client, tx_broadcaster, config_path=config_path, proxy=proxy )
    except Exception, e:
        log.exception(e)
        return {'error': 'Failed to sign and broadcast transfer transaction'}

    if 'transaction_hash' in resp:
        queue_append("transfer", fqu, resp['transaction_hash'],
                     owner_address=owner_address,
                     transfer_address=transfer_address,
                     config_path=config_path,
                     path=queue_path)
    else:
        log.error("Error transferring: %s" % fqu)
        log.error(resp)
        return {'error': 'Failed to broadcast transfer transaction'}

    return resp


def async_renew(fqu, owner_privkey_info, payment_privkey_info, renewal_fee, proxy=None, config_path=CONFIG_PATH, queue_path=DEFAULT_QUEUE_PATH):
    """
        Renew an already-registered name.

        @fqu: fully qualified name e.g., muneeb.id

        Return {'status': True, ...} on success
        Return {'error': ...} on error
    """

    if proxy is None:
        proxy = get_default_proxy(config_path=config_path)

    utxo_client = get_utxo_provider_client(config_path=config_path)
    tx_broadcaster = get_tx_broadcaster( config_path=config_path )

    # check renew queue first
    if in_queue("renew", fqu, path=queue_path):
        log.error("Already in renew queue: %s" % fqu)
        return {'error': 'Already in renew queue'}

    try:
        resp = do_renewal( fqu, owner_privkey_info, payment_privkey_info, renewal_fee, utxo_client, tx_broadcaster, config_path=config_path, proxy=proxy )
    except Exception, e:
        log.exception(e)
        return {'error': 'Failed to sign and broadcast renewal transaction'}

    if 'error' in resp or 'transaction_hash' not in resp:
        log.error("Error renewing: %s" % fqu)
        log.error(resp)
        return {'error': 'Failed to send renewal'}

    else:
        return resp


def async_revoke(fqu, owner_privkey_info, payment_privkey_info, proxy=None, config_path=CONFIG_PATH, queue_path=DEFAULT_QUEUE_PATH):
    """
        Revoke a name.

        @fqu: fully qualified name e.g., muneeb.id

        Return {'status': True, ...} on success
        Return {'error': ...} on error
    """

    if proxy is None:
        proxy = get_default_proxy(config_path=config_path)

    utxo_client = get_utxo_provider_client(config_path=config_path)
    tx_broadcaster = get_tx_broadcaster( config_path=config_path )
    
    # check revoke queue first
    if in_queue("revoke", fqu, path=queue_path):
        log.error("Already in revoke queue: %s" % fqu)
        return {'error': 'Already in revoke queue'}

    try:
        resp = do_revoke( fqu, owner_privkey_info, payment_privkey_info, utxo_client, tx_broadcaster, config_path=config_path, proxy=proxy )
    except Exception, e:
        log.exception(e)
        return {'error': 'Failed to sign and broadcast revoke transaction'}

    if 'error' in resp or 'transaction_hash' not in resp:
        log.error("Error revoking: %s" % fqu)
        log.error(resp)
        return {'error': 'Failed to send revoke'}

    else:
        return resp

