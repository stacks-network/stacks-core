# -*- coding: utf-8 -*-
"""
    Registrar
    ~~~~~
    :copyright: (c) 2014-2016 by Halfmoon Labs, Inc.
    :copyright: (c) 2016 blockstack.org
    :license: MIT, see LICENSE for more details.
"""

import os
import sys
import json
import pybitcoin

# Hack around absolute paths
current_dir = os.path.abspath(os.path.dirname(__file__))
parent_dir = os.path.abspath(current_dir + "/../")

from .queue import in_queue, queue_append, queue_findone

from .blockchain import get_tx_confirmations, get_utxo_client
from .blockchain import is_address_usable
from .blockchain import can_receive_name, get_balance, get_tx_fee

from crypto.utils import get_address_from_privkey, get_pubkey_from_privkey

from ..utils import pretty_print as pprint
from ..utils import pretty_dump

from ..config import PREORDER_CONFIRMATIONS, DEFAULT_QUEUE_PATH, CONFIG_PATH
from ..config import get_logger

from ..profile import hash_zonefile

from ..proxy import get_default_proxy
from ..proxy import getinfo as blockstack_getinfo
from ..proxy import get_name_cost as blockstack_get_name_cost
from ..proxy import get_name_blockchain_record as blockstack_get_name_blockchain_record
from ..proxy import get_namespace_blockchain_record as blockstack_get_namespace_blockchain_record
from ..proxy import is_name_registered, is_name_owner

from ..tx import sign_and_broadcast_tx, preorder_tx, register_tx, update_tx, transfer_tx, revoke_tx, \
        namespace_preorder_tx, namespace_reveal_tx, namespace_ready_tx, announce_tx, name_import_tx, sign_tx

from ..scripts import tx_make_subsidizable

from ..operations import fees_update, fees_transfer, fees_revoke

log = get_logger()


def estimate_preorder_tx_fee( name, name_cost, payment_pubkey_hex, utxo_client, config_path=CONFIG_PATH ):
    """
    Estimate the transaction fee of a preorder
    Return the number of satoshis on success
    Return None on error
    """
    fake_owner_address = '1PJeKxYXfTjE26FGFXmSuYpfnP2oRBu9kp'  # fake address
    fake_privkey = '5J8V3QacBzCwh6J9NJGZJHQ5NoJtMzmyUgiYFkBEgUzKdbFo7GX'   # fake private key
    fake_consensus_hash = 'd4049672223f42aac2855d2fbf2f38f0'

    unsigned_tx = preorder_tx( name, payment_pubkey_hex, fake_owner_address, name_cost, fake_consensus_hash, utxo_client )
    signed_tx = sign_tx( unsigned_tx, fake_privkey )
    tx_fee = get_tx_fee( signed_tx, config_path=config_path )

    return tx_fee


def estimate_register_tx_fee( name, payment_pubkey_hex, utxo_client, config_path=CONFIG_PATH ):
    """
    Estimate the transaction fee of a register
    Return the number of satoshis on success
    Return None on error
    """
    fake_owner_address = '1PJeKxYXfTjE26FGFXmSuYpfnP2oRBu9kp'  # fake address
    fake_privkey = '5J8V3QacBzCwh6J9NJGZJHQ5NoJtMzmyUgiYFkBEgUzKdbFo7GX'   # fake private key

    unsigned_tx = register_tx( name, payment_pubkey_hex, fake_owner_address, utxo_client )
    signed_tx = sign_tx( unsigned_tx, fake_privkey )
    tx_fee = get_tx_fee( signed_tx, config_path=config_path )

    return tx_fee


def estimate_renewal_tx_fee( name, payment_pubkey_hex, utxo_client, config_path=CONFIG_PATH ):
    """
    Estimate the transaction fee of a renewal
    Return the number of satoshis on success
    Return None on error
    """
    return estimate_register_tx_fee( name, payment_pubkey_hex, utxo_client, config_path=config_path )


def estimate_update_tx_fee( name, owner_pubkey_hex, payment_privkey, utxo_client, config_path=CONFIG_PATH ):
    """
    Estimate the transaction fee of an update
    Return the number of satoshis on success
    Return None on error
    """
    fake_privkey = '5J8V3QacBzCwh6J9NJGZJHQ5NoJtMzmyUgiYFkBEgUzKdbFo7GX'   # fake private key
    fake_consensus_hash = 'd4049672223f42aac2855d2fbf2f38f0'
    fake_zonefile_hash = '20b512149140494c0f7d565023973226908f6940'

    unsigned_tx = update_tx( name, fake_zonefile_hash, fake_consensus_hash, owner_pubkey_hex, utxo_client, subsidize=True )
    subsidized_tx = tx_make_subsidizable( unsigned_tx, fees_update, 21 * 10**14, payment_privkey, utxo_client )
    signed_subsidized_tx = sign_tx( subsidized_tx, fake_privkey )

    tx_fee = get_tx_fee( signed_subsidized_tx, config_path=config_path )
    return tx_fee


def estimate_transfer_tx_fee( name, owner_pubkey_hex, payment_privkey, utxo_client, config_path=CONFIG_PATH ):
    """
    Estimate the transaction fee of a transfer
    Return the number of satoshis on success
    Return None on error
    """
    fake_recipient_address = '1LL4X7wNUBCWoDhfVLA2cHE7xk1ZJMT98Q'
    fake_privkey = '5J8V3QacBzCwh6J9NJGZJHQ5NoJtMzmyUgiYFkBEgUzKdbFo7GX'   # fake private key
    fake_consensus_hash = 'd4049672223f42aac2855d2fbf2f38f0'
    
    unsigned_tx = transfer_tx( name, fake_recipient_address, True, fake_consensus_hash, owner_pubkey_hex, utxo_client, subsidize=True )
    subsidized_tx = tx_make_subsidizable( unsigned_tx, fees_transfer, 21 * 10**14, payment_privkey, utxo_client )
    signed_subsidized_tx = sign_tx( subsidized_tx, fake_privkey )

    tx_fee = get_tx_fee( signed_subsidized_tx, config_path=config_path )
    return tx_fee


def estimate_revoke_tx_fee( name, owner_pubkey_hex, payment_privkey, utxo_client, config_path=CONFIG_PATH ):
    """
    Estimate the transaction fee of a revoke
    Return the number of satoshis on success
    Return None on error
    """
    fake_privkey = '5J8V3QacBzCwh6J9NJGZJHQ5NoJtMzmyUgiYFkBEgUzKdbFo7GX'   # fake private key

    unsigned_tx = revoke_tx( name, owner_pubkey_hex, utxo_client, subsidize=True )
    subsidized_tx = tx_make_subsidizable( unsigned_tx, fees_revoke, 21 * 10**14, payment_privkey, utxo_client )
    signed_subsidized_tx = sign_tx( subsidized_tx, fake_privkey )

    tx_fee = get_tx_fee( signed_subsidized_tx, config_path=config_path )
    return tx_fee


def estimate_name_import_tx_fee( fqu, payment_pubkey_hex, utxo_client, config_path=CONFIG_PATH ):
    """
    Estimate the transaction fee of a name import
    Return the number of satoshis on success
    Return None on error
    """
    fake_privkey = '5J8V3QacBzCwh6J9NJGZJHQ5NoJtMzmyUgiYFkBEgUzKdbFo7GX'   # fake private key
    fake_zonefile_hash = '20b512149140494c0f7d565023973226908f6940'
    fake_recipient_address = '1LL4X7wNUBCWoDhfVLA2cHE7xk1ZJMT98Q'

    unsigned_tx = name_import_tx( fqu, fake_recipient_address, fake_zonefile_hash, payment_pubkey_hex, utxo_client )
    signed_tx = sign_tx( unsigned_tx, fake_privkey )
    tx_fee = get_tx_fee( signed_tx, config_path=config_path )

    return tx_fee


def estimate_namespace_preorder_tx_fee( namespace_id, cost, payment_pubkey_hex, utxo_client, config_path=CONFIG_PATH ):
    """
    Estimate the transaction fee of a namespace preorder
    Return the number of satoshis on success
    Return None on error
    """
    fake_privkey = '5J8V3QacBzCwh6J9NJGZJHQ5NoJtMzmyUgiYFkBEgUzKdbFo7GX'   # fake private key
    fake_reveal_address = '1LL4X7wNUBCWoDhfVLA2cHE7xk1ZJMT98Q'
    fake_consensus_hash = 'd4049672223f42aac2855d2fbf2f38f0'

    unsigned_tx = namespace_preorder_tx( namespace_id, fake_reveal_address, cost, fake_consensus_hash, payment_pubkey_hex, utxo_client )
    signed_tx = sign_tx( unsigned_tx, fake_privkey )
    tx_fee = get_tx_fee( signed_tx, config_path=config_path )
    
    return tx_fee


def estimate_namespace_reveal_tx_fee( namespace_id, payment_pubkey_hex, utxo_client, config_path=CONFIG_PATH ):
    """
    Estimate the transaction fee of a namespace reveal
    Return the number of satoshis on success
    Return None on error
    """
    fake_privkey = '5J8V3QacBzCwh6J9NJGZJHQ5NoJtMzmyUgiYFkBEgUzKdbFo7GX'   # fake private key
    fake_reveal_address = '1LL4X7wNUBCWoDhfVLA2cHE7xk1ZJMT98Q'

    unsigned_tx = namespace_reveal_tx( namespace_id, fake_reveal_address, 1, 2, 3, [4,5,6,7,8,9,10,11,12,13,14,15,0,1,2,3], 4, 5, payment_pubkey_hex, utxo_client )
    signed_tx = sign_tx( unsigned_tx, fake_privkey )
    tx_fee = get_tx_fee( signed_tx, config_path=config_path )

    return tx_fee


def estimate_namespace_ready_tx_fee( namespace_id, reveal_pubkey_hex, utxo_client, config_path=CONFIG_PATH ):
    """
    Estimate the transaction fee of a namespace ready
    Return the number of satoshis on success
    Return None on error
    """
    fake_privkey = '5J8V3QacBzCwh6J9NJGZJHQ5NoJtMzmyUgiYFkBEgUzKdbFo7GX'   # fake private key

    unsigned_tx = namespace_ready_tx( namespace_id, reveal_pubkey_hex, utxo_client )
    signed_tx = sign_tx( unsigned_tx, fake_privkey ) 
    tx_fee = get_tx_fee( signed_tx, config_path=config_path )

    return tx_fee


def estimate_announce_tx_fee( sender_pubkey_hex, utxo_client, config_path=CONFIG_PATH ):
    """
    Estimate the transaction fee of an announcement tx
    Return the number of satoshis on success
    Return None on error
    """
    fake_privkey = '5J8V3QacBzCwh6J9NJGZJHQ5NoJtMzmyUgiYFkBEgUzKdbFo7GX'   # fake private key
    fake_announce_hash = '20b512149140494c0f7d565023973226908f6940'

    unsigned_tx = announce_tx( fake_announce_hash, sender_pubkey_hex, utxo_client )
    signed_tx = sign_tx( unsigned_tx, fake_privkey )
    tx_fee = get_tx_fee( signed_tx, config_path=config_path )

    return tx_fee


def do_preorder( fqu, payment_privkey, owner_address, cost, utxo_client, config_path=CONFIG_PATH, proxy=None ):
    """
    Preorder a name
    Return {'status': True, 'transaction_hash': ...} on success
    Return {'error': ...} on failure
    """

    if proxy is None:
        proxy = get_default_proxy()

    if not can_receive_name(owner_address, proxy=proxy):
        log.debug("Address %s owns too many names already." % owner_address)
        return {'error': 'Address owns too many names'}

    payment_pubkey_hex = pybitcoin.BitcoinPrivateKey( payment_privkey ).public_key().to_hex()
    payment_address = pybitcoin.BitcoinPrivateKey( payment_privkey ).public_key().address()

    if not is_address_usable(payment_address, config_path=config_path):
        log.debug("Payment address not ready: %s" % payment_address)
        return {'error': 'Payment address is not ready'}

    blockstack_info = blockstack_getinfo( proxy=proxy )
    if 'error' in blockstack_info:
        return {'error': 'Failed to get consensus hash'}

    consensus_hash = blockstack_info['consensus']
    tx_fee = estimate_preorder_tx_fee( fqu, cost, payment_pubkey_hex, utxo_client, config_path=config_path )
    if tx_fee is None:
        return {'error': 'Failed to estimate the tx fee'}

    log.debug("Preordering (%s, %s, %s), tx_fee = %s" % (fqu, payment_address, owner_address, tx_fee))

    try:
        unsigned_tx = preorder_tx( fqu, payment_pubkey_hex, owner_address, cost, consensus_hash, utxo_client, tx_fee=tx_fee )
        resp = sign_and_broadcast_tx( unsigned_tx, payment_privkey, utxo_client=utxo_client )
    except Exception, e:
        log.exception(e)
        return {'error': 'Failed to create and broadcast preorder transaction'}

    return resp


def do_register( fqu, payment_privkey, owner_address, utxo_client, renewal_fee=None, config_path=CONFIG_PATH, proxy=None ):
    """
    Register/renew a name
    Return {'status': True, 'transaction_hash': ...} on success
    Return {'error': ...} on failure
    """
    if proxy is None:
        proxy = get_default_proxy()
    
    resp = {}
    payment_pubkey_hex = pybitcoin.BitcoinPrivateKey( payment_privkey ).public_key().to_hex()
    payment_address = pybitcoin.BitcoinPrivateKey( payment_privkey ).public_key().address()

    # name must not be registered yet (unless we're renewing)
    if renewal_fee is None:
        if is_name_registered(fqu, proxy=proxy):
            log.debug("Already registered %s" % fqu)
            return {'error': 'Already registered'}

    else:
        # check ownership
        blockchain_record = blockstack_get_name_blockchain_record( fqu, proxy=proxy )
        if blockchain_record is None or 'error' in blockchain_record:
            log.debug("Failed to read blockchain record for %s" % fqu)
            return {'error': 'Failed to read blockchain record for name'}

        if owner_address != blockchain_record['address']:
            log.debug("Given privkey/address doesn't own this name.")
            return {'error': 'Not name owner'}

    # check address usability
    if not is_address_usable(payment_address, config_path=config_path, utxo_client=utxo_client):
        log.debug("Payment address not ready: %s" % payment_address)
        return {'error': 'Payment address has unconfirmed transactions'}

    tx_fee = estimate_register_tx_fee( fqu, payment_pubkey_hex, utxo_client, config_path=config_path ) 
    log.debug("Registering (%s, %s, %s), tx_fee = %s" % (fqu, payment_address, owner_address, tx_fee))

    # now send it
    unsigned_tx = register_tx( fqu, payment_pubkey_hex, owner_address, utxo_client, renewal_fee=renewal_fee, tx_fee=tx_fee )

    try:
        resp = sign_and_broadcast_tx( unsigned_tx, payment_privkey, config_path=config_path, utxo_client=utxo_client )
    except Exception, e:
        log.exception(e)
        return {'error': 'Failed to sign and broadcast transaction'}

    return resp


def do_update( fqu, zonefile_hash, owner_privkey, payment_privkey, utxo_client, config_path=CONFIG_PATH, proxy=None ):
    """
    Put a new zonefile hash for a name
    Return {'status': True, 'transaction_hash': ...} on success
    Return {'error': ...} on failure
    """

    if proxy is None:
        proxy = get_default_proxy
    
    owner_public_key = pybitcoin.BitcoinPrivateKey(owner_privkey).public_key().to_hex()
    owner_address = pybitcoin.BitcoinPublicKey(owner_public_key).address()
    payment_address = pybitcoin.BitcoinPrivateKey( payment_privkey ).public_key().address()

    # get consensus hash
    blockstack_info = blockstack_getinfo(proxy=proxy)
    if 'error' in blockstack_info:
        log.debug("Failed to look up consensus hash: %s" % blockstack_info['error'])
        return {'error': 'Failed to look up consensus hash'}

    consensus_hash = blockstack_info['consensus']

    # check ownership
    blockchain_record = blockstack_get_name_blockchain_record( fqu, proxy=proxy )
    if blockchain_record is None or 'error' in blockchain_record:
        log.debug("Failed to read blockchain record for %s" % fqu)
        return {'error': 'Failed to read blockchain record for name'}

    if owner_address != blockchain_record['address']:
        log.debug("Given privkey/address doesn't own this name.")
        return {'error': 'Not name owner'}

    # check address usability
    if not is_address_usable(payment_address, config_path=config_path):
        log.debug("Payment address not ready: %s" % payment_address)
        return {'error': 'Payment address has unconfirmed transactions'}

    tx_fee = estimate_update_tx_fee( fqu, owner_public_key, payment_privkey, utxo_client, config_path=config_path ) 

    log.debug("Updating (%s, %s)" % (fqu, zonefile_hash))
    log.debug("<owner, payment> (%s, %s) tx_fee = %s" % (owner_address, payment_address, tx_fee))

    unsigned_tx = update_tx( fqu, zonefile_hash, consensus_hash, owner_public_key, utxo_client, subsidize=True, tx_fee=tx_fee )
    subsidized_tx = tx_make_subsidizable( unsigned_tx, fees_update, 21 * (10**6) * (10**8), payment_privkey, utxo_client, tx_fee=tx_fee )

    resp = {}
    try:
        resp = sign_and_broadcast_tx( subsidized_tx, owner_privkey, config_path=config_path, utxo_client=utxo_client )
    except Exception, e:
        log.exception(e)
        return {'error': 'Failed to sign and broadcast transaction'}

    return resp


def do_transfer( fqu, transfer_address, keep_data, owner_privkey, payment_privkey, utxo_client, config_path=CONFIG_PATH, proxy=None ):
    """
    Transfer a name to a new address
    Return {'status': True, 'transaction_hash': ...} on success
    Return {'error': ...} on failure
    """
    
    if proxy is None:
        proxy = get_default_proxy()

    owner_pubkey_hex = pybitcoin.BitcoinPrivateKey( owner_privkey ).public_key().to_hex()
    owner_address = pybitcoin.BitcoinPrivateKey(owner_privkey).public_key().address()
    payment_address = pybitcoin.BitcoinPrivateKey(payment_privkey).public_key().address()

    # get consensus hash
    blockstack_info = blockstack_getinfo(proxy=proxy)
    if 'error' in blockstack_info:
        log.debug("Failed to look up consensus hash: %s" % blockstack_info['error'])
        return {'error': 'Failed to look up consensus hash'}

    consensus_hash = blockstack_info['consensus']

    # name must exist
    blockchain_record = blockstack_get_name_blockchain_record( fqu, proxy=proxy )
    if blockchain_record is None or 'error' in blockchain_record:
        log.debug("Failed to read blockchain record for %s" % fqu)
        return {'error': 'Failed to read blockchain record for name'}

    # must be owner
    if blockchain_record['address'] != owner_address:
        log.debug("Given privkey/address doesn't own this name.")
        return {'error': 'Given keypair does not own this name'}

    # recipient must have space
    if not can_receive_name(transfer_address, proxy=proxy):
        log.debug("Address %s owns too many names already." % transfer_address)
        return {'error': 'Recipient owns too many names'}
    
    # payment address must be usable
    if not is_address_usable(payment_address, config_path=config_path):
        log.debug("Payment address not ready: %s" % payment_address)
        return {'error': 'Payment address has unconfirmed transactions'}

    tx_fee = estimate_transfer_tx_fee( fqu, owner_pubkey_hex, payment_privkey, utxo_client, config_path=config_path )

    unsigned_tx = transfer_tx( fqu, transfer_address, keep_data, consensus_hash, owner_pubkey_hex, utxo_client, subsidize=True, tx_fee=tx_fee )
    subsidized_tx = tx_make_subsidizable( unsigned_tx, fees_transfer, 21 * (10**6) * (10**8), payment_privkey, utxo_client, tx_fee=tx_fee )

    log.debug("Transferring (%s, %s)" % (fqu, transfer_address))
    log.debug("<owner, payment> (%s, %s) tx_fee = %s" % (owner_address, payment_address, tx_fee))

    resp = {}
    try:
        resp = sign_and_broadcast_tx( subsidized_tx, owner_privkey, config_path=config_path, utxo_client=utxo_client )
    except Exception, e:
        log.exception(e)
        return {'error': 'Failed to sign and broadcast transaction'}

    return resp


def do_renewal( fqu, payment_privkey, owner_address, renewal_fee, utxo_client, config_path=CONFIG_PATH, proxy=None ):
    """
    Renew a name
    Return {'status': True, 'transaction_hash': ...} on success
    Return {'error': ...} on failure
    """
    return do_register( fqu, payment_privkey, owner_address, utxo_client, renewal_fee=renewal_fee, config_path=config_path, proxy=proxy )


def do_revoke( fqu, owner_privkey, payment_privkey, utxo_client, config_path=CONFIG_PATH, proxy=None ):
    """
    Revoke a name
    Return {'status': True, 'transaction_hash': ...} on success
    Return {'error': ...} on failure
    """
    if proxy is None:
        proxy = get_default_proxy()

    owner_pubkey_hex = pybitcoin.BitcoinPrivateKey( owner_privkey ).public_key().to_hex()
    tx_fee = estimate_revoke_tx_fee( fqu, owner_pubkey_hex, payment_privkey, utxo_client, config_path=config_path )

    owner_address = pybitcoin.BitcoinPublicKey( owner_pubkey_hex ).address()
    payment_address = pybitcoin.BitcoinPrivateKey( payment_privkey ).public_key().address()

    # name must exist
    blockchain_record = blockstack_get_name_blockchain_record( fqu, proxy=proxy )
    if blockchain_record is None or 'error' in blockchain_record:
        log.debug("Failed to read blockchain record for %s" % fqu)
        return {'error': 'Failed to read blockchain record for name'}

    # must be owner
    if blockchain_record['address'] != owner_address:
        log.debug("Given privkey/address doesn't own this name.")
        return {'error': 'Given keypair does not own this name'}

    unsigned_tx = revoke_tx( fqu, owner_pubkey_hex, utxo_client, subsidize=True, tx_fee=tx_fee )
    subsidized_tx = tx_make_subsidizable( unsigned_tx, fees_revoke, 21 ** (10**6) * (10**8), payment_privkey, utxo_client, tx_fee=tx_fee )

    log.debug("Revoking %s" % fqu)
    log.debug("<owner, payment> (%s, %s) tx_fee = %s" % (owner_address, payment_address, tx_fee))

    resp = {}
    try:
        resp = sign_and_broadcast_tx( subsidized_tx, owner_privkey, config_path=config_path, utxo_client=utxo_client )
    except Exception, e:
        log.exception(e)
        return {'error': 'Failed to sign and broadcast revoke transaction'}

    return resp


def do_name_import( fqu, importer_privkey, recipient_address, zonefile_hash, utxo_client, config_path=CONFIG_PATH, proxy=None ):
    """
    Import a name
    Return {'status': True, 'transaction_hash': ...} on success
    Return {'error': ...} on failure
    """
    if proxy is None:
        proxy = get_default_proxy()

    payment_pubkey_hex = pybitcoin.BitcoinPrivateKey( importer_privkey ).public_key().to_hex()
    payment_address = pybitcoin.BitcoinPrivateKey( importer_privkey ).public_key().address()
    tx_fee = estimate_name_import_tx_fee( fqu, payment_pubkey_hex, utxo_client, config_path=config_path )

    unsigned_tx = name_import_tx( fqu, recipient_address, zonefile_hash, payment_pubkey_hex, utxo_client, tx_fee=tx_fee )
    signed_tx = sign_tx( unsigned_tx, importer_privkey )

    log.debug("Import (%s, %s, %s)" % (fqu, recipient_address, zonefile_hash))
    resp = {}
    try:
        resp = sign_and_broadcast_tx( signed_tx, importer_privkey, config_path=config_path, utxo_client=utxo_client )
    except Exception, e:
        log.exception(e)
        return {'error': 'Failed to sign and broadcast import transaction'}

    return resp


def do_namespace_preorder( namespace_id, cost, payment_privkey, reveal_address, utxo_client, config_path=CONFIG_PATH, proxy=None ):
    """
    Preorder a namespace
    Return {'status': True, 'transaction_hash': ...} on success
    Return {'error': ...} on failure
    """
    if proxy is None:
        proxy = get_default_proxy()

    payment_pubkey_hex = pybitcoin.BitcoinPrivateKey( payment_privkey ).public_key().to_hex()
    payment_address = pybitcoin.BitcoinPrivateKey( payment_privkey ).public_key().address()

    blockstack_info = blockstack_getinfo( proxy=proxy )
    if 'error' in blockstack_info:
        return {'error': 'Failed to get consensus hash'}

    consensus_hash = blockstack_info['consensus']

    # namespace must not exist
    blockchain_record = blockstack_get_namespace_blockchain_record( namespace_id, proxy=proxy )
    if blockchain_record is None or 'error' in blockchain_record:
        if blockchain_record is None:
            log.debug("FAiled to read blockchain record for %s" % namespace_id)
            return {'error': 'Failed to read blockchain record for namespace'}

        if blockchain_record['error'] != 'No such namespace':
            log.debug("Failed to read blockchain record for %s" % namespace_id)
            return {'error': 'Failed to read blockchain record for namespace'}

    else:
        # exists 
        return {'error': 'Namespace already exists'}

    tx_fee = estimate_namespace_preorder_tx_fee( namespace_id, cost, payment_pubkey_hex, utxo_client, config_path=config_path )
    if tx_fee is None:
        return {'error': 'Failed to estimate the tx fee'}

    log.debug("Preordering namespace (%s, %s, %s), tx_fee = %s" % (namespace_id, payment_address, reveal_address, tx_fee))

    unsigned_tx = namespace_preorder_tx( namespace_id, reveal_address, cost, consensus_hash, payment_pubkey_hex, utxo_client, tx_fee=tx_fee )
    resp = {}

    try:
        resp = sign_and_broadcast_tx( unsigned_tx, payment_privkey, utxo_client=utxo_client )
    except Exception, e:
        log.exception(e)
        return {'error': 'Failed to sign and broadcast namespace preorder transaction'}

    return resp


def do_namespace_reveal( namespace_id, reveal_address, lifetime, coeff, base_cost, bucket_exponents, nonalpha_discount, no_vowel_discount, payment_privkey, utxo_client, config_path=CONFIG_PATH, proxy=None ):
    """
    Reveal a namespace
    Return {'status': True, 'transaction_hash': ...} on success
    Return {'error': ...} on failure
    """
    if proxy is None:
        proxy = get_default_proxy()

    payment_pubkey_hex = pybitcoin.BitcoinPrivateKey( payment_privkey ).public_key().to_hex()
    payment_address = pybitcoin.BitcoinPrivateKey( payment_privkey ).public_key().address()
    
    # namespace must not exist
    blockchain_record = blockstack_get_namespace_blockchain_record( namespace_id, proxy=proxy )
    if blockchain_record is None or 'error' in blockchain_record:
        if blockchain_record['error'] != 'No such namespace':
            log.debug("Failed to read blockchain record for %s" % namespace_id)
            return {'error': 'Failed to read blockchain record for namespace'}

    else:
        # exists 
        return {'error': 'Namespace already exists'}

    tx_fee = estimate_namespace_reveal_tx_fee( namespace_id, payment_pubkey_hex, utxo_client, config_path=config_path )
    if tx_fee is None:
        return {'error': 'Failed to estimate the tx fee'}

    log.debug("Revealing namespace (%s, %s, %s), tx_fee = %s" % (namespace_id, payment_address, reveal_address, tx_fee))

    unsigned_tx = namespace_reveal_tx( namespace_id, reveal_address, lifetime, coeff, base_cost, bucket_exponents, nonalpha_discount, no_vowel_discount, payment_pubkey_hex, utxo_client, tx_fee=tx_fee )
    resp = {}

    try:
        resp = sign_and_broadcast_tx( unsigned_tx, payment_privkey, utxo_client=utxo_client )
    except Exception, e:
        log.exception(e)
        return {'error': 'Failed to sign and broadcast namespace reveal transaction'}

    return resp


def do_namespace_ready( namespace_id, reveal_privkey, utxo_client, config_path=CONFIG_PATH, proxy=None ):
    """
    Open a namespace for registration
    Return {'status': True, 'transaction_hash': ...} on success
    Return {'error': ...} on failure
    """
    
    if proxy is None:
        proxy = get_default_proxy()

    reveal_pubkey_hex = pybitcoin.BitcoinPrivateKey( reveal_privkey ).public_key().to_hex()
    reveal_address = pybitcoin.BitcoinPrivateKey( reveal_privkey ).public_key().address()

    # namespace must exist, but not be ready
    blockchain_record = blockstack_get_namespace_blockchain_record( namespace_id, proxy=proxy )
    if blockchain_record is None or 'error' in blockchain_record:
        log.debug("Failed to read blockchain record for %s" % namespace_id)
        return {'error': 'Failed to read blockchain record for namespace'}

    if blockchain_record['ready']:
        # exists 
        return {'error': 'Namespace already exists'}

    tx_fee = estimate_namespace_ready_tx_fee( namespace_id, reveal_pubkey_hex, utxo_client, config_path=config_path )
    if tx_fee is None:
        return {'error': 'Failed to estimate the tx fee'}

    log.debug("Readying namespace (%s, %s), tx_fee = %s" % (namespace_id, reveal_address, tx_fee) )

    unsigned_tx = namespace_ready_tx( namespace_id, reveal_pubkey_hex, utxo_client, tx_fee=tx_fee )
    resp = {}

    try:
        resp = sign_and_broadcast_tx( unsigned_tx, reveal_privkey, utxo_client=utxo_client )
    except Exception, e:
        log.exception(e)
        return {'error': 'Failed to sign and broadcast namespace ready transaction'}

    return resp


def do_announce( message_hash, sender_privkey, utxo_client, config_path=CONFIG_PATH, proxy=None ):
    """
    Send an announcement hash to the blockchain
    Return {'status': True, 'transaction_hash': ...} on success
    Return {'error': ...} on failure
    """

    if proxy is None:
        proxy = get_default_proxy()

    sender_pubkey_hex = pybitcoin.BitcoinPrivateKey( sender_privkey ).public_key().to_hex()
    sender_address = pybitcoin.BitcoinPrivateKey( sender_privkey ).public_key().address()

    tx_fee = estimate_announce_tx_fee( sender_pubkey_hex, utxo_client, config_path=config_path )
    if tx_fee is None:
        return {'error': 'Failed to estimate the tx fee'}

    log.debug("Announce (%s, %s) tx_fee = %s" % (message_hash, sender_address, tx_fee))

    unsigned_tx = announce_tx( message_hash, sender_pubkey_hex, utxo_client, tx_fee=tx_fee )
    resp = {}

    try:
        resp = sign_and_serialize_tx( unsigned_tx, sender_privkey, utxo_client=utxo_client )
    except Exception, e:
        log.exception(e)
        return {'error': 'Failed to sign and broadcast announce transaction'}

    return resp


def async_preorder(fqu, payment_privkey, owner_address, cost, proxy=None, config_path=CONFIG_PATH, queue_path=DEFAULT_QUEUE_PATH):
    """
        Preorder a fqu (step #1)

        @fqu: fully qualified name e.g., muneeb.id
        @owner_address: will own the fqu
        @payment_privkey: private key that will pay

        Returns True/False and stores tx_hash in queue
    """

    if proxy is None:
        proxy = get_default_proxy(config_path=config_path)

    utxo_client = get_utxo_client( config_path=config_path )
    
    # stale preorder will get removed from preorder_queue
    if in_queue("register", fqu, path=queue_path):
        log.debug("Already in register queue: %s" % fqu)
        return {'error': 'Already in register queue'}

    if in_queue("preorder", fqu, path=queue_path):
        log.debug("Already in preorder queue: %s" % fqu)
        return {'error': 'Already in preorder queue'}

    try:
        resp = do_preorder( fqu, payment_privkey, owner_address, cost, utxo_client, config_path=CONFIG_PATH )
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
        log.debug("Error preordering: %s with %s for %s" % (fqu, payment_address, owner_address))
        log.debug("Error below\n%s" % json.dumps(resp, indent=4, sort_keys=True))
        return {'error': 'Failed to preorder: %s' % resp['error']}

    return resp


def async_register(fqu, payment_privkey, owner_address, auto_preorder=True, proxy=None, config_path=CONFIG_PATH, queue_path=DEFAULT_QUEUE_PATH):
    """
        Register a previously preordered fqu (step #2)

        @fqu: fully qualified name e.g., muneeb.id
        @auto_preorder: automatically preorder if the name is not already preordered.

        Uses from preorder queue:
        @payment_address: used for making the payment
        @owner_address: will own the fqu (must be same as preorder owner_address)

        Return {'status': True, ...} on success
        Return {'error': ...} on error
    """

    if proxy is None:
        proxy = get_default_proxy(config_path=config_path)

    utxo_client = get_utxo_client(config_path=config_path)

    # check register_queue first
    # stale preorder will get removed from preorder_queue
    if in_queue("register", fqu, path=queue_path):
        log.debug("Already in register queue: %s" % fqu)
        return {'error': 'Already in register queue'}

    if not in_queue("preorder", fqu, path=queue_path):
        if auto_preorder:

            # get fees
            cost_info = blockstack_get_name_cost( fqu, proxy=proxy )
            if 'error' in cost_info:
                return {'error': 'Failed to look up name cost'}

            # do preorder
            return do_preorder(fqu, payment_address, owner_address, cost_info, utxo_client, proxy=proxy)

        else:
            log.debug("No preorder sent yet: %s" % fqu)
            return {'error': 'No preorder sent yet'}

    preorder_entry = queue_findone( "preorder", fqu, path=queue_path )
    if len(preorder_entry) == 0:
        log.error("No preorder for '%s'" % fqu)
        return {'error': 'No preorder found'}

    preorder_tx = preorder_entry[0]['tx_hash']
    tx_confirmations = get_tx_confirmations(preorder_tx, config_path=config_path)

    if tx_confirmations < PREORDER_CONFIRMATIONS:
        log.debug("Waiting on preorder confirmations: (%s, %s)"
                  % (preorder_tx, tx_confirmations))

        return {'error': 'Waiting on preorder confirmations'}

    try:
        resp = do_register( fqu, payment_privkey, owner_address, utxo_client, config_path=config_path, proxy=proxy )
    except:
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
        log.debug("Error registering: %s" % fqu)
        log.debug(pprint(resp))
        return {'error': 'Failed to send registration'}


def async_update(fqu, zonefile, profile, owner_private_key, payment_privkey, config_path=CONFIG_PATH,
                 proxy=None, wallet_keys=None, queue_path=DEFAULT_QUEUE_PATH):
    """
        Update a previously registered fqu, using a different payment address

        @fqu: fully qualified name e.g., muneeb.id
        @zonefile: new zonefile json, hash(zonefile) goes to blockchain
        @owner_privkey: privkey of owner address, to sign update
        @payment_address: the address which is paying for the cost

        Returns True/False and stores tx_hash in queue
    """

    if proxy is None:
        proxy = get_default_proxy(config_path=config_path)

    utxo_client = get_utxo_client(config_path=config_path)

    if in_queue("update", fqu, path=queue_path):
        log.debug("Already in update queue: %s" % fqu)
        return {'error': 'Already in update queue'}

    zonefile_hash = hash_zonefile( zonefile )

    resp = {}
    try:
        resp = do_update( fqu, zonefile_hash, owner_private_key, payment_privkey, utxo_client, config_path=config_path, proxy=proxy )
    except Exception, e:
        log.exception(e)
        return {'error': 'Failed to sign and broadcast update transaction'}

    if 'transaction_hash' in broadcast_resp:
        queue_append("update", fqu, broadcast_resp['transaction_hash'],
                     zonefile=zonefile,
                     profile=profile,
                     owner_address=owner_address,
                     config_path=config_path,
                     path=queue_path)

        broadcast_resp['zonefile_hash'] = zonefile_hash
        return broadcast_resp

    else:
        log.debug("Error updating: %s" % fqu)
        log.debug(broadcast_resp)
        return {'error': 'Failed to broadcast update transaction'}


def async_transfer(fqu, transfer_address, owner_privkey, payment_privkey, config_path=CONFIG_PATH, proxy=None, queue_path=DEFAULT_QUEUE_PATH):
    """
        Transfer a previously registered fqu, using a different payment address.
        Preserves the zonefile.

        @fqu: fully qualified name e.g., muneeb.id
        @transfer_address: new owner address
        @owner_privkey: privkey of current owner address, to sign tx
        @payment_privkey: the key which is paying for the cost

        Return {'status': True, 'transaction_hash': ...} on success
        Return {'error': ...} on failure
    """

    if proxy is None:
        proxy = get_default_proxy(config_path=config_path)

    utxo_client = get_utxo_client(config_path=config_path)

    if in_queue("transfer", fqu, path=queue_path):
        log.debug("Already in transfer queue: %s" % fqu)
        return {'error': 'Already in transfer queue'}

    try:
        resp = do_transfer( fqu, transfer_address, True, owner_privkey, payment_privkey, utxo_client, config_path=config_path, proxy=proxy )
    except Exception, e:
        log.exception(e)
        return {'error': 'Failed to sign and broadcast transfer transaction'}

    if 'transaction_hash' in broadcast_resp:
        queue_append("transfer", fqu, broadcast_resp['transaction_hash'],
                     owner_address=owner_address,
                     transfer_address=transfer_address,
                     config_path=config_path,
                     path=queue_path)
    else:
        log.debug("Error transferring: %s" % fqu)
        log.debug(broadcast_resp)
        return {'error': 'Failed to broadcast transfer transaction'}

    return broadcast_resp
