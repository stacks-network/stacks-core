#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Search
    ~~~~~

    copyright: (c) 2014-2017 by Blockstack Inc.
    copyright: (c) 2017 by Blockstack.org

This file is part of Blockstack.

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

import sys
import os

import re
import ssl
import json
import traceback
import requests

from requests.exceptions import ConnectionError as RequestsConnectionError
from requests.exceptions import Timeout as RequestsTimeout
from flask import request, jsonify
from flask_crossdomain import crossdomain

from pybitcoin import get_unspents, BlockcypherClient
from pybitcoin.rpc import BitcoindClient
from pybitcoin import is_b58check_address, BitcoinPrivateKey

from . import app
from .errors import (
    InvalidProfileDataError, UsernameTakenError,
    InternalProcessingError, ResolverConnectionError,
    BroadcastTransactionError, DatabaseLookupError, InternalSSLError,
    DatabaseSaveError, DKIMPubkeyError, UsernameNotRegisteredError,
    UpgradeInprogressError, InvalidZoneFileSizeError,
    EmailTokenError, InvalidEmailError,
    GenericError, PaymentError, InvalidAddressError,
    InvalidZoneFileTypeError
)

from .parameters import parameters_required
from .dkim import dns_resolver, parse_pubkey_from_data, DKIM_RECORD_PREFIX
from .utils import zone_file_is_too_big

# hack around absolute paths
current_dir = os.path.abspath(os.path.dirname(__file__))
parent_dir = os.path.abspath(current_dir + "/../")

sys.path.insert(0, parent_dir)

from resolver.server import get_users

from blockstack_client.proxy import get_name_blockchain_record

@app.route('/v1/users/<usernames>', methods=['GET'])
@crossdomain(origin='*')
def api_user(usernames):

    data = get_users(usernames)

    print data

    usernames = usernames.split(',')

    if len(usernames) is 1:
        username = usernames[0]
        if 'error' in data:
            del data['error']
            error = UsernameNotRegisteredError('')
            data[username] = {
                'error': error.to_dict()
            }
            return jsonify(data), 200

    for username in usernames:
        if username not in data:
            error = UsernameNotRegisteredError('')
            data[username] = {
                'error': error.to_dict()
            }

        try:
            json.loads(json.dumps(data[username]))
        except:
            error = InvalidProfileDataError('')
            data[username] = {
                'error': error.to_dict()
            }

    return jsonify(data), 200


@app.route('/v1/users', methods=['POST'])
@parameters_required(['username', 'recipient_address'])
@crossdomain(origin='*')
def register_user():
    REGISTRATION_MESSAGE = (
        "This profile was registered using the Onename"
        " API - https://api.onename.com")

    data = json.loads(request.data)

    username = data['username']

    user_lookup = api_user(username)

    if 'error' in user_lookup.data and user_lookup.status_code == 200:
        if 'profile' in data:
            zone_file = str(data['profile'])
            if isinstance(zone_file, dict):
                zone_file = json.dumps(zone_file)
        elif 'zone_file' in data:
            zone_file = str(data['zone_file'])
        else:
            zone_file = json.dumps({
                'status': 'registered',
                'message': REGISTRATION_MESSAGE
            })
    else:
        raise UsernameTakenError()

    if not isinstance(zone_file, str):
        raise InvalidZoneFileTypeError()

    if zone_file_is_too_big(zone_file):
        raise InvalidZoneFileSizeError()

    if not is_b58check_address(str(data['recipient_address'])):
        raise InvalidAddressError(data['recipient_address'])

    matching_records = Blockchainid.objects(username=username)

    if len(matching_records):
        """ Someone else already tried registering this name
            but the username is not yet registered on the blockchain.
            Don't tell the client that someone else's request is processing.
        """
        pass
    else:
        new_entry = Blockchainid(username=username, profile=zone_file,
                                 transfer_address=data['recipient_address'])
        try:
            new_entry.save()
        except Exception as e:
            raise DatabaseSaveError()

    resp = {'status': 'success'}

    return jsonify(resp), 200


@app.route('/v1/users/<username>/update', methods=['POST'])
@parameters_required(['profile', 'owner_pubkey'])
@crossdomain(origin='*')
def update_user(username):

    reply = {}

    try:
        user = get_authenticated_user(request.authorization)
    except Exception as e:
        raise GenericError(str(e))

    try:
        hex_privkey = aes_decrypt(user.encrypted_privkey, SECRET_KEY)
    except Exception as e:
        raise GenericError(str(e))

    wallet = HDWallet(hex_privkey)
    data = json.loads(request.data)

    fqu = username + "." + DEFAULT_NAMESPACE
    profile = data['profile']
    profile_hash = get_hash(profile)
    owner_pubkey = data['owner_pubkey']

    try:
        blockchain_record = bs_client.get_name_blockchain_record(fqu)
    except Exception as e:
        raise GenericError(str(e))

    if 'value_hash' not in blockchain_record:
        raise GenericError("Not yet registered %s" % fqu)

    owner_address = blockchain_record['address']

    check_address = get_address_from_pubkey(str(owner_pubkey))

    if check_address != owner_address:
        raise GenericError("Given pubkey/address doesn't own this name.")

    if USE_DEFAULT_PAYMENT and PAYMENT_PRIVKEY is not None:

        payment_privkey = BitcoinPrivateKey(PAYMENT_PRIVKEY)
        payment_privkey = payment_privkey.to_hex()
    else:
        pubkey, payment_privkey = wallet.get_next_keypair()

        if payment_privkey is None:
            raise PaymentError(addresses=wallet.get_keypairs(DEFAULT_CHILD_ADDRESSES))

    resp = {}

    try:
        resp = bs_client.update_subsidized(fqu, profile_hash,
                                           public_key=owner_pubkey,
                                           subsidy_key=payment_privkey)
    except Exception as e:
        reply['error'] = str(e)
        return jsonify(reply), 200

    if 'subsidized_tx' in resp:
        reply['unsigned_tx'] = resp['subsidized_tx']
    else:
        if 'error' in resp:
            reply['error'] = resp['error']
        else:
            reply['error'] = resp

    return jsonify(reply), 200


@app.route('/v1/users/<username>/transfer', methods=['POST'])
@parameters_required(['transfer_address', 'owner_pubkey'])
@crossdomain(origin='*')
def transfer_user(username):

    reply = {}

    try:
        user = get_authenticated_user(request.authorization)
    except Exception as e:
        raise GenericError(str(e))

    try:
        hex_privkey = aes_decrypt(user.encrypted_privkey, SECRET_KEY)
    except Exception as e:
        raise GenericError(str(e))

    wallet = HDWallet(hex_privkey)
    data = json.loads(request.data)

    fqu = username + "." + DEFAULT_NAMESPACE
    transfer_address = data['transfer_address']
    owner_pubkey = data['owner_pubkey']

    try:
        blockchain_record = bs_client.get_name_blockchain_record(fqu)
    except Exception as e:
        raise GenericError(str(e))

    if 'value_hash' not in blockchain_record:
        raise GenericError("Not yet registered %s" % fqu)

    owner_address = blockchain_record['address']

    check_address = get_address_from_pubkey(str(owner_pubkey))

    if check_address != owner_address:
        raise GenericError("Given pubkey/address doesn't own this name.")

    if not is_b58check_address(transfer_address):
        raise InvalidAddressError(transfer_address)

    if USE_DEFAULT_PAYMENT and PAYMENT_PRIVKEY is not None:

        payment_privkey = BitcoinPrivateKey(PAYMENT_PRIVKEY)
        payment_privkey = payment_privkey.to_hex()
    else:
        pubkey, payment_privkey = wallet.get_next_keypair()

        if payment_privkey is None:
            raise PaymentError(addresses=wallet.get_keypairs(DEFAULT_CHILD_ADDRESSES))

    resp = {}

    try:
        resp = bs_client.transfer_subsidized(fqu, transfer_address,
                                             keep_data=True,
                                             public_key=owner_pubkey,
                                             subsidy_key=payment_privkey)
    except Exception as e:
        reply['error'] = str(e)
        return jsonify(reply), 200

    if 'subsidized_tx' in resp:
        reply['unsigned_tx'] = resp['subsidized_tx']
    else:
        if 'error' in resp:
            reply['error'] = resp['error']
        else:
            reply['error'] = resp

    return jsonify(reply), 200


@app.route('/v1/search', methods=['GET'])
@parameters_required(parameters=['query'])
@crossdomain(origin='*')
def search_people():

    search_url = SEARCH_URL + '/search'

    name = request.values['query']

    try:
        resp = requests.get(url=search_url, params={'query': name})
    except (RequestsConnectionError, RequestsTimeout) as e:
        raise InternalProcessingError()

    data = resp.json()
    if not ('results' in data and isinstance(data['results'], list)):
        data = {'results': []}

    return jsonify(data), 200


@app.route('/v1/transactions', methods=['POST'])
@parameters_required(['signed_hex'])
@crossdomain(origin='*')
def broadcast_tx():

    data = json.loads(request.data)
    signed_hex = data['signed_hex']

    try:
        bitcoind_response = bitcoind.sendrawtransaction(signed_hex)
    except ssl.SSLError:
        raise InternalSSLError()
    except Exception as e:
        traceback.print_exc()
        raise BroadcastTransactionError()

    if 'code' in bitcoind_response:
        raise BroadcastTransactionError(bitcoind_response['message'])

    resp = {'transaction_hash': bitcoind_response, 'status': 'success'}

    return jsonify(resp), 200


@app.route('/v1/addresses/<address>/unspents', methods=['GET'])
@crossdomain(origin='*')
def get_address_unspents(address):

    client = BlockcypherClient(api_key=BLOCKCYPHER_TOKEN)
    unspent_outputs = get_unspents(address, blockchain_client=client)

    resp = {'unspents': unspent_outputs}

    return jsonify(resp), 200


@app.route('/v1/addresses/<addresses>/names', methods=['GET'])
@crossdomain(origin='*')
def get_address_names(addresses):

    resp = {}
    results = []

    addresses = addresses.split(',')

    for address in addresses:

        data = {}
        names_owned = []

        invalid_address = False

        try:
            is_b58check_address(str(address))
        except:
            data['error'] = "Invalid address"
            invalid_address = True

        if not invalid_address:
            bs_client = Proxy(BLOCKSTORED_IP, BLOCKSTORED_PORT)

            try:
                resp = bs_client.get_names_owned_by_address(address)
                names_owned = resp[0]
            except:
                pass

        data['address'] = address
        data['names'] = names_owned

        results.append(data)

    resp = {'results': results}

    return jsonify(resp), 200


@app.route('/v1/users', methods=['GET'])
@crossdomain(origin='*')
def get_all_users():

    BASE_URL = RESOLVER_URL + '/v2/namespace'

    try:
        resp = requests.get(BASE_URL, timeout=10, verify=False)
    except (RequestsConnectionError, RequestsTimeout) as e:
        raise ResolverConnectionError()

    data = resp.json()

    return jsonify(data), 200


@app.route('/v1/stats/users', methods=['GET'])
@crossdomain(origin='*')
def get_user_stats():

    data = get_all_users().data
    data = json.loads(data)

    resp = {'stats': data['stats']}

    return jsonify(resp), 200


@app.route('/v1/domains/<domain>/dkim', methods=['GET'])
@crossdomain(origin='*')
def get_dkim_pubkey(domain):

    domain = DKIM_RECORD_PREFIX + domain
    data = dns_resolver(domain)
    public_key_data = parse_pubkey_from_data(data)

    if public_key_data['public_key'] is None:
        raise DKIMPubkeyError()

    resp = public_key_data

    return jsonify(resp), 200

