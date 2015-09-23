# -*- coding: utf-8 -*-
"""
    Onename API
    Copyright 2015 Halfmoon Labs, Inc.
    ~~~~~
"""

import json
import traceback
import requests
import ssl
from requests.exceptions import ConnectionError as RequestsConnectionError
from requests.exceptions import Timeout as RequestsTimeout
from flask import request, jsonify
from pybitcoin.rpc import namecoind
from flask_crossdomain import crossdomain

from . import app
from .errors import InvalidProfileDataError, UsernameTakenError, \
    InternalProcessingError, ResolverConnectionError, \
    BroadcastTransactionError, DatabaseLookupError, InternalSSLError, \
    DatabaseSaveError, NotYetSupportedError
from .parameters import parameters_required
from .auth import auth_required
from .db import utxo_index, address_to_utxo, address_to_keys
from .settings import BTC_RESOLVER_URL, SEARCH_URL
from .models import User

from basicrpc import Proxy
from .settings import DHT_MIRROR, DHT_MIRROR_PORT

proxy = Proxy(DHT_MIRROR, DHT_MIRROR_PORT)

from blockstore.blockstore_cli import printValue, printError, shutDown, getFormat


def format_utxo_data(utxo_id, utxo_data):
    unspent = None
    if 'scriptPubKey' in utxo_data and 'value' in utxo_data:
        unspent = {
            'txid': utxo_id.rsplit('_')[0],
            'vout': utxo_id.rsplit('_')[1],
            'scriptPubKey': utxo_data['scriptPubKey'],
            'amount': utxo_data['value']
        }
    return unspent


def get_unspents(address):
    unspents = []
    entries = address_to_utxo.find({'address': address})
    for entry in entries:
        if 'utxo' in entry:
            utxo_id = entry['utxo']
            utxo = utxo_index.find_one({'id': utxo_id})
            if 'data' in utxo:
                unspent = format_utxo_data(utxo_id, utxo['data'])
                unspents.append(unspent)
    return unspents


@app.route('/v2/users/<usernames>', methods=['GET'])
@auth_required(exception_paths=['/v2/users/fredwilson'])
@crossdomain(origin='*')
def v2_api_user(usernames):
    BASE_URL = BTC_RESOLVER_URL + '/v2/users/'

    try:
        resp = requests.get(BASE_URL + usernames, timeout=10, verify=False)
    except (RequestsConnectionError, RequestsTimeout) as e:
        raise ResolverConnectionError()

    data = resp.json()

    for username in usernames.split(','):
        if username not in data:
            error = InvalidProfileDataError('')
            data[username] = {
                'error': error.to_dict()
            }

    return jsonify(data), 200


@app.route('/v2/users', methods=['POST'])
@auth_required()
@parameters_required(['username', 'recipient_address'])
@crossdomain(origin='*')
def v2_register_user():

    raise NotYetSupportedError()

    REGISTRATION_MESSAGE = (
        "This profile was registered using the Onename"
        " API - https://api.onename.com")

    data = json.loads(request.data)

    username = data['username']

    profile_lookup = api_user(username)
    if 'error' in profile_lookup.data and profile_lookup.status_code == 404:
        raise UsernameTakenError()

    if 'profile' in data:
        profile = data['profile']
    else:
        profile = {
            'status': 'registered',
            'message': REGISTRATION_MESSAGE
        }

    matching_profiles = profile.objects(username=username)

    if len(matching_profiles):
        """ Someone else already tried registering this name
            but the username is not yet registered on the blockchain.
            Don't tell the client that someone else's request is processing.
        """
        pass
    else:
        new_user = User(username=username, profile=json.dumps(profile),
                            transfer_address=data['recipient_address'])
        try:
            new_user.save()
        except Exception as e:
            raise DatabaseSaveError()

    resp = {'status': 'success'}

    return jsonify(resp), 200


@app.route('/v2/addresses/<address>/unspents', methods=['GET'])
@auth_required(exception_paths=[
    '/v2/addresses/N8PcBQnL4oMuM6aLsQow6iG59yks1AtQX4/unspents'])
@crossdomain(origin='*')
def v2_get_address_unspents(address):

    raise NotYetSupportedError()

    try:
        unspent_outputs = get_unspents(address)
    except Exception as e:
        traceback.print_exc()
        raise DatabaseLookupError()

    resp = {'unspents': unspent_outputs}

    return jsonify(resp), 200


@app.route('/v2/addresses/<address>/names', methods=['GET'])
@auth_required(exception_paths=[
    '/v2/addresses/MyVZe4nwF45jeooXw2v1VtXyNCPczbL2EE/names'])
@crossdomain(origin='*')
def v2_get_address_names(address):

    raise NotYetSupportedError()

    try:
        results = address_to_keys.find({'address': address})
    except Exception as e:
        raise DatabaseLookupError()

    names_owned = []
    for result in results:
        if 'key' in result:
            names_owned.append(result['key'].lstrip('u/'))

    resp = {'names': names_owned}

    return jsonify(resp), 200


@app.route('/v2/users', methods=['GET'])
@auth_required()
@crossdomain(origin='*')
def v2_get_all_users():

    raise NotYetSupportedError()

    resp_json = {}

    # Specify the URL for the namespace call. If 'recent_blocks' is present,
    # limit the call to only the names registered in that recent # of blocks.
    namespace_url = RESOLVER_URL + '/v2/namespace'
    if 'recent_blocks' in request.values:
        try:
            recent_blocks_int = int(request.values['recent_blocks'])
        except:
            abort(400)
        else:
            if not (recent_blocks_int > 0 and recent_blocks_int <= 100):
                recent_blocks_int = 100
            namespace_url += '/recent/' + str(recent_blocks_int)

    # Add in the data for the namespace call.
    try:
        namespace_resp = requests.get(namespace_url, timeout=10, verify=False)
        resp_json.update(namespace_resp.json())
    except (RequestsConnectionError, RequestsTimeout) as e:
        raise ResolverConnectionError()

    # Add in userbase stats, but only if the user is asking for the entire
    # namespace.
    stats_url = RESOLVER_URL + '/v2/users'
    if not 'recent_blocks' in request.values:
        try:
            stats_resp = requests.get(stats_url, timeout=10, verify=False)
            resp_json.update(stats_resp.json())
        except (RequestsConnectionError, RequestsTimeout) as e:
            raise ResolverConnectionError()

    return jsonify(resp_json), 200


@app.route('/v2/domains/<domain>/dkim', methods=['GET'])
@auth_required(exception_paths=['/v2/domains/onename.com/dkim'])
@crossdomain(origin='*')
def v2_get_dkim_pubkey(domain):
    domain = DKIM_RECORD_PREFIX + domain
    data = dns_resolver(domain)
    public_key_data = parse_pubkey_from_data(data)

    if public_key_data['public_key'] is None:
        raise DKIMPubkeyError()

    resp = public_key_data

    return jsonify(resp), 200


@app.route('/v2/data/<hash>', methods=['GET'])
@auth_required()
@crossdomain(origin='*')
def v2_get_immutable_data(hash):

    resp = proxy.get(hash)

    return jsonify(resp), 200


@app.route('/v2/data', methods=['POST'])
@auth_required()
@parameters_required(['hash', 'payload'])
@crossdomain(origin='*')
def v2_write_immutable_data():

    resp = proxy.set(hash, payload)

    return jsonify(resp), 200