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
    DatabaseSaveError, DKIMPubkeyError, UsernameNotRegisteredError

from .parameters import parameters_required
from .auth import auth_required
from .db import utxo_index, address_to_utxo, address_to_keys
from .settings import NMC_RESOLVER_URL, SEARCH_URL
from .models import User
from .dkim import dns_resolver, parse_pubkey_from_data, DKIM_RECORD_PREFIX


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


@app.route('/v1/users/<usernames>', methods=['GET'])
@auth_required(exception_paths=['/v1/users/fredwilson'])
@crossdomain(origin='*')
def api_user(usernames):
    BASE_URL = NMC_RESOLVER_URL + '/v1/users/'

    try:
        resp = requests.get(BASE_URL + usernames, timeout=10, verify=False)
    except (RequestsConnectionError, RequestsTimeout) as e:
        raise ResolverConnectionError()

    data = resp.json()

    usernames = usernames.split(',')

    if len(usernames) is 1:
        username = usernames[0]
        if 'error' in data:
            error = UsernameNotRegisteredError('')
            data[username] = {
                'error': error.to_dict()
            }
            return jsonify(data), 404

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
@auth_required()
@parameters_required(['username', 'recipient_address'])
@crossdomain(origin='*')
def register_user():
    REGISTRATION_MESSAGE = (
        "This profile was registered using the Onename"
        " API - https://api.onename.com")

    data = json.loads(request.data)

    username = data['username']

    profile_lookup = api_user(username)

    if 'error' in profile_lookup.data and profile_lookup.status_code == 404:

        if 'profile' in data:
            profile = data['profile']
        else:
            profile = {
                'status': 'registered',
                'message': REGISTRATION_MESSAGE
            }
    else:
        raise UsernameTakenError()

    matching_profiles = User.objects(username=username)

    if len(matching_profiles):
        """ Someone else already tried registering this name
            but the username is not yet registered on the blockchain.
            Don't tell the client that someone else's request is processing.
        """
        pass
    else:
        profile = User(username=username, profile=json.dumps(profile),
                            transfer_address=data['recipient_address'])
        try:
            profile.save()
        except Exception as e:
            raise DatabaseSaveError()

    resp = {'status': 'success'}

    return jsonify(resp), 200


@app.route('/v1/search', methods=['GET'])
@auth_required(exception_queries=['fredwilson', 'wenger'])
@parameters_required(parameters=['query'])
@crossdomain(origin='*')
def search_people():

    search_url = SEARCH_URL + '/search/name'

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
@auth_required()
@parameters_required(['signed_hex'])
@crossdomain(origin='*')
def broadcast_tx():
    data = json.loads(request.data)
    signed_hex = data['signed_hex']

    try:
        namecoind_response = namecoind.sendrawtransaction(signed_hex)
    except ssl.SSLError:
        raise InternalSSLError()
    except Exception as e:
        traceback.print_exc()
        raise BroadcastTransactionError()

    if 'code' in namecoind_response:
        raise BroadcastTransactionError(namecoind_response['message'])

    resp = {'transaction_hash': namecoind_response, 'status': 'success'}

    return jsonify(resp), 200


@app.route('/v1/addresses/<address>/unspents', methods=['GET'])
@auth_required(exception_paths=[
    '/v1/addresses/N8PcBQnL4oMuM6aLsQow6iG59yks1AtQX4/unspents'])
@crossdomain(origin='*')
def get_address_unspents(address):
    try:
        unspent_outputs = get_unspents(address)
    except Exception as e:
        traceback.print_exc()
        raise DatabaseLookupError()

    resp = {'unspents': unspent_outputs}

    return jsonify(resp), 200


@app.route('/v1/addresses/<address>/names', methods=['GET'])
@auth_required(exception_paths=[
    '/v1/addresses/MyVZe4nwF45jeooXw2v1VtXyNCPczbL2EE/names'])
@crossdomain(origin='*')
def get_address_names(address):
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


@app.route('/v1/users', methods=['GET'])
@auth_required()
@crossdomain(origin='*')
def get_all_users():
    resp_json = {}

    # Specify the URL for the namespace call. If 'recent_blocks' is present,
    # limit the call to only the names registered in that recent # of blocks.
    namespace_url = NMC_RESOLVER_URL + '/v1/namespace'
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

    return jsonify(resp_json), 200


@app.route('/v1/stats/users', methods=['GET'])
@crossdomain(origin='*')
def get_user_stats():
    resp_json = {}

    stats_url = NMC_RESOLVER_URL + '/v1/users'
    try:
        stats_resp = requests.get(stats_url, timeout=10, verify=False)
        resp_json.update(stats_resp.json())
    except (RequestsConnectionError, RequestsTimeout) as e:
        raise ResolverConnectionError()

    return jsonify(resp_json), 200


@app.route('/v1/domains/<domain>/dkim', methods=['GET'])
@auth_required(exception_paths=['/v1/domains/onename.com/dkim'])
@crossdomain(origin='*')
def get_dkim_pubkey(domain):
    domain = DKIM_RECORD_PREFIX + domain
    data = dns_resolver(domain)
    public_key_data = parse_pubkey_from_data(data)

    if public_key_data['public_key'] is None:
        raise DKIMPubkeyError()

    resp = public_key_data

    return jsonify(resp), 200
