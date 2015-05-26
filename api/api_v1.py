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
from .errors import InvalidProfileDataError, PassnameTakenError, \
    InternalProcessingError, ResolverConnectionError, \
    BroadcastTransactionError, DatabaseLookupError, InternalSSLError
from .parameters import parameters_required
from .crossdomain import crossdomain
from .auth import auth_required
from .db import register_queue, utxo_index, address_to_utxo, address_to_keys
from .settings import RESOLVER_URL, SEARCH_URL


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


@app.route('/v1/users/<passnames>', methods=['GET'])
@auth_required(exception_paths=['/v1/users/fredwilson'])
@crossdomain(origin='*')
def api_user(passnames):
    BASE_URL = RESOLVER_URL + '/v1/users/'

    try:
        resp = requests.get(BASE_URL + passnames, timeout=10, verify=False)
    except (RequestsConnectionError, RequestsTimeout) as e:
        raise ResolverConnectionError()

    data = resp.json()

    for passname in passnames.split(','):
        if passname not in data:
            error = InvalidProfileDataError('')
            data[passname] = {
                'error': error.to_dict()
            }

    return jsonify(data), 200


@app.route('/v1/users', methods=['POST'])
@auth_required()
@parameters_required(['passname', 'recipient_address'])
@crossdomain(origin='*')
def register_user():
    REGISTRATION_MESSAGE = (
        "This passcard was registered using the Onename"
        " API - https://api.onename.com")

    data = json.loads(request.data)

    passname = data['passname']

    try:
        was_registered = namecoind.check_registration('u/' + passname)
    except ssl.SSLError:
        raise InternalSSLError()
    except Exception as e:
        raise InternalProcessingError()

    if was_registered:
        raise PassnameTakenError()

    if 'passcard' in data:
        passcard = data['passcard']
    else:
        passcard = {
            'status': 'registered',
            'message': REGISTRATION_MESSAGE
        }

    user = {
        'passname': passname,
        'passcard': passcard,
        'transfer_address': data['recipient_address']
    }

    find_user = register_queue.find_one({'passname': passname})

    if find_user is not None:
        """ Someone else already tried registering this name
            but the passname is not yet registered on the blockchain.
            Don't tell the client that someone else's request is processing.
        """
        pass
    else:
        try:
            register_queue.save(user)
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


@app.route('/v1/users', methods=['GET'])
@crossdomain(origin='*')
def user_stats():
    BASE_URL = RESOLVER_URL + '/v1/users'

    try:
        resp = requests.get(BASE_URL, timeout=10, verify=False)
    except (RequestsConnectionError, RequestsTimeout) as e:
        raise ResolverConnectionError()

    return jsonify(resp.json()), 200


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


@app.route('/v1/addresses/<address>', methods=['GET'])
@auth_required(
    exception_paths=['/v1/addresses/NBSffD6N6sABDxNooLZxL26jwGetiFHN6H'])
@crossdomain(origin='*')
def get_address_info(address):
    resp = {}

    try:
        unspent_outputs = get_unspents(address)
    except Exception as e:
        traceback.print_exc()
        raise DatabaseLookupError()

    try:
        address_names = address_to_keys.find_one({'address': address})
    except Exception as e:
        raise DatabaseLookupError()

    names_owned = []
    if address_names is not None and 'keys' in address_names:
        names_owned = address_names['keys']

    resp = {'unspent_outputs': unspent_outputs, 'names_owned': names_owned}

    return jsonify(resp), 200
