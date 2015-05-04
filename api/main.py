# -*- coding: utf-8 -*-
"""
    Onename API
    Copyright 2015 Halfmoon Labs, Inc.
    ~~~~~
"""

import requests
import json

from flask import redirect, url_for, render_template, request
from flask import jsonify

from . import app
from .errors import APIError
from .helper import parameters_required
from .crossdomain import crossdomain
from .auth import auth_required

from pybitcoin.rpc import namecoind

from pymongo import MongoClient
from settings import AWSDB_URI
aws_db = MongoClient(AWSDB_URI)['onename-api']
register_queue = aws_db.queue

namecoin_index = MongoClient(NAMECOIN_DB_URI)['namecoin_index']
address_utxo = namecoin_index.address_utxo
address_to_keys = namecoin_index.address_to_keys

# --------------------------------------
@app.route('/')
def index():
    return render_template('index.html')


# --------------------------------------
@app.route('/versions', methods=['GET'])
@crossdomain(origin='*')
def versions():
    data = {
        'api': '1',
        'passcard_specs': '0.2',
    }

    return jsonify(data), 200


# --------------------------------------
#@auth_required(exception_queries=['fredwilson'])
@app.route('/v1/search', methods=['GET'])
@parameters_required(parameters=['query'])
@crossdomain(origin='*')
def search_people():

    search_url = 'http://search.halfmoonlabs.com/search/name'

    name = request.values['query']

    try:
        results = requests.get(url=search_url, params={'query': name})
    except:
        raise APIError('Something went wrong', status_code=500)

    if results.status_code == 404:
        raise APIError(status_code=404)
    else:
        return jsonify(results.json()), 200

    if not ('results' in results and isinstance(results['results'], list)):
        results = []
    else:
        results = results['results']

    return jsonify({'results': results}), 200


# --------------------------------------
#@auth_required(exception_paths=['/v1/user_count/example'])
@app.route('/v1/users')
@crossdomain(origin='*')
def user_count():

    BASE_URL = 'http://resolver.onename.com/v1/users'

    try:
        reply = requests.get(BASE_URL, timeout=10)

    except Exception as e:
        raise APIError(str(e), status_code=404)

    return jsonify(reply.json()), 200


# --------------------------------------
#@auth_required(exception_paths=['/v1/users/example'])
@app.route('/v1/users/<passname>')
@crossdomain(origin='*')
def api_user(passname):

    BASE_URL = 'http://resolver.onename.com/v1/users/'

    try:
        reply = requests.get(BASE_URL + passname, timeout=10)
    except Exception as e:
        raise APIError(str(e), status_code=404)

    return jsonify(reply.json()), 200


# --------------------------------------
#@auth_required(exception_paths=['/v1/users/example'])
@app.route('/v1/users/<passname>/register', methods=['POST'])
@parameters_required(['transfer_address'])
@crossdomain(origin='*')
def register_user(passname):

    if namecoind.check_registration('u/' + passname):
        raise APIError("passname already registered", status_code=403)

    data = json.loads(request.data)

    user = {}
    user['passname'] = passname

    user['transfer_address'] = data['transfer_address']

    try:
        user['passcard'] = data['passcard']
    except:
        user['passcard'] = {'status': 'registered',
                            'message': 'This passcard was registered using the Onename API -- http://api.onename.com'}

    find_user = register_queue.find_one({"passname": passname})

    if find_user is not None:
        # someone else already tried registering this name
        # but the passname is not registered on the blockchain
        # don't tell the client that someone else's request is processing

        pass
    else:
        try:
            register_queue.save(user)
        except Exception as e:
            raise APIError(str(e), status_code=404)

    reply = {}
    reply['status'] = 'success'
    return jsonify(reply), 200


# --------------------------------------
#@auth_required(exception_paths=['/v1/users/example'])
@app.route('/v1/transactions/send', methods=['POST'])
@parameters_required(['signed_hex'])
@crossdomain(origin='*')
def broadcast_tx():

    data = json.loads(request.data)

    signed_hex = data['signed_hex']

    reply = {}

    try:
        tx_hash = namecoind.sendrawtransaction(signed_hex)
    except Exception as e:
        raise APIError(str(e), status_code=404)

    reply['transaction_hash'] = tx_hash

    return jsonify(reply), 200

# --------------------------------------
#@auth_required(exception_paths=['/v1/users/example'])
@app.route('/v1/addresses/<address>', methods=['GET'])
@crossdomain(origin='*')
def get_unspent(address):

    reply = {}

    try:
        reply['unspent_outputs'] = address_utxo.find_one({"address": address})
    except Exception as e:
        raise APIError(str(e), status_code=404)

    try:
        reply['names_owned'] = address_to_keys.find_one({"address": address})
    except Exception as e:
        raise APIError(str(e), status_code=404)

    return jsonify(reply), 200