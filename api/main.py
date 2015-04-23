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
        'passcard_directory': '0.1',
    }

    return jsonify(data), 200


# --------------------------------------
#@auth_required(exception_queries=['fredwilson'])
@app.route('/v1/search', methods=['GET'])
@parameters_required(parameters=['query'])
@crossdomain(origin='*')
def search_people():

    search_url = 'https://search.halfmoonlabs.com/search/name'

    name = request.values['query']

    try:
        results = requests.get(url=search_url, params={'query': name}, verify=False)
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

    BASE_URL = 'https://resolver.onename.com/v1/users'

    try:
        reply = requests.get(BASE_URL, timeout=3, verify=False)

    except Exception as e:
        raise APIError(str(e), status_code=404)

    return jsonify(reply.json()), 200


# --------------------------------------
#@auth_required(exception_paths=['/v1/users/example'])
@app.route('/v1/users/<username>')
@crossdomain(origin='*')
def api_user(username):

    BASE_URL = 'https://resolver.onename.com/v1/users/'

    try:
        reply = requests.get(BASE_URL + username, timeout=3, verify=False)
    except Exception as e:
        raise APIError(str(e), status_code=404)

    return jsonify(reply.json()), 200


# --------------------------------------
#@auth_required(exception_paths=['/v1/users/example'])
@app.route('/v1/users/<username>/register', methods=['POST'])
@parameters_required(['transfer_address'])
@crossdomain(origin='*')
def register_user(username):

    if namecoind.check_registration('u/' + username):
        raise APIError("username already registered", status_code=403)

    data = json.loads(request.data)

    user = {}
    user['username'] = username

    user['transfer_address'] = data['transfer_address']

    try:
        user['profile'] = data['profile']
    except:
        user['profile'] = {'status': 'registered',
                           'message': 'This username was registered using the Onename API -- http://api.onename.com'}

    find_user = register_queue.find_one({"username": username})

    if find_user is not None:
        # someone else already tried registering this name
        # but the username is not registered on the blockchain
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
