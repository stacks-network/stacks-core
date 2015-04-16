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
@app.route('/search', methods=['GET'])
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
@app.route('/users')
@crossdomain(origin='*')
def user_count():

    BASE_URL = 'http://resolver.onename.com/v1/users'

    try:
        reply = requests.get(BASE_URL, timeout=3)

    except Exception as e:
        raise APIError(str(e), status_code=404)

    return jsonify(reply.json()), 200


# --------------------------------------
#@auth_required(exception_paths=['/v1/users/example'])
@app.route('/users/<username>')
@crossdomain(origin='*')
def api_user(username):

    BASE_URL = 'http://resolver.onename.com/v1/users/'

    try:
        reply = requests.get(BASE_URL + username, timeout=3)
    except Exception as e:
        raise APIError(str(e), status_code=404)

    return jsonify(reply.json()), 200


# --------------------------------------
#@auth_required(exception_paths=['/v1/users/example'])
@app.route('/transactions/send', methods=['POST'])
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
