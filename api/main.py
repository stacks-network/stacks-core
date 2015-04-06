# -*- coding: utf-8 -*-
"""
    Onename API
    Copyright 2015 Halfmoon Labs, Inc.
    ~~~~~
"""

import requests

from flask import redirect, url_for, render_template, request
from flask import jsonify

from . import app
from .errors import APIError
from .helper import parameters_required
from .crossdomain import crossdomain
from .auth import auth_required


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
        'openname_specs': '0.2',
        'openname_directory': '0.1',
    }

    return jsonify(data), 200


# --------------------------------------
@app.route('/search', methods=['GET'])
@auth_required(exception_queries=['fredwilson'])
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
@auth_required(exception_paths=['/v1/user_count/example'])
@crossdomain(origin='*')
@app.route('/users')
def user_count():

    BASE_URL = 'https://resolver.onename.com/v1/users/'

    try:
        reply = requests.get(BASE_URL, timeout=1)
    except Exception as e:
        raise APIError(str(e), status_code=404)

    return reply


# --------------------------------------
@app.route('/users/<username>')
@auth_required(exception_paths=['/v1/users/example'])
@crossdomain(origin='*')
def api_user(username):

    BASE_URL = 'https://resolver.onename.com/v1/users/'

    try:
        reply = requests.get(BASE_URL + username, timeout=1)
    except Exception as e:
        raise APIError(str(e), status_code=404)

    return reply