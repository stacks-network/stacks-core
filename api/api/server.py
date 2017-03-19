#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstack Core
    ~~~~~

    copyright: (c) 2014-2017 by Blockstack Inc.
    copyright: (c) 2017 by Blockstack.org

This file is part of Blockstack Core.

    Blockstack Core is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Blockstack Core is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Blockstack Core. If not, see <http://www.gnu.org/licenses/>.
"""

import sys
import os
import requests
import json

from flask import Flask, jsonify
from flask_crossdomain import crossdomain
from flask import render_template, send_from_directory

from .utils import get_api_calls

app = Flask(__name__)

# hack around absolute paths
current_dir = os.path.abspath(os.path.dirname(__file__))
parent_dir = os.path.abspath(current_dir + "/../")

sys.path.insert(0, parent_dir)

import blockstack_client.config as blockstack_constants

from blockstack_client.rpc import BlockstackAPIEndpoint
from blockstack_client.rpc import local_api_connect, local_api_start, local_api_action
from blockstack_client.wallet import make_wallet

wallet_keys = make_wallet('password', encrypt=False)
api_password = "password"
port = 6269
host = 'localhost'
config_path = blockstack_constants.CONFIG_PATH

#local_api_action("start", password="temptemptemp", api_pass=api_password)

local_api_start(password='password')

#api_server = local_api_connect(api_host=host, api_port=port)
print local_api_action('status')

#BlockstackAPIEndpoint(api_password, wallet_keys, host=host, port=port, config_path=config_path)

BASE_API_URL = "http://localhost:6270"

@app.route('/v1/node/ping', methods=['GET'])
@crossdomain(origin='*')
def api_ping():

    API_URL = BASE_API_URL + '/v1/node/ping'

    resp = requests.get(API_URL)

    return jsonify(resp.json()), 200

@app.route('/v1/names/<name>', methods=['GET'])
@crossdomain(origin='*')
def api_names(name):


    API_URL = BASE_API_URL + '/v1/names/' + name

    resp = requests.get(API_URL)

    return jsonify(resp.json()), 200


@app.route('/')
def index():
    api_calls = get_api_calls('api/api_v1.md')
    return render_template('index.html', api_calls=api_calls)


@app.route('/favicon.ico')
def favicon():
    return send_from_directory(app.static_folder, 'favicon.ico')
