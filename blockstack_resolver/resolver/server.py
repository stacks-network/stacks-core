# -*- coding: utf-8 -*-
"""
    Resolver
    ~~~~~

    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016 by Blockstack.org

This file is part of Resolver.

    Resolver is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Resolver is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Resolver. If not, see <http://www.gnu.org/licenses/>.
"""

import json
import re
import pylibmc
import logging

from flask import Flask, make_response, jsonify, abort, request
from time import time
from basicrpc import Proxy

from proofchecker import profile_to_proofs
from .crossdomain import crossdomain

from .config import DEBUG
from .config import DEFAULT_HOST, MEMCACHED_SERVERS, MEMCACHED_USERNAME
from .config import MEMCACHED_PASSWORD, MEMCACHED_TIMEOUT, MEMCACHED_ENABLED
from .config import USERSTATS_TIMEOUT
from .config import VALID_BLOCKS, RECENT_BLOCKS
from .config import BLOCKSTORED_IP, BLOCKSTORED_PORT
from .config import DHT_MIRROR_IP, DHT_MIRROR_PORT
from .config import DEFAULT_NAMESPACE

app = Flask(__name__)

mc = pylibmc.Client(MEMCACHED_SERVERS, binary=True,
                    username=MEMCACHED_USERNAME, password=MEMCACHED_PASSWORD,
                    behaviors={"no_block": True,
                               "connect_timeout": 500})

logging.basicConfig()
log = logging.getLogger('resolver')

if DEBUG:
    log.setLevel(level=logging.DEBUG)
else:
    log.setLevel(level=logging.INFO)


def validName(name):
    """ Return True if valid name
    """

    # current regrex doesn't account for .namespace
    regrex = re.compile('^[a-z0-9_]{1,60}$')

    if regrex.match(name):
        return True
    else:
        return False


def refresh_user_count():

    active_users_list = 'xx'  # fetch user info here

    if type(active_users_list) is list:
        mc.set("total_users", str(len(active_users_list)), int(time() + USERSTATS_TIMEOUT))
        mc.set("total_users_old", str(len(active_users_list)), 0)

    return len(active_users_list)


@app.route('/v2/users', methods=['GET'])
@crossdomain(origin='*')
def get_user_count():

    resp = {}
    resp['error'] = "not yet supported"
    return jsonify(resp)

    active_users = []

    if MEMCACHED_ENABLED:

        total_user_count = mc.get("total_users")

        if total_user_count is None:

            total_user_count = mc.get("total_users_old")

            if total_user_count is None:

                total_user_count = refresh_user_count()

            else:

                thread = Thread(target=refresh_user_count)
                thread.start()
    else:

        total_user_count = refresh_user_count()

    info = {}
    stats = {}

    stats['registrations'] = total_user_count
    info['stats'] = stats

    return jsonify(info)


def fetch_from_dht(profile_hash):
    """ Given a @profile_hash fetch full profile JSON
    """

    dht_client = Proxy(DHT_MIRROR_IP, DHT_MIRROR_PORT)
    dht_resp = dht_client.get(profile_hash)
    dht_resp = dht_resp[0]

    try:
        profile = json.loads(dht_resp['value'])
    except:
        profile = {}

    return profile


def format_profile(profile, username):
    """ Process profile data and
        1) Insert verifications
        2) Check if profile data is valid JSON
    """

    data = {}

    if 'error' in profile:
        data['profile'] = None
        data['error'] = "Malformed profile data"
        data['verifications'] = []
    else:
        data['profile'] = profile
        data['verifications'] = profile_to_proofs(profile, username)

    return data


def get_profile(username, refresh=False, namespace=DEFAULT_NAMESPACE):

    global MEMCACHED_ENABLED

    if refresh:
        log.debug("Forcing refresh: %s" % username)
        # refresh is on, turning off memcache
        MEMCACHED_ENABLED = False

    username = username.lower()

    try:
        blockstore_client = Proxy(BLOCKSTORED_IP, BLOCKSTORED_PORT)
        blockstore_resp = blockstore_client.get_name_blockchain_record(username + "." + namespace)
        blockstore_resp = blockstore_resp[0]
    except:
        return {}

    if blockstore_resp is None:
        abort(404)

    if MEMCACHED_ENABLED:
        log.debug("Memcache get: %s" % username)
        cache_reply = mc.get("profile_" + str(username))
    else:
        cache_reply = None

    if cache_reply is None:

        if 'value_hash' in blockstore_resp:
            profile_hash = blockstore_resp['value_hash']
            profile = fetch_from_dht(profile_hash)
            data = format_profile(profile, username)

            if MEMCACHED_ENABLED or refresh:
                log.debug("Memcache set: %s" % username)
                mc.set("profile_" + str(username), json.dumps(data),
                       int(time() + MEMCACHED_TIMEOUT))
        else:
            data = {"error": "Not found"}
    else:
        data = json.loads(cache_reply)

    return data


@app.route('/v2/users/<usernames>', methods=['GET'])
@crossdomain(origin='*')
def get_users(usernames):

    reply = {}
    refresh = False

    try:
        refresh = request.args.get('refresh')
    except:
        pass

    if usernames is None:
        reply['error'] = "No usernames given"
        return jsonify(reply)

    if ',' not in usernames:

        username = usernames

        info = get_profile(username, refresh=refresh)

        if 'error' in info:
            reply = {"error": "Not found"}
            return jsonify(reply), 502
        else:
            reply[username] = info

        return jsonify(reply), 200

    try:
        usernames = usernames.rsplit(',')
    except:
        reply['error'] = "Invalid input format"
        return jsonify(reply)

    for username in usernames:

        try:
            profile = get_profile(username, refresh=refresh)

            if 'error' in profile:
                pass
            else:
                reply[username] = profile
        except:
            pass

    return jsonify(reply), 200


@app.route('/v2/namespace')
@crossdomain(origin='*')
def get_namespace():

    resp = {}
    resp['error'] = "not yet supported"
    return jsonify(resp)

    results = {}

    namespace = 'xx'  # get namespace info

    results['usernames'] = namespace['namespace']
    results['profiles'] = namespace['profiles']

    return jsonify(results)


@app.route('/')
def index():

    reply = '<hmtl><body>Welcome to this Blockchain ID resolver, see \
            <a href="http://github.com/blockstack/resolver"> \
            this Github repo</a> for details.</body></html>'

    return reply


@app.errorhandler(500)
def internal_error(error):

    reply = []
    return json.dumps(reply)


@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error': 'Not found'}), 404)
