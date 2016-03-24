# -*- coding: utf-8 -*-
"""
    Resolver
    ~~~~~
    :copyright: (c) 2014-2016 by Halfmoon Labs, Inc.
    :copyright: (c) 2016 blockstack.org
    :license: MIT, see LICENSE for more details.
"""

import re
import json
import collections
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
from .config import BLOCKSTACKD_IP, BLOCKSTACKD_PORT
from .config import DHT_MIRROR_IP, DHT_MIRROR_PORT
from .config import DEFAULT_NAMESPACE
from .config import NAMES_FILE

import requests
requests.packages.urllib3.disable_warnings()

app = Flask(__name__)

logging.basicConfig()
log = logging.getLogger('resolver')

if DEBUG:
    log.setLevel(level=logging.DEBUG)
else:
    log.setLevel(level=logging.INFO)


def get_mc_client():
    """ Return a new connection to memcached
    """

    mc = pylibmc.Client(MEMCACHED_SERVERS, binary=True,
                        username=MEMCACHED_USERNAME,
                        password=MEMCACHED_PASSWORD,
                        behaviors={"no_block": True,
                                   "connect_timeout": 200})

    return mc

mc = get_mc_client()


def validName(name):
    """ Return True if valid name
    """

    # current regrex doesn't account for .namespace
    regrex = re.compile('^[a-z0-9_]{1,60}$')

    if regrex.match(name):
        return True
    else:
        return False


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
    """ Given a fully-qualified username (username.namespace)
        get the data associated with that fqu.
        Return cached entries, if possible.
    """

    global MEMCACHED_ENABLED
    global mc

    username = username.lower()

    if MEMCACHED_ENABLED and not refresh:
        log.debug("Memcache get: %s" % username)
        cache_reply = mc.get("profile_" + str(username))
    else:
        log.debug("Memcache disabled: %s" % username)
        cache_reply = None

    if cache_reply is None:

        try:
            bs_client = Proxy(BLOCKSTACKD_IP, BLOCKSTACKD_PORT)
            bs_resp = bs_client.get_name_blockchain_record(username + "." + namespace)
            bs_resp = bs_resp[0]
        except:
            return {}

        if bs_resp is None:
            abort(404)

        if 'value_hash' in bs_resp:
            profile_hash = bs_resp['value_hash']
            profile = fetch_from_dht(profile_hash)

            data = format_profile(profile, username)
            data['owner_address'] = bs_resp['address']

            if MEMCACHED_ENABLED or refresh:
                log.debug("Memcache set: %s" % username)
                mc.set("profile_" + str(username), json.dumps(data),
                        int(time() + MEMCACHED_TIMEOUT))
        else:
            data = {"error": "Not found"}
    else:
        data = json.loads(cache_reply)

    return data


def get_all_users():
    """ Return all users in the .id namespace
    """

    fout = open(NAMES_FILE, 'r')
    data = fout.read()
    data = json.loads(data)
    fout.close()

    return data


@app.route('/v2/users/<usernames>', methods=['GET'], strict_slashes=False)
@crossdomain(origin='*')
def get_users(usernames):
    """ Fetch data from username in .id namespace
    """

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


@app.route('/v2/namespace', strict_slashes=False)
@crossdomain(origin='*')
def get_namespace():
    """ Get stats on registration and all names registered
        (old endpoint, still here for compatibility)
    """

    reply = {}
    total_users = get_all_users()
    reply['stats'] = {'registrations': len(total_users)}
    reply['usernames'] = total_users

    return jsonify(reply)


@app.route('/v2/namespaces', strict_slashes=False)
@crossdomain(origin='*')
def get_all_namespaces():
    """ Get stats on registration and all names registered
    """

    json.encoder.c_make_encoder = None

    reply = {}
    all_namespaces = []
    total_users = get_all_users()

    id_namespace = collections.OrderedDict([("namespace", "id"),
                                            ("registrations", len(total_users)),
                                            ("names", total_users)])

    all_namespaces.append(id_namespace)

    reply['namespaces'] = all_namespaces

    # disable Flask's JSON sorting
    app.config["JSON_SORT_KEYS"] = False

    return jsonify(reply)


@app.route('/v2/users/', methods=['GET'], strict_slashes=False)
@crossdomain(origin='*')
def get_user_count():
    """ Get stats on registered names
    """

    reply = {}

    total_users = get_all_users()
    reply['stats'] = {'registrations': len(total_users)}

    return jsonify(reply)


@app.route('/')
def index():
    """ Default HTML display if someone visits the resolver
    """

    reply = '<hmtl><body>Welcome to this Blockstack resolver, see \
            <a href="http://github.com/blockstack/blockstack-resolver"> \
            this Github repo</a> for details.</body></html>'

    return reply


@app.errorhandler(500)
def internal_error(error):

    reply = []
    return json.dumps(reply)


@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error': 'Not found'}), 404)
