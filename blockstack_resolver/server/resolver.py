# -*- coding: utf-8 -*-
"""
    BNS Resolver
    ~~~~~

    :copyright: (c) 2015 by Openname.org
    :license: MIT, see LICENSE for more details.
"""

from flask import Flask, make_response, jsonify, abort, request
import json
import re

app = Flask(__name__)

from .config import DEBUG
from .config import DEFAULT_HOST, MEMCACHED_SERVERS, MEMCACHED_USERNAME
from .config import MEMCACHED_PASSWORD, MEMCACHED_TIMEOUT, MEMCACHED_ENABLED
from .config import USERSTATS_TIMEOUT
from .config import NAMECOIND_SERVER, NAMECOIND_PORT, NAMECOIND_USE_HTTPS
from .config import NAMECOIND_USER, NAMECOIND_PASSWD
from .config import VALID_BLOCKS, RECENT_BLOCKS

from commontools import log, get_json, error_reply
import logging

log.setLevel(logging.DEBUG if DEBUG else logging.INFO)

import pylibmc
from time import time
mc = pylibmc.Client(MEMCACHED_SERVERS, binary=True,
                    username=MEMCACHED_USERNAME, password=MEMCACHED_PASSWORD,
                    behaviors={"no_block": True, 
                               "connect_timeout": 500})

from pybitcoin.rpc import NamecoindClient
namecoind = NamecoindClient(NAMECOIND_SERVER, NAMECOIND_PORT,
                            NAMECOIND_USER, NAMECOIND_PASSWD,
                            NAMECOIND_USE_HTTPS)

from .proofcheck import profile_to_proofs
from .crossdomain import crossdomain

from threading import Thread

from pymongo import MongoClient

db = MongoClient()['resolver_index']

namespaces = db.namespaces
profiles = db.profiles


def username_is_valid(username):

    regrex = re.compile('^[a-z0-9_]{1,60}$')

    if regrex.match(username):
        return True
    else:
        return False


def refresh_user_count():

    active_users_list = namecoind.name_filter('u/')

    if type(active_users_list) is list:
        mc.set("total_users", str(len(active_users_list)), int(time() + USERSTATS_TIMEOUT))
        mc.set("total_users_old", str(len(active_users_list)), 0)

    return len(active_users_list)


@app.route('/v1/users', methods=['GET'])
@crossdomain(origin='*')
def get_user_count():

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


def get_user_profile(username, refresh=False):

    global MEMCACHED_ENABLED

    if refresh:
        MEMCACHED_ENABLED = False

    username = username.lower()

    check_entry = profiles.find({"username": username}).limit(1)

    if check_entry.count() == 0:
        abort(404)

    if MEMCACHED_ENABLED:
        cache_reply = mc.get("profile_" + str(username))
    else:
        cache_reply = None

    if cache_reply is None:

        info = {}

        profile = profiles.find_one({"username": username})['profile']

        if 'error' in profile:
            info['profile'] = None
            info['error'] = "Malformed profile data"
            info['verifications'] = []
        else:
            info['profile'] = profile
            info['verifications'] = profile_to_proofs(profile, username)

        if MEMCACHED_ENABLED or refresh:
            mc.set("profile_" + str(username), json.dumps(info),
                   int(time() + MEMCACHED_TIMEOUT))
    else:
        info = json.loads(cache_reply)

    return info


@app.route('/v1/users/<usernames>', methods=['GET'])
@crossdomain(origin='*')
def get_users(usernames):

    reply = {}

    if usernames is None:
        return jsonify(error_reply("No usernames given"))

    if ',' not in usernames:

        username = usernames

        info = get_user_profile(username)
        reply[username] = info

        if 'error' in info:
            return jsonify(reply), 502

        return jsonify(reply), 200

    try:
        usernames = usernames.rsplit(',')
    except:
        return jsonify(error_reply("Invalid input format"))

    for username in usernames:

        try:
            reply[username] = get_user_profile(username)
        except:
            pass

    return jsonify(reply), 200


@app.route('/v1/namespace')
@crossdomain(origin='*')
def get_namespace():

    results = {}

    namespace = namespaces.find_one({"blocks": VALID_BLOCKS})

    results['usernames'] = namespace['namespace']
    results['profiles'] = namespace['profiles'] 

    return jsonify(results)


@app.route('/v1/namespace/recent/<blocks>')
@crossdomain(origin='*')
def get_recent_namespace(blocks):

    results = {}

    blocks = int(blocks)

    if blocks > VALID_BLOCKS:
        blocks = VALID_BLOCKS

    if blocks == VALID_BLOCKS:
        namespace = namespaces.find_one({"blocks": VALID_BLOCKS})
        results['usernames'] = namespace['namespace']
    elif blocks == RECENT_BLOCKS:
        namespace = namespaces.find_one({"blocks": RECENT_BLOCKS})
        results['usernames'] = namespace['namespace']
    else:

        users = namecoind.name_filter('u/', blocks)

        list = []

        for user in users:

            username = user['name'].lstrip('u/').lower()

            if username_is_valid(username):
                list.append(username)

        results['usernames'] = list

    return jsonify(results)


@app.route('/')
def index():
    reply = '<hmtl><body>Welcome to this resolver, see \
            <a href="http://github.com/openname/resolver"> \
            this Github repo</a> for details.</body></html>'

    return reply


@app.errorhandler(500)
def internal_error(error):

    reply = []
    return json.dumps(reply)


@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error': 'Not found'}), 404)
