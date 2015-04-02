#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Username Resolver
    ~~~~~

    :copyright: (c) 2015 by Openname.org
    :license: MIT, see LICENSE for more details.
"""

from flask import Flask, make_response, jsonify, abort, request
import json

app = Flask(__name__)

from .config import DEBUG
from .config import DEFAULT_HOST, MEMCACHED_SERVERS, MEMCACHED_USERNAME
from .config import MEMCACHED_PASSWORD, MEMCACHED_TIMEOUT, MEMCACHED_ENABLED
from .config import NAMECOIND_SERVER, NAMECOIND_PORT, NAMECOIND_USE_HTTPS
from .config import NAMECOIND_USER, NAMECOIND_PASSWD

from commontools import error_reply, log
import logging

log.setLevel(logging.DEBUG if DEBUG else logging.INFO)

import pylibmc
from time import time
mc = pylibmc.Client(MEMCACHED_SERVERS, binary=True,
                    username=MEMCACHED_USERNAME, password=MEMCACHED_PASSWORD)

from coinrpc import NamecoindServer
namecoind = NamecoindServer(NAMECOIND_SERVER, NAMECOIND_PORT,
                            NAMECOIND_USER, NAMECOIND_PASSWD,
                            NAMECOIND_USE_HTTPS)

from .helper import requires_auth
from .proofcheck import profile_to_proofs
from .crossdomain import crossdomain


# -----------------------------------
def name_show_mem(key):

    if MEMCACHED_ENABLED:
        cache_reply = mc.get("name_" + str(key))
    else:
        cache_reply = None

    if cache_reply is None:
        try:
            info = namecoind.name_show(key)

            if MEMCACHED_ENABLED:
                mc.set("name_" + str(key), json.dumps(info['value']),
                       int(time() + MEMCACHED_TIMEOUT))
                log.debug("cache miss: " + str(key))
        except:
            info = {}
    else:
        log.debug("cache hit: " + str(key))
        info = {}
        info['value'] = json.loads(cache_reply)

    return info


# -----------------------------------
def full_profile_mem(key):

    check_profile = name_show_mem(key)

    try:
        check_profile = check_profile['value']
    except:
        return check_profile

    if 'next' in check_profile:

        child_data = full_profile_mem(check_profile['next'])

        if 'value' in child_data:
            child_data = child_data['value']

        del check_profile['next']

        merged_data = {key: value for (key, value) in (check_profile.items() +
                       child_data.items())}
        return merged_data

    else:
        return check_profile


# -----------------------------------
def get_key_value(key):

    try:
        key = key.lower()
    except:
        return jsonify(error_reply("No key given"))

    info = name_show_mem(key)

    if 'status' in info:
        if info['status'] == 404:
            abort(404)

    return jsonify(info)


# -----------------------------------------
@app.route('/v1/users', methods=['GET'])
@requires_auth
@crossdomain(origin='*')
def get_user_count():

    active_users = []

    if MEMCACHED_ENABLED:

        total_user_count = mc.get("total_users")

        if total_user_count is None:
            active_users_list = namecoind.name_filter('u/')

            if type(active_users_list) is list:
                mc.set("total_users", str(len(active_users_list)), int(time() + MEMCACHED_TIMEOUT))

                total_user_count = len(active_users_list)
            else:
                total_user_count = 0

    info = {}
    stats = {}

    stats['registrations'] = total_user_count
    info['stats'] = stats
    return jsonify(info)


# -----------------------------------
def get_user_profile(username):

    username = username.lower()
    key = 'u/' + username

    if MEMCACHED_ENABLED:
        log.debug('cache enabled')
        cache_reply = mc.get("profile_" + str(key))
    else:
        cache_reply = None
        log.debug("cache off")

    if cache_reply is None:

        info = {}
        profile = full_profile_mem(key)

        if not profile:
            #abort(404)
            print "abort"
        else:
            info['profile'] = profile
            info['verifications'] = profile_to_proofs(profile, username)

        if MEMCACHED_ENABLED:
            mc.set("profile_" + str(key), json.dumps(info),
                   int(time() + MEMCACHED_TIMEOUT))
            log.debug("cache miss full_profile")
    else:
        log.debug("cache hit full_profile")
        info = json.loads(cache_reply)

    return info


# -----------------------------------
@app.route('/v1/users/<usernames>', methods=['GET'])
@requires_auth
@crossdomain(origin='*')
def get_users(usernames):

    if usernames is None:
        return jsonify(error_reply("No usernames given"))

    if ',' not in usernames:
        info = get_user_profile(usernames)

        try:
            jsonify(info)
        except:
            return error_reply("Malformed profile")

        if 'status' in info:
            if info['status'] == 404:
                abort(404)

        return jsonify(info)

    try:
        usernames = usernames.rsplit(',')
    except:
        return jsonify(error_reply("Invalid input format"))

    list = []

    for username in usernames:

        result = {}
        result[username] = get_user_profile(username)
        list.append(result)

    return jsonify(results=list)


# -----------------------------------
@app.route('/v1/namespace')
@requires_auth
@crossdomain(origin='*')
def get_namespace():

    from commontools import get_json

    users = namecoind.name_filter('u/')

    list = []

    for user in users:
        try:
            username = user['name'].lstrip('u/').lower()
            profile = get_json(user['value'])

            if 'status' in profile and profile['status'] == -1:
                continue

            if 'status' in profile and profile['status'] == 'reserved':
                continue

            if profile == {}:
                continue

            if 'next' in profile:
                profile = full_profile_mem('u/' + username)

            result = {}
            result["username"] = username
            result["profile"] = profile
            list.append(result)

        except Exception as e:
            continue

    return jsonify(results=list)


# -----------------------------------
@app.route('/')
def index():
    reply = '<hmtl><body>Welcome to this resolver, see \
            <a href="http://github.com/openname/resolver"> \
            this Github repo</a> for details.</body></html>'

    return reply


# -----------------------------------
@app.errorhandler(500)
def internal_error(error):

    reply = []
    return json.dumps(reply)


# -----------------------------------
@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error': 'Not found'}), 404)
