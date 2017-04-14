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

import re
import json
import collections
import logging
import xmlrpclib

from flask import Flask, make_response, jsonify, abort, request
from flask import Blueprint
from flask_crossdomain import crossdomain

from time import time
from basicrpc import Proxy

from blockstack_proofs import profile_to_proofs, profile_v3_to_proofs
from blockstack_profiles import resolve_zone_file_to_profile
from blockstack_profiles import get_token_file_url_from_zone_file
from blockstack_profiles import get_profile_from_tokens
#from blockstack_profiles import is_profile_in_legacy_format
from blockstack_zones import parse_zone_file

from blockstack_client.proxy import get_name_blockchain_record

from api.utils import cache_control, get_mc_client

from .config import DEBUG
from .config import DEFAULT_HOST, MEMCACHED_TIMEOUT, MEMCACHED_ENABLED
from .config import USERSTATS_TIMEOUT
from .config import VALID_BLOCKS, RECENT_BLOCKS
from .config import BLOCKSTACKD_IP, BLOCKSTACKD_PORT
from .config import DHT_MIRROR_IP, DHT_MIRROR_PORT
from .config import DEFAULT_NAMESPACE
from .config import NAMES_FILE

import requests
requests.packages.urllib3.disable_warnings()

resolver = Blueprint('resolver', __name__, url_prefix='')

logging.basicConfig()
log = logging.getLogger('resolver')

if DEBUG:
    log.setLevel(level=logging.DEBUG)
else:
    log.setLevel(level=logging.INFO)

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

    try:
        dht_resp = dht_client.get(profile_hash)
    except:
        #abort(500, "Connection to DHT timed out")
        return {"error": "Data not saved in DHT yet."}

    dht_resp = dht_resp[0]

    if dht_resp is None:
        return {"error": "Data not saved in DHT yet."}

    return dht_resp['value']


def fetch_proofs(profile, username, profile_ver=2, refresh=False):
    """ Get proofs for a profile and:
        a) check cached entries
        b) check which version of profile we're using
    """

    if MEMCACHED_ENABLED and not refresh:
        log.debug("Memcache get proofs: %s" % username)
        proofs_cache_reply = mc.get("proofs_" + str(username))
    else:
        proofs_cache_reply = None

    if proofs_cache_reply is None:

        if profile_ver == 3:
            proofs = profile_v3_to_proofs(profile, username)
        else:
            proofs = profile_to_proofs(profile, username)

        if MEMCACHED_ENABLED or refresh:
            log.debug("Memcache set proofs: %s" % username)
            mc.set("proofs_" + str(username), json.dumps(proofs),
                   int(time() + MEMCACHED_TIMEOUT))
    else:

        proofs = json.loads(proofs_cache_reply)

    return proofs


def is_profile_in_legacy_format(profile):
    """
    Is a given profile JSON object in legacy format?
    """
    if isinstance(profile, dict):
        pass
    elif isinstance(profile, (str, unicode)):
        try:
            profile = json.loads(profile)
        except ValueError:
            return False
    else:
        return False

    if "@type" in profile:
        return False

    if "@context" in profile:
        return False

    is_in_legacy_format = False

    if "avatar" in profile:
        is_in_legacy_format = True
    elif "cover" in profile:
        is_in_legacy_format = True
    elif "bio" in profile:
        is_in_legacy_format = True
    elif "twitter" in profile:
        is_in_legacy_format = True
    elif "facebook" in profile:
        is_in_legacy_format = True

    return is_in_legacy_format


def parse_uri_from_zone_file(zone_file):

    token_file_url = None
    zone_file = dict(parse_zone_file(zone_file))

    if isinstance(zone_file["uri"], list) and len(zone_file["uri"]) > 0:

        index = 0
        while(index < len(zone_file["uri"])):

            record = zone_file["uri"][index]

            if 'name' in record and record['name'] == '_http._tcp':
                first_uri_record = zone_file["uri"][index]
                token_file_url = first_uri_record["target"]
                break

            index += 1

    return token_file_url


def resolve_zone_file_from_rpc(zone_file, owner_address):

    rpc_uri = parse_uri_from_zone_file(zone_file)

    try:
        uri, fqu = rpc_uri.rsplit('#')
    except:
        return None

    try:
        s = xmlrpclib.ServerProxy(uri, allow_none=True)
        data = s.get_profile(fqu)
    except Exception as e:
        print e

    data = json.loads(data)
    profile = json.loads(data['profile'])
    pubkey = profile[0]['parentPublicKey']

    try:
        profile = get_profile_from_tokens(profile, pubkey)
    except Exception as e:
        print e

    return profile


def resolve_zone_file_to_profile(zone_file, address_or_public_key):

    profile = None

    if is_profile_in_legacy_format(zone_file):
        return zone_file

    try:
        token_file_url = get_token_file_url_from_zone_file(zone_file)

        r = requests.get(token_file_url)

        profile_token_records = json.loads(r.text)

        profile = get_profile_from_tokens(profile_token_records, address_or_public_key)
    except Exception as e:

        profile = resolve_zone_file_from_rpc(zone_file, address_or_public_key)

    print profile
    return profile, None


def format_profile(profile, username, address, refresh=False):
    """ Process profile data and
        1) Insert verifications
        2) Check if profile data is valid JSON
    """

    data = {}
    zone_file = profile

    if 'error' in profile:
        data['profile'] = {}
        data['error'] = profile['error']
        data['verifications'] = []
        data['owner_address'] = address
        data['zone_file'] = zone_file

        return data

    try:
        profile, error = resolve_zone_file_to_profile(zone_file, address)
    except:
        if 'message' in profile:
            data['profile'] = json.loads(profile)
            data['verifications'] = []
            data['owner_address'] = address
            data['zone_file'] = zone_file
            return data

    if profile is None:
        data['profile'] = {}

        if error is not None:
            data['error'] = error
        else:
            data['error'] = "Malformed profile data."
        data['verifications'] = []

    else:

        profile_in_legacy_format = is_profile_in_legacy_format(profile)

        if not profile_in_legacy_format:
            data['profile'] = profile
            data['verifications'] = fetch_proofs(data['profile'], username,
                                                 profile_ver=3, refresh=refresh)
        else:
            if type(profile) is not dict:
                data['profile'] = json.loads(profile)
            else:
                data['profile'] = profile
            data['verifications'] = fetch_proofs(data['profile'], username,
                                                 refresh=refresh)

    data['zone_file'] = zone_file
    data['owner_address'] = address

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
        log.debug("Memcache get DHT: %s" % username)
        dht_cache_reply = mc.get("dht_" + str(username))
    else:
        log.debug("Memcache disabled: %s" % username)
        dht_cache_reply = None

    if dht_cache_reply is None:

        try:
            bs_resp = get_name_blockchain_record(username + "." + namespace)
        except:
            abort(500, "Connection to blockstack-server %s:%s timed out" % (BLOCKSTACKD_IP, BLOCKSTACKD_PORT))

        if bs_resp is None or 'error' in bs_resp:
            abort(404)

        if 'value_hash' in bs_resp:
            profile_hash = bs_resp['value_hash']
            dht_response = fetch_from_dht(profile_hash)

            dht_data = {}
            dht_data['dht_response'] = dht_response
            dht_data['owner_address'] = bs_resp['address']

            if MEMCACHED_ENABLED or refresh:
                log.debug("Memcache set DHT: %s" % username)
                mc.set("dht_" + str(username), json.dumps(dht_data),
                       int(time() + MEMCACHED_TIMEOUT))
        else:
            dht_data = {"error": "Not found"}
    else:
        dht_data = json.loads(dht_cache_reply)

    data = format_profile(dht_data['dht_response'], username, dht_data['owner_address'])

    return data


def get_all_users():
    """ Return all users in the .id namespace
    """

    try:
        fout = open(NAMES_FILE, 'r')
        data = fout.read()
        data = json.loads(data)
        fout.close()
    except:
        data = {}

    return data

# aaron note: do we need to support multiple users in a query?
#    this seems like a potential avenue for abuse.

@resolver.route('/v2/users/<usernames>', methods=['GET'], strict_slashes=False)
@crossdomain(origin='*')
@cache_control(MEMCACHED_TIMEOUT)
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
            reply[username] = info
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


@resolver.route('/v2/namespace', strict_slashes=False)
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


@resolver.route('/v2/namespaces', strict_slashes=False)
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


@resolver.route('/v2/users/', methods=['GET'], strict_slashes=False)
@crossdomain(origin='*')
def get_user_count():
    """ Get stats on registered names
    """

    reply = {}

    total_users = get_all_users()
    reply['stats'] = {'registrations': len(total_users)}

    return jsonify(reply)
