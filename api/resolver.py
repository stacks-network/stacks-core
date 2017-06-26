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

from flask import Flask, make_response, jsonify, abort, request
from flask import Blueprint
from flask_crossdomain import crossdomain

from time import time

from blockstack_proofs import profile_to_proofs, profile_v3_to_proofs

import blockstack_client.profile

from blockstack_client.schemas import OP_NAME_PATTERN, OP_NAMESPACE_PATTERN

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

# copied and patched from proofs.py
def site_data_to_fixed_proof_url(account, zonefile):
    service = account['service']
    proof = None
    if (service in zonefile and 'proof' in zonefile[service]):
        proof = zonefile[service]['proof']
        if isinstance(proof, dict):
            if 'url' in proof:
                proof = proof['url']
            elif 'id' in proof and 'username' in zonefile[service]:
                username = zonefile[service]['username']
                if service == "twitter":
                    proof = "https://twitter.com/" + username + "/status/" + proof["id"]
                elif service == "github":
                    proof = "https://gist.github.com/" + username + "/" + proof["id"]
                elif service == "facebook":
                    proof = "https://facebook.com/" + username + "/posts/" + proof["id"]
            else:
                proof = None
    if proof:
        account['proofUrl'] = proof


def fetch_proofs(profile, username, profile_ver=2, zonefile = None, refresh=False):
    """ Get proofs for a profile and:
        a) check cached entries
        b) check which version of profile we're using
    """

    if MEMCACHED_ENABLED and not refresh:
        log.debug("Memcache get proofs: %s" % username)
        proofs_cache_reply = mc.get("proofs_" + str(username))
    else:
        proofs_cache_reply = None

    if 'account' not in profile:
        return []
    # fix up missing proofUrls
    for account in profile['account']:
        if ('proofType' in account and account['proofType'] == 'http'
            and 'proofUrl' not in account):
            site_data_to_fixed_proof_url(account, zonefile)

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

def format_profile(profile, fqa, zone_file, refresh=False):
    """ Process profile data and
        1) Insert verifications
        2) Check if profile data is valid JSON
    """

    data = {'profile' : profile,
            'zone_file' : zone_file}

    try:
        username, ns = fqa.split(".")
    except:
        data = {'error' : "Failed to split fqa into name and namespace."}
        return data
    if ns != 'id':
        data['verifications'] = ["No verifications for non-id namespaces."]
        return data

    profile_in_legacy_format = is_profile_in_legacy_format(profile)

    if not profile_in_legacy_format:
        data['verifications'] = fetch_proofs(data['profile'], username,
                                             profile_ver=3, zonefile=zone_file,
                                             refresh=refresh)
    else:
        if type(profile) is not dict:
            data['profile'] = json.loads(profile)
        data['verifications'] = fetch_proofs(data['profile'], username,
                                             refresh=refresh)

    return data

NAME_PATTERN = re.compile(OP_NAME_PATTERN)
NS_PATTERN = re.compile(OP_NAMESPACE_PATTERN)
def is_valid_fqa(fqa):
    try:
        username, ns = fqa.split(".")
    except:
        return False
    return ((NAME_PATTERN.match(username) is not None) and
            (NS_PATTERN.match(ns) is not None))

def get_profile(fqa, refresh=False):
    """ Given a fully-qualified username (username.namespace)
        get the data associated with that fqu.
        Return cached entries, if possible.
    """

    global MEMCACHED_ENABLED
    global mc

    fqa = fqa.lower()
    if not is_valid_fqa(fqa):
        return {'error' : 'Malformed name {}'.format(fqa)}

    if MEMCACHED_ENABLED and not refresh:
        log.debug("Memcache get DHT: %s" % fqa)
        dht_cache_reply = mc.get("dht_" + str(fqa))
    else:
        dht_cache_reply = None

    if dht_cache_reply is None:
        try:
            res = blockstack_client.profile.get_profile(fqa, use_legacy = True)
            if 'error' in res:
                log.error('Error from profile.get_profile: {}'.format(res['error']))
                return res
            profile = res['profile']
            zonefile = res['zonefile']
        except Exception as e:
            log.exception(e)
            abort(500, "Connection to blockstack-server %s:%s timed out" % 
                  (BLOCKSTACKD_IP, BLOCKSTACKD_PORT))

        if profile is None or 'error' in zonefile:
            log.error("{}".format(zonefile))
            abort(404)
            
        prof_data = {'response' : profile}
     
        if MEMCACHED_ENABLED or refresh:
            log.debug("Memcache set DHT: %s" % fqa)
            mc.set("dht_" + str(fqa), json.dumps(data),
                   int(time() + MEMCACHED_TIMEOUT))
    else:
        prof_data = json.loads(dht_cache_reply)

    data = format_profile(prof_data['response'], fqa, zonefile)

    return data


def get_all_users():
    """ Return all users in the .id namespace
    """

    # aaron: hardcode a non-response for the time being -- 
    #  the previous code was trying to load a non-existent file
    #  anyways. 
    return {}

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
        return jsonify(reply), 404

    if ',' not in usernames:
        usernames = [usernames]
    else:
        try:
            usernames = usernames.rsplit(',')
        except:
            reply['error'] = "Invalid input format"
            return jsonify(reply), 401

    for username in usernames:
        if "." not in username:
            fqa = "{}.{}".format(username, 'id')
        else:
            fqa = username
        profile = get_profile(fqa, refresh=refresh)

        if 'error' in profile:
            if len(usernames) == 1:
                reply[username] = profile
                return jsonify(reply), 502
        else:
            reply[username] = profile

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
