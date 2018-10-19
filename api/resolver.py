#!/usr/bin/env python2
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
import blockstack_zones

import blockstack
from blockstack.lib.schemas import OP_NAME_PATTERN, OP_NAMESPACE_PATTERN

from api.utils import cache_control

from .config import DEBUG
from .config import DEFAULT_HOST, DEFAULT_CACHE_TIMEOUT
from .config import NAMES_FILE
from .config import BASE_INDEXER_API_URL

import requests
requests.packages.urllib3.disable_warnings()

resolver = Blueprint('resolver', __name__, url_prefix='')

logging.basicConfig()
log = logging.getLogger('resolver')

if DEBUG:
    log.setLevel(level=logging.DEBUG)
else:
    log.setLevel(level=logging.INFO)

blockstack_indexer_url = BASE_INDEXER_API_URL

if blockstack_indexer_url is None:
    blockstack_working_dir = blockstack.lib.config.default_working_dir()
    blockstack_config = blockstack.lib.load_configuration(blockstack_working_dir)
    blockstack_indexer_url = blockstack_config['blockstack-api']['indexer_url']

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


def fetch_proofs(profile, username, address, profile_ver=2, zonefile = None):
    """ Get proofs for a profile and:
        a) check cached entries
        b) check which version of profile we're using
    """

    if 'account' not in profile:
        return []
    # fix up missing proofUrls
    for account in profile['account']:
        if ('proofType' in account and account['proofType'] == 'http'
            and 'proofUrl' not in account):
            site_data_to_fixed_proof_url(account, zonefile)

    if profile_ver == 3:
        proofs = profile_v3_to_proofs(profile, username, address = address)
    else:
        proofs = profile_to_proofs(profile, username, address = address)

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

def format_profile(profile, fqa, zone_file, address, public_key):
    """ Process profile data and
        1) Insert verifications
        2) Check if profile data is valid JSON
    """
    
    # if the zone file is a string, then parse it 
    if isinstance(zone_file, (str,unicode)):
        try:
            zone_file = blockstack_zones.parse_zone_file(zone_file)
        except:
            # leave as text
            pass

    data = {'profile' : profile,
            'zone_file' : zone_file,
            'public_key': public_key,
            'owner_address' : address}

    if not fqa.endswith('.id'):
        data['verifications'] = ["No verifications for non-id namespaces."]
        return data

    profile_in_legacy_format = is_profile_in_legacy_format(profile)

    if not profile_in_legacy_format:
        data['verifications'] = fetch_proofs(data['profile'], fqa, address,
                                             profile_ver=3, zonefile=zone_file)
    else:
        if type(profile) is not dict:
            data['profile'] = json.loads(profile)
        data['verifications'] = fetch_proofs(data['profile'], fqa, address)

    return data

def get_profile(fqa):
    """ Given a fully-qualified username (username.namespace)
        get the data associated with that fqu.
        Return cached entries, if possible.
    """

    profile_expired_grace = False

    fqa = fqa.lower()

    try:
        try:
            res = blockstack.lib.client.resolve_profile(
                    fqa, include_name_record=True, hostport=blockstack_indexer_url)
        except ValueError:
            # invalid name 
            res = {'error': 'Invalid name', 'status_code': 400}

        if 'error' in res:
            log.error('Error from profile.get_profile: {}'.format(res['error']))
            if "no user record hash defined" in res['error']:
                res['status_code'] = 404
            if "Failed to load user profile" in res['error']:
                res['status_code'] = 404

            if res.get('http_status'):
                # pass along 
                res['status_code'] = res['http_status']
                del res['http_status']

            return res

        log.warn(json.dumps(res['name_record']))

        profile = res['profile']
        zonefile = res['zonefile']
        public_key = res.get('public_key', None)
        address = res['name_record']['address']

        if 'expired' in res['name_record'] and res['name_record']['expired']:
            profile_expired_grace = True

    except Exception as e:
        log.exception(e)
        abort(500, json.dumps({'error': 'Server error fetching profile'}))

    if profile is None or 'error' in zonefile:
        log.error("{}".format(zonefile))
        abort(404)

    prof_data = {'response' : profile}

    data = format_profile(prof_data['response'], fqa, zonefile, address, public_key)

    if profile_expired_grace:
        data['expired'] = (
            'This name has expired! It is still in the renewal grace period, ' +
            'but must be renewed or it will eventually expire and be available' +
            ' for others to register.')

    return data


@resolver.route('/v1/users/<username>', methods=['GET'], strict_slashes=False)
@crossdomain(origin='*')
@cache_control(DEFAULT_CACHE_TIMEOUT)
def get_users(username):
    """ Fetch data from username in .id namespace
    """
    reply = {}


    if username is None:
        reply['error'] = "No username given"
        return jsonify(reply), 404

    if ',' in username:
        reply['error'] = 'Multiple username queries are no longer supported.'
        return jsonify(reply), 401


    if "." not in username:
        fqa = "{}.{}".format(username, 'id')
    else:
        fqa = username

    profile = get_profile(fqa)

    reply[username] = profile
    if 'error' in profile:
        status_code = 200
        if 'status_code' in profile:
            status_code = profile['status_code']
            del profile['status_code']
        return jsonify(reply), status_code
    else:
        return jsonify(reply), 200

@resolver.route('/v2/users/<username>', methods=['GET'], strict_slashes=False)
@crossdomain(origin='*')
@cache_control(DEFAULT_CACHE_TIMEOUT)
def get_users_v2(username):
    return get_users(username)
