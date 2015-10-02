# -*- coding: utf-8 -*-
"""
    Resolver
    ~~~~~

    copyright: (c) 2014 by Halfmoon Labs, Inc.
    copyright: (c) 2015 by Blockstack.org

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

import requests
import json
import hashlib
import pylibmc
from time import time

from .htmlparsing import get_search_text, get_github_text
from .sites import SITES
from ..config import MEMCACHED_PORT, MEMCACHED_TIMEOUT, DEFAULT_HOST, MEMCACHED_ENABLED

mc = pylibmc.Client([DEFAULT_HOST + ':' + str(MEMCACHED_PORT)], binary=True)


def contains_valid_proof_statement(search_text, username):
    search_text = search_text.lower()

    verification_styles = [
        "verifying myself: my bitcoin username is +%s" % username,
        "verifying myself: my bitcoin username is %s" % username,
        "verifying myself: my openname is %s" % username,
        "verifying that +%s is my bitcoin username" % username,
        "verifying that %s is my bitcoin username" % username,
        "verifying that %s is my openname" % username,
        "verifying that +%s is my openname" % username,
        "verifying i am +%s on my passcard" % username,
        "verifying that +%s is my blockchain id" % username
    ]

    for verification_style in verification_styles:
        if verification_style in search_text:
            return True

    if "verifymyonename" in search_text and ("+" + username) in search_text:
        return True

    return False


def is_valid_proof(site, site_username, username, proof_url):

    site_username = site_username.lower()
    proof_url = proof_url.lower()
    username = username.lower()

    if not site in SITES and 'base_url' in SITES[site]:
        return False

    check_url = SITES[site]['base_url'] + site_username

    if not proof_url.startswith(check_url):

        if site == 'facebook':
            check_url = SITES['facebook-www']['base_url'] + site_username
            if not proof_url.startswith(check_url):
                return False
        else:
            return False

    try:
        r = requests.get(proof_url)
    except:
        return False

    if site == "github":
        try:
            search_text = get_github_text(r.text)
        except:
            search_text = ''
    elif site in SITES:
        try:
            search_text = get_search_text(site, r.text)
        except:
            search_text = ''
    else:
        search_text = ''

    return contains_valid_proof_statement(search_text, username)


def site_data_to_proof_url(site_data, identifier):
    proof_url = None

    if "proof" in site_data:
        proof = site_data["proof"]
    else:
        return proof_url

    if isinstance(proof, (str, unicode)):
        proof_url = proof

    elif isinstance(proof, dict):
        if "url" in proof:
            proof_url = proof["url"]
        elif "id" in proof:
            if key == "twitter":
                proof_url = "https://twitter.com/" + username + "/status/" + proof["id"]
            elif key == "github":
                proof_url = "https://gist.github.com/" + username + "/" + proof["id"]
            elif key == "facebook":
                proof_url = "https://facebook.com/" + username + "/posts/" + proof["id"]

    return proof_url


def site_data_to_identifier(site_data):
    identifier = None
    if "username" in site_data:
        identifier = site_data["username"]
    if "identifier" in site_data:
        identifier = site_data["identifier"]
    if "userid" in site_data:
        identifier = site_data["userid"]
    return identifier


def profile_to_proofs(profile, username, refresh=False):

    global MEMCACHED_ENABLED

    if refresh:
        MEMCACHED_ENABLED = False

    proofs = []

    try:
        test = profile.items()
    except:
        return proofs

    for proof_site, site_data in profile.items():
        if proof_site in SITES and isinstance(site_data, dict):
            identifier = site_data_to_identifier(site_data)
            if identifier:
                proof_url = site_data_to_proof_url(site_data, identifier)
                if proof_url:
                    proof = {
                        "service": proof_site,
                        "proof_url": proof_url,
                        "identifier": identifier,
                        "valid": False
                    }

                    proof_url_hash = hashlib.md5(proof_url).hexdigest()

                    if MEMCACHED_ENABLED:
                        cache_reply = mc.get("proof_" + proof_url_hash)
                    else:
                        cache_reply = None
                        #log.debug("cache off")

                    if cache_reply is None:

                        if is_valid_proof(proof_site, identifier, username, proof_url):
                            proof["valid"] = True

                            if MEMCACHED_ENABLED:
                                mc.set("proof_" + proof_url_hash, username, int(time() + MEMCACHED_TIMEOUT))
                                #log.debug("cache miss")
                    else:
                        #log.debug("cache hit")
                        if cache_reply == username:
                            proof["valid"] = True

                    proofs.append(proof)
    return proofs
