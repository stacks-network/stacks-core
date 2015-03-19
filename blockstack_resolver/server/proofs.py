# -*- coding: utf-8 -*-

import requests
import json
import hashlib
from .htmlparsing import *

from .sites import SITES
from config import MEMCACHED_PORT, MEMCACHED_TIMEOUT, DEFAULT_HOST, MEMCACHED_ENABLED

import pylibmc
from time import time
mc = pylibmc.Client([DEFAULT_HOST + ':' + str(MEMCACHED_PORT)], binary=True)

from commontools import log


# -----------------------------------------
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
        "verifying my digital passport. My username is +%s" % username,
    ]

    for verification_style in verification_styles:
        if verification_style in search_text:
            return True

    if "verifymyonename" in search_text and ("+" + username) in search_text:
        return True

    return False


# -----------------------------------------
def is_valid_proof(site, site_username, openname, proof_url):
    site_username = site_username.lower()
    proof_url = proof_url.lower()
    openname = openname.lower()

    if not site in SITES and 'base_url' in SITES[site]:
        return False

    check_url = SITES[site]['base_url'] + site_username

    if not proof_url.startswith(check_url):
        return False

    try:
        r = requests.get(proof_url)
    except:
        return False

    if site == "github":
        search_text = get_github_text(r.text)
    elif site in SITES:
        search_text = get_search_text(site, r.text)
    else:
        search_text = ''

    return contains_valid_proof_statement(search_text, openname)


# -----------------------------------------
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


# -----------------------------------------
def site_data_to_identifier(site_data):
    identifier = None
    if "username" in site_data:
        identifier = site_data["username"]
    if "identifier" in site_data:
        identifier = site_data["identifier"]
    if "userid" in site_data:
        identifier = site_data["userid"]
    return identifier


# -----------------------------------------
def profile_to_proofs(profile, openname, refresh=False):

    global MEMCACHED_ENABLED

    if refresh:
        MEMCACHED_ENABLED = False

    proofs = []

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

                        if is_valid_proof(proof_site, identifier, openname, proof_url):
                            proof["valid"] = True

                            if MEMCACHED_ENABLED:
                                mc.set("proof_" + proof_url_hash,openname,int(time() + MEMCACHED_TIMEOUT))
                                #log.debug("cache miss")
                    else:
                        #log.debug("cache hit")
                        if cache_reply == openname:
                            proof["valid"] = True

                    proofs.append(proof)
    return proofs