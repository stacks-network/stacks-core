#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Search
    ~~~~~

    copyright: (c) 2014 by Halfmoon Labs, Inc.
    copyright: (c) 2015 by Blockstack.org

This file is part of Search.

    Search is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Search is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Search. If not, see <http://www.gnu.org/licenses/>.
"""

import sys
import json
import requests

from proofchecker import profile_to_proofs
from proofchecker import contains_valid_proof_statement
from proofchecker.domain import get_proof_from_txt_record

from pybitcoin import is_b58check_address

from .db import search_db
from .db import namespace
from .db import twitter_payment, facebook_payment
from .db import github_payment, domain_payment
from .db import proofs_cache


def flush_collection():

    search_db.drop_collection('twitter_payment')
    search_db.drop_collection('facebook_payment')
    search_db.drop_collection('github_payment')
    search_db.drop_collection('domain_payment')


def optimize_db():

    twitter_payment.ensure_index('twitter_handle')
    facebook_payment.ensure_index('facebook_username')
    github_payment.ensure_index('github_username')
    domain_payment.ensure_index('domain_url')
    proofs_cache.ensure_index('username')


def get_btc_address(profile):

    addressValid = False

    if 'bitcoin' in profile:

        try:
            btc_address = profile['bitcoin']
            btc_address = btc_address['address']
        except:
            pass

    try:
        addressValid = is_b58check_address(str(btc_address))
    except Exception as e:
        pass

    if addressValid:
        return btc_address
    else:
        return None


def get_proofs(username, profile):

    check_proofs = proofs_cache.find_one({"username": username})

    if check_proofs is None:
        proofs = profile_to_proofs(profile, username)

        new_entry = {}
        new_entry['username'] = username
        new_entry['proofs'] = proofs
        proofs_cache.save(new_entry)
    else:
        print "hitting cache!"
        proofs = check_proofs['proofs']

    return proofs


def create_twitter_payment_index():

    counter = 0

    for entry in namespace.find(no_cursor_timeout=True):

        profile = json.loads(entry['profile'])

        btc_address = get_btc_address(profile)

        # if no valid btc address, ignore
        if btc_address is None:
            continue

        if 'twitter' in profile:

            try:
                twitter_handle = profile['twitter']
            except:
                continue

            if 'proof' not in twitter_handle:
                continue

            proofs = get_proofs(entry['username'], profile)

            for proof in proofs:
                if 'service' in proof and proof['service'] == 'twitter':
                    if proof['valid']:
                        #print proof
                        new_entry = {}
                        new_entry['username'] = entry['username']
                        new_entry['twitter_handle'] = proof['identifier'].lower()
                        new_entry['profile'] = profile

                        check_entry = twitter_payment.find_one({"username": entry['username']})

                        if check_entry is not None:
                            print "already in index"
                        else:
                            print new_entry
                            twitter_payment.save(new_entry)

                            counter += 1
                            print counter


def create_facebook_payment_index():

    counter = 0

    for entry in namespace.find(timeout=False):

        profile = json.loads(entry['profile'])

        btc_address = get_btc_address(profile)

        # if no valid btc address, ignore
        if btc_address is None:
            continue

        if 'facebook' in profile:

            try:
                facebook_username = profile['facebook']
            except:
                continue

            if 'proof' not in facebook_username:
                continue

            proofs = get_proofs(entry['username'], profile)

            for proof in proofs:
                if 'service' in proof and proof['service'] == 'facebook':
                    if proof['valid']:
                        #print proof
                        new_entry = {}
                        new_entry['username'] = entry['username']
                        new_entry['facebook_username'] = proof['identifier'].lower()
                        new_entry['profile'] = profile

                        check_entry = facebook_payment.find_one({"username": entry['username']})

                        if check_entry is not None:
                            print "already in index"
                        else:
                            print new_entry
                            facebook_payment.save(new_entry)

                            counter += 1
                            print counter


def create_github_payment_index():

    counter = 0

    for entry in namespace.find(no_cursor_timeout=True):

        profile = json.loads(entry['profile'])

        btc_address = get_btc_address(profile)

        # if no valid btc address, ignore
        if btc_address is None:
            continue

        if 'github' in profile:

            try:
                github_username = profile['github']
            except:
                continue

            if 'proof' not in github_username:
                continue

            proofs = profile_to_proofs(profile, entry['username'])

            for proof in proofs:
                if 'service' in proof and proof['service'] == 'github':
                    if proof['valid']:
                        #print proof
                        new_entry = {}
                        new_entry['username'] = entry['username']
                        new_entry['github_username'] = proof['identifier'].lower()
                        new_entry['profile'] = profile

                        check_entry = github_payment.find_one({"username": entry['username']})

                        if check_entry is not None:
                            print "already in index"
                        else:
                            print new_entry
                            github_payment.save(new_entry)

                            counter += 1
                            print counter


def create_domain_payment_index():

    TEST_DOMAIN_VERIFICATIONS = ['muneeb', 'blockstack', 'ryan']

    counter = 0

    for entry in namespace.find(no_cursor_timeout=True):

        if entry['username'] not in TEST_DOMAIN_VERIFICATIONS:
            continue

        profile = json.loads(entry['profile'])

        btc_address = get_btc_address(profile)

        # if no valid btc address, ignore
        if btc_address is None:
            continue

        if 'website' in profile:

            try:
                website_url = profile['website']
            except:
                continue

            print website_url

            domain = website_url.lstrip('https')
            domain = domain.lstrip('://')
            domain = domain.lstrip('www')
            domain = domain.lstrip('.')

            print domain

            proof_txt = get_proof_from_txt_record(domain)

            validProof = contains_valid_proof_statement(proof_txt, entry['username'])

            if validProof:

                new_entry = {}
                new_entry['username'] = entry['username']
                new_entry['domain_url'] = domain
                new_entry['profile'] = profile

                check_entry = domain_payment.find_one({"username": entry['username']})

                if check_entry is not None:
                    print "already in index"
                else:
                    print new_entry
                    domain_payment.save(new_entry)

                    counter += 1
                    print counter


def search_payment(query):

    data = []

    query = query.rsplit(':')

    try:
        query_type = query[0]
        query_keyword = query[1].lower()
    except:
        return data

    if query_type == 'twitter':

        check_entry = twitter_payment.find({"twitter_handle": query_keyword})

        for entry in check_entry:
            new_result = {}
            new_result[entry['username']] = entry['profile']
            data.append(new_result)

        return data

    elif query_type == 'facebook':

        check_entry = facebook_payment.find({"facebook_username": query_keyword})

        for entry in check_entry:
            new_result = {}
            new_result[entry['username']] = entry['profile']
            data.append(new_result)

        return data

    elif query_type == 'github':

        check_entry = github_payment.find({"github_username": query_keyword})

        for entry in check_entry:
            new_result = {}
            new_result[entry['username']] = entry['profile']
            data.append(new_result)

        return data

    elif query_type == 'domain':

        check_entry = domain_payment.find({"domain_url": query_keyword})

        for entry in check_entry:
            new_result = {}
            new_result[entry['username']] = entry['profile']
            data.append(new_result)

        return data


if __name__ == "__main__":

    if(len(sys.argv) < 2):
        print "Usage error"
        exit(0)

    option = sys.argv[1]

    if(option == '--flush'):
        flush_collection()

    elif(option == '--optimize'):
        optimize_db()

    elif(option == '--create_twitter'):
        create_twitter_payment_index()

    elif(option == '--create_facebook'):
        create_facebook_payment_index()

    elif(option == '--create_github'):
        create_github_payment_index()

    elif(option == '--create_domain'):
        create_domain_payment_index()

    else:
        print "Usage error"
