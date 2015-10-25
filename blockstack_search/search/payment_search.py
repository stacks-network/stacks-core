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

import json
import requests

from proofchecker import profile_to_proofs
from pybitcoin import is_b58check_address

from .db import search_db
from .db import namespace, twitter_payment


def flush_collection():

    search_db.drop_collection('twitter_payment')


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


def create_twitter_payment_index():

    counter = 0

    for entry in namespace.find():

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

            proofs = profile_to_proofs(profile, entry['username'])

            for proof in proofs:
                if 'service' in proof and proof['service'] == 'twitter':
                    if proof['valid']:
                        #print proof
                        new_entry = {}
                        new_entry['username'] = entry['username']
                        new_entry['twitter_handle'] = proof['identifier'].lower()
                        new_entry['profile'] = profile

                        check_entry = twitter_payment.find_one({"twitter_handle": new_entry['twitter_handle']})

                        if check_entry is not None:
                            print "already in index"
                        else:
                            print new_entry
                            twitter_payment.save(new_entry)

                            counter += 1
                            print counter


def search_payment(query):

    data = {}

    query = query.rsplit(':')

    try:
        query_type = query[0]
        query_keyword = query[1].lower()
    except:
        return data

    if query_type == 'twitter':

        check_entry = twitter_payment.find_one({"twitter_handle": query_keyword})

        if check_entry is not None:
            del check_entry['twitter_handle']
            del check_entry['_id']
            return check_entry

    return data


if __name__ == "__main__":

    #flush_collection()

    create_twitter_payment_index()
