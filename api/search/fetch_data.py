#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Search
    ~~~~~

    copyright: (c) 2014-2017 by Blockstack Inc.
    copyright: (c) 2017 by Blockstack.org

This file is part of Blockstack.

    Blockstack is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Blockstack is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Blockstack. If not, see <http://www.gnu.org/licenses/>.
"""

import sys, os
import json

from api.config import (
    SEARCH_BLOCKCHAIN_DATA_FILE, SEARCH_PROFILE_DATA_FILE,
    SEARCH_LAST_INDEX_DATA_FILE)

from .utils import validUsername
from .utils import get_json, config_log

from blockstack_client  import proxy
from blockstack_client.profile import get_profile
from api.utils import profile_log
import logging

log = config_log(__name__)

def fetch_namespace():
    """
        Fetch all names in a namespace that should be indexed.
        Data is saved in data/ directory
    """

    info_resp = proxy.getinfo()
    last_block_processed = info_resp['last_block_processed']

    resp = proxy.get_all_names()

    with open(SEARCH_BLOCKCHAIN_DATA_FILE, 'w') as fout:
        fout.write(json.dumps(resp))
    with open(SEARCH_LAST_INDEX_DATA_FILE, 'w') as fout:
        fout.write(json.dumps(last_block_processed))

def print_status_bar(filled, total):
    pct = float(filled) / total
    bar = max((int(pct * 60) - 1), 0)
    out = "\r[%s>%s] %.1f%%" % ( ("=" * bar), " " * (59 - bar), pct * 100)
    sys.stdout.write(out)
    sys.stdout.flush()

def update_profiles():
    if not os.path.exists(SEARCH_LAST_INDEX_DATA_FILE):
        return {'error' : 'No last index, you need to rebuild the whole index.'}
    with open(SEARCH_LAST_INDEX_DATA_FILE, 'r') as fin:
        last_block_processed = json.load(fin)

    info_resp = proxy.getinfo()
    new_block_height = info_resp['last_block_processed']

    if last_block_processed - 1 > new_block_height:
        return {'status' : True, 'message' : 'No new blocks since last indexing'}

    # aaron: note, sometimes it may take a little while for
    #  new zonefiles to have propagated to the network, so
    #  we over-fetch a little bit
    zonefiles_resp = proxy.get_zonefiles_by_block(
        last_block_processed - 1, new_block_height)
    zonefiles_updated = zonefiles_resp['zonefile_info']
    names_updated = set(
        [ zf_info['name'] for zf_info in zonefiles_updated
          if 'name' in zf_info ])
    updated_profiles = {}
    actually_updated_names = set()
    print "Updating {} entries...".format(len(names_updated))
    for ix, name in enumerate(names_updated):
        print_status_bar(ix, len(names_updated))
        profile_entry = {}
        profile_entry['fqu'] = name

        try:
            profile_entry['profile'] = get_profile(name, use_legacy = True)['profile']
            updated_profiles[name] = (profile_entry)
            actually_updated_names.add(name)
        except KeyboardInterrupt as e:
            raise e
        except:
            import traceback as tb; tb.print_exc()

    names_updated = actually_updated_names
    with open(SEARCH_PROFILE_DATA_FILE, 'r') as fin:
        all_profiles = json.load(fin)
    to_remove = []
    for ix, profile in enumerate(all_profiles):
        if profile['fqu'] in names_updated:
            all_profiles[ix] = updated_profiles[profile['fqu']]

    with open(SEARCH_PROFILE_DATA_FILE, 'w') as fout:
        json.dump(all_profiles, fout)

    return {'status' : True, 'message' : 'Indexed {} profiles'.format(len(names_updated))}

def fetch_profiles(max_to_fetch = None, just_test_set = False):
    """
        Fetch profile data using Blockstack Core and save the data.
        Data is saved in: data/profile_data.json
        Format of the data is <fqu, profile>
        * fqu: fully-qualified name
        * profile: json profile data
    """

    with open(SEARCH_BLOCKCHAIN_DATA_FILE, 'r') as fin:
        all_names = json.load(file)

    all_profiles = []

    if max_to_fetch == None:
        max_to_fetch = len(all_names)

    if just_test_set:
        from api.tests.search_tests import SEARCH_TEST_USERS
        all_names = ["{}.id".format(u) for u in SEARCH_TEST_USERS]

    for ix, fqu in enumerate(all_names):
        if ix % 100 == 0:
            print_status_bar(ix, max_to_fetch)
        if ix >= max_to_fetch:
            break

        resp = {}
        resp['fqu'] = fqu

        try:
            resp['profile'] = get_profile(fqu, use_legacy = True)['profile']
            all_profiles.append(resp)
        except KeyboardInterrupt as e:
            raise e
        except:
            pass

    with open(SEARCH_PROFILE_DATA_FILE, 'w') as fout:
        json.dump(all_profiles, fout)

if __name__ == "__main__":

    if(len(sys.argv) < 2):
        print "Usage error"
        exit(0)

    option = sys.argv[1]

    if(option == '--fetch_namespace'):
        # Step 1
        fetch_namespace()

    elif(option == '--fetch_profiles'):
        # Step 2
        args = {}
        if len(sys.argv) > 2:
            if sys.argv[2] == '--test':
                args['just_test_set'] = True
            else:
                args['max_to_fetch'] = int(sys.argv[2])
        fetch_profiles(**args)
    elif(option == '--update_profiles'):
        print json.dumps(update_profiles(),
                         indent = 2)
    else:
        print "Usage error"
