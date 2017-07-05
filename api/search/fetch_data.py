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

import sys
import json

from api.config import SEARCH_BLOCKCHAIN_DATA_FILE as BLOCKCHAIN_DATA_FILE, \
    SEARCH_PROFILE_DATA_FILE as PROFILE_DATA_FILE

from .utils import validUsername
from .utils import get_json, config_log

from blockstack_client.proxy import get_all_names
from blockstack_client.profile import get_profile
from api.utils import profile_log
import logging

log = config_log(__name__)

def fetch_namespace():
    """
        Fetch all names in a namespace that should be indexed.
        Data is saved in data/ directory
    """

    resp = get_all_names()

    fout = open(BLOCKCHAIN_DATA_FILE, 'w')
    fout.write(json.dumps(resp))
    fout.close()

    return

def print_status_bar(filled, total):
    pct = float(filled) / total
    bar = max((int(pct * 60) - 1), 0)
    out = "\r[%s>%s] %.1f%%" % ( ("=" * bar), " " * (59 - bar), pct * 100)
    sys.stdout.write(out)
    sys.stdout.flush()

def fetch_profiles(max_to_fetch = None, just_test_set = False):
    """
        Fetch profile data using Blockstack Core and save the data.
        Data is saved in: data/profile_data.json
        Format of the data is <fqu, profile>
        * fqu: fully-qualified name
        * profile: json profile data
    """

    fin = open(BLOCKCHAIN_DATA_FILE, 'r')
    file = fin.read()
    fin.close()

    all_names = json.loads(file)

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

    fout = open(PROFILE_DATA_FILE, 'w')
    fout.write(json.dumps(all_profiles))
    fout.close()

    return


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

    else:
        print "Usage error"
