# -*- coding: utf-8 -*-
"""
    Registrar
    ~~~~~
    :copyright: (c) 2014-2016 by Halfmoon Labs, Inc.
    :copyright: (c) 2016 blockstack.org
    :license: MIT, see LICENSE for more details.
"""

import os
import json

from pymongo import MongoClient

try:
    INDEXDB_URI = os.environ['INDEXDB_URI']
except:
    INDEXDB_URI = None

STATE_FILE = 'diff_state.json'

c = MongoClient(INDEXDB_URI)
state_diff = c['namespace'].state_diff


def dump_diff():

    namespace = []

    for entry in state_diff.find():
        del entry['_id']
        namespace.append(entry)

    print namespace
    fout = open(STATE_FILE, 'w')

    fout.write(json.dumps(namespace))
    fout.close()


def get_diff():

    for user in state_diff.find():
        print user
        print '-' * 5

if __name__ == '__main__':

    #get_diff()
    dump_diff()
