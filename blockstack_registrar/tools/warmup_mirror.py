#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Registrar
    ~~~~~

    copyright: (c) 2014 by Halfmoon Labs, Inc.
    copyright: (c) 2015 by Blockstack.org

This file is part of Registrar.

    Registrar is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Registrar is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Registrar. If not, see <http://www.gnu.org/licenses/>.
"""

import os
import json
from basicrpc import Proxy
from pymongo import MongoClient

try:
    INDEXDB_URI = os.environ['INDEXDB_URI']
except:
    INDEXDB_URI = None

from registrar.config import DHT_MIRROR, DHT_MIRROR_PORT
from registrar.config import IGNORE_USERNAMES

c = MongoClient(INDEXDB_URI)
state_diff = c['namespace'].state_diff

dht_mirror = Proxy(DHT_MIRROR, DHT_MIRROR_PORT)


def pretty_print(data):

    try:
        data = data[0]
    except:
        pass

    if type(data) is not dict:
        try:
            data = json.loads(data)
        except Exception as e:
            print "got here"
            print e

    print json.dumps(data, sort_keys=True, indent=4, separators=(',', ': '))


def warmup_mirror():

    counter = 0

    for entry in state_diff.find():

        if entry['username'] in IGNORE_USERNAMES:
            continue

        print entry['username']
        key = entry['profile_hash']
        value = json.dumps(entry['profile'], sort_keys=True)

        print key
        print value

        try:
            resp = dht_mirror.set(key, value)
            pretty_print(resp)
            counter += 1
            print counter
            print '-' * 5
        except Exception as e:
            print e
            print "problem %s" % entry['username']
            print key
            print value

# ------------------------------
if __name__ == '__main__':

    warmup_mirror()
