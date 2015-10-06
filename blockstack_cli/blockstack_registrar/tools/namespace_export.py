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
