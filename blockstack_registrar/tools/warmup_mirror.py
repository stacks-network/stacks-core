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

import json

from registrar.config import IGNORE_USERNAMES

from registrar.db import users
from registrar.db import state_diff

from registrar.network import dht_client

from registrar.utils import get_hash
from registrar.utils import pretty_print


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
            resp = dht_client.set(key, value)
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

    username = 'fboya'
    #warmup_mirror()

    refresh_entry(username)
