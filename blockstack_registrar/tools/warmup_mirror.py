# -*- coding: utf-8 -*-
"""
    Registrar
    ~~~~~
    :copyright: (c) 2014-2016 by Halfmoon Labs, Inc.
    :copyright: (c) 2016 blockstack.org
    :license: MIT, see LICENSE for more details.
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
