# -*- coding: utf-8 -*-
"""
    Resolver
    ~~~~~
    :copyright: (c) 2014-2016 by Halfmoon Labs, Inc.
    :copyright: (c) 2016 blockstack.org
    :license: MIT, see LICENSE for more details.
"""

import json

from config import NAMES_FILE, NEW_NAMES_FILE
# hack to ensure local, until we update client
from blockstack_client import client as bs_client

if __name__ == "__main__":

    total_names = []

    offset = 60000
    count = 100

    try:
        fout = open(NAMES_FILE, 'r')
        data = fout.read()
        data = json.loads(data)

        old_counter = len(data)
    except:
        old_counter = 0

    print old_counter

    total_names = bs_client.get_all_names()
       
    new_counter = len(total_names)

    if new_counter > old_counter:

        fout = open(NEW_NAMES_FILE, 'w')
        fout.write(json.dumps(total_names))

    else:
        print "(old_counter, new_counter): (%s, %s)" % (old_counter, new_counter)
