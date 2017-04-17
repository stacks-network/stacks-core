# -*- coding: utf-8 -*-
"""
    Resolver
    ~~~~~
    :copyright: (c) 2014-2016 by Halfmoon Labs, Inc.
    :copyright: (c) 2016 blockstack.org
    :license: MIT, see LICENSE for more details.
"""

import json

from config import BLOCKSTACKD_IP
from config import BLOCKSTACKD_PORT
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

    #while 1:

    #    # start session using blockstack_client
    #    #bs_client.session(server_host=BLOCKSTACKD_IP, server_port=BLOCKSTACKD_PORT,
    #    #                  set_global=True)

    total_names = bs_client.get_all_names()
       
    #    if len(new_names) == 0:
    #        break

    #    # check for blockstack errors
    #    if len(new_names) == 1 and "error" in new_names:
    #        print "Blockstack error: " + new_names["error"]
    #        break

    #    total_names += new_names
    #    offset += count

    #    print offset

    new_counter = len(total_names)

    if new_counter > old_counter:

        fout = open(NEW_NAMES_FILE, 'w')
        fout.write(json.dumps(total_names))

    else:
        print "(old_counter, new_counter): (%s, %s)" % (old_counter, new_counter)
