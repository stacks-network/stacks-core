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
import blockstack

blockstack_working_dir = blockstack.lib.config.default_working_dir()
blockstack_config = blockstack.lib.load_configuration(blockstack_working_dir)
blockstack_indexer_url = blockstack_config['blockstack-api']['indexer_url']

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

    total_names = blockstack.lib.client.get_all_names(hostport=blockstack_indexer_url)
       
    new_counter = len(total_names)

    if new_counter > old_counter:

        fout = open(NEW_NAMES_FILE, 'w')
        fout.write(json.dumps(total_names))

    else:
        print "(old_counter, new_counter): (%s, %s)" % (old_counter, new_counter)
