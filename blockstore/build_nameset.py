"""
    Blockstore
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016 by Blockstack.org

    This file is part of Blockstore

    Blockstore is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Blockstore is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with Blockstore. If not, see <http://www.gnu.org/licenses/>.
"""

import datetime
from pprint import pprint
from lib import get_nameops_in_block, build_nameset, NameDb
from lib import config

from opennamed import bitcoind

# DEPRECATED 
def refresh_index(first_block, last_block):
    """
    """

    start = datetime.datetime.now()

    print "block count: %i" % bitcoind.getblockcount()

    nameop_sequence = []

    for block_number in range(first_block, last_block + 1):
        print block_number
        block_nameops = get_nameops_in_block(bitcoind, block_number)
        nameop_sequence.append((block_number, block_nameops))

    print nameop_sequence

    print "%s seconds" % (datetime.datetime.now() - start).seconds

    db = NameDb()
    merkle_snapshot = build_nameset(db, nameop_sequence)
    db.save_names('namespace.txt')

    print "merkle snapshot: %s\n" % merkle_snapshot
    pprint(db.name_records)

    fout = open('lastblock.txt', 'w')  # to overwrite
    fout.write(str(last_block))
    fout.close()

if __name__ == '__main__':
    refresh_index(335563, 335566)
