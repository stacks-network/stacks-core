import datetime
from pprint import pprint
from lib import get_nameops_in_block, build_nameset, NameDb
from lib import config

from opennamed import bitcoind


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
