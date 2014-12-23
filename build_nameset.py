import traceback
import json
import datetime
from pprint import pprint
from coinkit import BitcoindClient
from opennamelib import *
from opennamelib import config

from coinrpc import bitcoind


def main():
    start = datetime.datetime.now()

    '''
    bitcoind_client = BitcoindClient(
        config.BITCOIND_USER, config.BITCOIND_PASSWD,
        server=config.BITCOIND_SERVER, port=config.BITCOIND_PORT)
    bitcoind = bitcoind_client.bitcoind
    '''

    first_block, last_block = 335563, 335566
    print "block count: %i" % bitcoind.getblockcount()

    nameop_sequence = []
    for block_number in range(first_block, last_block + 1):
        print block_number
        block_nameops = get_nameops_in_block(bitcoind, block_number)
        nameop_sequence.append((block_number, block_nameops))

    """nameop_sequence = [
        (335563, []),
        (335564, [
            {'consensus_hash': '2a9148d8b13939723d2aca16c75c6d68',
             'fee': 10000, 'opcode': 'NAME_PREORDER',
              'name_hash': 'd6bf93f3644075e2e26c0410d5e95daafb8ed640',
              'sender': '76a9144b78801a273f444a394881e57659342649c1d3cf88ac'},
        ]),
        (335565, []),
        (33556, [
            {'salt': '83675d4f5c112b74e86af99b7ec83cec', 'fee': 10000,
             'opcode': 'NAME_REGISTRATION', 'name': 'ryanshea',
             'sender': '76a9144b78801a273f444a394881e57659342649c1d3cf88ac'},
        ])
    ]"""
    print nameop_sequence

    print "%s seconds" % (datetime.datetime.now() - start).seconds

    db = NameDb()
    merkle_snapshot = build_nameset(db, nameop_sequence)
    db.save_names('data/namespace.txt')

    print "merkle snapshot: %s\n" % merkle_snapshot
    pprint(db.name_records)

if __name__ == '__main__':
    main()
