import os, json, traceback
from pprint import pprint

from coinkit import *
from opennamelib import *

def get_nulldata_txs_from_file(filename):
    try:
        with open(filename, 'r') as f:
            data = json.loads(f.read())
    except Exception as e:
        traceback.print_exc()
        return None
    return data

def get_bitcoind_client_from_file(filename):
    try:
        with open(filename, 'r') as f:
            SECRETS = json.loads(f.read())
    except Exception as e:
        traceback.print_exc()
        return None

    bitcoind_client = BitcoindClient(SECRETS['rpc_username'], SECRETS['rpc_password'])
    return bitcoind_client

def main():
    testnet = True
    if testnet:
        first_block = FIRST_BLOCK_MAINNET_TESTSPACE
    else:
        first_block = FIRST_BLOCK_MAINNET
    bitcoind_client = get_bitcoind_client_from_file('data/secrets.json')
    block_count = bitcoind_client.bitcoind.getblockcount()
    last_block = block_count

    db = NameDb()
    nulldata_txs = get_nulldata_txs_from_file('data/nulldata_txs.txt')
    merkle_snapshot = build_nameset(db, nulldata_txs, first_block, last_block)
    print "merkle snapshot: %s" % merkle_snapshot
    db.save_names('data/namespace.txt')
    print "\n"
    pprint(db.name_records)
    print ""

if __name__ == '__main__':
    main()
