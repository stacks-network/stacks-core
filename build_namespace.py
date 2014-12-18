import os, json, traceback
from pprint import pprint

from coinkit import BitcoindClient
from opennamelib import NameDb, build_nameset
from opennamelib import config

def get_nulldata_txs_from_file(filename):
    try:
        with open(filename, 'r') as f:
            data = json.loads(f.read())
    except Exception as e:
        traceback.print_exc()
        return None
    return data

def main():
    bitcoind_client = BitcoindClient(
        config.BITCOIND_USER, config.BITCOIND_PASSWD,
        server=config.BITCOIND_SERVER, port=config.BITCOIND_PORT)
    block_count = bitcoind_client.bitcoind.getblockcount()

    db = NameDb()
    nulldata_txs = get_nulldata_txs_from_file('data/nulldata_txs.txt')
    merkle_snapshot = build_nameset(db, nulldata_txs, config.FIRST_BLOCK,
        block_count)
    
    print "merkle snapshot: %s\n" % merkle_snapshot
    db.save_names('data/namespace.txt')
    pprint(db.name_records)

if __name__ == '__main__':
    main()
