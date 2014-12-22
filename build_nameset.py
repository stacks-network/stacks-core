import traceback, json, datetime
from pprint import pprint
from coinkit import BitcoindClient
from opennamelib import *
from opennamelib import config

def main():
    start = datetime.datetime.now()

    bitcoind_client = BitcoindClient(
        config.BITCOIND_USER, config.BITCOIND_PASSWD,
        server=config.BITCOIND_SERVER, port=config.BITCOIND_PORT)
    bitcoind = bitcoind_client.bitcoind
    
    first_block, last_block = 334753, 334756
    block_count = bitcoind.getblockcount()
    nameop_sequence = get_nameops_in_block_range(bitcoind, first_block, last_block)
    print nameop_sequence
    
    print "%s seconds" % (datetime.datetime.now() - start).seconds
    
    db = NameDb()
    merkle_snapshot = build_nameset(db, nameop_sequence)
    db.save_names('data/namespace.txt')
    
    print "merkle snapshot: %s\n" % merkle_snapshot    
    pprint(db.name_records)

if __name__ == '__main__':
    main()
