import os, json, traceback

from opennamelib import *

def get_nulldata_txs_from_file(filename):
    try:
        with open(filename, 'r') as f:
            data = json.loads(f.read())
    except Exception as e:
        traceback.print_exc()
        return None
    return data

def main():
    db = NameDb()
    nulldata_txs = get_nulldata_txs_from_file('data/nulldata_txs.txt')
    merkle_snapshot = build_namespace(db, nulldata_txs, 333747, 333759)
    print "merkle snapshot: %s" % merkle_snapshot
    db.save_names('data/namespace.txt')

if __name__ == '__main__':
    main()
