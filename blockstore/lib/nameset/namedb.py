import json
import traceback

from collections import defaultdict


class NameDb():
    def __init__(self, names_filename, snapshots_filename):
        self.name_records = {}
        self.preorders = {}

        self.pending_registrations = defaultdict(list)
        self.pending_updates = defaultdict(list)
        self.pending_transfers = defaultdict(list)
        self.pending_renewals = defaultdict(list)

        self.block_expirations = defaultdict(dict)

        self.consensus_hashes = defaultdict(dict)

        if names_filename:
            try:
                with open(names_filename, 'r') as f:
                    db_dict = json.loads(f.read())
                    if 'registrations' in db_dict:
                        self.name_records = db_dict['registrations']
                    if 'preorders' in db_dict:
                        self.preorders = db_dict['preorders']
            except Exception as e:
                pass

        if snapshots_filename:
            try:
                with open(snapshots_filename, 'r') as f:
                    db_dict = json.loads(f.read())
                    if 'snapshots' in db_dict:
                        self.consensus_hashes = db_dict['snapshots']
            except Exception as e:
                pass

    def save_names(self, filename):
        try:
            with open(filename, 'w') as f:
                db_dict = {
                    'registrations': self.name_records,
                    'preorders': self.preorders
                }
                f.write(json.dumps(db_dict))
        except Exception as e:
            traceback.print_exc()
            return False
        return True

    def save_snapshots(self, filename):
        try:
            with open(filename, 'w') as f:
                db_dict = {
                    'snapshots': self.consensus_hashes
                }
                f.write(json.dumps(db_dict))
        except Exception as e:
            traceback.print_exc()
            return False
        return True


def get_value_hash_for_name(name, db):
    if name in db.name_records and 'value_hash' in db.name_records[name]:
        value_hash = db.name_records[name]['value_hash']
        return value_hash
    return None


def lookup_name(name, db):
    value_hash = get_value_hash_for_name(name, db)

    if value_hash in db.content:
        return db.content[value_hash]
    return None
