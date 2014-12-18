import json, traceback

from collections import defaultdict

class NameDb():
    def __init__(self, names_filename=None, content_filename=None):
        self.name_records = {}
        self.preorders = {}
        self.content = {}

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
                    if 'names_records' in db_dict:
                        self.name_records = db_dict['names']
                    if 'preorders' in db_dict:
                        self.preorders = db_dict['preorders']
                    if 'consensus_hashes' in db_dict:
                        self.consensus_hashes = db_dict['consensus_hashes']
            except Exception as e:
                pass

        if content_filename:
            try:
                with open(content_filename, 'r') as f:
                    content_dict = json.loads(f.read())
                    self.content = content_dict
            except Exception as e:
                pass

    def save_names(self, filename):
        try:
            with open(filename, 'w') as f:
                db_dict = {
                    'name_records': self.name_records,
                    'preorders': self.preorders,
                    'consensus_hashes': self.consensus_hashes
                }
                f.write(json.dumps(db_dict))
        except Exception as e:
            traceback.print_exc()
            return False
        return True

    def save_content(self, filename):
        try:
            with open(filename, 'w') as f:
                f.write(json.dumps(self.content))
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
