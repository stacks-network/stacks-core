import os, json, traceback

from pyopenname import *

def get_nulldata_txs_from_file(filename):
    try:
        with open(filename, 'r') as f:
            data = json.loads(f.read())
    except Exception as e:
        traceback.print_exc()
        return None
    return data

def has_preordered_name(db, name_hash, sender):
    if name_hash in db.preorders:
        if sender == db.preorders[name_hash]['sender']:
            return True
    return False

def is_name_owner(db, name, senders):
    if name in db.names and 'owner' in db.names[name]:
        if db.names[name]['owner'] in senders:
            return True
    return False

def record_nameop(db, nameop, mining_fee, senders):
    primary_sender = senders[0]['script_pubkey']
    opcode = eval(nameop['opcode'])

    if opcode == NAME_PREORDER:
        #if nameop['name'] in db.names:
        # record the preorder
        preorder = { 'sender': primary_sender, 'hash': nameop['hash'] }
        db.preorders[nameop['hash']] = preorder
    elif opcode == NAME_CLAIM:
        name = nameop['name']
        salt = nameop['salt']
        try:
            name_hash = hash_name(name, salt)
        except ValueError:
            name_hash = None

        if has_preordered_name(db, name_hash, primary_sender):
            if is_mining_fee_sufficient(name, mining_fee):
                # remove the preorder
                del db.preorders[name_hash]
                # register the name under the owner
                db.names[name] = { 'value_hash': None, 'owner': primary_sender }
    elif opcode == NAME_UPDATE:
        name = nameop['name']
        if is_name_owner(db, name, primary_sender):
            # update the name's value
            db.names[name]['value_hash'] = nameop['update']
    elif opcode == NAME_TRANSFER:
        name = nameop['name']
        new_owner = nameop['recipient']
        if is_name_owner(db, name, primary_sender):
            # transfer the name to a new owner
            db.names[name]['owner'] = new_owner
    else:
        return False

def main():
    db = NameDb()

    nulldata_txs = get_nulldata_txs_from_file('data/nulldata_txs.txt')
    block_numbers = sorted(nulldata_txs)
    for block_number in block_numbers:
        print "="*20 + str(block_number) + "="*20
        block = nulldata_txs[block_number]
        for tx in block:
            nulldata = tx['data']
            outputs = tx['outputs']
            mining_fee = tx['mining_fee']
            senders = tx['senders']
            nameop = parse_nameop(str(nulldata), outputs)
            print nameop
            if nameop:
                record_nameop(db, nameop, mining_fee, senders)

    db.save_names('data/namespace.txt')

if __name__ == '__main__':
    main()
