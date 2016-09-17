# -*- coding: utf-8 -*-
"""
    Registrar
    ~~~~~
    :copyright: (c) 2014-2016 by Halfmoon Labs, Inc.
    :copyright: (c) 2016 blockstack.org
    :license: MIT, see LICENSE for more details.
"""

import os
import json

from pymongo import MongoClient

from tinydb import TinyDB, Query

from .config import SERVER_MODE
from .config import LOCAL_DIR, LOCAL_STATE_DB, PEDNING_REQUESTS_DB
from .config import QUEUE_DB_URI

c = MongoClient()
state_diff = c['namespace'].state_diff

queue_db = MongoClient(QUEUE_DB_URI)['registrar']


class TinyDBConvertor(object):

    def __init__(self, collection_name, db_name, db_path=LOCAL_DIR):

        self.local_db_fullpath = os.path.join(db_path, db_name)
        self.local_db = TinyDB(self.local_db_fullpath)
        self.collection_name = collection_name

    def reload(self):
        self.local_db.close()
        self.local_db = TinyDB(self.local_db_fullpath)

    def find(self):
        self.reload()

        query = Query()
        resp = self.local_db.search(query.type == self.collection_name)
        self.local_db.close()

        return resp

    def find_one(self, entry):
        self.reload()

        query = Query()
        resp = self.local_db.search((query.type == self.collection_name) &
                                    (query.fqu == entry['fqu']))

        self.local_db.close()

        if len(resp) == 0:
            return None
        else:
            return resp[0]

    def save(self, new_entry):
        self.reload()

        new_entry['type'] = self.collection_name
        resp = self.local_db.insert(new_entry)
        self.local_db.close()

        return resp

    def remove(self, entry):
        self.reload()

        query = Query()

        resp = self.local_db.remove((query.type == self.collection_name) &
                                    (query.fqu == entry['fqu']))

        self.local_db.close()

        return resp


def get_preorder_queue():
    if SERVER_MODE:
        return queue_db.preorder_queue
    else:
        return TinyDBConvertor('preorder', db_name=LOCAL_STATE_DB)


def get_register_queue():
    if SERVER_MODE:
        return queue_db.register_queue
    else:
        return TinyDBConvertor('register', db_name=LOCAL_STATE_DB)


def get_update_queue():
    if SERVER_MODE:
        return queue_db.update_queue
    else:
        return TinyDBConvertor('update', db_name=LOCAL_STATE_DB)


def get_transfer_queue():
    if SERVER_MODE:
        return queue_db.transfer_queue
    else:
        return TinyDBConvertor('transfer', db_name=LOCAL_STATE_DB)

if SERVER_MODE:

    preorder_queue = queue_db.preorder_queue
    register_queue = queue_db.register_queue
    update_queue = queue_db.update_queue
    transfer_queue = queue_db.transfer_queue

    pending_queue = queue_db.pending_queue

    # to-do: rename this from 'migration'
    registrar_users = c['migration'].migration_users
    registrar_addresses = c['migration'].registrar_addresses

else:

    if not os.path.exists(LOCAL_DIR):
        os.makedirs(LOCAL_DIR)

    preorder_queue = TinyDBConvertor('preorder', db_name=LOCAL_STATE_DB)
    register_queue = TinyDBConvertor('register', db_name=LOCAL_STATE_DB)
    update_queue = TinyDBConvertor('update', db_name=LOCAL_STATE_DB)
    transfer_queue = TinyDBConvertor('transfer', db_name=LOCAL_STATE_DB)

    # use different db for pending_queue because read/write is not thread safe
    pending_queue = TinyDBConvertor('pending', db_name=PEDNING_REQUESTS_DB)
