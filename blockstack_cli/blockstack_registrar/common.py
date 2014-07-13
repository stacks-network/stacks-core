#!/usr/bin/env python
#-----------------------
# Copyright 2013 Halfmoon Labs, Inc.
# All Rights Reserved
#-----------------------

'''
    This file contains common code   
'''

from config import DEBUG
import logging
import json

#-----------------------------------
from pymongo import MongoClient
client = MongoClient() 
local_db = client['namecoin']
register_queue = local_db.queue

from config import MONGODB_URI
remote_client = MongoClient(MONGODB_URI)
remote_db = remote_client.get_default_database()
users = remote_db.user

#-------------------------
def get_logger():

    if(DEBUG):
        log = logging.getLogger()
        log.setLevel(logging.DEBUG)

        formatter = logging.Formatter('[%(levelname)s] %(message)s')
        handler_stream = logging.StreamHandler()
        handler_stream.setFormatter(formatter)
        log.addHandler(handler_stream)

    else:
        log = None

    return log

#-------------------------
#common logger
log = get_logger()

#-------------------------
def pretty_dump(input):

    return json.dumps(input, cls=MongoEncoder, sort_keys=False, indent=4, separators=(',', ': '))

#-------------------------
def pretty_print(input):
    log.debug(pretty_dump(input))

#-----------------------------------
def utf8len(s):

    if type(s) == unicode:
        return len(s)
    else:
        return len(s.encode('utf-8'))

#-----------------------------------------
def get_json(data):

    if isinstance(data,dict):
        pass 
    else:
        data = json.loads(data)
        
    return data

#-----------------------------------------
def get_string(data):

    if isinstance(data,dict):
        data = json.dumps(data) 
    else:
        pass
        
    return data