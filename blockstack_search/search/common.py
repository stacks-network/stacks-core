#!/usr/bin/env python
#-----------------------
# Copyright 2013 Halfmoon Labs, Inc.
# All Rights Reserved
#-----------------------

import json 
from json import JSONEncoder
from bson.objectid import ObjectId
import logging
from config import DEBUG

#-------------------------
def get_logger(log_name=None,log_type='stream'):

    if(DEBUG):
        log = logging.getLogger(log_name)
        log.setLevel(logging.DEBUG)

        formatter_stream = logging.Formatter('[%(levelname)s] %(message)s')
        handler_stream = logging.StreamHandler()
        handler_stream.setFormatter(formatter_stream)

        log.addHandler(handler_stream)
       
    else:
        log = None

    return log

#-------------------------
#common logger
log = get_logger()

class MongoEncoder(JSONEncoder):
    def default(self, obj, **kwargs):
        if isinstance(obj, ObjectId):
            return str(obj)
        else:            
            return JSONEncoder.default(obj, **kwargs)
#-------------------------
def pretty_dump(input):

    return json.dumps(input, cls=MongoEncoder, sort_keys=False, indent=4, separators=(',', ': '))

#-------------------------
def pretty_print(input):
    print pretty_dump(input)

#---------------------------------
def error_reply(msg):
	reply = {}
	reply['status'] = -1
	reply['message'] = "ERROR: " + msg
	return pretty_dump(reply)
