#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    OpenDig
    ~~~~~

    :copyright: (c) 2014 by OpenNameSystem.org
    :license: MIT, see LICENSE for more details.
"""

from opendig import ONS_SERVERS, NAMECOIND_PORT, NAMECOIND_USER, NAMECOIND_PASSWD, USE_HTTPS

import json
import hashlib
from coinrpc.namecoind_server import NamecoindServer 

#currently using namecoind for storing data (but ONS can use any blockchain)
#---------------------------------------

#---------------------------------
def error_reply(msg, code = -1):
    reply = {}
    reply['status'] = code
    reply['message'] = "ERROR: " + msg
    return reply 

#-----------------------------------
def ons_resolver(key): 

    counter = 0 

    server = ONS_SERVERS[counter]
    try:
        namecoind = NamecoindServer(server, NAMECOIND_PORT, NAMECOIND_USER, NAMECOIND_PASSWD)
        return_data = namecoind.get_full_profile('u/' + key)
    except:
        return error_reply("Couldn't connect to namecoind")

    data = json.dumps(return_data,sort_keys=True)
    data_hash = hashlib.md5(data).hexdigest()
 
    while counter < len(ONS_SERVERS) - 1:
        counter += 1
        server = ONS_SERVERS[counter]
        try:
            namecoind = NamecoindServer(server, NAMECOIND_PORT, NAMECOIND_USER, NAMECOIND_PASSWD)
            check_data = namecoind.get_full_profile('u/' + key)
        except:
            return error_reply("Couldn't connect to namecoind")
            
        check_data = json.dumps(check_data,sort_keys=True)

        if data_hash != hashlib.md5(check_data).hexdigest():
            return error_reply("Data from different ONS servers doens't match")

    return return_data
#-----------------------------------

if __name__ == "__main__":
    key = "ibrahim"
    print ons_resolver(key)
