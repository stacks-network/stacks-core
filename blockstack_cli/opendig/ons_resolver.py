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
import namecoinrpc
import hashlib

#currently using namecoind for storing data (but ONS can use any blockchain)
#---------------------------------------
class NamecoindServer(object):

    #-----------------------------------
    def __init__(self, server, port, user, passwd, use_https=True, passphrase=None):
        
        self.passphrase = passphrase
        self.server = server 

        self.namecoind = namecoinrpc.connect_to_remote(user, passwd, 
                                        host=server, port=port, 
                                        use_https=use_https)

    #-----------------------------------
    def get_value(self,input_key):

        reply = {}

        value = self.namecoind.name_show(input_key)
        
        try:
            profile = json.loads(value.get('value'))
        except:
            profile = value.get('value')
         
        if 'code' in value and value.get('code') == -4:
            return error_reply("Not found", 404)

        for key in value.keys():

            reply['namecoin_address'] = value['address']
            
            if(key == 'value'):
                try:
                    reply[key] = json.loads(value[key])
                except:
                    reply[key] = value[key]

        return reply

    #-----------------------------------
    def get_full_profile(self,key):

        check_profile = self.get_value(key)
        
        try:
            check_profile = check_profile['value']
        except:
            return check_profile
                    
        if 'next' in check_profile:
            try:
                child_data = self.get_full_profile(check_profile['next'])
            except:
                return check_profile

            del check_profile['next']

            merged_data = {key: value for (key, value) in (check_profile.items() + child_data.items())}

            return merged_data

        else:
            return check_profile

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
