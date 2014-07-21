#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Open Name System
    ~~~~~

    :copyright: (c) 2014 by opennamesystem.org
    :license: MIT, see LICENSE for more details.
"""

from config import NMC_SERVERS, NAMECOIND_PORT, NAMECOIND_USER, NAMECOIND_PASSWD, NAMECOIND_USE_HTTPS

import json
import rpc

namecoind = rpc.connect_to_remote(NAMECOIND_USER, NAMECOIND_PASSWD, 
                                        host=NMC_SERVERS[0], port=NAMECOIND_PORT, 
                                        use_https=NAMECOIND_USE_HTTPS)

#---------------------------------
def error_reply(msg, code = -1):
    reply = {}
    reply['status'] = code
    reply['message'] = "ERROR: " + msg
    return reply 

#-----------------------------------
def namecoind_name_show(input_key):

    reply = {}

    value = namecoind.name_show(input_key)
    
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
def get_full_profile(key):

    check_profile = namecoind_name_show(key)
    
    try:
        check_profile = check_profile['value']
    except:
        return check_profile
                
    if 'next' in check_profile:
        try:
            child_data = get_full_profile(check_profile['next'])
        except:
            return check_profile

        del check_profile['next']

        merged_data = {key: value for (key, value) in (check_profile.items() + child_data.items())}
        return merged_data

    else:
        return check_profile

#----------------------------------------
if __name__ == '__main__':

    #this is just for testing
    username = "u/muneeb"
    print namecoind_name_show(username)