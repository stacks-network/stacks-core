#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    OpenDig
    ~~~~~

    :copyright: (c) 2014 by OpenNameSystem.org
    :license: MIT, see LICENSE for more details.
"""

from opendig import ONS_SERVER, NAMECOIND_PORT, NAMECOIND_USER, NAMECOIND_PASSWD, USE_HTTPS

import json
import namecoinrpc

#currently using namecoind for storing data (but ONS can use any blockchain)
namecoind = namecoinrpc.connect_to_remote(NAMECOIND_USER, NAMECOIND_PASSWD, 
                                        host=ONS_SERVER, port=NAMECOIND_PORT, 
                                        use_https=USE_HTTPS)

#---------------------------------
def error_reply(msg, code = -1):
    reply = {}
    reply['status'] = code
    reply['message'] = "ERROR: " + msg
    return reply 

#-----------------------------------
def get_value(input_key):

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

    check_profile = get_value(key)
    
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

#-----------------------------------
def ons_resolver(key):

    return get_full_profile('u/' + key)
