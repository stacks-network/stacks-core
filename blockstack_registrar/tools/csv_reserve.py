#!/usr/bin/env python
# -*- coding: utf-8 -*-
#-----------------------
# Copyright 2014 Halfmoon Labs, Inc.
# All Rights Reserved
#-----------------------

import csv
from blockdata.register import register_name, update_name
from coinrpc import namecoind
 
from pymongo import Connection
con = Connection()
db = con['namecoin']
queue = db.queue

from ast import literal_eval
import json 

from config import MONGODB_URI

#-----------------------------------
from pymongo import MongoClient
remote_client = MongoClient(MONGODB_URI)
remote_db = remote_client.get_default_database()
codes = remote_db.codes 

#-----------------------------------
def format_key_value(key, name=None):

    #need u/ for OneName usernames
    key = 'u/' + key.lower()

    value = {}

    value['status'] = "reserved"

    if name is not None and name != '' and name != ' ': 

        value["message"] = "This username is reserved for " + name.lstrip(' ') 
        value["message"] += ". If this is you, please email reservations@onename.io to claim it for free."

    else:

        value["message"] = "This username was parked to evade name squatting, but can be made available upon reasonable request"
        value["message"] += " at no charge. If you are interested in this name, please email reservations@onename.io with your twitter"
        value["message"] += " handle and why you would like this particular name."

    return key, value 
        

#-----------------------------------
def main_loop(key, name=None):

    key, value = format_key_value(key,name)

    reply = queue.find_one({'key':key})

    if namecoind.check_registration(key):
        
        profile = namecoind.name_show(key)
        profile = profile['value']
        if 'status' in profile and profile['status'] == 'reserved':
            print "already reserved: " + key
            #update_name(key,value)
        else:
            print "registered but not reserved: " + key
            #update_name(key,value)
    elif reply is not None:
        #currently being processed
        pass
    else:
        #not in DB and not registered
        print "not registered: " + key
        register_name(key,value)

    print '-' * 5

#-----------------------------------
from base64 import b64encode
def get_url(username, access_code):
    return 'http://onename.io?a=' + b64encode(username + '-' + access_code)

#-----------------------------------
def get_random_hex(size=10):
    #every byte of data is converted into the corresponding 2-digit hex representation
    return binascii.b2a_hex(os.urandom(size))

#-----------------------------------
if __name__ == '__main__':

    with open('tools/data.csv') as csvfile:
        spamreader = csv.reader(csvfile)
        for row in spamreader:
            try:
                main_loop(row[0], row[1])
            except:
                main_loop(row[0])
   
    '''
    with open('tools/email_invites_dataset.txt') as f:
        users = json.loads(f.read())

        counter = 0
        skip = 881
        for i in users:
            counter += 1

            if counter < skip:
                continue  
            
            #print i['twitter_handle'], i['full_name'], i['email']
            print counter
            main_loop(i['twitter_handle'],i['full_name']) 
    '''