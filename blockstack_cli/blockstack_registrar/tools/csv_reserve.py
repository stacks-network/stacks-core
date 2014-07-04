#!/usr/bin/env python
# -*- coding: utf-8 -*-
#-----------------------
# Copyright 2014 Halfmoon Labs, Inc.
# All Rights Reserved
#-----------------------

import csv
from blockdata.register import register_name, update_name
from coinrpc.namecoin.namecoind_wrapper import check_registration, namecoind_name_show

from pymongo import Connection
con = Connection()
db = con['namecoin']
queue = db.queue

from ast import literal_eval

#-----------------------------------
def format_key_value(key, name=None):

    #need u/ for OneName usernames
    key = 'u/' + key.lower()

    value = {}

    value['status'] = "reserved"

    if name is not None and name != '' and name != ' ': 

        value["message"] = "This OneName username is reserved for " + name.lstrip(' ') 
        value["message"] += ". If this is you, please email reservations@onename.io to claim it for free."

    else:

        value["message"] = "This OneName username was parked to evade name squatting, but can be made available upon reasonable request"
        value["message"] += " at no charge. If you are interested in this name, please email reservations@onename.io with your twitter"
        value["message"] += " handle and why you would like this particular name."

    return key, value 
        

#-----------------------------------
def main_loop(key, name=None):

    key, value = format_key_value(key,name)

    reply = queue.find_one({'key':key})

    if check_registration(key):
        #print "already registered: " + key
        profile = namecoind_name_show(key)['value']
        if 'status' in profile and profile['status'] == 'reserved':
            print "already reserved: " + key
            #update_name(key,value)
        else:
            print "registered but not reserved: " + key
    elif reply is not None:
        #already in local DB/queue
        pass
    else:
        #not in DB and not registered
        print "not registered: " + key
        register_name(key,value)
        
#-----------------------------------
if __name__ == '__main__':

    '''
    with open('tools/data.csv') as csvfile:
        spamreader = csv.reader(csvfile)
        for row in spamreader:
            try:
                main_loop(row[0], row[1])
            except:
                main_loop(row[0])
    '''


    with open('tools/angel_list.txt') as f:
        users = [list(literal_eval(line)) for line in f]

        for user in users:
            for i in user:
                local = queue.find_one({'key':"u/" + i})

                if local is not None:
                    print "already in DB"
                else:
                    main_loop(i) 
