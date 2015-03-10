#!/usr/bin/env python
# -*- coding: utf-8 -*-
#-----------------------
# Copyright 2014 Halfmoon Labs, Inc.
# All Rights Reserved
#-----------------------

import json

from blockdata.register import process_user

from time import sleep

from coinrpc import namecoind

from commontools import get_json

#-----------------------------------
from pymongo import MongoClient
from config import MONGODB_URI, OLD_DB
 
remote_db = MongoClient(MONGODB_URI).get_default_database()
users = remote_db.user

old_db = MongoClient(OLD_DB).get_default_database()
old_users = old_db.user

MAX_PENDING_TX = 50

#-----------------------------------
def pending_transactions(): 

    reply = namecoind.listtransactions("",10000)

    counter = 0 

    for i in reply:
        if i['confirmations'] == 0:
            counter += 1 


        if counter == MAX_PENDING_TX:
            return True 

    return False

#-----------------------------------
if __name__ == '__main__':

    from blockdata.renew_names import get_expiring_names, get_expired_names
    expired_users = get_expired_names('u/')

    #ignore_users = ['frm','rfd','meng','bjorn']
    ignore_users = [] 

    count_twitter = 0 
    count_github = 0
    count_website = 0 
    count_bio = 0 

    counter = 0
    
    tx_sent = MAX_PENDING_TX

    for i in expired_users:

        if tx_sent >= MAX_PENDING_TX:
            tx_sent = 0
            print "check for pending tx"
            while pending_transactions():
                print "pending transactions, sleeping ..."
                sleep(60 * 5)
 

        username = i['name'].lstrip('u/')

        if username in ignore_users:
            continue 

        new_user = users.find_one({'username':username}) 
        if  new_user is not None:
            print username + " in new DB"
         
            profile = get_json(new_user['profile'])
            try:
                process_user(username,profile)
            except Exception as e:
                print e
            tx_sent += 1
            print '-' * 5
            continue 
        
        old_user = old_users.find_one({'username':username})
        if  old_user is not None:
            print username + " in old DB"
            profile = get_json(old_user['profile'])
            
            try:
                process_user(username,profile)
                tx_sent += 1
            except Exception as e:
                print e

            continue

        print username + " not our user"
        print '-' * 5   

