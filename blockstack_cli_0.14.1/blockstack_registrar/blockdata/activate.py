#!/usr/bin/env python
# -*- coding: utf-8 -*-
#-----------------------
# Copyright 2014 Halfmoon Labs, Inc.
# All Rights Reserved
#-----------------------

import os 
import json
import requests

from time import sleep
from coinrpc.namecoin.namecoind_wrapper import namecoind_blocks, namecoind_firstupdate

from pymongo import MongoClient
client = MongoClient()
db = client['namecoin']
queue = db.queue

LOAD_BALANCER = os.environ['LOAD_BALANCER']

blocks = namecoind_blocks()

#-----------------------------------
def do_name_firstupdate():

    #remove entries that are already active
    queue.remove({"activated":True})

    print "Checking for new activations"
    print '-' * 5 
    
    for entry in queue.find():

        #entry is registered; but not activated
        if entry.get('activated') is not None and entry.get('activated') == False:
            
            #print "Processing: " + entry['key'] 

            #compare the current block with 'wait_till_block'
            current_blocks = blocks['blocks']

            if current_blocks > entry['wait_till_block'] and entry['backend_server'] == int(LOAD_BALANCER):
                #lets activate the entry
                print "Activating: " + entry['key']
                
                #check if 'value' is a json or not
                try:
                    update_value = json.loads(entry['value'])
                    update_value = json.dumps(update_value)     #no error while parsing; dump into json again
                except:
                    update_value = entry['value']    #error: treat it as a string

                print "Activating entry: '%s' to point to '%s'" % (entry['key'], update_value)
            
                output = namecoind_firstupdate(entry['key'],entry['rand'],update_value,entry['longhex'])

                print "Transaction ID ", output

                if 'message' in output and output['message'] == "this name is already active":
                    entry['activated'] = True
                elif 'code' in output:
                    entry['activated'] = False
                    print "Not activated. Try again."
                else:
                    entry['activated'] = True

                entry['tx_id'] = output
                queue.save(entry)

                print '----'

            else:
                print "wait: " + str(entry['wait_till_block'] - current_blocks) + " blocks for: " + entry['key'] 

#-----------------------------------
if __name__ == '__main__':

    do_name_firstupdate()