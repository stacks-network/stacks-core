#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import requests

from time import sleep
from coinrpc.coinrpc import namecoind_blocks, namecoind_firstupdate

blocks = namecoind_blocks()

from pymongo import Connection
con = Connection()
db = con['namecoin']
queue = db.queue

import os 

LOAD_BALANCER = os.environ['LOAD_BALANCER']

#-----------------------------------
def check_name_firstupdate_errors(key):

    reply = queue.find_one({'key':key})

    #all activated entries should have final tx_id
    try:
        if(reply['activated'] is True):
        
            try: 
                temp = json.loads(reply['tx_id'])
                print temp['code']
                print key + " had error"
                reply['activated'] = False
                queue.save(reply)
            except:
                pass
    except Exception as e:
        print key + " not in DB"

#-----------------------------------
def do_name_firstupdate():

    print "Checking for new activations"
    #print '---'

    #first check for errors of last run and set activated = False
    #for entry in queue.find():
    #    check_name_firstupdate_errors(entry['key'])
    
    for entry in queue.find():

        #entry is registered; but not activated
        if entry.get('activated') is not None and entry.get('activated') == False:
            
            #print "Processing: " + entry['key'] 

            #compare the current block with 'wait_till_block'
            current_blocks = blocks['blocks']

            if current_blocks > entry['wait_till_block'] and entry['backend_server'] == int(LOAD_BALANCER):
                #lets activate the entry
                print "Activating: " + entry['key']
                print '----'

                #check if 'value' is a json or not
                try:
                    update_value = json.loads(entry['value'])
                    update_value = json.dumps(update_value)     #no error while parsing; dump into json again
                except:
                    update_value = entry['value']    #error: treat it as a string

                print "Activating entry: '%s' to point to '%s'" % (entry['key'], update_value)
            
                output = namecoind_firstupdate(entry['key'],entry['rand'],update_value,entry['longhex'])

                #output = namecoind_firstupdate(entry['key'], entry['rand'], update_value, entry['longhex'])
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

                #sleep(1)
            else:
                pass

#-----------------------------------
if __name__ == '__main__':

    do_name_firstupdate()