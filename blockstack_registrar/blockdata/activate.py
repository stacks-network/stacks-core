#!/usr/bin/env python
# -*- coding: utf-8 -*-
#-----------------------
# Copyright 2014 Halfmoon Labs, Inc.
# All Rights Reserved
#-----------------------

from coinrpc.namecoin.namecoind_server import NamecoindServer 

from coinrpc.config import NAMECOIND_PORT, NAMECOIND_USER, NAMECOIND_PASSWD, NAMECOIND_WALLET_PASSPHRASE, NAMECOIND_USE_HTTPS, NAMECOIND_SERVER
from coinrpc.config import MAIN_SERVER, LOAD_SERVERS

namecoind = NamecoindServer(NAMECOIND_SERVER, NAMECOIND_PORT, NAMECOIND_USER, NAMECOIND_PASSWD, NAMECOIND_USE_HTTPS, NAMECOIND_WALLET_PASSPHRASE)

from commontools import get_string
from commontools import utf8len, log

from time import sleep

#-----------------------------------
from pymongo import MongoClient
client = MongoClient() 
local_db = client['namecoin']
register_queue = local_db.queue

blocks = namecoind.blocks()

#-----------------------------------
def do_name_firstupdate():

    #remove entries that are already active
    register_queue.remove({"activated":True})

    log.debug("Checking for new activations")
    log.debug('-' * 5)
    
    for entry in register_queue.find():

        #entry is registered; but not activated
        if entry.get('activated') is not None and entry.get('activated') == False:
            
            key = entry['key']

            #compare the current block with 'wait_till_block'
            current_blocks = blocks['blocks']

            if current_blocks > entry['wait_till_block']:
                
                update_value = get_string(entry['value'])
                
                log.debug("Activating entry: '%s' to point to '%s'" % (key, update_value))

                server = entry['server']

                namecoind = NamecoindServer(server, NAMECOIND_PORT, NAMECOIND_USER, NAMECOIND_PASSWD, NAMECOIND_USE_HTTPS, NAMECOIND_WALLET_PASSPHRASE)

                output = namecoind.firstupdate(key,entry['rand'],update_value,entry['longhex'])
                log.debug("tx: %s", output)

                if 'message' in output and output['message'] == "this name is already active":
                    entry['activated'] = True
                elif 'code' in output:
                    entry['activated'] = False
                    log.debug("Not activated. Try again.")
                else:
                    entry['activated'] = True

                entry['tx_id'] = output
                register_queue.save(entry)

                log.debug('-' * 5)

            else:
                log.debug("wait: %s block for: %s" % ((entry['wait_till_block'] - current_blocks + 1), entry['key']))

#-----------------------------------
if __name__ == '__main__':

    do_name_firstupdate()