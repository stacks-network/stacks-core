#!/usr/bin/env python
# -*- coding: utf-8 -*-
#-----------------------
# Copyright 2014 Halfmoon Labs, Inc.
# All Rights Reserved
#-----------------------

from coinrpc.namecoind_server import NamecoindServer 

from config import MAIN_SERVER, LOAD_SERVERS

from coinrpc import namecoind

from commontools import get_string
from commontools import utf8len, log

from time import sleep

from config import NAMECOIND_PORT, NAMECOIND_USER, NAMECOIND_PASSWD, NAMECOIND_WALLET_PASSPHRASE, NAMECOIND_USE_HTTPS, NAMECOIND_SERVER

#-----------------------------------
from pymongo import MongoClient
client = MongoClient() 
local_db = client['namecoin']
register_queue = local_db.queue

blocks = namecoind.blocks()

from blockdata.namecoind_cluster import pending_transactions
MAX_PENDING_TX = 50

#-----------------------------------
def do_name_firstupdate():

    #remove entries that are already active
    register_queue.remove({"activated":True})

    log.debug("Checking for new activations")
    log.debug('-' * 5)

    ignore_servers = []
    counter = 0
    counter_pending = 0

    for entry in register_queue.find():

        counter += 1

        if counter % 10 == 0:
            for server in ignore_servers:
                if pending_transactions(server) > MAX_PENDING_TX:
                    pass
                else:
                    ignore_servers.remove(server)

        from coinrpc import namecoind
        #print entry['key']
        if not namecoind.check_registration(entry['key']):

            counter_pending += 1

        #entry is registered; but not activated
        #if entry.get('activated') is not None and entry.get('activated') == False:

            key = entry['key']

            #compare the current block with 'wait_till_block'
            current_blocks = blocks
            wait_till_block = entry['wait_till_block'] + 8

            if current_blocks > wait_till_block:

                server = entry['server']

                log.debug(server)

                if server in ignore_servers:
                    continue
                
                if pending_transactions(server) > MAX_PENDING_TX:
                        log.debug("pending tx on server, try again")
                        ignore_servers.append(server)
                        continue

                
                update_value = get_string(entry['value'])
                
                log.debug("Activating entry: '%s' to point to '%s'" % (key, update_value))
                
                namecoind = NamecoindServer(server, NAMECOIND_PORT, NAMECOIND_USER, NAMECOIND_PASSWD, NAMECOIND_USE_HTTPS, NAMECOIND_WALLET_PASSPHRASE)

                output = namecoind.firstupdate(key,entry['rand'],update_value,entry['longhex'])
                log.debug(output)
                #except Exception as e:
                #    log.debug(e)

                if 'message' in output and output['message'] == "this name is already active":
                    entry['activated'] = True
                elif 'message' in output and output['message'] == "previous transaction is not in the wallet":
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
                log.debug("wait: %s block for: %s" % ((wait_till_block - current_blocks + 1), entry['key']))

        else:
            log.debug("key %s already active" % (entry['key']))
            register_queue.remove(entry)

    print "Pending activations: %s" %counter_pending
    sleep(1 * 60)

#-----------------------------------
if __name__ == '__main__':

    while(1):
        try:
            do_name_firstupdate()
        except Exception as e:
            print e