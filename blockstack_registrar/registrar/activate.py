# -*- coding: utf-8 -*-
"""
    registrar
    ~~~~~

    copyright: (c) 2014 by Halfmoon Labs, Inc.
    copyright: (c) 2015 by Blockstack.org
    license: MIT, see LICENSE for more details.
"""

from pybitcoin.rpc.namecoind_client import NamecoindClient as NamecoindServer

from config import MAIN_SERVER, LOAD_SERVERS

from commontools import get_string
from commontools import utf8len, log

from time import sleep

from config import NAMECOIND_SERVER, NAMECOIND_PORT
from config import NAMECOIND_USER, NAMECOIND_PASSWD
from config import NAMECOIND_WALLET_PASSPHRASE, NAMECOIND_USE_HTTPS

from pymongo import MongoClient
from config import AWSDB_URI
aws_db = MongoClient(AWSDB_URI)['blockdata']
register_queue = aws_db.queue

from config import MONGODB_URI
remote_client = MongoClient(MONGODB_URI)
remote_db = remote_client.get_default_database()
users = remote_db.user

from pybitcoin.rpc.namecoind_cluster import pending_transactions
MAX_PENDING_TX = 50

from .nameops import slice_profile


def refresh_value(entry):
    """get the latest value for key:value being registered
    """

    username = entry['username']
    user = users.find_one({"username": username})

    if user is None:
        return None

    profile = user['profile']
    keys, values = slice_profile(username, profile)

    counter = 0
    for key in keys:
        if entry['key'] == key:
            return values[counter]
        counter += 1


def clean_wallet():

    for entry in register_queue.find():
        if entry['tx_sent'] is True:
            entry['tx_sent'] = False
            register_queue.save(entry)


def do_name_firstupdate():

    log.debug("Checking for new activations")
    log.debug('-' * 5)

    ignore_servers = []
    counter = 0
    counter_pending = 0

    from coinrpc import namecoind
    blocks = namecoind.blocks()

    for entry in register_queue.find():

        counter += 1

        if counter % 10 == 0:
            for server in ignore_servers:
                if pending_transactions(server) > MAX_PENDING_TX:
                    pass
                else:
                    ignore_servers.remove(server)

        from coinrpc import namecoind
        if not namecoind.check_registration(entry['key']):

            counter_pending += 1

            key = entry['key']
            server = entry['server']
            namecoind = NamecoindServer(server, NAMECOIND_PORT, NAMECOIND_USER,
                                        NAMECOIND_PASSWD, NAMECOIND_USE_HTTPS,
                                        NAMECOIND_WALLET_PASSPHRASE)

            if 'tx_sent' in entry and entry['tx_sent'] is True:
                log.debug('Already sent name_firstupdate: %s' % entry['key'])
                continue

            if 'wait_till_block' not in entry:

                reply = namecoind.gettransaction(entry['txid'])

                if 'code' in reply:
                    register_queue.remove(entry)
                    continue

                if reply['confirmations'] > 1:
                    log.debug('Got confirmations on name_new: %s' % entry['key'])
                    entry['wait_till_block'] = namecoind.blocks() + (12 - reply['confirmations'])
                    register_queue.save(entry)
                else:
                    log.debug('No confirmations on name_new: %s' % entry['key'])
                    continue

            if entry['wait_till_block'] <= blocks:

                if server in ignore_servers:
                    continue

                if pending_transactions(server) > MAX_PENDING_TX:
                        log.debug("Pending tx on server, try again")
                        ignore_servers.append(server)
                        continue

                update_value = None
                if 'username' in entry:
                    update_value = get_string(refresh_value(entry))

                if update_value is None:
                    update_value = get_string(entry['value'])

                log.debug("Activating entry: '%s' to point to '%s'" % (key, update_value))

                output = namecoind.firstupdate(key,entry['rand'],update_value,entry['txid'])

                log.debug(output)

                if 'message' in output and output['message'] == "this name is already active":
                    register_queue.remove(entry)
                elif 'message' in output and output['message'] == "previous transaction is not in the wallet":
                    register_queue.remove(entry)
                elif 'code' in output:
                    log.debug("Not activated. Try again.")
                else:
                    entry['tx_sent'] = True
                    register_queue.save(entry)

                log.debug('-' * 5)

            else:
                log.debug("wait: %s blocks for: %s" % ((entry['wait_till_block'] - blocks), entry['key']))

        else:
            log.debug("key %s already active" % (entry['key']))
            register_queue.remove(entry)

    print "Pending activations: %s" % counter_pending
    current_block = namecoind.blocks()
    while(1):
        new_block = namecoind.blocks()

        if current_block == new_block:
            log.debug('No new block. Sleeping ... ')
            sleep(15)
        else:
            break

if __name__ == '__main__':

    #clean_wallet()
    do_name_firstupdate()
    exit(0)

    while(1):
        try:
            do_name_firstupdate()
        except Exception as e:
            print e
