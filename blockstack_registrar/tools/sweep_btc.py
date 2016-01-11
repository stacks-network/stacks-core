# -*- coding: utf-8 -*-
"""
    Registrar
    ~~~~~

    copyright: (c) 2014 by Halfmoon Labs, Inc.
    copyright: (c) 2015 by Blockstack.org

This file is part of Registrar.

    Registrar is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Registrar is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Registrar. If not, see <http://www.gnu.org/licenses/>.
"""

import os
import json
import requests

from registrar.config import MONGODB_URI, OLD_DB
from registrar.config_local import CHAIN_API_KEY

from registrar.crypto.bip38 import bip38_decrypt
from coinkit import BitcoinKeypair, NamecoinKeypair

from commontools import log
from coinrpc.bitcoind_server import BitcoindServer
from registrar.config import BITCOIND_SERVER, BITCOIND_PORT, BITCOIND_USER, BITCOIND_PASSWD, BITCOIND_USE_HTTPS, BITCOIND_WALLET_PASSPHRASE 
bitcoind = BitcoindServer(BITCOIND_SERVER, BITCOIND_PORT, BITCOIND_USER, BITCOIND_PASSWD, BITCOIND_USE_HTTPS, BITCOIND_WALLET_PASSPHRASE) 

from pymongo import MongoClient

remote_db = MongoClient(MONGODB_URI).get_default_database()
new_users = remote_db.user
transfer = remote_db.name_transfer

old_db = MongoClient(OLD_DB).get_default_database()
old_users = old_db.user

try:
    WALLET_SECRET = os.environ['WALLET_SECRET']
except:
    log.debug("ERROR: WALLET_SECRET not set (check web app env variables)")
    WALLET_SECRET = ''


def sweep_btc(transfer_user, LIVE=False):

    user_id = transfer_user['user_id']
    new_user = new_users.find_one({"_id": user_id})

    if new_user is None:
        return

    old_user = old_users.find_one({'username': new_user['username']})

    if old_user is None:
        return

    new_btc_address = new_user['bitcoin_address']
    old_btc_address = json.loads(old_user['profile'])['bitcoin']['address']

    wif_pk = bip38_decrypt(str(transfer_user['encrypted_private_key']), WALLET_SECRET)

    keypair = BitcoinKeypair.from_private_key(wif_pk)

    if old_btc_address == keypair.address():

        balance = fetch_balance(old_btc_address)

        if balance == float(0):
            return False

        log.debug(new_user['username'])
        log.debug("old btc address: " + old_btc_address)
        bitcoind.importprivkey(keypair.wif_pk())

        if LIVE:
            log.debug("sending " + str(balance) + " to " + new_btc_address)
            tx = bitcoind.sendtoaddress(new_btc_address, balance)
            log.debug(tx)
        else:
            log.debug("need to send " + str(balance) + " to " + new_btc_address)

        log.debug("final balance: %s", balance)
        log.debug('-' * 5)

        return True

    return False


def fetch_balance(btc_address):

    try:
        r = requests.get('https://api.chain.com/v1/bitcoin/addresses/' + btc_address + '?api-key-id=' + CHAIN_API_KEY)
        balance = r.json()['balance'] * 0.00000001 #convert to BTC from Satoshis
    except Exception as e:
        return None

    return balance
