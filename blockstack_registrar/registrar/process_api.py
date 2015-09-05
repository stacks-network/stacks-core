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

from pymongo import MongoClient

from pybitcoin.rpc import NamecoindClient
from pybitcoin.rpc.namecoind_cluster import check_address

from registrar.nameops import process_user, update_name, register_name
from registrar.nameops import get_namecoind
from registrar.transfer import transfer_name, nameTransferred

from registrar.config import NAMECOIND_PORT, NAMECOIND_USER, NAMECOIND_PASSWD
from registrar.config import NAMECOIND_USE_HTTPS, NAMECOIND_SERVER
from registrar.config import NAMECOIND_WALLET_PASSPHRASE

namecoind = NamecoindClient(NAMECOIND_SERVER, NAMECOIND_PORT,
                            NAMECOIND_USER, NAMECOIND_PASSWD,
                            NAMECOIND_WALLET_PASSPHRASE, NAMECOIND_USE_HTTPS)


api_db = MongoClient(MONGOLAB_URI).get_default_database()
#api_db = MongoClient()['onename_api8']


def process_api_registraions(LIVE=False):

    base_url = 'http://resolver.onename.com/v1/users/'

    new_users = api_db['passcard']

    for entry in new_users.find():
        username = entry['passname']
        transfer_address = entry['transfer_address']
        profile = json.loads(entry['payload'])

        resp = requests.get(base_url + username)

        data = resp.json()

        if 'error' in data:

            # if not registered on the blockchain
            print "register: " + username
            if LIVE:
                process_user(username, profile)
        else:
            # if registered and not in our DBs
            check_user_db1 = users.find_one({"username": username})
            check_user_db2 = old_users.find_one({"username": username})

            if check_user_db1 is None and check_user_db2 is None:
                profile = namecoind.name_show('u/' + username)
                check_address = profile['address']
                if check_address == transfer_address:
                    print "already transferred"
                    if LIVE:
                        new_users.remove(entry)
                else:
                    print "transfer: " + username
                    print transfer_address
                    if LIVE:
                        transfer_name(username, transfer_address, live=True)


if __name__ == '__main__':

    process_api_registraions()
