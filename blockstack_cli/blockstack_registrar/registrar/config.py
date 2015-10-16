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

BLOCKSTORED_IP = '52.20.98.85'
BLOCKSTORED_PORT = 6264
DHT_MIRROR_IP = '52.20.98.85'
DHT_MIRROR_PORT = 6266

DEFAULT_NAMESPACE = "id"

IGNORE_USERNAMES = []
MONGODB_URI = os.environ['MONGODB_URI']
INDEXDB_URI = os.environ['INDEXDB_URI']
BTC_PRIV_KEY = os.environ['BTC_PRIV_KEY']

DEFAULT_HOST = '127.0.0.1'
MEMCACHED_PORT = '11211'
MEMCACHED_TIMEOUT = 15 * 60

DEBUG = True

try:
    from config_local import *
except Exception as e:

    print e
    print "using default config"

    email_regrex = ''  # if it's not defined in config_local

    # --------------------------------------------------

    #BITCOIND_USE_HTTPS = True

    #BITCOIND_PORT = os.environ['BITCOIND_PORT']
    #BITCOIND_SERVER = os.environ['BITCOIND_SERVER']
    #BITCOIND_USER = os.environ['BITCOIND_USER']
    #BITCOIND_PASSWD = os.environ['BITCOIND_PASSWD']
    #WALLET_PASSPHRASE = os.environ['WALLET_PASSPHRASE']
    #--------------------------------------------------

    #MONGODB_URI = os.environ['MONGODB_URI']
    #OLD_DB = os.environ['OLD_DB']
    AWSDB_URI = os.environ['AWSDB_URI']
    #MONGOLAB_URI = os.environ['MONGOLAB_URI']

    #FRONTEND_SECRET = os.environ['FRONTEND_SECRET']
