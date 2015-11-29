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

BLOCKSTORED_IP = '127.0.0.1'
BLOCKSTORED_PORT = 6264
DHT_MIRROR_IP = '52.20.98.85'
DHT_MIRROR_PORT = 6266

DEFAULT_NAMESPACE = "id"

# current defined drivers being used for registrar
REGISTRAR_DRIVERS = ['webapp', 'api']

IGNORE_USERNAMES = []

# for registrar's internal queue
QUEUE_DB_URI = os.environ['QUEUE_DB_URI']

# for encrypting DB entries like privkeys
SECRET_KEY = os.environ['SECRET_KEY']

BLOCKCYPHER_TOKEN = os.environ['BLOCKCYPHER_TOKEN']

DEFAULT_HOST = '127.0.0.1'
MEMCACHED_PORT = '11211'
MEMCACHED_TIMEOUT = 15 * 60

TX_FEE = 0.0002  # around 7 cents
TARGET_BALANCE_PER_ADDRESS = 0.009
MINIMUM_BALANCE = 0.002
CHAINED_PAYMENT_AMOUNT = 0.01

DEBUG = False  # can change in config_local

PREORDER_CONFIRMATIONS = 6
PREORDER_REJECTED = 110  # no. of blocks after which preorder should be removed
RATE_LIMIT = 20   # target tx per block
SLEEP_INTERVAL = 20  # in seconds
RETRY_INTERVAL = 10  # if a tx is not picked up by x blocks
TX_CONFIRMATIONS_NEEDED = 10

try:
    from config_local import *
except Exception as e:

    print e
    print "using default config"

    email_regrex = ''  # if it's not defined in config_local
