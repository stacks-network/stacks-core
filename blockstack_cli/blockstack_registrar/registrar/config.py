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

try:
    from config_local import *
except Exception as e:

    print e
    print "using default config"

    import os

    DEBUG = True

    # --------------------------------------------------
    NAMECOIND_READONLY = False

    NAMECOIND_USE_HTTPS = True

    NAMECOIND_PORT = os.environ['NAMECOIND_PORT']
    NAMECOIND_SERVER = os.environ['NAMECOIND_SERVER']
    NAMECOIND_USER = os.environ['NAMECOIND_USER']
    NAMECOIND_PASSWD = os.environ['NAMECOIND_PASSWD']
    #WALLET_PASSPHRASE = os.environ['WALLET_PASSPHRASE']
    #--------------------------------------------------

    MONGODB_URI = os.environ['MONGODB_URI']
    OLD_DB = os.environ['OLD_DB']
    AWSDB_URI = os.environ['AWSDB_URI']
    MONGOLAB_URI = os.environ['MONGOLAB_URI']

    DEFAULT_HOST = '127.0.0.1'
    MEMCACHED_PORT = '11211'
    MEMCACHED_TIMEOUT = 15 * 60

    FRONTEND_SECRET = os.environ['FRONTEND_SECRET']
