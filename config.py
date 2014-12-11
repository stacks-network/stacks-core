"""
    Opennamed
    ~~~~~
    :copyright: (c) 2014 by Openname.org
    :license: MIT, see LICENSE for more details.
"""

import os

DEBUG = True

DEFAULT_PORT = '8344'
LISTEN_IP = '0.0.0.0'
VERSION = 'v0.1-beta'
RPC_TIMEOUT = 5  # seconds

try:
    OPENNAMED_SERVER = os.environ['OPENNAMED_SERVER']
    OPENNAMED_PORT = os.environ['OPENNAMED_PORT']
except:
    OPENNAMED_SERVER = 'localhost'
    OPENNAMED_PORT = DEFAULT_PORT

try:
    BITCOIND_SERVER = os.environ['BITCOIND_SERVER']
    BITCOIND_PORT = os.environ['BITCOIND_PORT']
    BITCOIND_USER = os.environ['BITCOIND_USER']
    BITCOIND_PASSWD = os.environ['BITCOIND_PASSWD']
except:
    BITCOIND_SERVER = 'btcd.onename.com'
    BITCOIND_PORT = '8332'
    BITCOIND_USER = 'openname'
    BITCOIND_PASSWD = 'opennamesystem'
