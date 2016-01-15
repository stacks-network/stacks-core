# -*- coding: utf-8 -*-
"""
    Onename API
    Copyright 2015 Halfmoon Labs, Inc.
    ~~~~~
"""

import os
import re

# Debugging

DEFAULT_PORT = 5000
DEFAULT_HOST = '0.0.0.0'

MEMCACHED_ENABLED = True
MEMCACHED_PORT = '11211'
MEMCACHED_TIMEOUT = 30*60

MAIL_USERNAME = 'support@onename.com'

SEARCH_URL = 'http://search.onename.com'
RESOLVER_URL = 'http://resolver.onename.com'

BLOCKSTORED_IP = 'blockstore.onename.com'
BLOCKSTORED_PORT = 6264

BITCOIND_SERVER = 'btcd.onename.com'
BITCOIND_PORT = 8332
BITCOIND_USER = 'openname'
BITCOIND_PASSWD = 'opennamesystem'
BITCOIND_USE_HTTPS = True

MAX_PROFILE_LIMIT = (8 * 1024) - 50  # roughly 8kb max limit

EMAIL_REGREX = r'[^@]+@[^@]+\.[^@]+'

DEFAULT_NAMESPACE = "id"
USE_DEFAULT_PAYMENT = False

try:
    PAYMENT_PRIVKEY = os.environ['PAYMENT_PRIVKEY']
except:
    PAYMENT_PRIVKEY = None

try:
    from .secrets import *
except:
    pass

# Secret settings
secrets_list = [
    'MAILGUN_API_KEY', 'SECRET_KEY',
    'API_DB_URI', 'API_DB_NAME',
    'BLOCKCYPHER_TOKEN',
    'EMAILS_TOKEN'
]

for env_variable in os.environ:
    if env_variable in secrets_list:
        env_value = os.environ[env_variable]
        exec(env_variable + " = \"\"\"" + env_value + "\"\"\"")

if 'DYNO' in os.environ:
    DEBUG = False
    APP_URL = 'api.onename.com'
else:
    DEBUG = True
    APP_URL = 'localhost:5000'

    API_DB_NAME = 'onename-api-test'
    API_DB_URI = 'mongodb://%s:%s/%s' % ('localhost', str(27017), API_DB_NAME)


# Needed for mongoengine
MONGODB_SETTINGS = {
    'db': API_DB_NAME,
    'host': API_DB_URI
}
