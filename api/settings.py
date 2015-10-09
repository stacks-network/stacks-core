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
NMC_RESOLVER_URL = 'http://resolver-nmc.onename.com'
BTC_RESOLVER_URL = 'http://resolver-btc.onename.com'

DHT_MIRROR = '54.173.110.67'
DHT_MIRROR_PORT = 6266

try:
    from .secrets import *
except:
    pass

# Secret settings
secrets_list = [
    'INDEX_DB_URI', 'SECRET_KEY', 'MONGODB_PASSWORD',
    'MAILGUN_API_KEY', 'MONGODB_URI', 'MONGODB_DB'
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

    MONGODB_DB = 'onename-api-test'
    MONGODB_URI = 'mongodb://%s:%s/%s' % (
        'localhost', str(27017), MONGODB_DB)
