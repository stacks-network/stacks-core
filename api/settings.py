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

SEARCH_URL = 'http://search.halfmoonlabs.com'
RESOLVER_URL = 'http://resolver.onename.com'

try:
    from .secrets import *
except:
    pass

# Secret settings
INDEX_DB_URI = None

secrets_list = [
    'INDEX_DB_URI', 'SECRET_KEY', 'MONGODB_PASSWORD',
    'MAILGUN_API_KEY', 'MONGOLAB_URI'
]
for env_variable in os.environ:
    if env_variable in secrets_list:
        env_value = os.environ[env_variable]
        exec(env_variable + " = \"\"\"" + env_value + "\"\"\"")

if 'DYNO' in os.environ:
    DEBUG = False

    APP_URL = 'api.onename.com'

    MONGODB_URI = MONGOLAB_URI
    parts = re.split(':|/|@|mongodb://', MONGOLAB_URI)
    (_, MONGODB_USERNAME, MONGODB_PASSWORD, MONGODB_HOST, MONGODB_PORT,
        MONGODB_DB) = parts
elif 'AWS' in os.environ:
    DEBUG = False

    MONGODB_DB = 'onename_api'
    MONGODB_URI = MONGOLAB_URI
else:
    DEBUG = True

    APP_URL = 'localhost:5000'

    MONGODB_HOST = 'localhost'
    MONGODB_PORT = 27017
    MONGODB_DB = 'onename_api'

    MONGODB_URI = 'mongodb://%s:%s/%s' % (
        MONGODB_HOST, str(MONGODB_PORT), MONGODB_DB)
