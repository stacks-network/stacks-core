# -*- coding: utf-8 -*-
"""
    Onename API
    Copyright 2015 Halfmoon Labs, Inc.
    ~~~~~
"""

import os
import re

# Debugging
DEBUG = True

# URI for remote DB with user info
try:
    USERDB_URI = os.environ['USERDB_URI']
except:
    pass

DEFAULT_PORT = 5000
DEFAULT_HOST = '0.0.0.0'

MEMCACHED_ENABLED = True
MEMCACHED_PORT = '11211'
MEMCACHED_TIMEOUT = 30*60

MAIL_USERNAME = 'support@onename.com'

SEARCH_URL = 'http://search.halfmoonlabs.com'
RESOLVER_URL = 'http://resolver.onename.com'

# Secret settings
for env_variable in os.environ:
    env_value = os.environ[env_variable]
    exec(env_variable + " = \"\"\"" + env_value + "\"\"\"")

if 'DYNO' in os.environ:
    APP_URL = 'api.onename.com'

    MONGODB_URI = MONGOLAB_URI
    parts = re.split(':|/|@|mongodb://', MONGOLAB_URI)
    _, MONGODB_USERNAME, MONGODB_PASSWORD, MONGODB_HOST, MONGODB_PORT, MONGODB_DB = parts
elif 'AWS' in os.environ:
    MONGODB_DB = 'onename_api'
    MONGODB_URI = os.environ['AWSDB_URI'] + '/' + MONGODB_DB
else:
    APP_URL = 'localhost:5000'

    MONGODB_HOST = 'localhost'
    MONGODB_PORT = 27017
    MONGODB_DB = 'onename_api'

    MONGODB_URI = 'mongodb://' + MONGODB_HOST + ':' + str(MONGODB_PORT) + '/' + MONGODB_DB

try:
    AWSDB_URI = os.environ['AWSDB_URI']
    INDEX_DB_URI = os.environ['INDEX_DB_URI']
except:
    AWSDB_URI = None
    INDEX_DB_URI = None
