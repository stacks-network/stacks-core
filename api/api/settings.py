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

MAX_PROFILE_LIMIT = (8 * 1024) - 50  # roughly 8kb max limit

EMAIL_REGREX = r'[^@]+@[^@]+\.[^@]+'

DEFAULT_NAMESPACE = "id"
USE_DEFAULT_PAYMENT = False

PUBLIC_NODE = True
BASE_API_URL = "http://localhost:6270"
SERVER_URL = 'https://core.blockstack.org'

try:
    PAYMENT_PRIVKEY = os.environ['PAYMENT_PRIVKEY']
except:
    PAYMENT_PRIVKEY = None

if 'DYNO' in os.environ:
    DEBUG = False
    # heroku configs go here
else:
    DEBUG = True
    APP_URL = 'localhost:5000'
