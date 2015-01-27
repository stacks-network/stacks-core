# -*- coding: utf-8 -*-
"""
    Onename API
    Copyright 2014 Halfmoon Labs, Inc.
    ~~~~~
"""

import os
import re

if 'DYNO' in os.environ:
    # Debugging
    DEBUG = True

    # Secret settings
    for env_variable in os.environ:
        env_value = os.environ[env_variable]
        exec(env_variable + " = '" + env_value + "'")

    MONGODB_URI = MONGOLAB_URI
    parts = re.split(':|/|@|mongodb://', MONGOLAB_URI)
    _, MONGODB_USERNAME, MONGODB_PASSWORD, MONGODB_HOST, MONGODB_PORT, MONGODB_DB = parts
else:
    APP_URL = 'localhost:5000'

    # Debugging
    DEBUG = True

    # Database
    MONGODB_HOST = 'localhost'
    MONGODB_PORT = 27017
    MONGODB_DB = 'onename_api'

    # Secret settings
    from .secrets import *

    MONGODB_URI = 'mongodb://' + MONGODB_HOST + ':' + str(MONGODB_PORT) + '/' + MONGODB_DB

MAIL_USERNAME = 'support@onename.io'
