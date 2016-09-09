# -*- coding: utf-8 -*-
"""
    Onename API
    Copyright 2015 Halfmoon Labs, Inc.
    ~~~~~
"""

import traceback
from pymongo import MongoClient

from . import app


#try:
#    db_client = MongoClient(app.config['API_DB_URI'])[app.config['API_DB_NAME']]
#except Exception as e:
#    traceback.print_exc()
