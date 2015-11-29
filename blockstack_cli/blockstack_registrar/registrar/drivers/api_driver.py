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
import json

from pymongo import MongoClient

from ..config import DEFAULT_NAMESPACE

from ..utils import pretty_print as pprint
from ..utils import get_hash, config_log

"""
    API Driver file that has all necessary functions for
    using registrar with API data
"""

log = config_log(__name__)

try:
    # incoming requests from an API
    API_DB_URI = os.environ['API_DB_URI']
except:
    log.debug("API_DB_URI not defined")
    exit(0)

api_db = MongoClient(API_DB_URI).get_default_database()


class APIDriver(object):
    """ Registrar driver for API
    """

    def __init__(self):

        self.registrations = api_db['blockchainid']

    def process_api_registraions(self):

        for entry in self.registrations.find():

            fqu = entry['username'] + "." + DEFAULT_NAMESPACE
            transfer_address = entry['transfer_address']
            profile = json.loads(entry['profile'])
            profile_hash = get_hash(profile)

            log.debug("Processing: %s" % fqu)

    def display_stats(self):

        log.debug("Pending registrations: %s" % self.registrations.find().count())
        #log.debug("Pending updates: %s" % self.updates.find().count())