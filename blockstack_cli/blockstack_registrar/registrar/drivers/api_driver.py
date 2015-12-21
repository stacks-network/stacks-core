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
from ..config import MINIMUM_LENGTH_NAME
from ..config import IGNORE_NAMES_STARTING_WITH

from ..utils import pretty_print as pprint
from ..utils import get_hash, config_log
from ..utils import validAddress, ignoreRegistration

from ..server import RegistrarServer
from ..states import registrationComplete

from ..network import refresh_resolver

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
        self.registrar_server = RegistrarServer()

    def process_new_users(self, nameop=None, live_delete=False):

        self.registrar_server.reset_flag()

        for entry in self.registrations.find(no_cursor_timeout=True):

            # test for minimum name length
            if len(entry['username']) < MINIMUM_LENGTH_NAME:
                log.debug("Expensive name %s. Skipping." % entry['username'])
                continue

            # test for ignoring names starting with certain patterns
            if ignoreRegistration(entry['username'], IGNORE_NAMES_STARTING_WITH):
                log.debug("Ignoring: %s" % entry['username'])

                if live_delete:
                    self.registrations.remove({"username": entry['username']})

                continue

            fqu = entry['username'] + "." + DEFAULT_NAMESPACE
            transfer_address = entry['transfer_address']
            profile = json.loads(entry['profile'])
            profile_hash = get_hash(profile)

            if not validAddress(transfer_address):
                log.debug("Invalid transfer address for: %s. Skipping." % fqu)
                continue

            log.debug("Processing: %s" % fqu)

            if registrationComplete(fqu, profile, transfer_address):
                log.debug("Registration complete %s. Removing." % fqu)
                self.registrations.remove({"username": entry['username']})

                refresh_resolver(entry['username'])
            else:
                try:
                    self.registrar_server.process_nameop(fqu, profile,
                                                         transfer_address,
                                                         nameop=nameop)
                except Exception as e:
                    log.debug(e)

    def display_stats(self):

        log.debug("Pending registrations: %s" % self.registrations.find().count())
        #log.debug("Pending updates: %s" % self.updates.find().count())

    def remove_entry(self, username):

        check_entry = self.registrations.find_one({"username": username})

        if check_entry is None:
            log.debug("No such user")
        else:
            log.debug("Removing: %s" % username)
            self.registrations.remove({"username": username})
