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

import json

from .db import api_db
from .server import register_user
from .config import DEFAULT_NAMESPACE

from .config import REGISTRAR_ADDRESS, REGISTRAR_ADDRESS_KEY, BTC_PRIV_KEY

from .network import blockstore_client as c

from .utils import pretty_print as pprint
from .utils import get_hash

def process_api_registraions(LIVE=False):

    new_users = api_db['blockchainid']

    for entry in new_users.find():

        fqu = entry['username'] + "." + DEFAULT_NAMESPACE
        btc_address = entry['transfer_address']
        profile = json.loads(entry['profile'])
        profile_hash = get_hash(profile)

        print "Processing: %s" % fqu

        if fqu != "testington5.id":
            continue

        #print c.preorder(temp_fqu, BTC_PRIV_KEY, REGISTRAR_ADDRESS)
        #print c.register(temp_fqu, BTC_PRIV_KEY, REGISTRAR_ADDRESS)

        pprint(c.update(fqu, profile_hash, REGISTRAR_ADDRESS_KEY))

        #register_user(fqu, profile, btc_address)

if __name__ == '__main__':

    process_api_registraions()

