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
import csv
from base64 import b64encode
from blockdata.register import register_name, update_name
from coinrpc import namecoind

from pymongo import Connection

con = Connection()
db = con['namecoin']
queue = db.queue

from ast import literal_eval

CONTACT_EMAIL = 'support@onename.com'


def format_key_value(key, name=None):

    # need u/ for usernames from Namecoin u/ space
    key = 'u/' + key.lower()

    value = {}

    value['status'] = "reserved"

    if name is not None and name != '' and name != ' ':

        value["message"] = "This blockchain ID is reserved for %s." \
                            "If this is you, please email %s" \
                            " to claim it for free." % (name.lstrip(' '), CONTACT_EMAIL)

    else:

        value["message"] = "This blockchain ID was parked to evade name squatting," \
                           " but can be made available upon reasonable request" \
                           " at no charge. If you are interested in this name," \
                           " please email %s with your twitter" \
                           " handle and why you would like this particular name." % CONTACT_EMAIL

    return key, value


def main_loop(key, name=None):

    key, value = format_key_value(key, name)

    reply = queue.find_one({'key': key})

    if namecoind.check_registration(key):

        profile = namecoind.name_show(key)
        try:
            profile = profile['value']
        except:
            pass

        if 'status' in profile and profile['status'] == 'reserved':
            print "already reserved: " + key
            #update_name(key,value)
        else:
            print "registered but not reserved: " + key
            #update_name(key,value)
    elif reply is not None:
        # currently being processed
        pass
    else:
        #not in DB and not registered
        print "not registered: " + key
        register_name(key, value)

    print '-' * 5


def get_url(username, access_code):
    return 'http://onename.io?a=' + b64encode(username + '-' + access_code)


def get_random_hex(size=10):
    # every byte of data is converted into the corresponding 2-digit hex representation
    return binascii.b2a_hex(os.urandom(size))


if __name__ == '__main__':

    with open('tools/data.csv') as csvfile:
        spamreader = csv.reader(csvfile)
        for row in spamreader:
            try:
                main_loop(row[0], row[1])
            except:
                main_loop(row[0])
