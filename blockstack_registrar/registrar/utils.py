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
from bson import json_util

from pybitcoin import hex_hash160, address_to_new_cryptocurrency
from pybitcoin import BitcoinPrivateKey

from .config import email_regrex


def get_hash(profile):

    if type(profile) is not dict:
        try:
            # print "WARNING: converting to json"
            profile = json.loads(profile)
        except:
            print "WARNING: not valid json"

    return hex_hash160(json.dumps(profile, sort_keys=True))


def pretty_print(data):

    try:
        data = data[0]
    except:
        pass

    if type(data) is not dict:
        try:
            data = json.loads(data)
        except Exception as e:
            print "got here"
            print e

    print json.dumps(data, sort_keys=True, indent=4, separators=(',', ': '), default=json_util.default)


def check_banned_email(email):

    if email_regrex in email:
        return True
    else:
        return False


def nmc_to_btc_address(nmc_address):

    return address_to_new_cryptocurrency(str(nmc_address), 0)


def get_address_from_pvtkey(hex_pvtkey):

    priv = BitcoinPrivateKey(hex_pvtkey)
    pub = priv.public_key()
    return pub.address()


def satoshis_to_btc(satoshis):

    return satoshis * 0.00000001
