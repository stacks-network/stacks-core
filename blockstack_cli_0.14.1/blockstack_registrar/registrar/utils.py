"""
    Registrar
    ~~~~~

    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016 by Blockstack.org

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
import logging

from bson import json_util

from pybitcoin import hex_hash160, address_to_new_cryptocurrency
from pybitcoin import BitcoinPrivateKey
from pybitcoin import is_b58check_address

from .config import email_regrex, DEBUG


def config_log(name):

    from commontools import setup_logging
    setup_logging()

    log = logging.getLogger(name)

    if DEBUG:
        log.setLevel(level=logging.DEBUG)
    else:
        log.setLevel(level=logging.INFO)

    blockcypher_log = logging.getLogger("blockcypher.api")
    blockcypher_log.setLevel(logging.WARNING)

    return log

log = config_log(__name__)


def get_hash(profile):

    if type(profile) is not dict:
        try:
            # print "WARNING: converting to json"
            profile = json.loads(profile)
        except:
            log.debug("WARNING: not valid json")

    return hex_hash160(json.dumps(profile, sort_keys=True))


def pretty_dump(data):

    try:
        del data['_id']
    except:
        pass

    return json.dumps(data, sort_keys=True, indent=4, separators=(',', ': '), default=json_util.default)


def pretty_print(data):

    try:
        data = data[0]
    except:
        pass

    if type(data) is not dict:
        try:
            data = json.loads(data)
        except Exception as e:
            log.debug("ERROR in pretty print: %s" % e)

    print pretty_dump(data)


def check_banned_email(email):

    if email_regrex in email:
        return True
    else:
        return False


def ignoreRegistration(name, ignore_patterns):

    for pattern in ignore_patterns:

        if name.startswith(pattern):
            return True

    return False


def nmc_to_btc_address(nmc_address):

    return address_to_new_cryptocurrency(str(nmc_address), 0)


def satoshis_to_btc(satoshis):

    return satoshis * 0.00000001


def btc_to_satoshis(btc):

    return int(btc / 0.00000001)


def validAddress(address):

    try:
        validAddress = is_b58check_address(str(address))
    except Exception as e:
        log.debug(e)

    if validAddress:
        return True
    else:
        return False
