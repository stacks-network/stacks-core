# -*- coding: utf-8 -*-
"""
    Registrar
    ~~~~~
    :copyright: (c) 2014-2016 by Halfmoon Labs, Inc.
    :copyright: (c) 2016 blockstack.org
    :license: MIT, see LICENSE for more details.
"""

import json
import logging

from bson import json_util

from pybitcoin import hex_hash160, address_to_new_cryptocurrency
from pybitcoin import BitcoinPrivateKey
from pybitcoin import is_b58check_address

from .config import email_regrex, DEBUG
from .config import whitelist_email_regrex
from .config import API_WHITE_LISTED_KEYS

try:
    from .config_local import custom_white_list
    from .config_local import custom_email_checks
except:
    pass


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
            # if string with valid JSON, convert
            profile = json.loads(profile)
        except:
            # if not valid JSON
            return hex_hash160(profile)

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


def cleanup_email(email):

    try:
        address = email.split('@')[0]
        domain = email.split('@')[1]
    except:
        print email
        return email

    # drop everything after a +
    address = address.split('+')[0]

    # replace any .
    address = address.replace('.', '')

    return address + '@' + domain


def check_banned_email(email):

    email = cleanup_email(email)

    if email_regrex in email:
        return True
    else:
        return False


def whiteListedUser(email, profile):
    """ Wrapper function for white-listing users
        You can define your custom white-listing mechanism
    """

    try:
        return custom_white_list(email, profile)
    except:
        pass

    # if no custom white-listing mechanism is defined
    return True


def whiteListedAPIKey(api_key):
    """
        Check if given API key is white listed or not
    """

    if api_key in API_WHITE_LISTED_KEYS:
        return True
    else:
        return False


def validRegistrationEmail(email, email_list):
    """ Wrapper function for checks for registration email
        You can define your custom checks
    """

    try:
        return custom_email_checks(email, email_list)
    except:
        pass

    # if no custom white-listing mechanism is defined
    return True


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
