#!/usr/bin/env python
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

from tools.crypto_tools import aes_encrypt, aes_decrypt
from tools.crypto_tools import get_address_from_privkey

from .utils import pretty_print as pprint
from .utils import config_log

from .db import registrar_users

from .config import SECRET_KEY

from .network import blockstore_client as c

log = config_log(__name__)


def get_registrar_users():
    """ Display users where registrar currently has the private key
    """

    counter = 0

    for entry in registrar_users.find():

        fqu = entry['username'] + ".id"

        data = c.get_name_blockchain_record(fqu)

        if 'error' in data:
            log.debug("Error while processing: (%s, %s)" % (fqu, data))
            continue

        if entry['btc_address'] != data['address']:
            log.debug("registrar doesn't own: %s" % fqu)
            continue

        log.debug(pprint(entry))
        log.debug('-' * 5)

        counter += 1

    log.debug("Total names: %s" % counter)


def test_registrar_users():
    """ Test if registrar has access to correct private keys
    """

    for entry in registrar_users.find():

        fqu = entry['username'] + ".id"

        data = c.get_name_blockchain_record(fqu)

        if 'error' in data:
            log.debug("Error while processing: (%s, %s)" % (fqu, data))
            continue

        if entry['btc_address'] != data['address']:
            log.debug("registrar doesn't own: %s" % fqu)
            continue

        privkey = aes_decrypt(entry['encrypted_privkey'], SECRET_KEY)

        if get_address_from_privkey(privkey) == entry['btc_address']:
            log.debug("Correct pvtkey: %s" % fqu)
        else:
            log.debug("ERROR: wrong pvtkey: %s")

if __name__ == '__main__':

    get_registrar_users()
    #test_registrar_users()
