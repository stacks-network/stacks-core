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

from .nameops import get_namecoind
from pybitcoin.rpc import NamecoindClient


def test_private_key(passphrase, nmc_address):

    from coinkit.keypair import NamecoinKeypair

    keypair = NamecoinKeypair.from_passphrase(passphrase)

    print keypair.wif_pk()

    generated_nmc_address = keypair.address()

    if(generated_nmc_address == nmc_address):
        print "found a match"
        return True
    else:
        print "don't match"
        return False


def nameTransferred(user, namecoind):

    try:
        resp = namecoind.name_show('u/' + user['username'])
    except:
        return False

    if 'address' in resp and resp['address'] == user['namecoin_address']:
        return True
    else:
        return False


def transfer_name(username, transfer_address, live=False):
    """ recursively transfer next pointers
    """

    key = 'u/' + username

    namecoind = get_namecoind(key)

    # -----------------------------
    def transfer_inner(key):

        namecoind = get_namecoind(key)

        if(live):
            print namecoind.name_transfer(key, transfer_address)
        else:
            print "Will transfer %s, to %s" % (key, transfer_address)

    transfer_inner(key)

    while(1):
        value = namecoind.name_show(key)['value']

        next_blob = None

        try:
            next_blob = value['next']
        except Exception as e:
            break

        if next_blob is not None:
            key = next_blob
            transfer_inner(key)


def transfer_key(username, transfer_address, live=False, server=None):
    """ transfer single key
    """

    key = 'u/' + username

    if server == None:
        namecoind = get_namecoind(key)
    else:
        namecoind = NamecoindClient(server)

    if(live):
        print namecoind.name_transfer(key, transfer_address)
    else:
        print "Will transfer %s to %s" % (key, transfer_address)


if __name__ == '__main__':

    live = False

    username = "clone66"
    address = 'NMCinvalid'

    transfer_name(username, address, live)
