#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -----------------------
# Copyright 2015 Halfmoon Labs, Inc.
# All Rights Reserved
# -----------------------

from .nameops import get_namecoind


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


def name_transfer(passname, transfer_address, live=False):

    key = 'u/' + passname
    namecoind = get_namecoind(key)

    # -----------------------------
    def name_transfer_inner(key):

        if(live):
            print namecoind.name_transfer(key, transfer_address)
        else:
            print "Will transfer %s, to %s" % (key, transfer_address)

    name_transfer_inner(key)

    while(1):
        value = namecoind.name_show(key)['value']

        next_blob = None

        try:
            next_blob = value['next']
        except Exception as e:
            break

        if next_blob is not None:
            key = next_blob
            name_transfer_inner(key)


if __name__ == '__main__':

    live = False

    username = "clone66"
    address = 'NCinvalid'

    name_transfer(username, address, live)
