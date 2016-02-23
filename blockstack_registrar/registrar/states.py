# -*- coding: utf-8 -*-
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

from .network import get_blockchain_record, get_dht_profile
from .utils import get_hash
from .utils import config_log

log = config_log(__name__)

"""
    registrar/states defines the different states a name can be in
"""


def nameRegistered(fqu):
    """ return True if @fqu registered on blockchain
    """

    data = get_blockchain_record(fqu)

    if "first_registered" in data:
        return True
    else:
        return False


def profileonBlockchain(fqu, profile):
    """ return True if hash(@profile) published on blockchain
    """

    record = get_blockchain_record(fqu)

    profile_hash = get_hash(profile)

    if 'value_hash' in record and record['value_hash'] == profile_hash:
        # if hash of profile is in correct
        return True

    return False


def profileonDHT(fqu, profile):
    """ return True if hash(@profile) published on DHT
    """

    profile_hash = get_hash(profile)

    dht_profile = get_dht_profile(fqu)

    if dht_profile is None:
        return False
    else:
        if get_hash(dht_profile) == profile_hash:
            return True
        else:
            return False


def profilePublished(fqu, profile):
    """ return True if:
        1) hash(@profile) published on blockchain, and
        2) @profile published on DHT
    """

    if profileonBlockchain(fqu, profile) and profileonDHT(fqu, profile):
        return True
    else:
        return False


def ownerName(fqu, address):
    """ return True if @btc_address owns @fqu
    """

    record = get_blockchain_record(fqu)

    if 'address' in record and record['address'] == address:
        return True
    else:
        return False


def registrationComplete(fqu, profile, transfer_address):
    """ return True if properly registered

        Three conditions that need to be met:
        1) @fqu is registered on blockchain
        2) correct hash(@profile) is published
        3) @owner_address owns the fqu
    """

    if not nameRegistered(fqu):
        return False

    if not profilePublished(fqu, profile):
        return False

    if not ownerName(fqu, transfer_address):
        return False

    return True
