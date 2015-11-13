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

from .nameops import get_blockchain_record
from .nameops import get_dht_profile, write_dht_profile
from .nameops import usernameRegistered

from .blockchain import get_block_height, txRejected

from .utils import get_hash
from .utils import config_log

from .config import DHT_IGNORE

log = config_log(__name__)


def alreadyinQueue(queue, fqu):

    check_queue = queue.find_one({"fqu": fqu})

    if check_queue is not None:
        return True

    return False


def add_to_queue(queue, fqu, profile, profile_hash, btc_address, tx_hash):

    new_entry = {}
    new_entry["fqu"] = fqu
    new_entry['tx_hash'] = tx_hash
    new_entry['profile_hash'] = profile_hash
    new_entry['profile'] = profile
    new_entry['btc_address'] = btc_address
    new_entry['block_height'] = get_block_height()

    queue.save(new_entry)


def cleanup_queue(queue):

    for entry in queue.find(no_cursor_timeout=True):

        log.debug("checking: %s" % entry['fqu'])

        if entry['fqu'] in DHT_IGNORE:
            continue

        if usernameRegistered(entry['fqu']):

            record = get_blockchain_record(entry['fqu'])

            if record['value_hash'] == entry['profile_hash']:

                log.debug("Registered on blockchain: %s" % entry['fqu'])

                profile = get_dht_profile(entry['fqu'])

                if profile is None:
                    log.debug("data not in DHT")
                    write_dht_profile(entry['profile'])

                else:
                    if get_hash(profile) == entry['profile_hash']:
                        log.debug("data in DHT")
                        log.debug("removing from queue: %s" % entry['fqu'])
                        queue.remove({"fqu": entry['fqu']})

        if txRejected(entry['tx_hash'], entry['block_height']):

            log.debug("TX rejected by network, removing TX: \
                      %s" % entry['tx_hash'])
            queue.remove({"fqu": entry['fqu']})
