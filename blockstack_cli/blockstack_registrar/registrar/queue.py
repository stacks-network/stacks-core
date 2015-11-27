#!/usr/bin/env python
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

from .blockchain import get_block_height, txRejected
from .blockchain import get_tx_confirmations

from .utils import get_hash
from .utils import config_log
from .utils import pretty_print as pprint

from .config import DHT_IGNORE

log = config_log(__name__)


def alreadyinQueue(queue, fqu):

    check_queue = queue.find_one({"fqu": fqu})

    if check_queue is not None:
        return True

    return False


def add_to_queue(queue, fqu, payment_address=None, tx_hash=None,
                 owner_address=None, profile=None, profile_hash=None):

    new_entry = {}

    # required for all queues
    new_entry['fqu'] = fqu
    new_entry['payment_address'] = payment_address
    new_entry['tx_hash'] = tx_hash

    new_entry['block_height'] = get_block_height()

    # optional, depending on queue
    new_entry['owner_address'] = owner_address
    new_entry['profile'] = profile
    new_entry['profile_hash'] = profile_hash

    queue.save(new_entry)


def cleanup_rejected_tx(queue):

    for entry in queue.find(no_cursor_timeout=True):

        if txRejected(entry['tx_hash'], entry['block_height']):

            log.debug("TX rejected by network, removing TX: \
                      %s" % entry['tx_hash'])
            queue.remove({"fqu": entry['fqu']})


def display_queue(queue):

    for entry in queue.find():

        pprint(entry)

        try:
            confirmations = get_tx_confirmations(entry['tx_hash'])
        except:
            continue

        log.debug('-' * 5)
        log.debug("%s %s" % (queue.name, entry['fqu']))
        log.debug("(%s, confirmations %s)" % (entry['tx_hash'],
                                              confirmations))
        log.debug("payment: %s" % entry['payment_address'])
        log.debug("owner: %s" % entry['owner_address'])

        if entry['payment_address'] == entry['owner_address']:
            log.debug("problem")


def remove_from_queue(queue):

    for entry in queue.find():
        fqu = entry['fqu']

        log.debug("-" * 5)
        log.debug("checking: %s" % fqu)

        if 'state' in entry:
            if entry['state'] is 'preorder' or 'register':
                if usernameRegistered(fqu):
                    log.debug("Record on blockchain, removing from queue: %s"
                              % fqu)

                    queue.remove({"fqu": fqu, "state": entry['state']})
                else:
                    log.debug("(%s, %s, confirmations %s)" %
                              (entry['state'], entry['tx_hash'],
                               get_tx_confirmations(entry['tx_hash'])))

        if entry['fqu'] in DHT_IGNORE:
            continue

        """
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
            """
