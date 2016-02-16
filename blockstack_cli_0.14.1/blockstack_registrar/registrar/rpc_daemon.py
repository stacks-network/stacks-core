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

import os
import sys
import signal
from time import sleep
import json
import xmlrpclib

from SimpleXMLRPCServer import SimpleXMLRPCServer
from config import REGISTRAR_IP, REGISTRAR_PORT

from .queue import get_queue_state, alreadyinQueue
from .queue import add_to_queue, pending_queue
from .queue import preorder_queue
from .queue import alreadyProcessing

from .nameops import preorder, register
from .subsidized_nameops import subsidized_update, subsidized_transfer

from .states import nameRegistered
from .states import profileonBlockchain, profileonDHT
from .states import ownerName

from .blockchain import get_block_height

from .crypto.utils import get_address_from_privkey

from .network import write_dht_profile

from .config import SLEEP_INTERVAL


FILE_NAME = 'rpc_daemon.py'

server = None


class RegistrarRPCServer(SimpleXMLRPCServer):

    finished = False

    payment_address = None
    owner_address = None

    payment_privkey = None
    owner_privkey = None

    def register_signal(self, signum):
        signal.signal(signum, self.signal_handler)

    def signal_handler(self, signum, frame):
        print "Caught signal", signum
        self.shutdown()
        self.server_close()

    def shutdown(self):
        self.finished = True
        return 1

    def serve_forever(self):
        while not self.finished:
            try:
                server.handle_request()
            except:
                print "Exiting server."

    def ping(self):
        """ Check if RPC daemon is alive
        """

        data = {'status': 'alive'}
        return data

    def state(self):
        """ Return status on current registrations
        """

        data = get_queue_state()
        return json.dumps(data)

    def set_wallet(self, payment_keypair, owner_keypair):
        """ Keeps payment privkey in memory (instead of disk)
            for the time that server is alive
        """

        self.payment_address = payment_keypair[0]
        self.owner_address = owner_keypair[0]

        self.payment_privkey = payment_keypair[1]
        self.owner_privkey = owner_keypair[1]

        data = {}
        data['success'] = True
        return data

    def get_wallet(self):
        """ Keeps payment privkey in memory (instead of disk)
            for the time that server is alive
        """

        data = {}
        data['payment_address'] = self.payment_address
        data['owner_address'] = self.owner_address

        data['payment_privkey'] = self.payment_privkey
        data['owner_privkey'] = self.owner_privkey
        return json.dumps(data)

    def register(self, fqu, profile):
        """ Enter a new registration in queue
            The entered registration is picked up
            by the monitor process.
        """

        data = {}

        if self.payment_privkey is None or self.owner_privkey is None:
            data['success'] = False
            data['error'] = "Wallet is not unlocked."
            return data

        if alreadyProcessing(fqu):
            data['success'] = False
            data['error'] = "Already in queue."
            return data

        add_to_queue(pending_queue, fqu,
                     profile=profile,
                     payment_address=self.payment_address,
                     owner_address=self.owner_address)

        data['success'] = True
        data['message'] = "Added to registration queue. Takes several hours. You can check status at anytime."
        return data


def init_rpc_daemon():

    global server

    server = RegistrarRPCServer((REGISTRAR_IP, REGISTRAR_PORT), logRequests=False)

    server.register_function(server.ping)
    server.register_function(server.state)
    server.register_function(server.register)
    server.register_function(server.get_wallet)
    server.register_function(server.set_wallet)
    server.register_function(server.shutdown)

    server.register_signal(signal.SIGHUP)
    server.register_signal(signal.SIGINT)
    server.register_signal(signal.SIGTSTP)


def start_rpc_daemon():

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


def process_nameop(fqu, profile, payment_privkey, owner_privkey,
                   payment_address, owner_address,
                   transfer_address):
    """ Process nameops based on what stage they are in
    """

    if not nameRegistered(fqu):
        if alreadyinQueue(preorder_queue, fqu):
            return register(fqu, payment_privkey=payment_privkey,
                            owner_address=owner_address)
        else:
            return preorder(fqu, None, owner_address,
                            payment_privkey=payment_privkey)

    elif not profileonBlockchain(fqu, profile):
        return subsidized_update(fqu, profile, owner_privkey, payment_address,
                                 payment_privkey=payment_privkey)

    elif not profileonDHT(fqu, profile):
        return write_dht_profile(profile)

    elif not ownerName(fqu, transfer_address):
        return subsidized_transfer(fqu, transfer_address, owner_privkey,
                                   payment_address,
                                   payment_privkey=payment_privkey)


def start_monitor():

    current_block = get_block_height()
    last_block = current_block - 1

    RPC_DAEMON = 'http://' + REGISTRAR_IP + ':' + str(REGISTRAR_PORT)
    wallet_data = None

    while(1):

        try:
            proxy = xmlrpclib.ServerProxy(RPC_DAEMON)
            wallet_data = json.loads(proxy.get_wallet())

        except:
            # if rpc daemon went offline, break monitoring loop as well
            # print "RPC daemon exited. Exiting."
            break

        try:
            if last_block == current_block:
                sleep(SLEEP_INTERVAL)
                current_block = get_block_height()
            else:

                # monitor process reads from pending queue
                # but never writes to it
                for entry in pending_queue.find():
                    resp = process_nameop(entry['fqu'], entry['profile'],
                                          wallet_data['payment_privkey'],
                                          wallet_data['owner_privkey'],
                                          wallet_data['payment_address'],
                                          wallet_data['owner_address'],
                                          entry['transfer_address'])

                last_block = current_block

                if current_block % 10 == 0:
                    # exit daemons, if no new requests for a while
                    if len(get_queue_state()) == 0:
                        proxy.shutdown()

        except KeyboardInterrupt:
            print "\nExiting."
            break


def background_process(start_command):

    current_dir = os.path.abspath(os.path.dirname(__file__))
    parent_dir = os.path.abspath(current_dir + "/../")
    os.chdir(parent_dir)

    command = sys.executable + ' -m registrar.rpc_daemon '
    command += start_command + ' &'
    os.system(command)

if __name__ == '__main__':

    arg = None

    try:
        arg = sys.argv[1]
    except:
        pass

    if arg == "start_daemon":
        init_rpc_daemon()
        start_rpc_daemon()
    elif arg == "start_monitor":
        start_monitor()
    else:
        print "Enter either start_daemon or start_monitor"
