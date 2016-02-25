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
import socket

from ConfigParser import SafeConfigParser

from SimpleXMLRPCServer import SimpleXMLRPCServer
from config import REGISTRAR_IP, REGISTRAR_PORT

from .queue import get_queue_state, alreadyinQueue
from .queue import add_to_queue, pending_queue
from .queue import get_preorder_queue
from .queue import get_update_queue, get_transfer_queue
from .queue import cleanup_all_queues

from .nameops import preorder, register
from .subsidized_nameops import subsidized_update, subsidized_transfer

from .states import nameRegistered
from .states import profileonBlockchain, profileonDHT
from .states import ownerName

from .blockchain import get_block_height

from .crypto.utils import get_address_from_privkey, aes_decrypt, aes_encrypt

from .network import write_dht_profile

from .config import SLEEP_INTERVAL

import logging
logging.disable(logging.CRITICAL)

FILE_NAME = 'rpc_daemon.py'
CONFIG_DIR_INIT = "~/.blockstack"
CONFIG_DIR = os.path.expanduser(CONFIG_DIR_INIT)
CONFIG_PATH = os.path.join(CONFIG_DIR, "client.ini")

server = None


def get_rpc_token(path=CONFIG_PATH):

    parser = SafeConfigParser()

    try:
        parser.read(path)
    except Exception, e:
        log.exception(e)
        return None

    if parser.has_section("blockstack-client"):

        if parser.has_option("blockstack-client", "rpc_token"):
            return parser.get("blockstack-client", "rpc_token")
    return None


class RegistrarRPCServer(SimpleXMLRPCServer):

    finished = False

    payment_address = None
    owner_address = None

    encrypted_payment_privkey = None
    encrypted_owner_privkey = None

    server_started_at = None

    def __init__(self, server_info):

        # log when rpc daemon was started
        self.server_started_at = get_block_height()

        SimpleXMLRPCServer.__init__(self, server_info, logRequests=False)

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

        rpc_token = get_rpc_token()

        self.payment_address = payment_keypair[0]
        self.owner_address = owner_keypair[0]

        self.encrypted_payment_privkey = aes_encrypt(payment_keypair[1],
                                                     rpc_token)
        self.encrypted_owner_privkey = aes_encrypt(owner_keypair[1],
                                                   rpc_token)

        data = {}
        data['success'] = True
        return data

    def get_start_block(self):
        """ Get the block at which rpc daemon was started
        """
        return self.server_started_at

    def get_payment_privkey(self):

        rpc_token = get_rpc_token()

        if self.encrypted_payment_privkey is None:
            return None

        privkey = aes_decrypt(self.encrypted_payment_privkey, rpc_token)

        return str(privkey)

    def get_owner_privkey(self):

        rpc_token = get_rpc_token()

        if self.encrypted_owner_privkey is None:
            return None

        privkey = aes_decrypt(self.encrypted_owner_privkey, rpc_token)

        return str(privkey)

    def get_wallet(self, rpc_token=None):
        """ Keeps payment privkey in memory (instead of disk)
            for the time that server is alive
        """

        data = {}
        valid_rpc_token = get_rpc_token()

        if str(valid_rpc_token) != str(rpc_token):
            data['error'] = "Incorrect RPC token"
            return json.dumps(data)

        data['payment_address'] = self.payment_address
        data['owner_address'] = self.owner_address

        data['payment_privkey'] = self.get_payment_privkey()
        data['owner_privkey'] = self.get_owner_privkey()

        return json.dumps(data)

    def preorder(self, fqu):
        """ Send preorder transaction and enter it in queue
            The entered registration is picked up
            by the monitor process.
        """

        data = {}

        if self.payment_address is None or self.owner_address is None:
            data['success'] = False
            data['error'] = "Wallet is not unlocked."
            return data

        preorder_queue = get_preorder_queue()
        if alreadyinQueue(preorder_queue, fqu):
            data['success'] = False
            data['error'] = "Already in queue."
            return data

        resp = None

        payment_privkey = self.get_payment_privkey()

        if not nameRegistered(fqu):
            resp = preorder(fqu, None, self.owner_address,
                            payment_privkey=payment_privkey)

        if resp:
            data['success'] = True
            data['message'] = "The name has been queued up for registration and"
            data['message'] += " will take a few hours to go through. You can"
            data['message'] += " check on the status at any time by running"
            data['message'] += " 'blockstack info'."
        else:
            data['success'] = False
            data['message'] = "Couldn't broadcast transaction. You can try again."
        return data

    def update(self, fqu, profile):
        """ Send update transaction and write data to DHT.
        """

        data = {}

        if self.payment_address is None or self.owner_address is None:
            data['success'] = False
            data['error'] = "Wallet is not unlocked."
            return data

        update_queue = get_update_queue()
        if alreadyinQueue(update_queue, fqu):
            data['success'] = False
            data['error'] = "Already in queue."
            return data

        resp = None

        payment_privkey = self.get_payment_privkey()
        owner_privkey = self.get_owner_privkey()

        if not profileonBlockchain(fqu, profile):
            resp = subsidized_update(fqu, profile, owner_privkey,
                                     self.payment_address,
                                     payment_privkey=payment_privkey)

            if not profileonDHT(fqu, profile):
                dht_resp = write_dht_profile(profile)

        if resp:
            data['success'] = True
            data['message'] = "The name has been queued up for update and"
            data['message'] += " will take ~1 hour to process. You can"
            data['message'] += " check on the status at any time by running"
            data['message'] += " 'blockstack info'."
        else:
            data['success'] = False
            data['message'] = "Couldn't broadcast transaction. You can try again."
        return data

    def transfer(self, fqu, transfer_address):
        """ Send transfer transaction.
        """

        data = {}

        if self.payment_address is None or self.owner_address is None:
            data['success'] = False
            data['error'] = "Wallet is not unlocked."
            return data

        transfer_queue = get_transfer_queue()
        if alreadyinQueue(transfer_queue, fqu):
            data['success'] = False
            data['error'] = "Already in queue."
            return data

        payment_privkey = self.get_payment_privkey()
        owner_privkey = self.get_owner_privkey()

        resp = None
        if not ownerName(fqu, transfer_address):
            resp = subsidized_transfer(fqu, transfer_address,
                                       owner_privkey,
                                       self.payment_address,
                                       payment_privkey=payment_privkey)

        if resp:
            data['success'] = True
            data['message'] = "The name has been queued up for transfer and"
            data['message'] += " will take ~1 hour to process. You can"
            data['message'] += " check on the status at any time by running"
            data['message'] += " 'blockstack info'."
        else:
            data['success'] = False
            data['message'] = "Couldn't broadcast transaction. You can try again."
        return data


def init_rpc_daemon():

    global server

    server = RegistrarRPCServer((REGISTRAR_IP, REGISTRAR_PORT))

    server.register_function(server.ping)
    server.register_function(server.state)
    server.register_function(server.preorder)
    server.register_function(server.update)
    server.register_function(server.transfer)
    server.register_function(server.get_wallet)
    server.register_function(server.set_wallet)
    server.register_function(server.get_start_block)
    server.register_function(server.shutdown)

    server.register_signal(signal.SIGHUP)
    server.register_signal(signal.SIGINT)
    server.register_signal(signal.SIGTSTP)

    # increase the default timeout
    socket.setdefaulttimeout(30)


def start_rpc_daemon():

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


def process_register(fqu, payment_privkey, owner_address):

    if not nameRegistered(fqu):
        preorder_queue = get_preorder_queue()
        if alreadyinQueue(preorder_queue, fqu):
            return register(fqu, payment_privkey=payment_privkey,
                            owner_address=owner_address)


def get_current_block():

    try:
        current_block = get_block_height()
    except:
        current_block = 5

    if current_block is None:
        current_block = 5

    return current_block


def start_monitor():

    current_block = get_current_block()
    last_block = current_block - 1

    RPC_DAEMON = 'http://' + REGISTRAR_IP + ':' + str(REGISTRAR_PORT)
    wallet_data = None

    while(1):

        try:
            rpc_token = get_rpc_token()
            proxy = xmlrpclib.ServerProxy(RPC_DAEMON)
            wallet_data = json.loads(proxy.get_wallet(rpc_token))

            while(wallet_data['owner_address'] is None):
                rpc_token = get_rpc_token()
                proxy = xmlrpclib.ServerProxy(RPC_DAEMON)
                wallet_data = json.loads(proxy.get_wallet(rpc_token))
                sleep(SLEEP_INTERVAL)

        except:
            # if rpc daemon went offline, break monitoring loop as well
            # print "RPC daemon exited. Exiting." 
            break

        try:
            if last_block == current_block:
                sleep(SLEEP_INTERVAL)
                current_block = get_current_block()
            else:

                # monitor process reads from preorder queue
                # but never writes to it
                preorder_queue = get_preorder_queue()
                for entry in preorder_queue.find():

                    try:
                        resp = process_register(entry['fqu'],
                                                wallet_data['payment_privkey'],
                                                wallet_data['owner_address'])
                    except:
                        pass

                last_block = current_block

                if current_block % 10 == 0:
                    # exit daemons, if no new requests for a while
                    server_started_at = proxy.get_start_block()

                    if current_block - server_started_at > 10:
                        if len(get_queue_state()) == 0:
                            proxy.shutdown()

                cleanup_all_queues()

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
