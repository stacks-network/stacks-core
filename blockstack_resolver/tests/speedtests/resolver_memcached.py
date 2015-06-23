#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
JSON-RPC Resolver w/ memcached

"""

import sys
import os

# hack around absolute paths
current_dir = os.path.abspath(os.path.dirname(__file__))
parent_dir = os.path.abspath(current_dir + "/../../")

sys.path.insert(0, parent_dir)

from server.config import MEMCACHED_SERVERS, MEMCACHED_USERNAME, MEMCACHED_PASSWORD

import pylibmc
mc = pylibmc.Client(MEMCACHED_SERVERS, binary=True,
                    username=MEMCACHED_USERNAME, password=MEMCACHED_PASSWORD,
                    behaviors={"no_block": True,
                               "connect_timeout": 500})

SERVER_PORT = 8080

from SocketServer import ThreadingMixIn
from jsonrpclib.SimpleJSONRPCServer import SimpleJSONRPCServer


class SimpleThreadedJSONRPCServer(ThreadingMixIn, SimpleJSONRPCServer):
    pass


def get_profile(username):
    return mc.get("profile_" + str(username))


def main():
    server = SimpleThreadedJSONRPCServer(('localhost', SERVER_PORT))
    server.register_function(get_profile)
    server.serve_forever()


if __name__ == '__main__':
    main()
