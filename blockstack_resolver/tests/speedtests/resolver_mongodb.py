#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
JSON-RPC Resolver w/ MongoDB

"""

import sys
import os

SERVER_PORT = 8080
VALID_BLOCKS = 36000

from SocketServer import ThreadingMixIn
from jsonrpclib.SimpleJSONRPCServer import SimpleJSONRPCServer

# hack around absolute paths
current_dir = os.path.abspath(os.path.dirname(__file__))
parent_dir = os.path.abspath(current_dir + "/../../")

sys.path.insert(0, parent_dir)

from server.resolver import profiles, namespaces


class SimpleThreadedJSONRPCServer(ThreadingMixIn, SimpleJSONRPCServer):
    pass


def get_profile(username):
    profile = profiles.find_one({"username": username})['profile']

    return profile


def get_namespace():

    namespace = namespaces.find_one({"blocks": VALID_BLOCKS})

    return namespace['profiles']


def main():
    server = SimpleThreadedJSONRPCServer(('localhost', SERVER_PORT))
    server.register_function(get_profile)
    server.register_function(get_namespace)
    server.serve_forever()


if __name__ == '__main__':
    main()
