#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Multithreaded JSONRPCServer example

"""

import sys
import os

SERVER_PORT = 8080

from SocketServer import ThreadingMixIn
from jsonrpclib.SimpleJSONRPCServer import SimpleJSONRPCServer

# hack around absolute paths
current_dir = os.path.abspath(os.path.dirname(__file__))
parent_dir = os.path.abspath(current_dir + "/../../")

sys.path.insert(0, parent_dir)

from server.resolver import profiles


class SimpleThreadedJSONRPCServer(ThreadingMixIn, SimpleJSONRPCServer):
    pass


def get_profile(username):
    profile = profiles.find_one({"username": username})['profile']

    return profile


def main():
    server = SimpleThreadedJSONRPCServer(('localhost', SERVER_PORT))
    server.register_function(get_profile)
    server.serve_forever()


if __name__ == '__main__':
    main()
