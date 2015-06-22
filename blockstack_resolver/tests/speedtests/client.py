#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
from multiprocessing.pool import Pool

from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException

proxy = AuthServiceProxy('http://none:none@localhost:8080')

# hack around absolute paths
current_dir = os.path.abspath(os.path.dirname(__file__))
parent_dir = os.path.abspath(current_dir + "/../")

sys.path.insert(0, parent_dir)

from server.resolver import namespaces


def get_data(username):
    return proxy.get_profile(username)

# -----------------------------------
if __name__ == '__main__':

    namespace = namespaces.find_one({"blocks": 36000})

    usernames = namespace['namespace']

    for username in usernames:
        print get_data(username)
