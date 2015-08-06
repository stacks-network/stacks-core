#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Resolver
    ~~~~~

    copyright: (c) 2014 by Halfmoon Labs, Inc.
    copyright: (c) 2015 by Blockstack.org

This file is part of Resolver.

    Resolver is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Resolver is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Resolver.  If not, see <http://www.gnu.org/licenses/>.
"""

import sys
import os

from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException

proxy = AuthServiceProxy('http://none:none@localhost:8080')

# hack around absolute paths
current_dir = os.path.abspath(os.path.dirname(__file__))
parent_dir = os.path.abspath(current_dir + "/../")

sys.path.insert(0, parent_dir)

from server.resolver import namespaces


def get_profile(username):
    return proxy.get_profile(username)


def get_namespace():
    return proxy.get_namespace()

# -----------------------------------
if __name__ == '__main__':

    namespace = namespaces.find_one({"blocks": 36000})

    usernames = namespace['namespace']

    #for username in usernames:
    #    print get_profile(username)

    print get_namespace()