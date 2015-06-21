#!/usr/bin/env python
# -*- coding: utf-8 -*-

import zerorpc

import sys
import os

# hack around absolute paths
current_dir = os.path.abspath(os.path.dirname(__file__))
parent_dir = os.path.abspath(current_dir + "/../")

sys.path.insert(0, parent_dir)

from server.config import MEMCACHED_SERVERS, MEMCACHED_USERNAME, MEMCACHED_PASSWORD

import pylibmc
mc = pylibmc.Client(MEMCACHED_SERVERS, binary=True,
                    username=MEMCACHED_USERNAME, password=MEMCACHED_PASSWORD,
                    behaviors={"no_block": True,
                               "connect_timeout": 500})


class ResolverRPC(object):
    def get_profile(self, username):
        profile = mc.get("profile_" + str(username))

        return profile

s = zerorpc.Server(ResolverRPC(), pool_size=100)
s.bind("tcp://0.0.0.0:4242")
s.run()
