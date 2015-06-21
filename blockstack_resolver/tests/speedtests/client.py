#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os

#hack around absolute paths
current_dir =  os.path.abspath(os.path.dirname(__file__))
parent_dir = os.path.abspath(current_dir + "/../")

sys.path.insert(0, parent_dir)

from server.resolver import namespaces

import zerorpc

from multiprocessing.pool import Pool

c = zerorpc.Client()
c.connect("tcp://127.0.0.1:4242")

import logging
logger = logging.getLogger()
logger.disabled = True
logger.propagate = False


def fetch_profile(username):

    print c.get_profile(username)


# -----------------------------------
if __name__ == '__main__':

    namespace = namespaces.find_one({"blocks": 36000})

    usernames = namespace['namespace']

    for username in usernames:
        fetch_profile(username)

    #pool = Pool(100)

    #pool.map(fetch_profile, usernames)