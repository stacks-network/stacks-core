#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Search
    ~~~~~

    copyright: (c) 2014-2017 by Blockstack Inc.
    copyright: (c) 2017 by Blockstack.org

This file is part of Blockstack.

    Blockstack is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Blockstack is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Blockstack. If not, see <http://www.gnu.org/licenses/>.
"""

import sys
import json

from .utils import validUsername
from .utils import get_json, config_log

from .config import RESOLVER_URL, ALL_USERS_ENDPOINT
from .config import BLOCKCHAIN_STATE_FILE, DHT_STATE_FILE

log = config_log(__name__)


def fetch_namespace():
    """
        Fetch all names in a namespace that should be indexed.
        Data is saved in: data/namespace_data.json
    """
    
    return


def fetch_profiles():
    """ 
        Fetch profile data using Blockstack Core and save the data.
        Data is saved in: data/profile_data.json
        Format of the data is <key, value>
        * key: fqu
        * value: json profile data
    """

    return
    

if __name__ == "__main__":

    if(len(sys.argv) < 2):
        print "Usage error"
        exit(0)

    option = sys.argv[1]

    if(option == '--fetch_namespace'):
        # Step 1
        flush_namespace()

    elif(option == '--fetch_profiles'):
        # Step 2
        fetch_profiles()

    else:
        print "Usage error"
