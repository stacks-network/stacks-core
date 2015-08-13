#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstore-client
    ~~~~~
    copyright: (c) 2014 by Halfmoon Labs, Inc.
    copyright: (c) 2015 by Blockstack.org
    
    This file is part of Blockstore-client.
    
    Blockstore-client is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    
    Blockstore-client is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with Blockstore-client.  If not, see <http://www.gnu.org/licenses/>.
"""

BLOCKSTORED_PORT = 6264
BLOCKSTORED_SERVER = "127.0.0.1"
DEBUG = True
VERSION = "v0.01-beta"
MAX_RPC_LEN = 1024 * 1024 * 1024

import logging

log = logging.getLogger()
log.setLevel(logging.DEBUG if DEBUG else logging.INFO)
console = logging.StreamHandler()
console.setLevel(logging.DEBUG if DEBUG else logging.INFO)
log_format = ('[%(levelname)s] [%(module)s:%(lineno)d] %(message)s' if DEBUG else '%(message)s')
formatter = logging.Formatter( log_format )
console.setFormatter(formatter)
log.addHandler(console)

