#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
    Blockstack-client
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016 by Blockstack.org

    This file is part of Blockstack-client.

    Blockstack-client is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Blockstack-client is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with Blockstack-client. If not, see <http://www.gnu.org/licenses/>.
"""

from .insight_api import InsightClient, _get_unspents, _broadcast_transaction

BLOCKSTACK_EXPLORER_URL = "https://explorer.blockstack.org"

class BlockstackExplorerClient(InsightClient):
    def __init__(self, url=BLOCKSTACK_EXPLORER_URL, min_confirmations=None):
        super(BlockstackExplorerClient, self).__init__(url, min_confirmations=min_confirmations)


get_unspents = _get_unspents
broadcast_transaction = _broadcast_transaction

