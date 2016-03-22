#!/usr/bin/env python
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
    along with Blockstack-client.  If not, see <http://www.gnu.org/licenses/>.
"""

import client
import config
import user
import drivers
import spv 
import storage

from client import getinfo, lookup, get_name_zonefile, ping, get_name_blockchain_record, get_namespace_blockchain_record, snv_lookup, lookup_snv
from client import preorder, update, transfer, renew, revoke, get_nameops_at
from client import namespace_preorder, namespace_reveal, namespace_ready
from client import get_immutable, get_mutable
from client import put_immutable, put_mutable, delete_immutable, delete_mutable
from client import list_mutable_data as list_mutable
from client import list_immutable_data as list_immutable
from client import blockstack_data_url_fetch as fetch_data
from client import session, register_storage

from storage import blockstack_mutable_data_url as make_mutable_data_url
from storage import blockstack_mutable_data_url_parse as parse_mutable_data_url
from storage import blockstack_immutable_data_url as make_immutable_data_url 
from storage import blockstack_immutable_data_url_parse as parse_immutable_data_url

from storage import BlockstackURLHandle, BlockstackHandler 
