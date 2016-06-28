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

import accounts
import client
import config
import data
import keys
import profile
import proxy
import user
import snv
import spv 
import rpc
import storage

from proxy import BlockstackRPCClient, get_default_proxy, set_default_proxy, json_traceback
from proxy import getinfo, ping, get_name_cost, get_namespace_cost, get_all_names, get_names_in_namespace, \
        get_names_owned_by_address, get_consensus_at, get_consensus_range, get_nameops_at, \
        get_nameops_hash_at, get_name_blockchain_record, get_namespace_blockchain_record
        
from keys import make_wallet_keys, get_owner_keypair, get_data_keypair, get_payment_keypair

from client import session, get_default_proxy, set_default_proxy, register_storage, load_storage

from snv import snv_lookup, lookup_snv
from data import get_immutable, get_immutable_by_name, get_mutable, put_immutable, put_mutable, delete_immutable, \
        delete_mutable, list_mutable_data, list_immutable_data, list_immutable_data_history, list_update_history, list_zonefile_history
from data import blockstack_url_fetch as fetch_data
from data import data_get, data_put, data_delete, data_list
from data import set_data_pubkey
from storage import get_announcement, put_announcement
from profile import get_name_profile, get_name_zonefile, zonefile_publish, get_and_migrate_profile
from accounts import list_accounts, get_account, put_account, delete_account

from config import get_logger, get_config, CONFIG_PATH, CONFIG_FILENAME, get_utxo_provider_client, get_tx_broadcaster, default_bitcoind_opts

from storage import blockstack_mutable_data_url as make_mutable_data_url
from storage import blockstack_mutable_data_url_parse as parse_mutable_data_url
from storage import blockstack_immutable_data_url as make_immutable_data_url 
from storage import blockstack_immutable_data_url_parse as parse_immutable_data_url

from storage import blockstack_data_url_parse as parse_data_url
from storage import blockstack_data_url as make_data_url
from storage import get_storage_handlers, hash_zonefile

from storage import BlockstackURLHandle, BlockstackHandler, get_data_hash, get_blockchain_compat_hash, get_zonefile_data_hash
from storage import parse_mutable_data as parse_signed_data

from config import USER_ZONEFILE_TTL

from wallet import get_payment_addresses_and_balances, get_owner_addresses_and_names, dump_wallet, load_wallet, get_wallet

from user import is_user_zonefile, user_zonefile_data_pubkey

from operations import *
from backend.nameops import *
