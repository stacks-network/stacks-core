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

from ConfigParser import SafeConfigParser

from virtualchain import AuthServiceProxy

from backend.utxo.blockstack_core import BlockstackCoreUTXOClient
from backend.utxo.blockcypher import BlockcypherClient
from backend.utxo.bitcoind_utxo import BitcoindClient
from backend.utxo.blockchain_info import BlockchainInfoClient
from backend.utxo.blockstack_explorer import BlockstackExplorerClient, BLOCKSTACK_EXPLORER_URL
from backend.utxo.blockstack_utxo import BlockstackUTXOClient, BLOCKSTACK_UTXO_URL

from backend.utxo.blockstack_core import get_unspents as blockstack_core_get_unspents
from backend.utxo.blockstack_core import broadcast_transaction as blockstack_core_broadcast_transaction

from backend.utxo.blockcypher import get_unspents as blockcypher_get_unspents
from backend.utxo.blockcypher import broadcast_transaction as blockcypher_broadcast_transaction

from backend.utxo.bitcoind_utxo import get_unspents as bitcoind_utxo_get_unspents
from backend.utxo.bitcoind_utxo import broadcast_transaction as bitcoind_utxo_broadcast_transaction

from backend.utxo.blockchain_info import get_unspents as blockchain_info_get_unspents
from backend.utxo.blockchain_info import broadcast_transaction as blockchain_info_broadcast_transaction

from backend.utxo.blockstack_explorer import get_unspents as blockstack_explorer_get_unspents
from backend.utxo.blockstack_explorer import broadcast_transaction as blockstack_explorer_broadcast_transaction

from backend.utxo.blockstack_utxo import get_unspents as blockstack_utxo_get_unspents
from backend.utxo.blockstack_utxo import broadcast_transaction as blockstack_utxo_broadcast_transaction

from constants import TX_MIN_CONFIRMATIONS

DEBUG = True
FIRST_BLOCK_MAINNET = 373601        # well-known value for blockstack-core; doesn't ever change


SUPPORTED_UTXO_PROVIDERS = [ "blockcypher", "blockchain_info", "bitcoind_utxo", "blockstack_core", "blockstack_explorer", "blockstack_utxo" ]
SUPPORTED_UTXO_PARAMS = {
    "blockcypher": ["api_token"],
    "blockchain_info": ["api_token"],
    "bitcoind_utxo": ["rpc_username", "rpc_password", "server", "port", "use_https", "version_byte"],
    "blockstack_core": ["server", "port"],
    "blockstack_explorer": ["url"],
    'blockstack_utxo': ["url"],
}

SUPPORTED_UTXO_PROMPT_MESSAGES = {
    'blockcypher': 'Please enter your Blockcypher API token.',
    'blockchain_info': 'Please enter your blockchain.info API token.',
    'bitcoind_utxo': 'Please enter your fully-indexed bitcoind node information.',
    'blockstack_core': 'Please enter your Blockstack Core node info.',
    'blockstack_explorer': 'Please enter your Blockstack Explorer info.',
    'blockstack_utxo': 'Please enter your Blockstack UTXO service info',
}



def default_utxo_provider_opts( utxo_provider, config_file=None ):
   """
   Get the default options for a utxo provider.
   """

   if utxo_provider == "blockcypher":
       return default_blockcypher_opts( config_file=config_file )

   elif utxo_provider == "blockchain_info":
       return default_blockchain_info_opts( config_file=config_file )

   elif utxo_provider == "bitcoind_utxo":
       return default_bitcoind_utxo_opts( config_file=config_file )

   elif utxo_provider == "blockstack_core":
       return default_blockstack_core_opts( config_file=config_file )
    
   elif utxo_provider == "blockstack_explorer":
       return default_blockstack_explorer_opts( config_file=config_file )

   elif utxo_provider == 'blockstack_utxo':
       return default_blockstack_utxo_opts( config_file=config_file )

   else:
       raise Exception("Unsupported UTXO provider '%s'" % utxo_provider)


def find_service_provider_sections( config_file, utxo_provider_name ):
    """
    Find the section of the config file with 'utxo_provider = ' set
    """
    parser = SafeConfigParser()
    parser.read( config_file )
    secs = []

    for sec in parser.sections():
        if parser.has_option(sec, 'utxo_provider') and parser.get(sec, 'utxo_provider') == utxo_provider_name:
            secs.append( sec )

    return secs


def default_blockcypher_opts( config_file=None ):
   """
   Get our default blockcypher.com options from a config file.
   Selects options from the first such section.
   """

   if config_file is None:
       raise Exception("No config file given")

   parser = SafeConfigParser()
   parser.read( config_file )

   blockcypher_opts = {}

   api_token = None
   provider_secs = find_service_provider_sections(config_file, 'blockcypher')
   if len(provider_secs) > 0:
       provider_sec = provider_secs[0]

       if parser.has_option(provider_sec, 'api_token'):
          api_token = parser.get(provider_sec, 'api_token')

   blockcypher_opts = {
       'api_token': api_token
   }

   # strip Nones
   for (k, v) in blockcypher_opts.items():
      if v is None:
         # token is optional 
         if k == 'api_token':
             blockcypher_opts[k] = ''
         else:
             del blockcypher_opts[k]

   blockcypher_opts['utxo_provider'] = 'blockcypher'
   return blockcypher_opts


def default_blockchain_info_opts( config_file=None ):
   """
   Get our default blockchain.info options from a config file.
   """

   if config_file is None:
       raise Exception("No config file given")

   parser = SafeConfigParser()
   parser.read( config_file )

   blockchain_info_opts = {}

   api_token = None
   provider_secs = find_service_provider_sections(config_file, 'blockchain_info')
   if len(provider_secs) > 0:
       provider_sec = provider_secs[0]

       if parser.has_option(provider_sec, "api_token"):
           api_token = parser.get(provider_sec, "api_token")

   blockchain_info_opts = {
       "api_token": api_token
   }

   # strip Nones
   for (k, v) in blockchain_info_opts.items():
      if v is None:
         del blockchain_info_opts[k]

   blockchain_info_opts['utxo_provider'] = 'blockchain_info'
   return blockchain_info_opts


def default_bitcoind_utxo_opts( config_file=None ):
   """
   Get our default bitcoind UTXO options from a config file.
   """

   if config_file is None:
       raise Exception("No config file given")

   parser = SafeConfigParser()
   parser.read( config_file )

   bitcoind_utxo_opts = {}

   server = None
   port = None
   rpc_username = None
   rpc_password = None
   use_https = None
   version_byte = None
   
   provider_secs = find_service_provider_sections(config_file, 'bitcoind_utxo')
   if len(provider_secs) > 0:
       provider_sec = provider_secs[0]

       if parser.has_option(provider_sec, "server"):
           server = parser.get(provider_sec, "server")

       if parser.has_option(provider_sec, "port"):
           port = int( parser.get(provider_sec, "port") )

       if parser.has_option(provider_sec, "rpc_username"):
           rpc_username = parser.get(provider_sec, "rpc_username")

       if parser.has_option(provider_sec, "rpc_password"):
           rpc_password = parser.get(provider_sec, "rpc_password")

       if parser.has_option(provider_sec, "use_https"):

            if parser.get(provider_sec, "use_https").lower() in ["y", "yes", "true"]:
                use_https = True
            else:
                use_https = False

       if parser.has_option(provider_sec, "version_byte"):
           version_byte = int(parser.get(provider_sec, "version_byte"))


   if use_https is None:
       use_https = True

   if version_byte is None:
       version_byte = 0

   if server is None:
       server = '127.0.0.1'

   if port is None:
       port = 8332

   bitcoind_utxo_opts = {
       "rpc_username": rpc_username,
       "rpc_password": rpc_password,
       "server": server,
       "port": port,
       "use_https": use_https,
       "version_byte": version_byte
   }

   # strip Nones
   for (k, v) in bitcoind_utxo_opts.items():
      if v is None:
         del bitcoind_utxo_opts[k]

   bitcoind_utxo_opts['utxo_provider'] = 'bitcoind_utxo'
   return bitcoind_utxo_opts


def default_blockstack_core_opts( config_file=None ):
   """
   Get our default Blockstack Core UTXO proxy options from a config file.
   """

   if config_file is None:
       raise Exception("No config file given")

   parser = SafeConfigParser()
   parser.read( config_file )

   blockstack_core_opts = {}

   server = None
   port = None

   provider_secs = find_service_provider_sections(config_file, 'blockstack_core')
   if len(provider_secs) > 0:
       provider_sec = provider_secs[0]

       if parser.has_option(provider_sec, "server"):
           server = parser.get(provider_sec, 'server')

       if parser.has_option(provider_sec, "port"):
           port = int(parser.get(provider_sec, "port"))

   blockstack_core_opts = {
       "server": server,
       "port": port
   }

   # strip Nones
   for (k, v) in blockstack_core_opts.items():
      if v is None:
         del blockstack_core_opts[k]

   blockstack_core_opts['utxo_provider'] = 'blockstack_core'
   return blockstack_core_opts


def default_blockstack_explorer_opts( config_file=None ):
    """
    Get our default Blockstack Explorer options from a config file.
    """

    if config_file is None:
        raise Exception("No config file given")

    parser = SafeConfigParser()
    parser.read(config_file)

    url = BLOCKSTACK_EXPLORER_URL

    provider_secs = find_service_provider_sections(config_file, 'blockstack_explorer')
    if len(provider_secs) > 0:
        provider_sec = provider_secs[0]
        
        if parser.has_option(provider_sec, "url"):
            url = parser.get(provider_sec, "url")

    blockstack_explorer_opts = {
        'url': url,
    }

    # strip nones 
    for (k, v) in blockstack_explorer_opts.items():
        if v is None:
            del blockstack_explorer_opts[k]

    blockstack_explorer_opts['utxo_provider'] = 'blockstack_explorer'
    return blockstack_explorer_opts


def default_blockstack_utxo_opts( config_file=None ):
    """
    Get our default Blockstack UTXO service options from a config file.
    """

    if config_file is None:
        raise Exception("No config file given")

    parser = SafeConfigParser()
    parser.read(config_file)

    url = BLOCKSTACK_UTXO_URL

    provider_secs = find_service_provider_sections(config_file, 'blockstack_utxo')
    if len(provider_secs) > 0:
        provider_sec = provider_secs[0]
        
        if parser.has_option(provider_sec, "url"):
            url = parser.get(provider_sec, "url")

    blockstack_explorer_opts = {
        'url': url,
    }

    # strip nones 
    for (k, v) in blockstack_explorer_opts.items():
        if v is None:
            del blockstack_explorer_opts[k]

    blockstack_explorer_opts['utxo_provider'] = 'blockstack_utxo'
    return blockstack_explorer_opts


def connect_utxo_provider( utxo_opts, min_confirmations=TX_MIN_CONFIRMATIONS ):
   """
   Set up and return a UTXO provider client.
   """

   global SUPPORTED_UTXO_PROVIDERS

   if not utxo_opts.has_key("utxo_provider"):
       raise Exception("No UTXO provider given")

   utxo_provider = utxo_opts['utxo_provider']
   if not utxo_provider in SUPPORTED_UTXO_PROVIDERS:
       raise Exception("Unsupported UTXO provider '%s'" % utxo_provider)

   elif utxo_provider == "blockcypher":
       return BlockcypherClient( utxo_opts['api_token'], min_confirmations=min_confirmations )

   elif utxo_provider == "blockchain_info":
       return BlockchainInfoClient( utxo_opts['api_token'], min_confirmations=min_confirmations )

   elif utxo_provider == "bitcoind_utxo":
       return BitcoindClient( utxo_opts['rpc_username'], utxo_opts['rpc_password'], use_https=utxo_opts['use_https'],
                              server=utxo_opts['server'], port=utxo_opts['port'], version_byte=utxo_opts['version_byte'],
                              min_confirmations=min_confirmations )

   elif utxo_provider == "blockstack_core":
       # setting min confirmations not supported by this backend
       return BlockstackCoreUTXOClient( utxo_opts['server'], utxo_opts['port'] )

   elif utxo_provider == "blockstack_explorer":
       return BlockstackExplorerClient( url=utxo_opts['url'], min_confirmations=min_confirmations )

   elif utxo_provider == "blockstack_utxo":
       return BlockstackUTXOClient( url=utxo_opts['url'], min_confirmations=min_confirmations )

   else:
       raise Exception("Unrecognized UTXO provider '%s'" % utxo_provider )


def get_unspents(address, blockchain_client, use_builtin=True):
    """
    Gets the unspent outputs for a given address.
    Returns [{
        "transaction_hash": str,
        'outpoint': {
            'index': index,
            'hash': txhash
        },
        "value": int,
        "out_script": str,
        "confirmations": int,
        }]
    on success.

    Raises exception on error
    """
    if isinstance(blockchain_client, BlockcypherClient):
        return blockcypher_get_unspents(address, blockchain_client)
    elif isinstance(blockchain_client, BlockchainInfoClient):
        return blockchain_info_get_unspents(address, blockchain_client)
    elif isinstance(blockchain_client, (BitcoindClient, AuthServiceProxy)):
        return bitcoind_utxo_get_unspents(address, blockchain_client)
    elif isinstance(blockchain_client, BlockstackCoreUTXOClient):
        return blockstack_core_get_unspents(address, blockchain_client)
    elif isinstance(blockchain_client, BlockstackExplorerClient):
        return blockstack_explorer_get_unspents(address, blockchain_client)
    elif isinstance(blockchain_client, BlockstackUTXOClient):
        return blockstack_utxo_get_unspents(address, blockchain_client)

    # default
    elif use_builtin and hasattr(blockchain_client, "get_unspents"):
        return blockchain_client.get_unspents( address )
    else:
        raise Exception('A blockchain client object is required')


def broadcast_transaction(hex_tx, blockchain_client):
    """
    Dispatches a raw hex transaction to the network.
    Returns {'status': True, 'tx_hash': str} on success
    Raises exception on error
    """
    if isinstance(blockchain_client, BlockcypherClient):
        return blockcypher_broadcast_transaction(hex_tx, blockchain_client)
    elif isinstance(blockchain_client, BlockchainInfoClient):
        return blockchain_info_broadcast_transaction(hex_tx, blockchain_client)
    elif isinstance(blockchain_client, (BitcoindClient, AuthServiceProxy)):
        return bitcoind_utxo_broadcast_transaction(hex_tx, blockchain_client)
    elif isinstance(blockchain_client, BlockstackCoreUTXOClient):
        return blockstack_core_broadcast_transaction(hex_tx, blockchain_client)
    elif isinstance(blockchain_client, BlockstackExplorerClient):
        return blockstack_explorer_broadcast_transaction(hex_tx, blockchain_client)
    elif isinstance(blockchain_client, BlockstackUTXOClient):
        return blockstack_utxo_broadcast_transaction(hex_tx, blockchain_client)

    # default
    elif hasattr(blockchain_client, "broadcast_transaction"):
        return blockchain_client.broadcast_transaction( hex_tx )
    else:
        raise Exception('A blockchain client object is required')


