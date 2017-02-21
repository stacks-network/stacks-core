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
    along with Blockstack-client. If not, see <http://www.gnu.org/licenses/>.
"""

import os
import sys
from ConfigParser import SafeConfigParser
import pybitcoin
import logging
import json
import traceback
from .blockstack_utxo import BlockstackUTXOClient

DEBUG = True
FIRST_BLOCK_MAINNET = 373601        # well-known value for blockstack-server; doesn't ever change


SUPPORTED_UTXO_PROVIDERS = [ "blockcypher", "blockchain_info", "bitcoind_utxo", "blockstack_utxo", "mock_utxo" ]
SUPPORTED_UTXO_PARAMS = {
    "blockcypher": ["api_token"],
    "blockchain_info": ["api_token"],
    "bitcoind_utxo": ["rpc_username", "rpc_password", "server", "port", "use_https", "version_byte"],
    "blockstack_utxo": ["server", "port"],
    "mock_utxo": []
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

   elif utxo_provider == "blockstack_utxo":
       return default_blockstack_utxo_opts( config_file=config_file )

   elif utxo_provider == "mock_utxo":
       return default_mock_utxo_opts( config_file=config_file )

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


def default_blockstack_utxo_opts( config_file=None ):
   """
   Get our default Blockstack UTXO proxy options from a config file.
   """

   if config_file is None:
       raise Exception("No config file given")

   parser = SafeConfigParser()
   parser.read( config_file )

   blockstack_utxo_opts = {}

   server = None
   port = None

   provider_secs = find_service_provider_sections(config_file, 'blockstack_utxo')
   if len(provider_secs) > 0:
       provider_sec = provider_secs[0]

       if parser.has_option(provider_sec, "server"):
           server = parser.get(provider_sec, 'server')

       if parser.has_option(provider_sec, "port"):
           port = int(parser.get(provider_sec, "port"))

   blockstack_utxo_opts = {
       "server": server,
       "port": port
   }

   # strip Nones
   for (k, v) in blockstack_utxo_opts.items():
      if v is None:
         del blockstack_utxo_opts[k]

   blockstack_utxo_opts['utxo_provider'] = 'blockstack_utxo'
   return blockstack_utxo_opts


def default_mock_utxo_opts( config_file=None ):
   """
   Get default options for the mock UTXO provider.
   """

   mock_tx_list = None
   mock_tx_file = None
   mock_start_block = FIRST_BLOCK_MAINNET
   mock_start_time = None
   mock_difficulty = None
   mock_initial_utxos = None
   mock_save_file = None

   if config_file is not None:

      provider_secs = find_service_provider_sections(config_file, 'mock_utxo')
      if len(provider_secs) > 0:
         provider_sec = provider_secs[0]

         parser = SafeConfigParser()
         parser.read(config_file)

         if parser.has_option(provider_sec, 'tx_list'):
            # should be a csv of raw transactions
            mock_tx_list = parser.get(provider_sec, 'tx_list').split(',')

         if parser.has_option(provider_sec, 'tx_file'):
            # should be a path
            mock_tx_file = parser.get(provider_sec, 'tx_file')

         if parser.has_option(provider_sec, 'start_block'):
            # should be an int
            try:
                mock_start_block = int( parser.get(provider_sec, 'start_block') )
            except:
                print >> sys.stderr, "Invalid 'start_block' value: expected int"
                return None

         if parser.has_option(provider_sec, 'difficulty'):
            # should be a float
            try:
                mock_difficulty = float( parser.get(provider_sec, 'difficulty') )
            except:
                print >> sys.stderr, "Invalid 'difficulty' value: expected float"
                return None

         if parser.has_option(provider_sec, 'start_block'):
            # should be an int
            try:
                mock_start_block = int( parser.get(provider_sec, 'start_block'))
            except:
                print >> sys.stderr, "Invalid 'start_block' value: expected int"
                return None

         if parser.has_option(provider_sec, 'save_file'):
             # should be a path 
             mock_save_file = parser.get(provider_sec, 'save_file')

         if parser.has_option(provider_sec, 'initial_utxos'):
            # should be a csv of privatekey:int
            try:
                # verify that we can parse this
                wallet_info = parser.get(provider_sec, 'initial_utxos').split(',')
                wallets = {}
                for wi in wallet_info:
                    privkey, value = wi.split(':')
                    wallets[ privkey ] = int(value)

                #mock_initial_utxos = wallets
                mock_initial_utxos = parser.get(provider_sec, 'initial_utxos')

            except:
                print >> sys.stderr, "Invalid 'mock_initial_utxos' value: expected CSV of wif_private_key:int"
                return None


   default_mock_utxo_opts = {
      "tx_list": mock_tx_list,
      "tx_file": mock_tx_file,
      "start_block": mock_start_block,
      "difficulty": mock_difficulty,
      "initial_utxos": mock_initial_utxos,
      "start_block": mock_start_block,
      "save_file": mock_save_file
   }

   # strip Nones
   for (k, v) in default_mock_utxo_opts.items():
      if v is None:
         del default_mock_utxo_opts[k]

   default_mock_utxo_opts['utxo_provider'] = 'mock_utxo'
   return default_mock_utxo_opts


def connect_utxo_provider( utxo_opts ):
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
       return pybitcoin.BlockcypherClient( utxo_opts['api_token'] )

   elif utxo_provider == "blockchain_info":
       return pybitcoin.BlockchainInfoClient( utxo_opts['api_token'] )

   elif utxo_provider == "bitcoind_utxo":
       return pybitcoin.BitcoindClient( utxo_opts['rpc_username'], utxo_opts['rpc_password'], use_https=utxo_opts['use_https'], server=utxo_opts['server'], port=utxo_opts['port'], version_byte=utxo_opts['version_byte'] )

   elif utxo_provider == "blockstack_utxo":
       return BlockstackUTXOClient( utxo_opts['server'], utxo_opts['port'] )

   elif utxo_provider == "mock_utxo":
       # requires blockstack tests to be installed
       try:
           from blockstack_integration_tests import connect_mock_utxo_provider
       except:
           raise Exception("Mock UTXO provider requires blockstack_integration_tests to be installed")

       return connect_mock_utxo_provider( utxo_opts )

   else:
       raise Exception("Unrecognized UTXO provider '%s'" % utxo_provider )


