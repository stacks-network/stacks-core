#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstack-utxo
    ~~~~~
    :copyright: (c) 2014-2016 by Halfmoon Labs, Inc.
    :copyright: (c) 2016 blockstack.org
    :license: MIT, see LICENSE for more details.
"""

import os
import sys
from ConfigParser import SafeConfigParser
import pybitcoin

SUPPORTED_UTXO_PROVIDERS = [ "chain_com", "blockcypher", "blockchain_info", "bitcoind_utxo", "mock_utxo" ]
SUPPORTED_UTXO_PARAMS = {
    "chain_com": ["api_key_id", "api_key_secret"],
    "blockcypher": ["api_token"],
    "blockchain_info": ["api_token"],
    "bitcoind_utxo": ["rpc_username", "rpc_password", "server", "port", "use_https", "version_byte"],
    "mock_utxo": []
}


def default_utxo_provider( config_file=None ):
   """
   Get defualt UTXO provider options from a config file.
   """

   global SUPPORTED_UTXO_PROVIDERS

   if config_file is None:
       raise Exception("No config file given")

   parser = SafeConfigParser()
   parser.read( config_file )

   for provider_name in SUPPORTED_UTXO_PROVIDERS:
       if parser.has_section( provider_name ):
           return provider_name

   return None


def all_utxo_providers( config_file=None ):
   """
   Get our defualt UTXO provider options from a config file.
   """

   global SUPPORTED_UTXO_PROVIDERS

   if config_file is None:
       raise Exception("No config file given")

   parser = SafeConfigParser()
   parser.read( config_file )

   provider_names = []

   for provider_name in SUPPORTED_UTXO_PROVIDERS:
       if parser.has_section( provider_name ):
           provider_names.append( provider_name )

   return provider_names


def default_utxo_provider_opts( utxo_provider, config_file=None ):
   """
   Get the default options for a utxo provider.
   """

   if utxo_provider == "chain_com":
       return default_chaincom_opts( config_file=config_file )

   elif utxo_provider == "blockcypher":
       return default_blockcypher_opts( config_file=config_file )

   elif utxo_provider == "blockchain_info":
       return default_blockchain_info_opts( config_file=config_file )

   elif utxo_provider == "bitcoind_utxo":
       return default_bitcoind_utxo_opts( config_file=config_file )

   elif utxo_provider == "mock_utxo":
       return default_mock_utxo_opts( config_file=config_file )

   else:
       raise Exception("Unsupported UTXO provider '%s'" % utxo_provider)


def default_chaincom_opts( config_file=None ):
   """
   Get our default chain.com options from a config file.
   """
   
   if config_file is None:
       raise Exception("No config file given")

   parser = SafeConfigParser()
   parser.read( config_file )

   chaincom_opts = {}

   api_key_id = None
   api_key_secret = None

   if parser.has_section('chain_com'):

      if parser.has_option('chain_com', 'api_key_id'):
         api_key_id = parser.get('chain_com', 'api_key_id')

      if parser.has_option('chain_com', 'api_key_secret'):
         api_key_secret = parser.get('chain_com', 'api_key_secret')

   chaincom_opts = {
       'utxo_provider': "chain_com",
       'api_key_id': api_key_id,
       'api_key_secret': api_key_secret
   }


   # strip Nones
   for (k, v) in chaincom_opts.items():
      if v is None:
         del chaincom_opts[k]

   return chaincom_opts


def default_blockcypher_opts( config_file=None ):
   """
   Get our default blockcypher.com options from a config file.
   """

   if config_file is None:
       raise Exception("No config file given")

   parser = SafeConfigParser()
   parser.read( config_file )

   blockcypher_opts = {}

   api_token = None

   if parser.has_section('blockcypher'):

      if parser.has_option('blockcypher', 'api_token'):
         api_token = parser.get('blockcypher', 'api_token')

   blockcypher_opts = {
       'utxo_provider': "blockcypher",
       'api_token': api_token
   }


   # strip Nones
   for (k, v) in blockcypher_opts.items():
      if v is None:
         del blockcypher_opts[k]

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

   if parser.has_section("blockchain_info"):

       if parser.has_option("blockchain_info", "api_token"):
           api_token = parser.get("blockchain_info", "api_token")

   blockchain_info_opts = {
       "utxo_provider": "blockchain_info",
       "api_token": api_token
   }

   # strip Nones
   for (k, v) in blockchain_info_opts.items():
      if v is None:
         del blockchain_info_opts[k]

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

   if parser.has_section("bitcoind_utxo"):

       if parser.has_option("bitcoind_utxo", "server"):
           server = parser.get("bitcoind_utxo", "server")

       if parser.has_option("bitcoind_utxo", "port"):
           port = int( parser.get("bitcoind_utxo", "port") )

       if parser.has_option("bitcoind_utxo", "rpc_username"):
           rpc_username = parser.get("bitcoind_utxo", "rpc_username")

       if parser.has_option("bitcoind_utxo", "rpc_password"):
           rpc_password = parser.get("bitcoind_utxo", "rpc_password")

       if parser.has_option("bitcoind_utxo", "use_https"):

            if parser.get("bitcoind_utxo", "use_https").lower() in ["y", "yes", "true"]:
                use_https = True
            else:
                use_https = False

       if parser.has_option("bitcoind_utxo", "version_byte"):
           version_byte = int(parser.get("bitcoind_utxo", "version_byte"))


   if use_https is None:
       use_https = True

   if version_byte is None:
       version_byte = 0

   if server is None:
       server = '127.0.0.1'

   if port is None:
       port = 8332

   bitcoind_utxo_opts = {
       "utxo_provider": "bitcoind_utxo",
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

   return bitcoind_utxo_opts


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

      parser = SafeConfigParser()
      parser.read(config_file)

      if parser.has_section("mock_utxo"):

         if parser.has_option('mock_utxo', 'tx_list'):
            # should be a csv of raw transactions
            mock_tx_list = parser.get('mock_utxo', 'tx_list').split(',')

         if parser.has_option('mock_utxo', 'tx_file'):
            # should be a path
            mock_tx_file = parser.get('mock_utxo', 'tx_file')

         if parser.has_option('mock_utxo', 'start_block'):
            # should be an int
            try:
                mock_start_block = int( parser.get('mock_utxo', 'start_block') )
            except:
                print >> sys.stderr, "Invalid 'start_block' value: expected int"
                return None

         if parser.has_option('mock_utxo', 'difficulty'):
            # should be a float
            try:
                mock_difficulty = float( parser.get('mock_utxo', 'difficulty') )
            except:
                print >> sys.stderr, "Invalid 'difficulty' value: expected float"
                return None

         if parser.has_option('mock_utxo', 'start_block'):
            # should be an int
            try:
                mock_start_block = int( parser.get('mock_utxo', 'start_block'))
            except:
                print >> sys.stderr, "Invalid 'start_block' value: expected int"
                return None

         if parser.has_option('mock_utxo', 'save_file'):
             # should be a path 
             mock_save_file = parser.get('mock_utxo', 'save_file')

         if parser.has_option('mock_utxo', 'initial_utxos'):
            # should be a csv of privatekey:int
            try:
                # verify that we can parse this
                wallet_info = parser.get('mock_utxo', 'initial_utxos').split(',')
                wallets = {}
                for wi in wallet_info:
                    privkey, value = wi.split(':')
                    wallets[ privkey ] = int(value)

                #mock_initial_utxos = wallets
                mock_initial_utxos = parser.get('mock_utxo', 'initial_utxos')

            except:
                print >> sys.stderr, "Invalid 'mock_initial_utxos' value: expected CSV of wif_private_key:int"
                return None


   default_mock_utxo_opts = {
      "utxo_provider": "mock_utxo",
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

   if utxo_provider == "chain_com":
       return pybitcoin.ChainComClient( utxo_opts['api_key_id'], utxo_opts['api_key_secret'] )

   elif utxo_provider == "blockcypher":
       return pybitcoin.BlockcypherClient( utxo_opts['api_token'] )

   elif utxo_provider == "blockchain_info":
       return pybitcoin.BlockchainInfoClient( utxo_opts['api_token'] )

   elif utxo_provider == "bitcoind_utxo":
       return pybitcoin.BitcoindClient( utxo_opts['rpc_username'], utxo_opts['rpc_password'], use_https=utxo_opts['use_https'], server=utxo_opts['server'], port=utxo_opts['port'], version_byte=utxo_opts['version_byte'] )

   elif utxo_provider == "mock_utxo":
       # requires blockstack tests to be installed
       try:
           from blockstack_integration_tests import connect_mock_utxo_provider
       except:
           # maybe legacy
           try:
               from blockstack.tests import connect_mock_utxo_provider
           except ImportError:
               raise Exception("Mock UTXO provider requires blockstack_integration_tests to be installed")

       return connect_mock_utxo_provider( utxo_opts )

   else:
       raise Exception("Unrecognized UTXO provider '%s'" % utxo_provider )


def get_utxo_provider_client(utxo_provider, config_file):
   """
   Get or instantiate our blockchain UTXO provider's client.
   Return None if we were unable to connect
   """

   utxo_opts = default_utxo_provider_opts( utxo_provider, config_file )

   try:
       utxo_provider = connect_utxo_provider( utxo_opts )
       return utxo_provider
   except Exception, e:
       log.exception(e)
       return None

