#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstore
    ~~~~~
    copyright: (c) 2014 by Halfmoon Labs, Inc.
    copyright: (c) 2015 by Blockstack.org
    
    This file is part of Blockstore
    
    Blockstore is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    
    Blockstore is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with Blockstore.  If not, see <http://www.gnu.org/licenses/>.
"""

import os
from ConfigParser import SafeConfigParser
import pybitcoin

import virtualchain

DEBUG = True
TESTNET = False
TESTSET = False

VERSION = "v0.01-beta"

# namespace version 
BLOCKSTORE_VERSION = 1

""" constants
"""

AVERAGE_MINUTES_PER_BLOCK = 10
DAYS_PER_YEAR = 365.2424
HOURS_PER_DAY = 24
MINUTES_PER_HOUR = 60
SECONDS_PER_MINUTE = 60
MINUTES_PER_YEAR = DAYS_PER_YEAR*HOURS_PER_DAY*MINUTES_PER_HOUR
SECONDS_PER_YEAR = int(round(MINUTES_PER_YEAR*SECONDS_PER_MINUTE))
BLOCKS_PER_YEAR = int(round(MINUTES_PER_YEAR/AVERAGE_MINUTES_PER_BLOCK))
BLOCKS_PER_DAY = int(round(float(MINUTES_PER_HOUR * HOURS_PER_DAY)/AVERAGE_MINUTES_PER_BLOCK))
EXPIRATION_PERIOD = BLOCKS_PER_YEAR*1
NAME_PREORDER_EXPIRE = BLOCKS_PER_DAY
# EXPIRATION_PERIOD = 10
AVERAGE_BLOCKS_PER_HOUR = MINUTES_PER_HOUR/AVERAGE_MINUTES_PER_BLOCK

""" blockstore configs
"""
MAX_NAMES_PER_SENDER = 1                # a sender can own exactly one name

""" RPC server configs 
"""
RPC_SERVER_PORT = 6264

""" DHT configs
"""
# 3 years
STORAGE_TTL = 3 * 60 * 60 * 24 * 365

DHT_SERVER_PORT = 6265  # blockstored default to port 6264

DEFAULT_DHT_SERVERS = [('dht.openname.org', DHT_SERVER_PORT),
                       ('dht.onename.com', DHT_SERVER_PORT),
                       ('dht.halfmoonlabs.com', DHT_SERVER_PORT),
                       ('127.0.0.1', DHT_SERVER_PORT)]


""" Bitcoin configs 
"""
DEFAULT_BITCOIND_SERVER = 'btcd.onename.com'
DEFAULT_BITCOIND_PORT = 8332 
DEFAULT_BITCOIND_PORT_TESTNET = 18332
DEFAULT_BITCOIND_USERNAME = 'openname'
DEFAULT_BITCOIND_PASSWD = 'opennamesystem'

""" block indexing configs
"""
REINDEX_FREQUENCY = 60 # seconds

FIRST_BLOCK_MAINNET = 372693 # 343883
FIRST_BLOCK_MAINNET_TESTSET = FIRST_BLOCK_MAINNET
# FIRST_BLOCK_TESTNET = 343883
FIRST_BLOCK_TESTNET = 529008
FIRST_BLOCK_TESTNET_TESTSET = FIRST_BLOCK_TESTNET

if TESTNET:
    if TESTSET:
        START_BLOCK = FIRST_BLOCK_TESTNET_TESTSET
    else:
        START_BLOCK = FIRST_BLOCK_TESTNET
else:
    if TESTSET:
        START_BLOCK = FIRST_BLOCK_MAINNET_TESTSET
    else:
        START_BLOCK = FIRST_BLOCK_MAINNET

""" magic bytes configs
"""

MAGIC_BYTES_TESTSET = 'eg'
MAGIC_BYTES_MAINSET = 'id'

if TESTSET:
    MAGIC_BYTES = MAGIC_BYTES_TESTSET
else:
    MAGIC_BYTES = MAGIC_BYTES_MAINSET

""" name operation data configs
"""

# Opcodes
NAME_PREORDER = '?'
NAME_REGISTRATION = ':'
NAME_UPDATE = '+'
NAME_TRANSFER = '>'
NAME_RENEWAL = ':'
NAME_REVOKE = '~'
NAME_IMPORT = ';'

NAME_SCHEME = MAGIC_BYTES_MAINSET + NAME_REGISTRATION

NAMESPACE_PREORDER = '*'
NAMESPACE_REVEAL = '&'
NAMESPACE_READY = '!'

TRANSFER_KEEP_DATA = '>'
TRANSFER_REMOVE_DATA = '~'

# list of opcodes we support
OPCODES = [
   NAME_PREORDER,
   NAME_REGISTRATION,
   NAME_UPDATE,
   NAME_TRANSFER,
   NAME_RENEWAL,
   NAME_REVOKE,
   NAME_IMPORT,
   NAMESPACE_PREORDER,
   NAMESPACE_REVEAL,
   NAMESPACE_READY
]

NAMESPACE_LIFE_INFINITE = 0xffffffff

# op-return formats
LENGTHS = {
    'magic_bytes': 2,
    'opcode': 1,
    'preorder_name_hash': 20,
    'consensus_hash': 16,
    'namelen': 1,
    'name_min': 1,
    'name_max': 34,
    'name_hash': 16,
    'update_hash': 20,
    'data_hash': 20,
    'blockchain_id_name': 34,
    'blockchain_id_namespace_life': 4,
    'blockchain_id_namespace_cost': 7,
    'blockchain_id_namespace_price_decay': 4,
    'blockchain_id_namespace_version': 2,
    'blockchain_id_namespace_id': 19
}

MIN_OP_LENGTHS = {
    'preorder': LENGTHS['preorder_name_hash'] + LENGTHS['consensus_hash'],
    'registration': LENGTHS['name_min'],
    'update': LENGTHS['name_hash'] + LENGTHS['update_hash'],
    'transfer': LENGTHS['name_hash'] + LENGTHS['consensus_hash'],
    'revoke': LENGTHS['name_min'],
    'name_import': LENGTHS['name_min'],
    'namespace_preorder': LENGTHS['preorder_name_hash'] + LENGTHS['consensus_hash'],
    'namespace_reveal': LENGTHS['blockchain_id_namespace_life'] + LENGTHS['blockchain_id_namespace_cost'] + \
                        LENGTHS['blockchain_id_namespace_price_decay'] + LENGTHS['blockchain_id_namespace_version'] + LENGTHS['name_min'],
    'namespace_ready': 1 + LENGTHS['name_min']
}

OP_RETURN_MAX_SIZE = 40

""" transaction fee configs
"""

DEFAULT_OP_RETURN_FEE = 10000
DEFAULT_DUST_FEE = 5500
DEFAULT_OP_RETURN_VALUE = 0
DEFAULT_FEE_PER_KB = 10000

""" name price configs
"""

SATOSHIS_PER_BTC = 10**8
PRICE_FOR_1LETTER_NAMES = 10*SATOSHIS_PER_BTC
PRICE_DROP_PER_LETTER = 10
PRICE_DROP_FOR_NON_ALPHABETIC = 10
ALPHABETIC_PRICE_FLOOR = 10**4

# NAMESPACE_BASE_COST = 64 * SATOSHIS_PER_BTC
NAMESPACE_BASE_COST = SATOSHIS_PER_BTC
NAMESPACE_COST_DECAY = 4.0
# NAMESPACE_MINIMUM_COST = SATOSHIS_PER_BTC / 10  # 0.1 BTC
NAMESPACE_MINIMUM_COST = 1

"""
NAMESPACE_1_CHAR_COST = 86.67 * SATOSHIS_PER_BTC        # ~$20,000
NAMESPACE_23_CHAR_COST = 8.67 * SATOSHIS_PER_BTC        # ~$2,000
NAMESPACE_4567_CHAR_COST = 0.867 * SATOSHIS_PER_BTC     # ~$200
NAMESPACE_8UP_CHAR_COST = 0.0867 * SATOSHIS_PER_BTC     # ~$20
"""
NAMESPACE_1_CHAR_COST = 86.67 * 0.001 * SATOSHIS_PER_BTC
NAMESPACE_23_CHAR_COST = 8.67 * 0.001 * SATOSHIS_PER_BTC
NAMESPACE_4567_CHAR_COST = 0.867 * 0.001 * SATOSHIS_PER_BTC
NAMESPACE_8UP_CHAR_COST = 0.0867 * 0.001 * SATOSHIS_PER_BTC


NAMESPACE_PREORDER_EXPIRE = BLOCKS_PER_DAY      # namespace preorders expire after 1 day, if not revealed
NAMESPACE_REVEAL_EXPIRE = BLOCKS_PER_YEAR       # namespace reveals expire after 1 year, if not readied.

# burn address for fees (the address of public key 0x0000000000000000000000000000000000000000)
BLOCKSTORE_BURN_ADDRESS = "1111111111111111111114oLvT2"

# default namespace record (i.e. for names with no namespace ID)
NAMESPACE_DEFAULT = {
   'opcode': 'NAMESPACE_REVEAL',
   'lifetime': EXPIRATION_PERIOD,
   'cost': 100000000000L,
   'price_decay': 1.0,
   'namespace_id': None,
   'namespace_id_hash': "",
   'sender': "",
   'recipient': "",
   'address': "",
   'recipient_address': "",
   'version': BLOCKSTORE_VERSION
}


""" Validation 
"""

def default_bitcoind_opts( config_file=None ):
   """
   Get our default bitcoind options, such as from a config file, 
   or from sane defaults 
   """
   
   bitcoind_server = None 
   bitcoind_port = None 
   bitcoind_user = None 
   bitcoind_passwd = None 
   bitcoind_use_https = None 
   
   loaded = False 
   
   if config_file is not None:
         
      parser = SafeConfigParser()
      parser.read(config_file)

      if parser.has_section('bitcoind'):

         if parser.has_option('bitcoind', 'server'):
            bitcoind_server = parser.get('bitcoind', 'server')
         
         if parser.has_option('bitcoind', 'port'):
            bitcoind_port = parser.get('bitcoind', 'port')
         
         if parser.has_option('bitcoind', 'user'):
            bitcoind_user = parser.get('bitcoind', 'user')
         
         if parser.has_option('bitcoind', 'passwd'):
            bitcoind_passwd = parser.get('bitcoind', 'passwd')
         
         if parser.has_option('bitcoind', 'use_https'):
            use_https = parser.get('bitcoind', 'use_https')
         else:
            use_https = 'no'

         if use_https.lower() == "yes" or use_https.lower() == "y":
            bitcoind_use_https = True
         else:
            bitcoind_use_https = False
            
         loaded = True

   if not loaded:

      if TESTNET:
         bitcoind_server = "localhost"
         bitcoind_port = DEFAULT_BITCOIND_PORT_TESTNET
         bitcoind_user = DEFAULT_BITCOIND_USERNAME
         bitcoind_passwd = DEFAULT_BITCOIND_PASSWD
         bitcoind_use_https = False
         
      else:
         bitcoind_server = DEFAULT_BITCOIND_SERVER
         bicoind_port = DEFAULT_BITCOIND_PORT
         bitcoind_user = DEFAULT_BITCOIND_USERNAME
         bitcoind_passwd = DEFAULT_BITCOIND_PASSWD
         bitcoind_use_https = True
        
   default_bitcoin_opts = {
      "bitcoind_user": bitcoind_user,
      "bitcoind_passwd": bitcoind_passwd,
      "bitcoind_server": bitcoind_server,
      "bitcoind_port": bitcoind_port,
      "bitcoind_use_https": bitcoind_use_https
   }
   
   # strip None's
   for (k, v) in default_bitcoin_opts.items():
      if v is None:
         del default_bitcoin_opts[k]
      
   return default_bitcoin_opts


def default_chaincom_opts( config_file=None ):
   """
   Get our default chain.com options from a config file.
   """
   
   if config_file is None:
      config_file = virtualchain.get_config_filename()
   
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
         'api_key_id': api_key_id,
         'api_key_secret': api_key_secret
      }
      
   
   # strip Nones 
   for (k, v) in chaincom_opts.items():
      if v is None:
         del chaincom_opts[k]
   
   return chaincom_opts


def default_dht_opts( config_file=None ):
   """
   Get our default DHT options from the config file.
   """
   
   global DHT_SERVER_PORT, DEFAULT_DHT_SERVERS
   
   if config_file is None:
      config_file = virtualchain.get_config_filename()
   
   
   defaults = {
      'disable': str(False),
      'port': str(DHT_SERVER_PORT),
      'servers': ",".join( ["%s:%s" % (host, port) for (host, port) in DEFAULT_DHT_SERVERS] )
   }
   
   parser = SafeConfigParser( defaults )
   parser.read( config_file )
   
   if parser.has_section('dht'):
      
      disable = parser.get('dht', 'disable')
      port = parser.get('dht', 'port')
      servers = parser.get('dht', 'servers')     # expect comma-separated list of host:port
      
      if disable is None:
         disable = False 
         
      if port is None:
         port = DHT_SERVER_PORT
         
      if servers is None:
         servers = DEFAULT_DHT_SERVERS
         
      try:
         disable = bool(disable)
      except:
         raise Exception("Invalid field value for dht.disable: expected bool")
      
      try:
         port = int(port)
      except:
         raise Exception("Invalid field value for dht.port: expected int")
      
      parsed_servers = []
      try:
         server_list = servers.split(",")
         for server in server_list:
            server_host, server_port = server.split(":")
            server_port = int(server_port)
            
            parsed_servers.append( (server_host, server_port) )
            
      except:
         raise Exception("Invalid field value for dht.servers: expected 'HOST:PORT[,HOST:PORT...]'")
      
      dht_opts = {
         'disable': disable,
         'port': port,
         'servers': parsed_servers
      }
      
      return dht_opts 
   
   else:
      
      # use defaults
      dht_opts = {
         'disable': False,
         'port': DHT_SERVER_PORT,
         'servers': DEFAULT_DHT_SERVERS
      }
         
      return dht_opts
   
      

def opt_strip( prefix, opts ):
   """
   Given a dict of opts that start with prefix,
   remove the prefix from each of them.
   """
   
   for (opt_name, opt_value) in opts.items():
      
      # remove prefix
      if opt_name.startswith(prefix):
         opt_name = opt_name[len(prefix):]
      
      opts[ opt_name ] = opt_value
      
   return opts 


def interactive_prompt( message, parameters ):
   """
   Prompt the user for a series of parameters
   Return a dict mapping the parameter name to the 
   user-given value.
   """
   
   # pretty-print the message 
   lines = message.split("\n")
   max_line_len = max( [len(l) for l in lines] )
   
   print '-' * max_line_len 
   print message 
   print '-' * max_line_len
   
   ret = {}
   
   for param in parameters:
      value = raw_input("%s: ")
      ret[param] = value 
   
   return ret


def find_missing( message, all_params, given_opts, prompt_missing=True ):
   """
   Find and interactively prompt the user for missing parameters,
   given the list of all valid parameters and a dict of known options.
   
   Return the (updated dict of known options, missing), with the user's input.
   """
   
   # are we missing anything for bitcoin?
   missing_params = []
   for missing_param in given_opts:
      if missing_param not in given_opts.keys():
         missing_params.append( missing_param )
      
   if len(missing_params) > 0 and prompt_missing:
      
      missing_values = interactive_prompt( message, missing_params )
      given_opts.update( missing_values )

   return given_opts, missing_params


def configure( config_file=None, force=False, interactive=True ):
   """
   Configure blockstore:  find and store configuration parameters to the config file.
   
   Optionally prompt for missing data interactively (with interactive=True).  Or, raise an exception
   if there are any fields missing.
   
   Optionally force a re-prompting for all configuration details (with force=True)
   
   Return (bitcoind_opts, chaincom_opts)
   """
   
   if config_file is None:
      try:
         config_file = virtualchain.get_config_filename()
      except:
         pass 
   
   bitcoind_message  = "Blockstore does not have enough information to connect\n"
   bitcoind_message += "to bitcoind.  Please supply the following parameters:"
   
   bitcoind_opts = {}
   bitcoind_params = ["server", "port", "user", "passwd", "use_https"]
   
   chaincom_message  = 'NOTE: Blockstore currently requires API access to chain.com\n'
   chaincom_message += 'for getting unspent outputs. We will add support for using\n'
   chaincom_message += 'bitcoind and/or other API providers in the next release.\n'
   chaincom_message += "\n"
   chaincom_message += "If you have not done so already, please go to https://chain.com\n"
   chaincom_message += "and register for an API key and secret.  Once you have them,"
   chaincom_message += "please enter them here."
   
   chaincom_opts = {}
   chaincom_params = ["api_key_id", "api_key_secret"]
   
   if not force:
      
      # get current set of bitcoind opts
      tmp_bitcoind_opts = default_bitcoind_opts( config_file=config_file )
      bitcoind_opts = opt_strip( "bitcoind_", tmp_bitcoind_opts )
         
      # get current set of chaincom opts 
      chaincom_opts = default_chaincom_opts( config_file=config_file )
      
   # get any missing fields 
   bitcoind_opts, missing_bitcoin_opts = find_missing( bitcoind_message, bitcoind_params, bitcoind_opts, prompt_missing=interactive )
   chaincom_opts, missing_chaincom_opts = find_missing( chaincom_message, chaincom_params, chaincom_opts, prompt_missing=interactive )
   
   if not interactive and (len(missing_bitcoin_opts) > 0 or len(missing_chaincom_opts) > 0):
       
       # cannot continue 
       raise Exception("Missing configuration fields: %s" % (",".join( missing_bitcoin_opts + missing_chaincom_opts )) )
                       
   return (bitcoind_opts, chaincom_opts)
      

def write_config_file( bitcoind_opts=None, chaincom_opts=None, config_file=None ):
   """
   Update a configuration file, given the bitcoind options and chain.com options.
   Return True on success 
   Return False on failure
   """
   
   if config_file is None:
      try:
         config_file = virtualchain.get_config_filename()
      except:
         return False
      
   if config_file is None:
      return False 
   
   parser = SafeConfigParser()
   parser.read(config_file)
   
   if bitcoind_opts is not None:
      
      bitcoind_opts = opt_strip( "bitcoind_", bitcoind_opts )
      
      for opt_name, opt_value in bitcoind_opts.items():
         parser.set( 'bitcoind', opt_name, opt_value )
      
   if chaincom_opts is not None:
      
      for opt_name, opt_value in chaincom_opts.items():
         parser.set( 'chain_com', opt_name, opt_value )
      
   with open(config_file, "w") as fout:
      parser.write( fout )
   
   return True

   