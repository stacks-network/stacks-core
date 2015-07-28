"""
    Blockstore
    ~~~~~
    :copyright: (c) 2015 by Openname.org
    :license: MIT, see LICENSE for more details.
"""

import os
from ConfigParser import SafeConfigParser

import schemas

DEBUG = True
TESTNET = False
TESTSET = True

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
EXPIRATION_PERIOD = BLOCKS_PER_YEAR*1
# EXPIRATION_PERIOD = 10
AVERAGE_BLOCKS_PER_HOUR = MINUTES_PER_HOUR/AVERAGE_MINUTES_PER_BLOCK

""" blockstore configs
"""

LISTEN_IP = '0.0.0.0'
VERSION = 'v0.1-beta'
RPC_TIMEOUT = 5  # seconds

DEFAULT_BLOCKSTORED_PORT = 6264  # port 6263 is 'NAME' on a phone keypad
BLOCKSTORED_PID_FILE = 'blockstored.pid'
BLOCKSTORED_LOG_FILE = 'blockstored.log'
BLOCKSTORED_TAC_FILE = 'blockstored.tac'
BLOCKSTORED_WORKING_DIR = '.blockstore'
BLOCKSTORED_NAMESPACE_FILE = 'namespace.txt'
BLOCKSTORED_SNAPSHOTS_FILE = 'snapshots.txt'
BLOCKSTORED_STORAGEDB_FILE = 'storagedb.txt'
BLOCKSTORED_LASTBLOCK_FILE = 'lastblock.txt'
BLOCKSTORED_CONFIG_FILE = 'blockstore.ini'

DEFAULT_BLOCKMIRRORD_PORT = 6266  # port 6263 is 'NAME' on a phone keypad
BLOCKMIRRORD_PID_FILE = 'blockmirrord.pid'
BLOCKMIRRORD_LOG_FILE = 'blockmirrord.log'
BLOCKMIRRORD_WORKING_DIR = '.blockmirror'
BLOCKMIRRORD_CONFIG_FILE = 'blockmirror.ini'

try:
    BLOCKSTORED_SERVER = os.environ['BLOCKSTORED_SERVER']
    BLOCKSTORED_PORT = os.environ['BLOCKSTORED_PORT']
    
    BLOCKMIRRORD_SERVER = os.environ['BLOCKMIRRORD_SERVER']
    BLOCKMIRRORD_PORT = os.environ['BLOCKMIRRORD_PORT']
    
except KeyError:
    BLOCKSTORED_SERVER = 'localhost'
    BLOCKSTORED_PORT = DEFAULT_BLOCKSTORED_PORT
    
    BLOCKMIRRORD_SERVER = 'localhost'
    BLOCKMIRRORD_PORT = DEFAULT_BLOCKMIRRORD_PORT

""" DHT configs
"""

DHT_SERVER_PORT = 6265  # blockstored default to port 6264

DEFAULT_DHT_SERVERS = [('dht.openname.org', DHT_SERVER_PORT),
                       ('dht.onename.com', DHT_SERVER_PORT),
                       ('dht.halfmoonlabs.com', DHT_SERVER_PORT),
                       ('127.0.0.1', DHT_SERVER_PORT)]

STORAGE_TTL = 3 * SECONDS_PER_YEAR

DEFAULT_BITCOIND_SERVER = 'btcd.onename.com'

BITCOIND_SERVER = None 
BITCOIND_PORT = None
BITCOIND_USER = None
BITCOIND_PASSWD = None
BITCOIND_USE_HTTPS = None

""" Caching 
"""

# cache for raw transactions: map txid to tx
CACHE_ENABLE = None
CACHE_BUFLEN = 10000
CACHE_ROOT = os.path.expanduser("~/.blockstore/cache")
CACHE_TX_DIR = os.path.join( CACHE_ROOT, "tx_data" )
CACHE_BLOCK_HASH_DIR = os.path.join( CACHE_ROOT, "block_hashes" )
CACHE_BLOCK_DATA_DIR = os.path.join( CACHE_ROOT, "block_data" )
CACHE_BLOCK_ID_DIR = os.path.join( CACHE_ROOT, "blocks" )

""" Multiprocessing
"""
MULTIPROCESS_NUM_WORKERS = 8
MULTIPROCESS_WORKER_BATCH = 8
MULTIPROCESS_RPC_RETRY = 3


def default_bitcoind_opts( config_file=None ):
   """
   Set bitcoind options globally.
   Call this before trying to talk to bitcoind.
   """
   
   global BITCOIND_SERVER, BITCOIND_PORT, BITCOIND_USER, BITCOIND_PASSWD, BITCOIND_USE_HTTPS, TESTNET
   global CACHE_ENABLE 
   global MULTIPROCESS_NUM_WORKERS, MULTIPROCESS_WORKER_BATCH
   
   loaded = False 
   
   if config_file is not None:
         
      parser = SafeConfigParser()
      parser.read(config_file)

      if parser.has_section('bitcoind'):

         BITCOIND_SERVER = parser.get('bitcoind', 'server')
         BITCOIND_PORT = parser.get('bitcoind', 'port')
         BITCOIND_USER = parser.get('bitcoind', 'user')
         BITCOIND_PASSWD = parser.get('bitcoind', 'passwd')
         
         if parser.has_option('bitcoind', 'use_https'):
            use_https = parser.get('bitcoind', 'use_https')
         else:
            use_https = 'no'

         if use_https.lower() == "yes" or use_https.lower() == "y":
            BITCOIND_USE_HTTPS = True
         else:
            BITCOIND_USE_HTTPS = False
            
         loaded = True

   if not loaded:

      if TESTNET:
         BITCOIND_SERVER = "localhost"
         BITCOIND_PORT = 18332
         BITCOIND_USER = 'openname'
         BITCOIND_PASSWD = 'opennamesystem'
         BITCOIND_USE_HTTPS = False
         
      else:
         BITCOIND_SERVER = DEFAULT_BITCOIND_SERVER
         BITCOIND_PORT = '8332'
         BITCOIND_USER = 'openname'
         BITCOIND_PASSWD = 'opennamesystem'
         BITCOIND_USE_HTTPS = True
        
   default_bitcoin_opts = {
      "bitcoind_user": BITCOIND_USER,
      "bitcoind_passwd": BITCOIND_PASSWD,
      "bitcoind_server": BITCOIND_SERVER,
      "bitcoind_port": BITCOIND_PORT,
      "bitcoind_use_https": BITCOIND_USE_HTTPS
   }
   
   # configure caching and multiiprocessing based on local vs nonlocal 
   if BITCOIND_SERVER == "localhost" or BITCOIND_SERVER == "127.0.0.1" or BITCOIND_SERVER == "::1":
      # local bitcoind--no need to cache, and no need for parallel RPC (lest we overwhelm it)
      if CACHE_ENABLE is None:
         CACHE_ENABLE = False
      MULTIPROCESS_NUM_WORKERS = 1
      MULTIPROCESS_WORKER_BATCH = 64
      
   else:
      # non-local bitcoind--open the pipe!
      if CACHE_ENABLE is None:
         CACHE_ENABLE = True 
      MULTIPROCESS_NUM_WORKERS = 8
      MULTIPROCESS_WORKER_BATCH = 8
      
   return default_bitcoin_opts



""" block indexing configs
"""

REINDEX_FREQUENCY = 10  # in seconds

FIRST_BLOCK_MAINNET = 367090 # 343883
FIRST_BLOCK_MAINNET_TESTSET = FIRST_BLOCK_MAINNET
# FIRST_BLOCK_TESTNET = 343883
FIRST_BLOCK_TESTNET = 508800
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

NAME_SCHEME = "id://"

MAGIC_BYTES_TESTSET = 'X\x88'
MAGIC_BYTES_MAINSET = 'X\x08'

if TESTSET:
    MAGIC_BYTES = MAGIC_BYTES_TESTSET
else:
    MAGIC_BYTES = MAGIC_BYTES_MAINSET

""" name operation data configs
"""

# Opcodes
NAME_PREORDER = 'a'
NAME_REGISTRATION = 'b'
NAME_UPDATE = 'c'
NAME_TRANSFER = 'd'
NAME_RENEWAL = 'e'

DATA_PUT = 'f'
DATA_REMOVE = 'g'

NAMESPACE_DEFINE = 'h'
NAMESPACE_BEGIN = 'i'

NAMESPACE_LIFE_INFINITE = 0xffffffff

# Other
LENGTHS = {
    'magic_bytes': 2,
    'opcode': 1,
    'preorder_name_hash': 20,
    'consensus_hash': 16,
    'namelen': 1,
    'name_min': 1,
    'name_max': 34,
    'unencoded_name': 34,
    'name_hash': 16,
    'update_hash': 20,
    'data_hash': 20,
    'blockchain_id_name': 40,
    'blockchain_id_scheme': len(NAME_SCHEME),
    'blockchain_id_namespace_life': 4,
    'blockchain_id_namespace_cost': 8,
    'blockchain_id_namespace_price_decay': 4,
    'blockchain_id_namespace_id_len': 1,
    'blockchain_id_namespace_id': 19
}

MIN_OP_LENGTHS = {
    'preorder': LENGTHS['preorder_name_hash'],
    'registration': LENGTHS['namelen'] + LENGTHS['name_min'],
    'update': LENGTHS['name_hash'] + LENGTHS['update_hash'],
    'transfer': LENGTHS['namelen'] + LENGTHS['name_min'],
    'data_put': LENGTHS['name_hash'] + LENGTHS['data_hash'],
    'data_remove': LENGTHS['name_hash'] + LENGTHS['data_hash'],
    'namespace_begin': LENGTHS['blockchain_id_namespace_id_len'] + 1,
    'namespace_define': LENGTHS['blockchain_id_namespace_life'] + LENGTHS['blockchain_id_namespace_cost'] + \
                       LENGTHS['blockchain_id_namespace_price_decay'] + LENGTHS['blockchain_id_namespace_id_len'] 
}

OP_RETURN_MAX_SIZE = 40

""" transaction fee configs
"""

DEFAULT_OP_RETURN_FEE = 10000
DEFAULT_DUST_SIZE = 5500
DEFAULT_OP_RETURN_VALUE = 0
DEFAULT_FEE_PER_KB = 10000

""" name price configs
"""

SATOSHIS_PER_BTC = 10**8
PRICE_FOR_1LETTER_NAMES = 10*SATOSHIS_PER_BTC
PRICE_DROP_PER_LETTER = 10
PRICE_DROP_FOR_NON_ALPHABETIC = 10
ALPHABETIC_PRICE_FLOOR = 10**4

# default namespace record (i.e. for names with no namespace ID)
NAMESPACE_DEFAULT = {
   'opcode': 'NAMESPACE_DEFINE',
   'lifetime': EXPIRATION_PERIOD,
   'cost': PRICE_FOR_1LETTER_NAMES,
   'price_decay': float(PRICE_DROP_PER_LETTER),
   'namespace_id': None 
}

""" consensus hash configs
"""

BLOCKS_CONSENSUS_HASH_IS_VALID = 4*AVERAGE_BLOCKS_PER_HOUR

""" Validation 
"""

PASSCARD_SCHEMA_V2 = {

   "name": {
      "formatted": schemas.STRING
   },
   
   "bio": schemas.STRING,
   
   schemas.OPTIONAL( "location" ): {
      "formatted": schemas.STRING 
   },
   
   "website": schemas.URL,
   
   "bitcoin": {
      "address": schemas.BITCOIN_ADDRESS
   },
   
   "avatar": { 
      "url": schemas.URL,
   },
   
   "cover": {
      "url": schemas.URL,
   },
   
   schemas.OPTIONAL( "pgp" ): {
      "url": schemas.URL,
      "fingerprint": schemas.PGP_FINGERPRINT,
   },
   
   schemas.OPTIONAL( "email" ): schemas.EMAIL,
   
   "twitter": {
      "username": schemas.STRING,
      "proof": {
         "url": schemas.URL
       }
   },
   
   "facebook": {
      "username": schemas.STRING,
      "proof": {
         "url": schemas.URL
       }
   },
   
   "github": {
      "username": schemas.STRING,
      "proof": {
         "url": schemas.URL
       }
   },
   
   schemas.OPTIONAL( "immutable_data" ): schemas.HASH160_ARRAY,
   
   "v": schemas.STRING
}
