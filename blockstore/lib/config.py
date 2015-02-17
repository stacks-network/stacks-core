"""
    Blockstore
    ~~~~~
    :copyright: (c) 2015 by Openname.org
    :license: MIT, see LICENSE for more details.
"""

import os
from ConfigParser import SafeConfigParser

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
BLOCKSTORED_LASTBLOCK_FILE = 'lastblock.txt'
BLOCKSTORED_CONFIG_FILE = 'blockstore.ini'

try:
    BLOCKSTORED_SERVER = os.environ['BLOCKSTORED_SERVER']
    BLOCKSTORED_PORT = os.environ['BLOCKSTORED_PORT']
except KeyError:
    BLOCKSTORED_SERVER = 'localhost'
    BLOCKSTORED_PORT = DEFAULT_BLOCKSTORED_PORT

""" DHT configs
"""

DHT_SERVER_PORT = 6265  # blockstored default to port 6264

DEFAULT_DHT_SERVERS = [('dht.openname.org', DHT_SERVER_PORT),
                       ('dht.onename.com', DHT_SERVER_PORT),
                       ('dht.halfmoonlabs.com', DHT_SERVER_PORT),
                       ('127.0.0.1', DHT_SERVER_PORT)]

STORAGE_TTL = 3 * SECONDS_PER_YEAR


from os.path import expanduser
home = expanduser("~")
working_dir = os.path.join(home, BLOCKSTORED_WORKING_DIR)
config_file = os.path.join(working_dir, BLOCKSTORED_CONFIG_FILE)

parser = SafeConfigParser()
parser.read(config_file)

DEFAULT_BITCOIND_SERVER = 'btcd.onename.com'

if parser.has_section('bitcoind'):

    BITCOIND_SERVER = parser.get('bitcoind', 'server')
    BITCOIND_PORT = parser.get('bitcoind', 'port')
    BITCOIND_USER = parser.get('bitcoind', 'user')
    BITCOIND_PASSWD = parser.get('bitcoind', 'passwd')
    use_https = parser.get('bitcoind', 'use_https')

    if use_https.lower() == "yes" or use_https.lower() == "y":
        BITCOIND_USE_HTTPS = True
    else:
        BITCOIND_USE_HTTPS = False

else:

    BITCOIND_SERVER = DEFAULT_BITCOIND_SERVER
    BITCOIND_PORT = '8332'
    BITCOIND_USER = 'openname'
    BITCOIND_PASSWD = 'opennamesystem'
    BITCOIND_USE_HTTPS = True

""" block indexing configs
"""

REINDEX_FREQUENCY = 10  # in seconds

FIRST_BLOCK_MAINNET = 343883
FIRST_BLOCK_MAINNET_TESTSET = FIRST_BLOCK_MAINNET
FIRST_BLOCK_TESTNET = 343883
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

""" api configs
"""

if parser.has_section('chain_com'):
    CHAIN_COM_API_ID = parser.get('chain_com', 'api_key_id')
    CHAIN_COM_API_SECRET = parser.get('chain_com', 'api_key_secret')

try:
    BLOCKCHAIN_INFO_API_KEY = os.environ['BLOCKCHAIN_INFO_API_KEY']
except KeyError:
    pass

""" magic bytes configs
"""

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

# Other
LENGTHS = {
    'magic_bytes': 2,
    'opcode': 1,
    'name_hash': 20,
    'consensus_hash': 16,
    'namelen': 1,
    'name_min': 1,
    'name_max': 16,
    'unencoded_name': 24,
    'update_hash': 20,
}

MIN_OP_LENGTHS = {
    'preorder': LENGTHS['name_hash'],
    'registration': LENGTHS['namelen'] + LENGTHS['name_min'],
    'update': (
        LENGTHS['namelen'] + LENGTHS['name_min'] + LENGTHS['update_hash']),
    'transfer': LENGTHS['namelen'] + LENGTHS['name_min']
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

""" consensus hash configs
"""

BLOCKS_CONSENSUS_HASH_IS_VALID = 4*AVERAGE_BLOCKS_PER_HOUR
