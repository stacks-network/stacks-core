"""
    Opennamed
    ~~~~~
    :copyright: (c) 2014 by Openname.org
    :license: MIT, see LICENSE for more details.
"""

import os

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

""" opennamed configs
"""

LISTEN_IP = '0.0.0.0'
VERSION = 'v0.1-beta'
RPC_TIMEOUT = 5  # seconds

DEFAULT_OPENNAMED_PORT = 6264  # port 6263 is 'NAME' on a phone keypad
OPENNAMED_PID_FILE = 'opennamed.pid'
OPENNAMED_LOG_FILE = 'opennamed.log'
OPENNAMED_TAC_FILE = 'opennamed.tac'

try:
    OPENNAMED_SERVER = os.environ['OPENNAMED_SERVER']
    OPENNAMED_PORT = os.environ['OPENNAMED_PORT']
except KeyError:
    OPENNAMED_SERVER = 'localhost'
    OPENNAMED_PORT = DEFAULT_OPENNAMED_PORT

""" DHT configs
"""

DHT_SERVER_PORT = 6265  # opennamed default to port 6264

DEFAULT_DHT_SERVERS = [('dht.openname.org', DHT_SERVER_PORT),
                       ('dht.onename.com', DHT_SERVER_PORT),
                       ('dht.halfmoonlabs.com', DHT_SERVER_PORT),
                       ('127.0.0.1', DHT_SERVER_PORT)]

STORAGE_TTL = 3 * SECONDS_PER_YEAR

try:
    BITCOIND_SERVER = os.environ['BITCOIND_SERVER']
    BITCOIND_PORT = os.environ['BITCOIND_PORT']
    BITCOIND_USER = os.environ['BITCOIND_USER']
    BITCOIND_PASSWD = os.environ['BITCOIND_PASSWD']
except KeyError:
    BITCOIND_SERVER = 'btcd.onename.com'
    BITCOIND_PORT = '8332'
    BITCOIND_USER = 'openname'
    BITCOIND_PASSWD = 'opennamesystem'

REINDEX_FREQUENCY = 5  # in seconds

""" api configs
"""

try:
    CHAIN_COM_API_ID = os.environ['CHAIN_COM_API_ID']
    CHAIN_COM_API_SECRET = os.environ['CHAIN_COM_API_SECRET']
except KeyError:
    pass

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
    'name_min': 1,
    'name_max': 16,
    'unencoded_name': 24,
    'salt': 16,
    'update_hash': 20,
}

MIN_OP_LENGTHS = {
    'preorder': LENGTHS['name_hash'],
    'registration': LENGTHS['name_min'] + LENGTHS['salt'],
    'update': LENGTHS['name_min'] + LENGTHS['update_hash'],
    'transfer': LENGTHS['name_min']
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

""" starting block configs
"""

FIRST_BLOCK_MAINNET = 334750
FIRST_BLOCK_MAINNET_TESTSET = 334750
FIRST_BLOCK_TESTNET = 311517
FIRST_BLOCK_TESTNET_TESTSET = 311517

if TESTNET:
    if TESTSET:
        FIRST_BLOCK = FIRST_BLOCK_TESTNET_TESTSET
    else:
        FIRST_BLOCK = FIRST_BLOCK_TESTNET
else:
    if TESTSET:
        FIRST_BLOCK = FIRST_BLOCK_MAINNET_TESTSET
    else:
        FIRST_BLOCK = FIRST_BLOCK_MAINNET
