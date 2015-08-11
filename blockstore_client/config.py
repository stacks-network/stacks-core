# client configuration 

BLOCKSTORED_PORT = 6264
BLOCKSTORED_SERVER = "127.0.0.1"
DEBUG = True
VERSION = "v0.01-beta"
MAX_RPC_LEN = 1024 * 1024 * 1024

import logging

log = logging.getLogger()
log.setLevel(logging.DEBUG if DEBUG else logging.INFO)
console = logging.StreamHandler()
console.setLevel(logging.DEBUG if DEBUG else logging.INFO)
formatter = logging.Formatter('%(message)s')
console.setFormatter(formatter)
# log.addHandler(logging.NullHandler())
log.addHandler(console)

