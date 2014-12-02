# Global magic bytes
MAGIC_BYTES_MAINSPACE = 'D\xf1'
MAGIC_BYTES_TESTSPACE = 'D\xf8'

# Opcodes
NAME_PREORDER = 'P'
NAME_CLAIM = 'C'
NAME_UPDATE = 'U'
NAME_TRANSFER = 'T'

# Other
LENGTHS = {
    'magic_bytes': 2,
    'opcode': 1,
    'name_hash': 20,
    'record_hash': 16,
    'name_min': 1,
    'name_max': 16,
    'unencoded_name': 24,
    'salt': 16,
    'update_hash': 20,
}

OP_RETURN_MAX_SIZE = 40

FIRST_BLOCK_MAINNET = 332182
FIRST_BLOCK_MAINNET_TESTSPACE = 332182
FIRST_BLOCK_TESTNET = 311517
FIRST_BLOCK_TESTNET_TESTSPACE = 311517

DEFAULT_OP_RETURN_FEE = 10000
DEFAULT_DUST_SIZE = 5500
DEFAULT_OP_RETURN_VALUE = 0
DEFAULT_FEE_PER_KB = 10000
