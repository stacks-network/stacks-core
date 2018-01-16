#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from __future__ import print_function

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

from .constants import (
    LENGTH_CONSENSUS_HASH,
    NAME_OPCODES,
    NAME_TRANSFER,
    TRANSFER_KEEP_DATA,
    TRANSFER_REMOVE_DATA,
    NAME_REGISTRATION,
    LENGTH_VALUE_HASH,
    LENGTH_MAX_NAME,
    LENGTH_MAX_NAMESPACE_ID)

import blockstack_profiles


OP_URLENCODED_NOSLASH_CLASS = r'[a-zA-Z0-9\-_.~%]'
OP_URLENCODED_NOSLASH_COLON_CLASS = r'[a-zA-Z0-9\-_.~%:]'
OP_URLENCODED_CLASS = r'[a-zA-Z0-9\-_.~%/]'
OP_NAME_CLASS = r'[a-z0-9\-_.+]{{{},{}}}'.format(3, LENGTH_MAX_NAME)
OP_NAMESPACE_CLASS = r'[a-z0-9\-_+]{{{},{}}}'.format(1, LENGTH_MAX_NAMESPACE_ID)
OP_BASE58CHECK_CLASS = r'[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]'
OP_CONSENSUS_HASH_PATTERN = r'^([0-9a-fA-F]{{{}}})$'.format(LENGTH_CONSENSUS_HASH * 2)
OP_BASE58CHECK_PATTERN = r'^({}+)$'.format(OP_BASE58CHECK_CLASS)
OP_ADDRESS_PATTERN = OP_BASE58CHECK_PATTERN
OP_PRIVKEY_PATTERN = OP_BASE58CHECK_PATTERN
OP_P2PKH_PATTERN = r'^76[aA]914[0-9a-fA-F]{40}88[aA][cC]$'
OP_SCRIPT_PATTERN = r'^[0-9a-fA-F]+$'
OP_CODE_PATTERN = r'^([{}]{{1}}|{}{}|{}{}|{}{})$'.format(
    ''.join(NAME_OPCODES.values()),
    NAME_TRANSFER, TRANSFER_KEEP_DATA,
    NAME_TRANSFER, TRANSFER_REMOVE_DATA,
    NAME_REGISTRATION, NAME_REGISTRATION
)
OP_CODE_NAME_PATTERN = '|'.join(NAME_OPCODES.keys())
OP_HEX_PATTERN = r'^([0-9a-fA-F]+)$'
OP_UUID_PATTERN = r'^([0-9a-fA-F\-]+)$'
OP_PUBKEY_PATTERN = OP_HEX_PATTERN
OP_SCRIPT_PATTERN = OP_HEX_PATTERN
OP_TXID_PATTERN = OP_HEX_PATTERN
OP_ZONEFILE_HASH_PATTERN = r'^([0-9a-fA-F]{{{}}})$'.format(LENGTH_VALUE_HASH * 2)
OP_NAME_PATTERN = r'^({})$'.format(OP_NAME_CLASS)
OP_SUBDOMAIN_NAME_PATTERN = r'^({})\.({})$'.format(OP_NAME_CLASS, OP_NAME_CLASS)
OP_NAME_OR_SUBDOMAIN_FRAGMENT = r'({})|({})'.format(OP_NAME_PATTERN, OP_SUBDOMAIN_NAME_PATTERN)
OP_NAME_OR_SUBDOMAIN_PATTERN = r'^{}$'.format(OP_NAME_OR_SUBDOMAIN_FRAGMENT)
OP_NAMESPACE_PATTERN = r'^({})$'.format(OP_NAMESPACE_CLASS)
OP_NAMESPACE_ID_HASH_PATTERN = r'^([0-9a-fA-F]{40})$'
OP_SUBDOMAIN_NAME_PATTERN = r'^([a-z0-9\-_.+]{{{},{}}})$'.format(5, LENGTH_MAX_NAME * 2)
OP_BASE64_PATTERN_SECTION = r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})'
OP_BASE64_PATTERN = r'^({})$'.format(OP_BASE64_PATTERN_SECTION)
OP_URLENCODED_NOSLASH_PATTERN = r'^({}+)$'.format(OP_URLENCODED_NOSLASH_CLASS)       # intentionally left out /
OP_URLENCODED_NOSLASH_OR_EMPTY_PATTERN = r'^({}*)$'.format(OP_URLENCODED_NOSLASH_CLASS)       # intentionally left out /, allow empty
OP_URLENCODED_OR_EMPTY_PATTERN = r'^({}*)$'.format(OP_URLENCODED_CLASS)
OP_URLENCODED_PATTERN = r'^({}+)$'.format(OP_URLENCODED_CLASS)
OP_DATASTORE_ID_CLASS = r'[a-zA-Z0-9\-_.~%]'
OP_DATASTORE_ID_PATTERN = r'^({}+)$'.format(OP_DATASTORE_ID_CLASS)
OP_URI_TARGET_PATTERN = r'^([a-z0-9+]+)://([a-zA-Z0-9\-_.~%#?&\\:/=]+)$'
OP_URI_TARGET_PATTERN_NOSCHEME = r'^([a-zA-Z0-9\-_.~%#?&\\:/=]+)$'
OP_TOMBSTONE_PATTERN = '^delete-([0-9]+):([a-zA-Z0-9\-_.~%#?&\\:/=]+)$'
OP_SIGNED_TOMBSTONE_PATTERN = '^delete-([0-9]+):([a-zA-Z0-9\-_.~%#?&\\:/=]+):({})$'.format(OP_BASE64_PATTERN_SECTION)
OP_DNS_NAME_PATTERN = r'([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]))*'
OP_APP_NAME_PATTERN = r'^(^({})\.1(:[0-9]+){{0,1}}$)|(^({})\.x$)$'.format(OP_DNS_NAME_PATTERN, OP_NAME_OR_SUBDOMAIN_FRAGMENT)

OP_ANY_TYPE_SCHEMA = [
    {
        'type': 'array',
    },
    {
        'type': 'number',
    },
    {
        'type': 'string',
    },
    {
        'type': 'null',
    },
    {
        'type': 'object',
    },
    {
        'type': 'boolean'
    },
]                

PRIVKEY_SINGLESIG_SCHEMA_WIF = {
    'type': 'string',
    'pattern': OP_PRIVKEY_PATTERN
}

PRIVKEY_SINGLESIG_SCHEMA_HEX = {
    'type': 'string',
    'pattern': OP_HEX_PATTERN
}

PRIVKEY_SINGLESIG_SCHEMA = {
    'anyOf': [
        PRIVKEY_SINGLESIG_SCHEMA_WIF,
        PRIVKEY_SINGLESIG_SCHEMA_HEX
    ],
}

PRIVKEY_MULTISIG_SCHEMA = {
    'type': 'object',
    'properties': {
        'address': {
            'type': 'string',
            'pattern': OP_ADDRESS_PATTERN,
        },
        'redeem_script': {
            'type': 'string',
            'pattern': OP_SCRIPT_PATTERN,
        },
        'private_keys': {
            'type': 'array',
            'items': PRIVKEY_SINGLESIG_SCHEMA,
        },
        'segwit': {
            'type': 'boolean',
        },
    },
    'required': [
        'address',
        'redeem_script',
        'private_keys'
    ],
}

PRIVKEY_INFO_SCHEMA = {
    'anyOf': [
        PRIVKEY_SINGLESIG_SCHEMA,
        PRIVKEY_MULTISIG_SCHEMA
    ],
}

ENCRYPTED_PRIVKEY_SINGLESIG_SCHEMA = {
    'type': 'string',
    'pattern': OP_BASE64_PATTERN
}

ENCRYPTED_PRIVKEY_MULTISIG_SCHEMA = {
    'type': 'object',
    'properties': {
        'address': {
            'type': 'string',
            'pattern': OP_ADDRESS_PATTERN,
        },
        'encrypted_redeem_script': {
            'type': 'string',
            'pattern': OP_BASE64_PATTERN,
        },
        'encrypted_private_keys': {
            'type': 'array',
            'items': {
                'type': 'string',
                'pattern': OP_BASE64_PATTERN
            },
        },
    },
    'required': [
        'address',
        'encrypted_redeem_script',
        'encrypted_private_keys',
    ],
}

ENCRYPTED_PRIVKEY_INFO_SCHEMA = {
    'anyOf': [
        ENCRYPTED_PRIVKEY_SINGLESIG_SCHEMA,
        ENCRYPTED_PRIVKEY_MULTISIG_SCHEMA
    ],
}

ENCRYPTED_WALLET_SCHEMA_PROPERTIES = {
    'data_pubkey': {
        'type': 'string',
        'pattern': OP_PUBKEY_PATTERN
    },
    'data_pubkeys': {
        'type': 'array',
        'items': {
            'type': 'string',
            'pattern': OP_PUBKEY_PATTERN,
            'minItems': 1,
            'maxItems': 1
        },
    },
    'encrypted_data_privkey': {
        'type': 'string',
        'pattern': OP_BASE64_PATTERN,
    },
    'encrypted_master_private_key': {
        'type': 'string',
        'pattern': OP_BASE64_PATTERN,
    },
    'encrypted_owner_privkey': ENCRYPTED_PRIVKEY_INFO_SCHEMA,
    'encrypted_payment_privkey': ENCRYPTED_PRIVKEY_INFO_SCHEMA,
    'owner_addresses': {
        'type': 'array',
        'items': {
            'type': 'string',
            'pattern': OP_ADDRESS_PATTERN,
            'minItems': 1,
            'maxItems': 1
        },
    },
    'payment_addresses': {
        'type': 'array',
        'items': {
            'type': 'string',
            'pattern': OP_ADDRESS_PATTERN,
            'minItems': 1,
            'maxItems': 1
        },
    },
    'version': {
        'type': 'string'
    },
}

# pre-0.13 wallet
ENCRYPTED_WALLET_SCHEMA_LEGACY = {
    'type': 'object',
    'properties': ENCRYPTED_WALLET_SCHEMA_PROPERTIES,
    'required': [
        'encrypted_master_private_key'
    ],
}

# some 0.13 wallets have this format
ENCRYPTED_WALLET_SCHEMA_LEGACY_013 = {
    'type': 'object',
    'properties': ENCRYPTED_WALLET_SCHEMA_PROPERTIES,
    'required': [
        'encrypted_owner_privkey',
        'encrypted_payment_privkey',
        'owner_addresses',
        'payment_addresses',
    ],
}

# in 0.14.0 and 0.14.1, we encrypted lots of fields separately
ENCRYPTED_WALLET_SCHEMA_LEGACY_014 = {
    'type': 'object',
    'properties': ENCRYPTED_WALLET_SCHEMA_PROPERTIES,
    'required': [
        'data_pubkey',
        'data_pubkeys',
        'encrypted_data_privkey',
        'encrypted_owner_privkey',
        'encrypted_payment_privkey',
        'owner_addresses',
        'payment_addresses',
        'version'
    ],
}

# in 0.14.2 and on, we encrypt the secret fields as one unit 
ENCRYPTED_WALLET_SCHEMA_CURRENT = {
    'type': 'object',
    'properties': {
        # unencrypted fields
        'data_pubkey': {
            'type': 'string',
            'pattern': OP_PUBKEY_PATTERN
        },
        'data_pubkeys': {
            'type': 'array',
            'items': {
                'type': 'string',
                'pattern': OP_PUBKEY_PATTERN,
                'minItems': 1,
                'maxItems': 1
            },
        },
        'owner_addresses': {
            'type': 'array',
            'items': {
                'type': 'string',
                'pattern': OP_ADDRESS_PATTERN,
                'minItems': 1,
                'maxItems': 1
            },
        },
        'payment_addresses': {
            'type': 'array',
            'items': {
                'type': 'string',
                'pattern': OP_ADDRESS_PATTERN,
                'minItems': 1,
                'maxItems': 1
            },
        },
        'version': {
            'type': 'string'
        },

        # encrypted fields 
        'enc': {
            'type': 'string',
            'pattern': OP_BASE64_PATTERN,
        },
    },
    'required': [
        'data_pubkey',
        'data_pubkeys',
        'owner_addresses',
        'payment_addresses',
        'version', 
        'enc'
    ],
    'additionalProperties': False,
}

# in 0.14.2 and on, we continue to tolerate the absence of a data key.
# however, certain features will not work.
ENCRYPTED_WALLET_SCHEMA_CURRENT_NODATAKEY = {
    'type': 'object',
    'properties': ENCRYPTED_WALLET_SCHEMA_CURRENT['properties'],
    'required': [
        'owner_addresses',
        'payment_addresses',
        'version',
        'enc'
    ],
    'additionalProperties': False,
}

# fully-decrypted wallet schema
WALLET_SCHEMA_PROPERTIES = {
    'data_pubkey': {
        'type': 'string',
        'pattern': OP_PUBKEY_PATTERN,
    },
    'data_pubkeys': {
        'type': 'array',
        'items': {
            'type': 'string',
            'pattern': OP_PUBKEY_PATTERN,
            'minItems': 1,
            'maxItems': 1,
        },
    },
    'data_privkey': {
        'type': 'string',
        'pattern': OP_HEX_PATTERN,
    },
    'owner_privkey': PRIVKEY_INFO_SCHEMA,
    'payment_privkey': PRIVKEY_INFO_SCHEMA,
    'owner_addresses': {
        'type': 'array',
        'items': {
            'type': 'string',
            'pattern': OP_ADDRESS_PATTERN,
            'minItems': 1,
            'maxItems': 1,
        },
    },
    'payment_addresses': {
        'type': 'array',
        'items': {
            'type': 'string',
            'pattern': OP_ADDRESS_PATTERN,
            'minItems': 1,
            'maxItems': 1,
        },
    },
    'version': {
        'type': 'string'
    },
}

WALLET_SCHEMA_CURRENT = {
    'type': 'object',
    'properties': WALLET_SCHEMA_PROPERTIES,
    'required': [
        'data_pubkey',
        'data_pubkeys',
        'data_privkey',
        'owner_privkey',
        'payment_privkey',
        'owner_addresses',
        'payment_addresses',
        'version'
    ],
}

# will be deprecated soon, but some features
# like profile-loading have to keep working
# even if the data key is missing.
WALLET_SCHEMA_CURRENT_NODATAKEY = {
    'type': 'object',
    'properties': WALLET_SCHEMA_PROPERTIES,
    'required': [
        'owner_privkey',
        'payment_privkey',
        'owner_addresses',
        'payment_addresses',
        'version'
    ],
}


URI_RECORD_SCHEMA = {
    'type': 'object',
    'properties': {
        'name': {
            'type': 'string'
        },
        'priority': {
            'type': 'integer',
            'minimum': 0,
            'maximum': 65535,
        },
        'weight': {
            'type': 'integer',
            'minimum': 0,
            'maximum': 65535,
        },
        'target': {
            'anyOf': [
                {
                    'type': 'string',
                    'pattern': OP_URI_TARGET_PATTERN,
                },
                {
                    'type': 'string',
                    'pattern': OP_URI_TARGET_PATTERN_NOSCHEME,
                },
            ],
        },
        'class': {
            'type': 'string'
        },
        '_missing_class': {
            'type': 'boolean'
        },
    },
    'required': [
        'name',
        'priority',
        'weight',
        'target'
    ],
}       

TXT_RECORD_SCHEMA = {
    'type': 'object',
    'properties': {
        'name': {
            'type': 'string',
            'pattern': OP_URLENCODED_PATTERN,
        },
        'txt': {
            'type': ['string', 
                     'array']
        },
    },
    'required': [
        'name',
        'txt'
    ],
}        

USER_ZONEFILE_SCHEMA = {
    'type': 'object',
    'properties': {
        'txt': {
            'type': 'array',
            'items': TXT_RECORD_SCHEMA,
        },
        'uri': {
            'type': 'array',
            'items': URI_RECORD_SCHEMA,
        },
        '$origin': {
            'type': 'string',
            'pattern': OP_NAME_PATTERN,
        },
        '$ttl': {
            'type': 'integer',
            'minimum': 0,
            'maximum': 2147483647,
        },
    },
    'required': [
        'uri',
        '$origin',
        '$ttl'
    ],
}

MUTABLE_DATUM_FILE_TYPE = 1
MUTABLE_DATUM_DIR_TYPE = 2

MUTABLE_DATUM_SCHEMA_BASE_PROPERTIES = {
    'type': {
        # file, directory
        'type': 'integer',
        'minimum': MUTABLE_DATUM_FILE_TYPE,
        'maximum': MUTABLE_DATUM_DIR_TYPE,
    },
    'owner': {
        # hash of public key
        'type': 'string',
        'pattern': OP_ADDRESS_PATTERN
    },
    'uuid': {
        # inode ID
        'type': 'string',
        'pattern': OP_UUID_PATTERN
    },
    'readers': {
        # who can read this inode?
        'type': 'array',
        'items': {
            # hash of public key
            'type': 'string',
            'pattern': OP_ADDRESS_PATTERN
        },
    },
    'reader_pubkeys': {
        # public keys (loaded at run-time, not stored)
        'type': 'array',
        'items': {
            'type': 'string',
            'pattern': OP_HEX_PATTERN
        },
    },
    'version': {
        # inode version
        'type': 'integer',
        'minimum': 1
    },
    'proto_version': {
        # version of the protocol
        'type': 'integer',
        'minimum': 1,
    },
}

# header contains hash of payload
MUTABLE_DATUM_SCHEMA_HEADER_PROPERTIES = MUTABLE_DATUM_SCHEMA_BASE_PROPERTIES.copy()
MUTABLE_DATUM_SCHEMA_HEADER_PROPERTIES.update({
    'data_hash': {
        # hash of associated inode data
        'type': 'string',
        'pattern': OP_HEX_PATTERN
    },
})

MUTABLE_DATUM_FILE_SCHEMA_PROPERTIES = MUTABLE_DATUM_SCHEMA_BASE_PROPERTIES.copy()
MUTABLE_DATUM_DIR_SCHEMA_PROPERTIES = MUTABLE_DATUM_SCHEMA_BASE_PROPERTIES.copy()

MUTABLE_DATUM_INODE_HEADER_SCHEMA = {
    'type': 'object',
    'properties': MUTABLE_DATUM_SCHEMA_HEADER_PROPERTIES,
    'additionalProperties': False,
    'required': list(set(MUTABLE_DATUM_SCHEMA_HEADER_PROPERTIES.keys()) - set(['reader_pubkeys']))  # headers only include reader pubkey hashes
}

MUTABLE_DATUM_DIRENT_SCHEMA = {
    'type': 'object',
    'properties': {
        'type': {
            'type': 'integer',
            'minimum': MUTABLE_DATUM_FILE_TYPE,
            'maximum': MUTABLE_DATUM_DIR_TYPE,
        },
        'uuid': {
            'type': 'string',
            'pattern': OP_UUID_PATTERN
        },
        'version': {
            'type': 'integer',
            'minimum': 1,
        },
    },
    'additionalProperties': False,
    'required': [
        'type',
        'uuid',
        'version',
    ],
}

# NOTE: *unserialized* idata
MUTABLE_DATUM_DIR_IDATA_SCHEMA = {
    'type': 'object',
    'properties': {
        'children': {
            'type': 'object',
            'patternProperties': {
                # maps name to UUID, links, and type
                OP_URLENCODED_NOSLASH_PATTERN: MUTABLE_DATUM_DIRENT_SCHEMA
            },
        },
        'header': MUTABLE_DATUM_INODE_HEADER_SCHEMA,
    },
    'required': [
        'children',
        'header',
    ],
    'additionalProperties': False,
}

MUTABLE_DATUM_FILE_IDATA_SCHEMA = {
    'type': 'string',
    'pattern': OP_BASE64_PATTERN
}

MUTABLE_DATUM_FILE_SCHEMA_PROPERTIES.update({
    'idata': MUTABLE_DATUM_FILE_IDATA_SCHEMA
})

MUTABLE_DATUM_DIR_SCHEMA_PROPERTIES.update({
    'idata': MUTABLE_DATUM_DIR_IDATA_SCHEMA
})

MUTABLE_DATUM_INODE_SCHEMA = {
    'type': 'object',
    'properties': MUTABLE_DATUM_SCHEMA_BASE_PROPERTIES,
    'additionalProperties': False,
    'required': list(set(MUTABLE_DATUM_SCHEMA_BASE_PROPERTIES.keys()) - set(['reader_pubkeys']))    # public keys are loaded at runtime, not stored
}


MUTABLE_DATUM_FILE_SCHEMA = {
    'type': 'object',
    'properties': MUTABLE_DATUM_FILE_SCHEMA_PROPERTIES,
    'additionalProperties': False,
    'required': list(set(MUTABLE_DATUM_FILE_SCHEMA_PROPERTIES.keys()) - set(['reader_pubkeys']))    # public keys are loaded at runtime, not stored
}

MUTABLE_DATUM_DIR_SCHEMA = {
    'type': 'object',
    'properties': MUTABLE_DATUM_DIR_SCHEMA_PROPERTIES,
    'additionalProperties': False,
    'required': list(set(MUTABLE_DATUM_DIR_SCHEMA_PROPERTIES.keys()) - set(['reader_pubkeys']))     # public keys are loaded at runtime, not stored
}

# replicated datastore
DATASTORE_SCHEMA = {
    'type': 'object',
    'properties': {
        'type': {
            'type': 'string',
            'pattern': r'([a-zA-Z0-9_]+)$',
        },
        'pubkey': {
            'type': 'string',
            'pattern': OP_PUBKEY_PATTERN,
        },
        'drivers': {
            'type': 'array',
            'items': {
                'type': 'string',
            },
        },
        'device_ids': {
            'type': 'array',
            'items': {
                'type': 'string',
            },
        },
        'root_uuid': {
            'type': 'string',
            'pattern': OP_UUID_PATTERN,
        },
    },
    'additionalProperties': False,
    'required': [
        'type',
        'pubkey',
        'root_uuid',
        'drivers',
        'device_ids',
    ]
}

# unlinked blob of data, not part of a datastore.
DATA_BLOB_SCHEMA = {
    'type': 'object',
    'properties': {
        'fq_data_id': {
            'type': 'string',
            'pattern': OP_URLENCODED_PATTERN
        },
        'version': {
            'type': 'integer',
            'minimum': 1,
        },
        'timestamp': {
            'type': 'integer',
            'minimum': 0,
        },
        'data': {
            'anyOf': OP_ANY_TYPE_SCHEMA,
        },

        # optional
        'blockchain_id': {
            'type': 'string',
            'pattern': OP_NAME_PATTERN,
        },
    },
    'required': [
        'version',
        'timestamp',
        'data',
        'fq_data_id'
    ],
    'additionalProperties': False,
}

APP_INFO_PROPERTIES = {
    'version': {
        'type': 'integer',
        'minimum': 1,
        'maximum': 1,
    },
    'blockchain_id': {
        'anyOf': [
            {
                'type': 'string',
                'pattern': OP_NAME_PATTERN,
            },
            {
                'type': 'null',
            },
        ],
    },
    'app_domain': {
        'anyOf': [
            {
                'type': 'string',
                'pattern': OP_URLENCODED_PATTERN,
            },
            {
                'type': 'string',
                'pattern': OP_URI_TARGET_PATTERN,
            },
            {
                'type': 'string',
                'pattern': OP_APP_NAME_PATTERN,
            }
        ]
    },
    'methods': {
        'type': 'array',
        'items':
        {
            'anyOf': [
                {
                    'type': 'string',
                    'pattern': '^[a-zA-Z_][a-zA-Z0-9_.]+$'   # method name
                },
                {'type': 'string', 'pattern': '^$'}
            ]
        }
    },
    'app_public_keys': {
        'type': 'array',
        'items': {
            'type': 'object',
            'properties': {
                'public_key': {
                    'type': 'string',
                    'pattern': OP_HEX_PATTERN,
                },
                'device_id': {
                    'type': 'string',
                    'pattern': '.+',
                },
            },
            'required': [
                'public_key',
                'device_id'
            ],
        },
    },
}

APP_SESSION_REQUEST_PROPERTIES = APP_INFO_PROPERTIES.copy()
APP_SESSION_REQUEST_PROPERTIES.update({
    'app_private_key': {
        'type': 'string',
        'pattern': OP_HEX_PATTERN,
    },
    'device_id': {
        'type': 'string',
        'pattern': '.+',
    },
})

STORAGE_CLASSES = {
    'type': 'object',
    'patternProperties': {
        '.+': {
            'type': 'array',
            'items': {
                'type': 'string',
                'pattern': '.+',
            },
        },
    },
}

APP_SESSION_PROPERTIES = APP_INFO_PROPERTIES.copy()
APP_SESSION_PROPERTIES.update({
    'app_user_id': {
        'type': 'string',
        'pattern': OP_URLENCODED_NOSLASH_PATTERN,
    },
    'api_endpoint': {
        'anyOf': [
            {
                'type': 'string',
                'pattern': OP_URI_TARGET_PATTERN,
            },
            {
                'type': 'string',
                'pattern': OP_URI_TARGET_PATTERN_NOSCHEME,
            },
        ],
    },
    'device_id': {
        'type': 'string',
        'pattern': '.+',
    },
    'storage': {
        'classes': STORAGE_CLASSES,
        'preferences': {
            'type': 'object',
            'patternProperties': {
                '.+': STORAGE_CLASSES
            },
        },
    },
    'timestamp': {
        'type': 'integer',
        'minimum': 0,
    },
    'expires': {
        'type': 'integer',
    },
})


# application session JWT payload
APP_SESSION_SCHEMA = {
    'type': 'object',
    'properties': APP_SESSION_PROPERTIES,
    'required': APP_SESSION_PROPERTIES.keys(),
}

# authentication-request payload
APP_SESSION_REQUEST_SCHEMA = {
    'type': 'object',
    'properties': APP_SESSION_REQUEST_PROPERTIES,
    'required': [
        'app_public_keys', 'app_domain', 'version', 'methods',
        'blockchain_id', 'device_id' ],
}

# old session request schema
APP_SESSION_REQUEST_SCHEMA_OLD = {
    'type': 'object',
    'properties': {
        'app_domain': {
            'anyOf': [
                {
                    'type': 'string',
                    'pattern': OP_URI_TARGET_PATTERN,
                },
                {
                    'type': 'string',
                    'pattern': OP_URI_TARGET_PATTERN_NOSCHEME,
                },
            ],
        },
        'app_public_key': {
            'type': 'string',
            'pattern': OP_PUBKEY_PATTERN,
        },
        'methods': {
            'type': 'array',
            'items': {
                'type': 'string',
                'pattern': '^[a-zA-Z_][a-zA-Z0-9_.]+$'   # method name
            },
        },
    },
    'required': [
        'app_domain',
        'app_public_key',
        'methods'
    ],
}

# app configuration schema (goes alongside the index.html file)
APP_CONFIG_SCHEMA = {
    'type': 'object',
    'properties': {
        'blockchain_id': {
            'type': 'string',
            'pattern': OP_NAME_PATTERN,
        },
        'app_domain': {
            'type': 'string',
            'pattern': OP_URLENCODED_PATTERN,
        },
        'index_uris': {
            'type': 'array',
            'items': URI_RECORD_SCHEMA,
        },
        'driver_hints': {
            'type': 'array',
            'items': {
                'type': 'string'
            },
        },
        'api_methods': {
            'type': 'array',
            'items': {
                'type': 'string',
                'pattern': '^([a-zA-Z][a-zA-Z0-9_.]+)$'
            },
        },
    },
    'additionalProperties': False,
    'required': [
        'blockchain_id',
        'app_domain',
        'index_uris',
        'api_methods',
    ],
}


CREATE_DATASTORE_INFO_SCHEMA = {
    'type': 'object',
    'properties': {
        'datastore_blob': {
            'type': 'string',
        },
        'root_blob_header': {
            'type': 'string',
        },
        'root_blob_idata': {
            'type': 'string',
        },
    },
    'additionalProperties': False,
    'required': [
        'datastore_blob',
        'root_blob_header',
        'root_blob_idata',
    ],
}

CREATE_DATASTORE_SIGS_SCHEMA = {
    'type': 'object',
    'properties': {
        'datastore_sig': {
            'type': 'string',
        },
        'root_sig': {
            'type': 'string',
        },
    },
    'additionalProperties': False,
    'required': [
        'datastore_sig',
        'root_sig',
    ],
}

CREATE_DATASTORE_REQUEST_SCHEMA = {
    'type': 'object',
    'properties': {
        'datastore_info': CREATE_DATASTORE_INFO_SCHEMA,
        'datastore_sigs': CREATE_DATASTORE_SIGS_SCHEMA,
        'root_tombstones': {
            'type': 'array',
            'items': {
                'type': 'string',
            },
        },
    },
    'additionalProperties': False,
    'required': [
        'datastore_info',
        'datastore_sigs',
        'root_tombstones'
    ],
}


DELETE_DATASTORE_REQUEST_SCHEMA = {
    'type': 'object',
    'properties': {
        'datastore_tombstones': {
            'type': 'array',
            'items': {
                'type': 'string',
            },
        },
        'root_tombstones': {
            'type': 'array',
            'items': {
                'type': 'string',
            },
        },
    },
    'additionalProperties': False,
    'required': [
        'datastore_tombstones',
        'root_tombstones',
    ],
}


DATASTORE_LOOKUP_PATH_ENTRY_SCHEMA = {
    'type': 'object',
    'properties': {
        'name': {
            'type': 'string',
            'pattern': OP_URLENCODED_NOSLASH_OR_EMPTY_PATTERN,
        },
        'uuid': {
            'type': 'string',
            'pattern': OP_UUID_PATTERN,
        },
        'parent': {
            'type': 'string',
            'pattern': OP_URLENCODED_OR_EMPTY_PATTERN,
        },
        'inode': MUTABLE_DATUM_DIR_SCHEMA,
    },
    'required': [
        'name',
        'uuid',
        'parent',
        'inode',
    ],
    'additionalProperties': False,
}


DATASTORE_LOOKUP_INODE_SCHEMA = {
    'type': 'object',
    'properties': {
        'name': {
            'type': 'string',
            'pattern': OP_URLENCODED_NOSLASH_OR_EMPTY_PATTERN,
        },
        'uuid': {
            'type': 'string',
            'pattern': OP_UUID_PATTERN,
        },
        'parent': {
            'type': 'string',
            'pattern': OP_URLENCODED_OR_EMPTY_PATTERN,
        },
        'inode': {
            'anyOf': [
                MUTABLE_DATUM_DIR_SCHEMA,
                MUTABLE_DATUM_FILE_SCHEMA,
                MUTABLE_DATUM_INODE_HEADER_SCHEMA,
            ],
        },
    },
    'required': [
        'name',
        'uuid',
        'parent',
        'inode',
    ],
    'additionalProperties': False,
}


DATASTORE_LOOKUP_RESPONSE_SCHEMA = {
    'type': 'object',
    'properties': {
        'data': {
            'anyOf': [
                MUTABLE_DATUM_DIR_IDATA_SCHEMA,
                MUTABLE_DATUM_FILE_IDATA_SCHEMA,
                MUTABLE_DATUM_INODE_HEADER_SCHEMA,
            ],
        },
        'status': {
            'type': 'boolean',
        },
    },
    'additionalProperties': False,
    'required': [
        'data',
        'status',
    ],
}


DATASTORE_LOOKUP_EXTENDED_RESPONSE_SCHEMA = {
    'type': 'object',
    'properties': {
        'path_info': {
            'type': 'object',
            'patternProperties': {
                OP_URLENCODED_OR_EMPTY_PATTERN: DATASTORE_LOOKUP_INODE_SCHEMA,
            },
        },
        'inode_info': DATASTORE_LOOKUP_INODE_SCHEMA,
        'status': {
            'type': 'boolean',
        },
    },
    'additionalProperties': False,
    'required': [
        'path_info',
        'inode_info',
        'status',
    ],
}

OP_HISTORY_SCHEMA = {
    'type': 'object',
    'properties': {
        'address': {
            'type': 'string',
            'pattern': OP_ADDRESS_PATTERN,
        },
        'base': {
            'type': 'integer',
            'minimum': 0,
            'maximum': 255,
        },
        'buckets': {
            'anyOf': [
                {
                    'type': 'string',
                    'pattern': r'^\[((0|1|2|3|4|5|6|7|8|9|10|11|12|13|14|15), ){15}(0|1|2|3|4|5|6|7|8|9|10|11|12|13|14|15)\]$'
                },
                {
                    'type': 'array',
                    'items': {
                        'type': 'integer',
                        'minItems': 16,
                        'maxItems': 16,
                    },
                },
                {
                    'type': 'null',
                },
            ],
        },
        'block_number': {
            'type': 'integer',
            'minimum': 0,
        },
        'coeff': {
            'anyOf': [
                {
                    'type': 'integer',
                    'minimum': 0,
                    'maximum': 255,
                },
                {
                    'type': 'null'
                },
            ],
        },
        'consensus_hash': {
            'anyOf': [
                {
                    'type': 'string',
                    'pattern': OP_CONSENSUS_HASH_PATTERN,
                },
                {
                    'type': 'null'
                },
            ],
        },
        'fee': {
            'type': 'integer',
            'minimum': 0,
        },
        'first_registered': {
            'type': 'integer',
            'minimum': 0,
        },
        'history_snapshot': {
            'type': 'boolean',
        },
        'importer': {
            'anyOf': [
                {
                    'type': 'string',
                    'pattern': OP_P2PKH_PATTERN,
                },
                {
                    'type': 'null',
                },
            ],
        },
        'importer_address': {
            'anyOf': [
                {
                    'type': 'string',
                    'pattern': OP_ADDRESS_PATTERN,
                },
                {
                    'type': 'null',
                },
            ],
        },
        'last_renewed': {
            'type': 'integer',
            'minimum': 0,
        },
        'op': {
            'type': 'string',
            'pattern': OP_CODE_PATTERN,
        },
        'op_fee': {
            'type': 'number',
        },
        'opcode': {
            'type': 'string',
            'pattern': OP_CODE_NAME_PATTERN,
        },
        'revoked': {
            'type': 'boolean',
        },
        'sender': {
            'type': 'string',
            'pattern': OP_SCRIPT_PATTERN,
        },
        'sender_pubkey': {
            'anyOf': [
                {
                    'type': 'string',
                    'pattern': OP_PUBKEY_PATTERN,
                },
                {
                    'type': 'null'
                },
            ],
        },
        'recipient': {
            'anyOf': [
                {
                    'type': 'string',
                    'pattern': OP_SCRIPT_PATTERN,
                },
                {
                    'type': 'null'
                },
            ],
        },
        'recipient_address': {
            'anyOf': [
                {
                    'type': 'string',
                    'pattern': OP_ADDRESS_PATTERN,
                },
                {
                    'type': 'null'
                },
            ],
        },
        'recipient_pubkey': {
            'anyOf': [
                {
                    'type': 'string',
                    'pattern': OP_PUBKEY_PATTERN,
                },
                {
                    'type': 'null'
                },
            ],
        },
        'txid': {
            'type': 'string',
            'pattern': OP_TXID_PATTERN,
        },
        'value_hash': {
            'anyOf': [
                {
                    'type': 'string',
                    'pattern': OP_ZONEFILE_HASH_PATTERN,
                },
                {
                    'type': 'null',
                },
            ],
        },
        'vtxindex': {
            'type': 'integer',
            'minimum': 0,
        },
    },
    'required': [
        'op',
        'opcode',
        'txid',
        'vtxindex'
    ],
}

NAMEOP_SCHEMA_PROPERTIES = {
    'address': OP_HISTORY_SCHEMA['properties']['address'],
    'block_number': OP_HISTORY_SCHEMA['properties']['block_number'],
    'consensus_hash': OP_HISTORY_SCHEMA['properties']['consensus_hash'],
    'expired': {
        # NOTE: filled in by the indexer
        'type': 'boolean',
    },
    'expire_block': {
        # NOTE: filled in by the indexer
        'type': 'integer',
        'minimum': -1,
    },
    'renewal_deadline': {
        # NOTE: filled in by the indexer
        'type': 'integer',
        'minimum': -1,
    },
    'first_registered': OP_HISTORY_SCHEMA['properties']['first_registered'],
    'history': {
        'type': 'object',
        'patternProperties': {
            '^([0-9]+)$': {
                'type': 'array',
                'items': OP_HISTORY_SCHEMA,
            },
        },
    },
    'history_snapshot': {
        'type': 'boolean',
    },
    'importer': OP_HISTORY_SCHEMA['properties']['importer'],
    'importer_address': OP_HISTORY_SCHEMA['properties']['importer_address'],
    'last_renewed': OP_HISTORY_SCHEMA['properties']['last_renewed'],
    'name': {
        'type': 'string',
        'pattern': OP_NAME_PATTERN,
    },
    'op': OP_HISTORY_SCHEMA['properties']['op'],
    'op_fee': OP_HISTORY_SCHEMA['properties']['op_fee'],
    'opcode': OP_HISTORY_SCHEMA['properties']['opcode'],
    'revoked': OP_HISTORY_SCHEMA['properties']['revoked'],
    'sender': OP_HISTORY_SCHEMA['properties']['sender'],
    'sender_pubkey': OP_HISTORY_SCHEMA['properties']['sender_pubkey'],
    'recipient': OP_HISTORY_SCHEMA['properties']['recipient'],
    'recipient_address': OP_HISTORY_SCHEMA['properties']['recipient_address'],
    'txid': OP_HISTORY_SCHEMA['properties']['txid'],
    'value_hash': OP_HISTORY_SCHEMA['properties']['value_hash'],
    'vtxindex': OP_HISTORY_SCHEMA['properties']['vtxindex'],
}

NAMESPACE_SCHEMA_PROPERTIES = {
    'address': OP_HISTORY_SCHEMA['properties']['address'],
    'base': OP_HISTORY_SCHEMA['properties']['base'],
    'block_number': OP_HISTORY_SCHEMA['properties']['block_number'],
    'buckets': OP_HISTORY_SCHEMA['properties']['buckets'],
    'coeff': OP_HISTORY_SCHEMA['properties']['coeff'],
    'fee': OP_HISTORY_SCHEMA['properties']['fee'],
    'history': {
        'type': 'object',
        'patternProperties': {
            '^([0-9]+)$': {
                'type': 'array',
                'items': OP_HISTORY_SCHEMA,
            },
        },
    },
    'lifetime': {
        'type': 'integer'
    },
    'namespace_id': {
        'type': 'string',
        'pattern': OP_NAMESPACE_PATTERN,
    },
    # legacy field
    'namespace_id_hash': {
        'type': 'string',
        'pattern': OP_NAMESPACE_ID_HASH_PATTERN,
    },
    'no_vowel_discount': {
        'type': 'integer',
        'minimum': 0,
        'maximum': 15,
    },
    'nonalpha_discount': {
        'type': 'integer',
        'minimum': 0,
        'maximum': 15,
    },
    'op': OP_HISTORY_SCHEMA['properties']['op'],
    'preorder_hash': {
        'type': 'string',
        'pattern': OP_NAMESPACE_ID_HASH_PATTERN,
    },
    'ready': {
        'type': 'boolean',
    },
    'ready_block': {
        'type': 'integer',
        'minimum': 0,
    },
    'recipient': OP_HISTORY_SCHEMA['properties']['recipient'],
    'recipient_address': OP_HISTORY_SCHEMA['properties']['recipient_address'],
    'reveal_block': {
        'type': 'integer',
        'minimum': 0,
    },
    'sender': OP_HISTORY_SCHEMA['properties']['sender'],
    'sender_pubkey': OP_HISTORY_SCHEMA['properties']['sender_pubkey'],
    'txid': OP_HISTORY_SCHEMA['properties']['txid'],
    'version': {
        'type': 'integer',
        'minimum': 1,
    },
    'vtxindex': OP_HISTORY_SCHEMA['properties']['vtxindex'],
}

NAMEOP_SCHEMA_REQUIRED = [
    'address',
    'block_number',
    'op',
    'op_fee',
    'opcode',
    'sender',
    'txid',
    'vtxindex'
]

NAMESPACE_SCHEMA_REQUIRED = [
    'address',
    'base',
    'block_number',
    'buckets',
    'coeff',
    'lifetime',
    'namespace_id',
    'no_vowel_discount',
    'nonalpha_discount',
    'op',
    'ready',
    'recipient',
    'recipient_address',
    'reveal_block',
    'sender',
    'sender_pubkey',
    'txid',
    'version',
    'vtxindex'
]

# schema for an account entry in a profile
PROFILE_ACCOUNT_SCHEMA = {
    'type': 'object',
    'properties': {
        'service': {
            'type': 'string',
        },
        'identifier': {
            'type': 'string',
        },
        'contentUrl': {
            'type': 'string',
            'pattern': OP_URI_TARGET_PATTERN,
        },
    },
    'additionalProperties': True,
    'required': [
        'service',
        'identifier',
    ],
}


# key delegation schema 
KEY_DELEGATION_SCHEMA = {
    'type': 'object',
    'properties': {
        'version': {
            'type': 'string',
            'pattern': '^1\.0$',
        },
        'name': {
            'type': 'string',
            'pattern': OP_NAME_PATTERN,
        },
        'devices': {
            'type': 'object',
            'patternProperties': {
                '^.+$': {
                    'type': 'object',
                    'properties': {
                        'app': {
                            'type': 'string',
                            'pattern': OP_PUBKEY_PATTERN,
                        },
                        'enc': {
                            'type': 'string',
                            'pattern': OP_PUBKEY_PATTERN,
                        },
                        'sign': {
                            'type': 'string',
                            'pattern': OP_PUBKEY_PATTERN,
                        },
                        'index': {
                            'type': 'integer',
                            'minimum': 0,
                            'maximum': 2**31 - 1,
                        },
                    },
                    'required': [
                        'app',
                        'enc',
                        'sign',
                        'index',
                    ],
                    'additionalProperties': False,
                },
            },
        },
    },
    'required': [
        'version',
        'name',
        'devices',
    ],
    'additionalProperties': False,
}


# App key bundle
APP_KEY_BUNDLE_SCHEMA = {
    'type': 'object',
    'properties': {
        'version': {
            'type': 'string',
            'pattern': '^1\.0$',
        },
        'apps': {
            'type': 'object',
            'patternProperties': {
                OP_NAME_PATTERN: {
                    'type': 'string',
                    'pattern': OP_PUBKEY_PATTERN,
                },
            },
        },
    },
    'required': [
        'version',
        'apps'
    ],
    'additionalProperties': False,
}


# Blockstack token file 
BLOCKSTACK_TOKEN_FILE_SCHEMA = {
    'type': 'object',
    'properties': {
        'version': {
            'type': 'string',
            'pattern': '^3\.0$',
        },
        'profile': blockstack_profiles.person.PERSON_SCHEMA,
        'keys': {
            'delegation': KEY_DELEGATION_SCHEMA,
            'apps': {
                'type': 'object',
                'patternProperties': {
                    '^.+$': APP_KEY_BUNDLE_SCHEMA
                },
            },
            'required': [
                'delegation',
                'apps',
            ],
            'additionalProperties': False,
        },
    },
    'required': [
        'version',
        'profile',
        'keys',
    ],
    'additionalProperties': False,
}

