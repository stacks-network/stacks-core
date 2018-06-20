#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
    Blockstack
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016-2018 by Blockstack.org

    This file is part of Blockstack.

    Blockstack is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Blockstack is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with Blockstack. If not, see <http://www.gnu.org/licenses/>.
"""

from .config import LENGTHS, NAME_OPCODES, NAME_TRANSFER, TRANSFER_KEEP_DATA, TRANSFER_REMOVE_DATA, NAME_REGISTRATION

# schema constants
OP_HEX_PATTERN = r'^([0-9a-fA-F]+)$'
OP_CONSENSUS_HASH_PATTERN = r'^([0-9a-fA-F]{{{}}})$'.format(LENGTHS['consensus_hash'] * 2)
OP_ZONEFILE_HASH_PATTERN = r'^([0-9a-fA-F]{{{}}})$'.format(LENGTHS['value_hash'] * 2)
OP_BASE64_EMPTY_PATTERN = '^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$'    # base64 with empty string
OP_BASE58CHECK_CLASS = r'[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]'
OP_BASE58CHECK_PATTERN = r'^({}+)$'.format(OP_BASE58CHECK_CLASS)
OP_ADDRESS_PATTERN = r'^({}{{1,35}})$'.format(OP_BASE58CHECK_CLASS)
OP_NAME_CHARS = r'a-z0-9\-_.+'
OP_NAME_CHARS_NOPERIOD = r'a-z0-9\-_+'
OP_NAMESPACE_CLASS = r'[{}]{{{},{}}}'.format(OP_NAME_CHARS, 1, LENGTHS['namespace_id'])
OP_NAME_CLASS = r'[{}]{{{},{}}}\.{}'.format(OP_NAME_CHARS_NOPERIOD, 1, LENGTHS['fqn_max'], OP_NAMESPACE_CLASS)
OP_NAMESPACE_PATTERN = r'^({})$'.format(OP_NAMESPACE_CLASS)
OP_NAMESPACE_ID_HASH_PATTERN = r'^([0-9a-fA-F]{40})$'
OP_NAME_PATTERN = r'^({})$'.format(OP_NAME_CLASS)
OP_SUBDOMAIN_NAME_PATTERN = r'^([{}]+){{1,{}}}\.({})$'.format(OP_NAME_CHARS_NOPERIOD, LENGTHS['fqn_max'], OP_NAME_CLASS)    # FIXME: this encodes arbitrary length subdomains
OP_NAME_OR_SUBDOMAIN_FRAGMENT = r'({})|({})'.format(OP_NAME_PATTERN, OP_SUBDOMAIN_NAME_PATTERN)
OP_NAME_OR_SUBDOMAIN_PATTERN = r'^{}$'.format(OP_NAME_OR_SUBDOMAIN_FRAGMENT)
OP_URI_TARGET_PATTERN = r'^([a-z0-9+]+)://([a-zA-Z0-9\-_.~%#?&\\:/=]+)$'
OP_URI_TARGET_PATTERN_NOSCHEME = r'^([a-zA-Z0-9\-_.~%#?&\\:/=]+)$'
OP_URLENCODED_CLASS = r'[a-zA-Z0-9\-_.~%/]'
OP_URLENCODED_PATTERN = r'^({}+)$'.format(OP_URLENCODED_CLASS)
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
OP_PUBKEY_PATTERN = OP_HEX_PATTERN
OP_TXID_PATTERN = OP_HEX_PATTERN

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
        '$origin',
        '$ttl'
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
        'did': {
            'type': 'string',
        },
        'domain': {
            'type': 'string',
            'pattern': OP_NAME_PATTERN,
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
        'name': {
            'type': 'string',
            'pattern': OP_NAME_OR_SUBDOMAIN_PATTERN,
        },
        'namespace_id': {
            'type': 'string',
            'pattern': OP_NAMESPACE_PATTERN,
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
        'pending': {
            'type': 'boolean'
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
        'sequence': {
            'type': 'integer',
            'minimum': 0,
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
        'resolver': {
            'anyOf': [
                {
                    'type': 'string',
                },
                {
                    'type': 'null',
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
        'zonefile': {
            'type': 'string',
            'pattern': OP_BASE64_EMPTY_PATTERN,
        },
    },
    'required': [
        'txid',
    ],
}

NAMEOP_SCHEMA_PROPERTIES = {
    'address': OP_HISTORY_SCHEMA['properties']['address'],
    'block_number': OP_HISTORY_SCHEMA['properties']['block_number'],
    'consensus_hash': OP_HISTORY_SCHEMA['properties']['consensus_hash'],
    'domain': OP_HISTORY_SCHEMA['properties']['domain'],
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
        'pattern': OP_NAME_OR_SUBDOMAIN_PATTERN,
    },
    'op': OP_HISTORY_SCHEMA['properties']['op'],
    'op_fee': OP_HISTORY_SCHEMA['properties']['op_fee'],
    'opcode': OP_HISTORY_SCHEMA['properties']['opcode'],
    'revoked': OP_HISTORY_SCHEMA['properties']['revoked'],
    'resolver': {
        'anyOf': [
            {
                'type': 'string',
            },
            {
                'type': 'null',
            },
        ],
    },
    'sender': OP_HISTORY_SCHEMA['properties']['sender'],
    'sender_pubkey': OP_HISTORY_SCHEMA['properties']['sender_pubkey'],
    'sequence': OP_HISTORY_SCHEMA['properties']['sequence'],
    'recipient': OP_HISTORY_SCHEMA['properties']['recipient'],
    'recipient_address': OP_HISTORY_SCHEMA['properties']['recipient_address'],
    'txid': OP_HISTORY_SCHEMA['properties']['txid'],
    'value_hash': OP_HISTORY_SCHEMA['properties']['value_hash'],
    'vtxindex': OP_HISTORY_SCHEMA['properties']['vtxindex'],
    'zonefile': OP_HISTORY_SCHEMA['properties']['zonefile'],
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

SUBDOMAIN_SCHEMA_REQUIRED = [
    'address',
    'domain',
    'name',
    'block_number',
    'sequence',
    'txid',
    'value_hash',
]

