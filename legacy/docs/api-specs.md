# Group Core Node Administration

Blockstack Core's API module provides a set of API calls for interacting with
the node's configuration.  Most configuration state is in the [Blockstack
Browser](https://github.com/blockstack/blockstack-browser).  Client-side state
is managed by [blockstack.js](https://github.com/blockstack/blockstack.js).

## Ping the node [GET /v1/node/ping]

Ping the Blockstack node to see if it's alive.

+ Public Endpoint
+ Response 200 (application/json)
  + Body

            {
                "status": "alive",
                "version": "###version###"
            }
  + Schema

            {
                "type": "object",
                "properties": {
                    "status": {
                        "type": "string"
                    },
                    "version": {
                        "type": "string"
                    }
                },
                "required": [
                    "status",
                    "version"
                ]
            }

# Group Managing Names

## Fetch zone file [GET /v1/names/{name}/zonefile]

Fetch a user's raw zone file.  This only works for RFC-compliant zone files.
This method returns an error for names that have non-standard zone files.

+ Public Endpoint
+ Parameters
  + name: bar.test (string) - fully-qualified name
+ Response 200 (application/json)
  + Body

            {
                "zonefile": "$ORIGIN bar.test\n$TTL 3600\n_https._tcp URI 10 1 \"https://gaia.blockstack.org/hub/17Zijx61Sp7SbVfRTdETo7PhizJHYEUxbY/profile.json\"\n"
            }

  + Schema

            {
                'anyOf': [
                  {
                    'type': 'object',
                    'properties': {
                        'zonefile': {
                            'type': 'string',
                            'pattern': '.+',
                        },
                   },
                   {
                     'type': 'object',
                     'properties': {
                        'error': {
                            'type': 'string',
                            'pattern': '.+',
                        },
                    },
                ]
            }

+ Response 400 (application/json)
  + Body

            { "error": "Invalid name or subdomain" }

  + Schema

            {
                'type': 'object',
                'properties': {
                    'error': { 'type': 'string' },
                },
            }

+ Response 404 (application/json)
  + Body

            { "error": "No zone file for name" }

  + Schema

            {
                'type': 'object',
                'properties': {
                    'error': { 'type': 'string' },
                },
            }

# Group Name Querying

This family of API endpoints deals with querying name information.

## Get all names [GET /v1/names?page={page}]
Fetch a list of all names known to the node.
+ Public Endpoint
+ Parameters
  + page: 23 (number) - names are returned in pages of size 100,
    so specify the page number.
+ Response 200 (application/json)
  + Body

               [ "aldenquimby.id", "aldeoryn.id",
                 "alderete.id", "aldert.id",
                 "aldi.id", "aldighieri.id", ... ]

  + Schema

              {
                 'type': 'array',
                 'items': {
                       'type': 'string',
                       'pattern': '^([a-z0-9\\-_.+]{3,37})$',
                 }
              }

+ Response 400 (application/json)
  + Body

            { "error": "Invalid page" }

  + Schema

            {
                'type': 'object',
                'properties': {
                    'error': { 'type': 'string' },
                },
            }


## Get all subdomains [GET /v1/subdomains?page={page}]
Fetch a list of all names known to the node.
+ Public Endpoint
+ Parameters
  + page: 3 (number) - names are returned in pages of size 100,
    so specify the page number.
+ Response 200 (application/json)
  + Body

                [ ...
                  "collegeinfogeek.verified.podcast",
                  "collider.verified.podcast",
                  "combatandclassics.verified.podcast",
                  "combatjack.verified.podcast",
                  "comedybangbang.verified.podcast",
                  "comedybutton.verified.podcast",
                  "commonsense.verified.podcast",
                  "concilio002.personal.id", ... ]

  + Schema

              {
                 'type': 'array',
                 'items': {
                       'type': 'string',
                       'pattern': '^([a-z0-9\\-_.+]{3,37})\.([a-z0-9\\-_.+]{3,37})$',
                 }
              }

+ Response 400 (application/json)
  + Body

            { "error": "Invalid page" }

  + Schema

            {
                'type': 'object',
                'properties': {
                    'error': { 'type': 'string' },
                },
            }

## Get name info [GET /v1/names/{name}]
+ Public Endpoint
+ Subdomain Aware
+ Parameters
  + name: muneeb.id (string) - fully-qualified name
+ Response 200 (application/json)
  + Body

              {
                "address": "1J3PUxY5uDShUnHRrMyU6yKtoHEUPhKULs",
                "blockchain": "bitcoin",
                "expire_block": 599266,
                "grace_period": false,
                "last_txid": "1edfa419f7b83f33e00830bc9409210da6c6d1db60f99eda10c835aa339cad6b",
                "renewal_deadline": 604266,
                "resolver": null,
                "status": "registered",
                "zonefile": "$ORIGIN muneeb.id\n$TTL 3600\n_http._tcp IN URI 10 1 \"https://gaia.blockstack.org/hub/1J3PUxY5uDShUnHRrMyU6yKtoHEUPhKULs/0/profile.json\"\n",
                "zonefile_hash": "37aecf837c6ae9bdc9dbd98a268f263dacd00361"
              }

  + Schema

               {
                 'type': 'object',
                 'properties': {
                   'address': {
                       'type': 'string',
                       'pattern': "^([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+)$",
                   },
                   'blockchain': {
                       'type': 'string',
                       'pattern': '^bitcoin$',
                   },
                   'expire_block': {
                       'type': 'integer',
                       'minimum': 0,
                   },
                   'grace_period': {
                       'type': 'integer',
                       'minimum': 0,
                   },
                   'last_txid': {
                       'type': 'string',
                       'pattern': '^[0-9a-fA-F]+$',
                   },
                   'resolver': {
                        'type': 'string',
                   },
                   'status': {
                       'type': 'string',
                       'pattern': '^(registered|revoked)$',
                   },
                   'zonefile': {
                       'anyOf': [
                          {
                              'type': 'string',
                          },
                          {
                              'type': 'object',
                              'properties': {
                                  'error': {
                                      'type': 'string',
                                  },
                              },
                          },
                       ],
                   },
                   'zonefile_hash': {
                       'type': 'string',
                       'pattern': '^[0-9a-fA-F]{20}$`,
                   },
                 },
                 { 'required':
                   [
                     'address', 'blockchain', 'last_txid',
                     'status', 'zonefile', 'zonefile_hash'
                   ]
                 }
               }

+ Response 400 (application/json)
  + Body

            { "error": "Invalid name or subdomain" }

  + Schema

            {
                'type': 'object',
                'properties': {
                    'error': { 'type': 'string' },
                },
            }

+ Response 404 (application/json)
  + Body

            { "error": "No such name" }

  + Schema

            {
                'type': 'object',
                'properties': {
                    'error': { 'type': 'string' },
                },
            }

## Get name history [GET /v1/names/{name}/history?page={page}]
Get a history of all blockchain records of a registered name.
+ Public Endpoint
+ Subdomain aware
+ Parameters
  + name: muneeb.id (string) - name to query
  + page: 0 (integer) - the page (in 20-entry pages) of the history to fetch
+ Response 200 (application/json)
  + Body

            {
              "373821": [
                {
                  "address": "1QJQxDas5JhdiXhEbNS14iNjr8auFT96GP",
                  "block_number": 373821,
                  "consensus_hash": null,
                  "first_registered": 373821,
                  "importer": "76a9143e2b5fdd12db7580fb4d3434b31d4fe9124bd9f088ac",
                  "importer_address": "16firc3qZU97D1pWkyL6ZYwPX5UVnWc82V",
                  "last_creation_op": ";",
                  "last_renewed": 373821,
                  "name": "muneeb.id",
                  "name_hash128": "deb7fe99776122b77925cbf0a24ab6f8",
                  "namespace_block_number": 373601,
                  "namespace_id": "id",
                  "op": ";",
                  "op_fee": 100000.0,
                  "opcode": "NAME_IMPORT",
                  "preorder_block_number": 373821,
                 }
               ]
             }

  + Schema

            {
             'type': 'object',
             'patternProperties': {
               '^[0-9]+': {
                 'type': 'array',
                 'items': {
                    'type': 'object',
                    'properties': {
                        'address': {
                            'type': 'string',
                            'pattern': "^([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+)$",
                        },
                        'base': {
                            'type': 'integer',
                            'minimum': 0,
                            'maximum': 255,
                        },
                        'buckets': {
                            'anyOf': [
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
                                    'pattern': '^[0-9a-fA-F]{32}',
                                },
                                {
                                    'type': 'null'
                                },
                            ],
                        },
                        'domain': {
                            'type': 'string',
                            'pattern': '^([a-z0-9\\-_.+]{3,37})$',
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
                                    'pattern': '^76[aA]914[0-9a-fA-F]{40}88[aA][cC]$',
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
                                    'pattern': "^([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+)$",
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
                            'pattern': '^([a-z0-9\\-_.+]{3,37})\.([a-z0-9\\-_.+]{3,37})$',
                        },
                        'op': {
                            'type': 'string',
                            'pattern': '^([>?+~:!&*:;#]{1}|>>|>~|::)$',
                        },
                        'op_fee': {
                            'type': 'number',
                        },
                        'opcode': {
                            'type': 'string',
                            'pattern': '^NAME_TRANSFER|NAME_PREORDER|NAME_UPDATE|NAME_REVOKE|NAME_REGISTRATION|NAMESPACE_READY|NAMESPACE_REVEAL|NAMESPACE_PREORDER|NAME_RENEWAL|NAME_IMPORT|ANNOUNCE$'
                        },
                        'revoked': {
                            'type': 'boolean',
                        },
                        'sender': {
                            'type': 'string',
                            'pattern': '^([0-9a-fA-F]+)$',
                        },
                        'sender_pubkey': {
                            'anyOf': [
                                {
                                    'type': 'string',
                                    'pattern': '^([0-9a-fA-F]+)$',
                                },
                                {
                                    'type': 'null'
                                },
                            ],
                        },
                        'sequence': {
                            'type': 'integer',
                            'minimum': 0
                        }
                        'recipient': {
                            'anyOf': [
                                {
                                    'type': 'string',
                                    'pattern': '^([0-9a-fA-F]+)$',
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
                                    'pattern': '^([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+)$',
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
                                    'pattern': '^([0-9a-fA-F]+)$',
                                },
                                {
                                    'type': 'null'
                                },
                            ],
                        },
                        'txid': {
                            'type': 'string',
                            'pattern': '^([0-9a-fA-F]+)$',
                        },
                        'value_hash': {
                            'anyOf': [
                                {
                                    'type': 'string',
                                    'pattern': '^([0-9a-fA-F]{40})$',
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
                        'txid',
                        'vtxindex'
                    ],
                  }
                }
              }
            }

+ Response 400 (application/json)
  + Body

            { "error": "Invalid page" }

  + Schema

            {
                'type': 'object',
                'properties': {
                    'error': { 'type': 'string' },
                },
            }

+ Response 404 (application/json)
  + Body

            { "error": "No such name" }

  + Schema

            {
                'type': 'object',
                'properties': {
                    'error': { 'type': 'string' },
                },
            }

## Get subdomains at transaction [GET /v1/subdomains/{txid}]
Fetches the list of subdomain operations processed by a given transaction.
The returned array includes subdomain operations that have not yet been accepted
as part of any subdomain's history (checkable via the `accepted` field).  If the
given transaction ID does not correspond to a Blockstack transaction that
introduced new subdomain operations, and empty array will be returned.

+ Public Endpoint
+ Subdomain aware
+ Parameters
  + txid: d04d708472ea3c147f50e43264efdb1535f71974053126dc4db67b3ac19d41fe (string) the transaction ID
+ Response 200 (application/json)
  + Body

            [
              {
                "accepted": 1,
                "block_height": 546199,
                "domain": "id.blockstack",
                "fully_qualified_subdomain": "nturl345.id.blockstack",
                "missing": "",
                "owner": "17Q8hcsxRLCk3ypJiGeXQv9tFK9GnHr5Ea",
                "parent_zonefile_hash": "58224144791919f6206251a9960a2dd5723b96b6",
                "parent_zonefile_index": 95780,
                "resolver": "https://registrar.blockstack.org",
                "sequence": 0,
                "signature": "None",
                "txid": "d04d708472ea3c147f50e43264efdb1535f71974053126dc4db67b3ac19d41fe",
                "zonefile_hash": "d3bdf1cf010aac3f21fac473e41450f5357e0817",
                "zonefile_offset": 0
              },
              {
                "accepted": 1,
                "block_height": 546199,
                "domain": "id.blockstack",
                "fully_qualified_subdomain": "dwerner1.id.blockstack",
                "missing": "",
                "owner": "17tFeKEBMUAAiHVsCgqKo8ccwYqq7aCn9X",
                "parent_zonefile_hash": "58224144791919f6206251a9960a2dd5723b96b6",
                "parent_zonefile_index": 95780,
                "resolver": "https://registrar.blockstack.org",
                "sequence": 0,
                "signature": "None",
                "txid": "d04d708472ea3c147f50e43264efdb1535f71974053126dc4db67b3ac19d41fe",
                "zonefile_hash": "ab79b1774fa7a4c5709b6ad4e5892fb7c0f79765",
                "zonefile_offset": 1
              }
            ]

  + Schema

            {
              'type': 'array',
              'items': {
                'type': 'object',
                'properties': {
                   'accepted': { 'type': 'integer', 'minimum': 0, 'maximum': 1 },
                   'block_height': { 'type': 'integer', 'minimum': 0 },
                   'domain': { 'type': 'string', 'pattern': '^([a-z0-9\\-_.+]{3,37})$|^([a-z0-9\\-_.+]){3,37}$' },
                   'fully_qualified_subdomain: { 'type': 'string', 'pattern': '^([a-z0-9\\-_.+]{3,37})\.([a-z0-9\\-_.+]{3,37})$' },
                   'missing': { 'type': 'string' },
                   'owner': { 'type': 'string', 'pattern': "^([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+)$" },
                   'parent_zonefile_hash': { 'type': 'string', 'pattern': '^[0-9a-fA-F]{40}' },
                   'parent_zonefile_index': { 'type': 'integer', 'minimum': 0 },
                   'resolver': { 'type': 'string' },
                   'sequence': { 'type': 'integer', 'minimum': 0 },
                   'signature': { 'type': 'string' },
                   'txid': { 'type': 'string', 'pattern': '^[0-9a-fA-F]{64}' },
                   'zonefile_hash': { 'type': 'string', 'pattern': '^[0-9a-fA-F]{40}' },
                   'zonefile_offset': { 'type': 'integer', 'minimum': 0 }
                },
                'required': [ 'accepted, 'block_height, 'domain',
                              'fully_qualified_subdomain', 'missing', 'owner',
                              'parent_zonefile_hash', 'parent_zonefile_index', 'resolver',
                              'sequence', 'signature', 'txid', 'zonefile_hash',
                              'zonefile_offset' ]
               }
            }
    
+ Response 400 (application/json)
  + Body

            { "error": "Invalid txid" }

  + Schema

            {
                'type': 'object',
                'properties': {
                    'error': { 'type': 'string' },
                },
            }
    
## Get historical zone file [GET /v1/names/{name}/zonefile/{zoneFileHash}]
Fetches the historical zonefile specified by the username and zone hash.
+ Public Endpoint
+ Subdomain aware
+ Parameters
  + name: muneeb.id (string) username to fetch
  + zoneFileHash: b100a68235244b012854a95f9114695679002af9
+ Response 200 (application/json)
  + Body

               {
                 "zonefile": "$ORIGIN muneeb.id\n$TTL 3600\n_http._tcp IN URI 10 1 \"https://blockstack.s3.amazonaws.com/muneeb.id\"\n"
               }

  + Schema

               {
                   'anyOf': [
                      {
                          'type': 'object',
                          'properties': {
                              'zonefile': { 'type': 'string' },
                          },
                      },
                      {
                          'type': 'object',
                          'properties': {
                              'error': { 'type': 'string' },
                          },
                      },
                   ],
               }

+ Response 400 (application/json)
  + Body

            { "error": "Invalid name or subdomain" }

  + Schema

            {
                'type': 'object',
                'properties': {
                    'error': { 'type': 'string' },
                },
            }

+ Response 404 (application/json)
  + Body

            { "error": "No such zonefile" }

  + Schema

            {
                'type': 'object',
                'properties': {
                    'error': { 'type': 'string' },
                },
            }

## Get names owned by address [GET /v1/addresses/{blockchain}/{address}]
Retrieves a list of names owned by the address provided.
+ Subdomain Aware
+ Public Endpoint
+ Parameters
  + blockchain: bitcoin (string) - the layer-1 blockchain for the address
  + address: 1QJQxDas5JhdiXhEbNS14iNjr8auFT96GP (string) - the address to lookup

+ Response 200 (application/json)
  + Body

               {
                   "names": ["muneeb.id"]
               }

   + Schema

               {
                   'type': 'object',
                   'properties': {
                       'names': {
                           'type': 'array',
                           'items': {
                               'type': 'string',
                               'pattern': '^([a-z0-9\-_.+]{3,37})$',
                           }
                       }
                   }
               }

+ Response 404 (application/json)
  + Body

            { "error": "Unsupported blockchain" }

  + Schema

            {
                'type': 'object',
                'properties': {
                    'error': { 'type': 'string' },
                },
            }

# Group Price Checks

## Get namespace price [GET /v2/prices/namespaces/{tld}]

This endpoint is used to get the price of a namespace, while explicitly
indicating the cryptocurrency units.  This is because going forward, namespaces
are not necessarily priced in Bitcoin.

+ Public Endpoint
+ Parameters
  + tld: id (string) - namespace to query price for
+ Response 200 (application/json)
  + Body

             {
               "units": "BTC",
               "amount": "4000000000"
             }

  + Schema

            {
                'type': 'object',
                'properties': {
                    'units': {
                        'type': 'string',
                    },
                    'amount': {
                        'type': 'string',
                        'pattern': '^[0-9]+$',
                    },
                },
                'required': [ 'units', 'amount' ]
            }

+ Response 400 (application/json)
  + Body

            { "error": "Invalid namespace" }

  + Schema

            {
                'type': 'object',
                'properties': {
                    'error': { 'type': 'string' },
                },
            },

## Get name price [GET /v2/prices/names/{name}]

This endpoint is used to get the price of a name, denoted in a specific
cryptocurrency (not necessarily Bitcoin).

+ Public Endpoint
+ Parameters
    + name: muneeb.id (string) - name to query price information for
+ Response 200 (application/json)
  + Body

               {
                  "name_price": {
                    "units": "BTC",
                    "amount": "100000"
                  },
               }

    + Schema

               {
                   'type': 'object',
                   'properties': {
                       'name_price': {
                           'type': 'object',
                           'properties': {
                               'units': { 'type': 'string' },
                               'amount': { 'type': 'string', 'pattern': '^[0-9]+$' }
                           },
                           'required': [ 'units', 'amount' ],
                       },
                      'required': [ 'name_price' ]
                   }
               }

+ Response 400 (application/json)
  + Body

            { "error": "Invalid name" }

  + Schema

            {
                'type': 'object',
                'properties': {
                    'error': { 'type': 'string' },
                },
            },

## Legacy Get namespace price [GET /v1/prices/namespaces/{tld}]

This endpoint is used to get the price of a namespace in Bitcoin.

+ Public Endpoint
+ Legacy Endpoint
+ Parameters
  + tld: id (string) - namespace to query price for
+ Response 200 (application/json)
  + Body

             {
               "satoshis": 4000000000,
               "units": "BTC",
               "amount": "4000000000"
             }

  + Schema

            {
                'type': 'object',
                'properties': {
                    'units': {
                        'type': 'string',
                    },
                    'amount': {
                        'type': 'string',
                        'pattern': '^[0-9]+$',
                    },
                    'satoshis': {
                        'type': 'integer',
                        'minimum': 0,
                    },
                },
                'required': [ 'satoshis' ]
            }

+ Response 400 (application/json)
  + Body

            { "error": "Invalid namepace" }

  + Schema

            {
                'type': 'object',
                'properties': {
                    'error': { 'type': 'string' },
                },
            }

## Legacy Get name price [GET /v1/prices/names/{name}]

This endpoint is used to get the price of a name in Bitcoin.

+ Public Endpoint
+ Legacy Endpoint
+ Parameters
    + name: muneeb.id (string) - name to query price information for
+ Response 200 (application/json)
  + Body

               {
                  "name_price": {
                    "satoshis": 100000,
                    "units": "BTC",
                    "amount": "100000"
                  },
               }

    + Schema

               {
                   'type': 'object',
                   'properties': {
                       'name_price': {
                           'type': 'object',
                           'properties': {
                               'satoshis': { 'type': 'integer', 'minimum': 0 },
                               'units': { 'type': 'string' },
                               'amount': { 'type': 'string', 'pattern': '^[0-9]+$' }
                           },
                           'required': [ 'satoshis' ],
                       },
                      'required': [ 'name_price' ]
                   }
               }

+ Response 400 (application/json)
  + Body

            { "error": "Invalid name" }

  + Schema

            {
                'type': 'object',
                'properties': {
                    'error': { 'type': 'string' },
                },
            }
# Group Blockchain Operations

## Get consensus hash [GET /v1/blockchains/{blockchainName}/consensus]

Get the current Blockstack consensus hash on a blockchain.
+ Public Endpoint
+ Parameters
  + blockchainName : bitcoin (string) - the given blockchain
+ Response 200 (application/json)
  + Body

               {
                  "consensus_hash": "2fcbdf66c350894fe03b42c6a2e8a6ac"
               }

  + Schema

               {
                 'type': 'object',
                 'properties': {
                     'consensus_hash': {
                         'type': 'string',
                         'pattern': '^[0-9a-fA-F]{32}$`,
                     },
                 },
              }

+ Response 404 (application/json)
  + Body

            { "error": "Unsupported blockchain" }

  + Schema

            {
                'type': 'object',
                'properties': {
                    'error': { 'type': 'string' },
                },
            }

## Get total names on blockchain [GET /v1/blockchains/{blockchainName}/name_count{?all}]

Get a count of the number of names on a blockchain.  This does not include
subdomains.
+ Public Endpoint
+ Parameters
  + blockchainName: bitcoin (string) - the given blockchain
  + all: true (enum[string], optional) - include expired names
+ Response 200 (application/json)
  + Body

            {
                "names_count": 73950
            }

  + Schema

            {
                'type': 'object',
                'properties': {
                    'names_count': {
                        'type': 'integer',
                        'minimum': 0,
                    },
                },
            }

+ Response 404 (application/json)
  + Body

            { "error": "Unsupported blockchain" }

  + Schema

            {
                'type': 'object',
                'properties': {
                    'error': { 'type': 'string' },
                },
            },


## Get total subdomains on blockchain [GET /v1/blockchains/{blockchainName}/subdomains_count]
Get the number of subdomains on a blockchain.
+ Public Endpoint
+ Parameters
  + blockchainName: bitcoin (string) - the given blockchain
+ Response 200 (application/json)
  + Body

            {
                "names_count": 1646
            }

  + Schema

            {
                'type': 'object',
                'properties': {
                    'names_count': {
                        'type': 'integer',
                        'minimum': 0,
                    },
                },
            }

+ Response 404 (application/json)
  + Body

            { "error": "Unsupported blockchain" }

  + Schema

            {
                'type': 'object',
                'properties': {
                    'error': { 'type': 'string' },
                },
            },


## Get operations in block [GET /v1/blockchains/{blockchainName}/operations/{blockHeight}]

Get the Blockstack operations in a given block
+ Public Endpoint
+ Parameters
  + blockchainName : bitcoin (string) - the given blockchain
  + blockHeight : 462592 (integer) - the block height
+ Response 200 (application/json)
  + Body

            [
              {
                "address": "1GS1eHthSK2gqnU9MW9Nis1pUyHP3bJnFK",
                "block_number": 462592,
                "burn_address": "1111111111111111111114oLvT2",
                "consensus_hash": "d206b2f615de00803402cade4d0d51d4",
                "op": "?",
                "op_fee": 6250,
                "opcode": "NAME_PREORDER",
                "preorder_hash": "ba22cdf24b05b9a7972e13ada69f96a7850b471e",
                "sender": "76a914a944d29012f83c00105778e0bc717c46ea2accfc88ac",
                "sender_pubkey": "0343b263f7adc6ae59e8d8310f4a6a87799f6b10cec608f3236cd6a802ffc71728",
                "txid": "b3f4f7a43d60666d1a9b42131f9117ad7deac34a478b6ca152344da3d734691f",
                "vtxindex": 173
              },
              {
                "address": "1gijbF8NkbgwzcoZR1nXMa76NbdcD7GQW",
                "block_number": 462592,
                "burn_address": "1111111111111111111114oLvT2",
                "consensus_hash": "d206b2f615de00803402cade4d0d51d4",
                "op": "?",
                "op_fee": 6250,
                "opcode": "NAME_PREORDER",
                "preorder_hash": "386e2de88a908ad056361e586faa95852be454ca",
                "sender": "76a91407830f81167f6a2aa253c0f176b7ff2e1c04c61a88ac",
                "sender_pubkey": "03b7795d33b362338179e5b2a579431b285f6c303d07ddd83c897277be4e5eb916",
                "txid": "4dd315ad1d1b318614a19e15e767efb7ef327bd5cd4ebaf8f80ede58fd1da107",
                "vtxindex": 174
              },
              {
                "address": "17QEd6rrhNZp4xoyWu6BpA8NQ4axyNKaZy",
                "block_number": 462592,
                "burn_address": "1111111111111111111114oLvT2",
                "consensus_hash": "d206b2f615de00803402cade4d0d51d4",
                "op": "?",
                "op_fee": 6250,
                "opcode": "NAME_PREORDER",
                "preorder_hash": "a7a388a2bbe0e7741c6cfdc54d7b5a67811cd582",
                "sender": "76a9144635b1794a22bfbe6c5c5eba17b693f4aaf0e34888ac",
                "sender_pubkey": "020d6e50b2660af27933c42bc1395fe93df90ffac5e2a989f6a134919fb8cf8075",
                "txid": "51d6bd117da5889e710c62967d03233a84fc27f7fad10ca4359111928818f017",
                "vtxindex": 332
              },
              {
                "address": "15YMyvqz6v9ATSbmqJnudwrdm7RiVfkU3s",
                "block_number": 462453,
                "consensus_hash": "f6491e1d2b9817fa58512fc9bf8cd3df",
                "first_registered": 462575,
                "importer": null,
                "importer_address": null,
                "keep_data": true,
                "last_renewed": 462575,
                "name": "ablankstein.id",
                "name_hash128": "943b8e0613d975c05a05ccd5472e2a72",
                "namespace_block_number": 373601,
                "namespace_id": "id",
                "op": ">>",
                "op_fee": 25000,
                "opcode": "NAME_TRANSFER",
                "preorder_block_number": 462453,
                "preorder_hash": "822d5cb6f2e3f0f901d6af8c1111ee466b6c07bd",
                "revoked": false,
                "sender": "76a91431cee995f242f0f66518080a291714cd7e8d2f5e88ac",
                "sender_pubkey": null,
                "txid": "121540e81223c45d139fbe03a9713ddd292372f2f88fe2b10b6a7c5e6738e87f",
                "value_hash": "96ec93cbc57d17b16a347c11ddfa7ea88d2cf93b",
                "vtxindex": 633
              },
              {
                "address": "1Dwq9oA5BNz7DAR1LtDncEa647ZxgmkoVV",
                "block_number": 462325,
                "consensus_hash": "1288cef43f52bf97e2f458a4afe40b61",
                "first_registered": 462359,
                "importer": null,
                "importer_address": null,
                "keep_data": true,
                "last_renewed": 462359,
                "name": "fpenrose.id",
                "name_hash128": "7af28a9834934a0af81a19ee14a45f8e",
                "namespace_block_number": 373601,
                "namespace_id": "id",
                "op": ">>",
                "op_fee": 25000,
                "opcode": "NAME_TRANSFER",
                "preorder_block_number": 462325,
                "preorder_hash": "59c25d7cddf433b5122cabcbf2ebcc1bc1519e4d",
                "revoked": false,
                "sender": "76a9148e002a93b9b1936b5d320967194eaff3deaa979088ac",
                "sender_pubkey": null,
                "txid": "6461bb4bbf517e9c80ffcac4c349836972656572e113aba736b356119655064e",
                "value_hash": "ac73155702ca7aea1161d0f0c7877ac81d48d8fc",
                "vtxindex": 637
              },
              {
                "address": "1Q44Md5KFr6gxQ6TdUSFaCRm3MaUyXMF6t",
                "block_number": 462316,
                "consensus_hash": "1288cef43f52bf97e2f458a4afe40b61",
                "first_registered": 462353,
                "importer": null,
                "importer_address": null,
                "keep_data": true,
                "last_renewed": 462353,
                "name": "rahulpradhan.id",
                "name_hash128": "c55ff9e14c72b2950b14ff10067d7e27",
                "namespace_block_number": 373601,
                "namespace_id": "id",
                "op": ">>",
                "op_fee": 25000,
                "opcode": "NAME_TRANSFER",
                "preorder_block_number": 462316,
                "preorder_hash": "fcb3389ca4d2ab8003ce8b6b3baa0a5ae1600cce",
                "revoked": false,
                "sender": "76a914fcdef125f40f984fafad4b58e30e3b1761a953f388ac",
                "sender_pubkey": null,
                "txid": "be58e02642c457fec2835a354fbc2de45e8c838aa5b7fd18ed831f67d08269e6",
                "value_hash": "e213e58ca1446875b79d866720130cc90cbca681",
                "vtxindex": 638
              },
              {
                "address": "1D8pL725X9HWvoTVgzqDNbTPayHGG7tkY6",
                "block_number": 462345,
                "consensus_hash": "919df884f14f34fd15a791af2fddb569",
                "first_registered": 462380,
                "importer": null,
                "importer_address": null,
                "keep_data": true,
                "last_renewed": 462380,
                "name": "sajithskurup.id",
                "name_hash128": "3fda1c60620c42e1ede385bb246bd5f0",
                "namespace_block_number": 373601,
                "namespace_id": "id",
                "op": ">>",
                "op_fee": 25000,
                "opcode": "NAME_TRANSFER",
                "preorder_block_number": 462345,
                "preorder_hash": "540daefe1f3b520253f7ab954dbc8bf131471133",
                "revoked": false,
                "sender": "76a914851bee0185dd799755234fb20710a26ec40354d288ac",
                "sender_pubkey": null,
                "txid": "e7d35196ca3eec697274d848136f5267b1c935055a917020f93e8ecaf821ba99",
                "value_hash": "92534954e934019718478bb52150765dfad79171",
                "vtxindex": 644
              },
              {
                "address": "1EbjXtYv9QCVBp8iWiDH6xQ1B74oFW696X",
                "block_number": 462345,
                "consensus_hash": "e0c31e03125f2feefd4090e5c635ee45",
                "first_registered": 462380,
                "importer": null,
                "importer_address": null,
                "keep_data": true,
                "last_renewed": 462380,
                "name": "hubject.id",
                "name_hash128": "03e8bf92dd3cbde65cac012350efb79d",
                "namespace_block_number": 373601,
                "namespace_id": "id",
                "op": ">>",
                "op_fee": 25000,
                "opcode": "NAME_TRANSFER",
                "preorder_block_number": 462345,
                "preorder_hash": "ded4d097614cf5321388bbe56b24d3d592b2ef76",
                "revoked": false,
                "sender": "76a914952b4844005dd98a1f7fc99813db2a649109b45988ac",
                "sender_pubkey": null,
                "txid": "7b7a2a2963f7454b93003031cfce64ac609f902b4c2cababfbbfad2c01bbeb9b",
                "value_hash": "be968a1f17ac828179e5b2fbc70d238056af7482",
                "vtxindex": 645
              },
              {
                "address": "14YsDo5qgAP7kmnq33tw9JdHVBywpg9pge",
                "block_number": 462326,
                "consensus_hash": "e0c31e03125f2feefd4090e5c635ee45",
                "first_registered": 462354,
                "importer": null,
                "importer_address": null,
                "keep_data": true,
                "last_renewed": 462354,
                "name": "ramimassoud.id",
                "name_hash128": "61a48b6f8aeb027883ecd1f8d808c8ac",
                "namespace_block_number": 373601,
                "namespace_id": "id",
                "op": ">>",
                "op_fee": 25000,
                "opcode": "NAME_TRANSFER",
                "preorder_block_number": 462326,
                "preorder_hash": "23aa275e42d7d6d7e538584a799252939687c457",
                "revoked": false,
                "sender": "76a91426ef31b7aac60eff23cbbab51d453b84700e330388ac",
                "sender_pubkey": null,
                "txid": "85babcf66caf41cb7beb2e637cbed4e728ab8030337fb5df8461d0e14dd2be75",
                "value_hash": "e27c9c3dcce8a8445d84fb8b4d81fbd30fac9749",
                "vtxindex": 646
              },
              {
                "address": "1H934mT7AVVZmHwjddUZ9EiostLwm655oF",
                "block_number": 462345,
                "consensus_hash": "919df884f14f34fd15a791af2fddb569",
                "first_registered": 462391,
                "importer": null,
                "importer_address": null,
                "keep_data": true,
                "last_renewed": 462391,
                "name": "was2bme.id",
                "name_hash128": "f2b5688682fd47b8f3fbf709bb35ef33",
                "namespace_block_number": 373601,
                "namespace_id": "id",
                "op": ">>",
                "op_fee": 6250,
                "opcode": "NAME_TRANSFER",
                "preorder_block_number": 462345,
                "preorder_hash": "3dfdcee2b0e64697c4bb0b0dd791518bcb078dc7",
                "revoked": false,
                "sender": "76a914b107105f8ae57e7bb5bad58caba666faa679c70f88ac",
                "sender_pubkey": null,
                "txid": "16171e4e20778354a94c5353b0c6ed0b29a3e73c1b59b9bfbcbe6d26c570fd0c",
                "value_hash": "ac73155702ca7aea1161d0f0c7877ac81d48d8fc",
                "vtxindex": 649
              },
              {
                "address": "1B4zxvVMPm1PBGarc8PrYQjQY2ezwniyG6",
                "block_number": 462345,
                "consensus_hash": "e0c31e03125f2feefd4090e5c635ee45",
                "first_registered": 462391,
                "importer": null,
                "importer_address": null,
                "keep_data": true,
                "last_renewed": 462391,
                "name": "tadas_serbenta.id",
                "name_hash128": "6d800932daf830925ab47dee5ceb8661",
                "namespace_block_number": 373601,
                "namespace_id": "id",
                "op": ">>",
                "op_fee": 6250,
                "opcode": "NAME_TRANSFER",
                "preorder_block_number": 462345,
                "preorder_hash": "07a85eac4dbf20000a66a14a4a89a01134b70fab",
                "revoked": false,
                "sender": "76a9146e72e44bbe4c1706ea5830096a4bb4449dcc948f88ac",
                "sender_pubkey": null,
                "txid": "e3f0b019550417a7acfe27addfbd34ec7ec5fc1dd9616ed8c6bc86a0ad148290",
                "value_hash": "fbac107ba5d9bbfc30ecdeae3e10ca3db72b3431",
                "vtxindex": 855
              },
              {
                "address": "16BF35VputeLEmbsk7gDnUcwKXcjwPDUvf",
                "block_number": 462345,
                "consensus_hash": "919df884f14f34fd15a791af2fddb569",
                "first_registered": 462359,
                "importer": null,
                "importer_address": null,
                "keep_data": true,
                "last_renewed": 462359,
                "name": "alexucf.id",
                "name_hash128": "d9bc88b0fdc536e7ac5467609faed518",
                "namespace_block_number": 373601,
                "namespace_id": "id",
                "op": ">>",
                "op_fee": 25000,
                "opcode": "NAME_TRANSFER",
                "preorder_block_number": 462345,
                "preorder_hash": "30f841114af6ada90ba720d563672113c4f74439",
                "revoked": false,
                "sender": "76a91438c8814ae2a9035e85bbf2b7976919c2e3387ac588ac",
                "sender_pubkey": null,
                "txid": "f8e9eebd48b9182b82b22e5ce10f805d3db38786bb2aaf56f9badf83aa3cc0ee",
                "value_hash": "8ae0f51263f540be175230d6b46f5d9609de799d",
                "vtxindex": 856
              },
              {
                "address": "1EmXTRHC6f9bnLJkVZRavv7HLG1owLgNir",
                "block_number": 462326,
                "consensus_hash": "31a304b682e3291811441a12f19d14e5",
                "first_registered": 462391,
                "importer": null,
                "importer_address": null,
                "keep_data": true,
                "last_renewed": 462391,
                "name": "seamur.id",
                "name_hash128": "09f3b9d2da3d0aa1999824f7884f0d18",
                "namespace_block_number": 373601,
                "namespace_id": "id",
                "op": ">>",
                "op_fee": 100000,
                "opcode": "NAME_TRANSFER",
                "preorder_block_number": 462326,
                "preorder_hash": "678991fd4d3833babe27f732206a40d1f15dd3ca",
                "revoked": false,
                "sender": "76a91497055c47fa0ab396fb321e9d37f6bce1796e3d5688ac",
                "sender_pubkey": null,
                "txid": "e32124770c359eaf57709e5a666894f2954aa687820c41c6911f214e9006b58e",
                "value_hash": "4bcdd931185537902ef1af9975198c6404d4c73e",
                "vtxindex": 857
              },
              {
                "address": "13pGtMcHsNdq3EeLMa1yVVKppP1WjSKgFG",
                "block_number": 462345,
                "consensus_hash": "e0c31e03125f2feefd4090e5c635ee45",
                "first_registered": 462354,
                "importer": null,
                "importer_address": null,
                "keep_data": true,
                "last_renewed": 462354,
                "name": "innergame.id",
                "name_hash128": "a3e4e010d82369ee19b64fccc2b97f69",
                "namespace_block_number": 373601,
                "namespace_id": "id",
                "op": ">>",
                "op_fee": 25000,
                "opcode": "NAME_TRANSFER",
                "preorder_block_number": 462345,
                "preorder_hash": "f54850caf10c3041cb2a4d9186bbb234dd7d9f85",
                "revoked": false,
                "sender": "76a9141ee10ff0ae9969e2dc39d94a959e3160b26b6adf88ac",
                "sender_pubkey": null,
                "txid": "28de7193e28e1b0c950a32af393284578669c15dc98bad68f382f8b920d94509",
                "value_hash": "bab40c2b10f676288edea119edade67ff5e853ba",
                "vtxindex": 869
              }
            ]

  + Schema

            {
              'type': 'array',
              'items': {
                 'type': 'object',
                 'properties': {
                     'address': {
                         'type': 'string',
                         'pattern': "^([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+)$",
                     },
                     'base': {
                         'type': 'integer',
                         'minimum': 0,
                         'maximum': 255,
                     },
                     'buckets': {
                         'anyOf': [
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
                                 'pattern': '^[0-9a-fA-F]{32}',
                             },
                             {
                                 'type': 'null'
                             },
                         ],
                     },
                     'domain': {
                         'type': 'string',
                         'pattern': '^([a-z0-9\-_.+]{3,37})$',
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
                                 'pattern': '^76[aA]914[0-9a-fA-F]{40}88[aA][cC]$',
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
                                 'pattern': "^([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+)$",
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
                         'pattern': '^([a-z0-9\\-_.+]{3,37})\.([a-z0-9\\-_.+]{3,37})$',
                     },
                     'op': {
                         'type': 'string',
                         'pattern': '^([>?+~:!&*:;#]{1}|>>|>~|::)$',
                     },
                     'op_fee': {
                         'type': 'number',
                     },
                     'opcode': {
                         'type': 'string',
                         'pattern': '^NAME_TRANSFER|NAME_PREORDER|NAME_UPDATE|NAME_REVOKE|NAME_REGISTRATION|NAMESPACE_READY|NAMESPACE_REVEAL|NAMESPACE_PREORDER|NAME_RENEWAL|NAME_IMPORT|ANNOUNCE$'
                     },
                     'revoked': {
                         'type': 'boolean',
                     },
                     'sender': {
                         'type': 'string',
                         'pattern': '^([0-9a-fA-F]+)$',
                     },
                     'sender_pubkey': {
                         'anyOf': [
                             {
                                 'type': 'string',
                                 'pattern': '^([0-9a-fA-F]+)$',
                             },
                             {
                                 'type': 'null'
                             },
                         ],
                     },
                     'sequence': {
                         'type': 'integer',
                         'minimum': 0
                     }
                     'recipient': {
                         'anyOf': [
                             {
                                 'type': 'string',
                                 'pattern': '^([0-9a-fA-F]+)$',
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
                                 'pattern': '^([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+)$',
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
                                 'pattern': '^([0-9a-fA-F]+)$',
                             },
                             {
                                 'type': 'null'
                             },
                         ],
                     },
                     'txid': {
                         'type': 'string',
                         'pattern': '^([0-9a-fA-F]+)$',
                     },
                     'value_hash': {
                         'anyOf': [
                             {
                                 'type': 'string',
                                 'pattern': '^([0-9a-fA-F]{40})$',
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
                     'txid',
                     'vtxindex'
                 ],
                }
              }
            }

+ Response 400 (application/json)
  + Body

            { "error": "Invalid name or subdomain" }

  + Schema

            {
                'type': 'object',
                'properties': {
                    'error': { 'type': 'string' },
                },
            }

+ Response 404 (application/json)
  + Body

            { "error": "No such name" }

  + Schema

            {
                'type': 'object',
                'properties': {
                    'error': { 'type': 'string' },
                },
            }

# Group Namespace Operations

## Get all namespaces [GET /v1/namespaces]
+ Public Endpoint
+ Response 200 (application/json)
  + Body

            {
              "namespaces": [
                "id",
                "helloworld",
                "podcast",
                "graphite",
                "blockstack"
              ]
            }

  + Schema

            {
               'type': 'object',
               'properties': {
                  'namespaces': {
                     'type': 'array',
                     'items': { 'type': 'string' }
                  }
               },
               'required': [ 'namespaces' ]
            }
                     
## Get namespace names [GET /v1/namespaces/{tld}/names?page={page}]

Fetch a list of names from the namespace.
+ Public Endpoint
+ Parameters
  + tld: id (string) - the namespace to fetch names from
  + page: 23 (number) - names are returned in pages of size 100,
    so specify the page number.
+ Response 200 (application/json)
  + Body

               [ "aldenquimby.id", "aldeoryn.id",
                 "alderete.id", "aldert.id",
                 "aldi.id", "aldighieri.id", ... ]

  + Schema

               {
                  'type': 'array',
                  'items': { 
                     'type': 'string',
                     'pattern': '^([a-z0-9\-_.+]{3,37})$'
                  }
               }

+ Response 400 (application/json)
  + Body

            { "error": "Invalid page" }

  + Schema

            {
                'type': 'object',
                'properties': {
                    'error': { 'type': 'string' },
                },
            }

+ Response 404 (application/json)
  + Body

            { "error": "No such namespace" }

  + Schema

            {
                'type': 'object',
                'properties': {
                    'error': { 'type': 'string' },
                },
            }

# Group Account Operations

The set of methods in this section correspond to querying the states of
Blockstack token accounts.  Each token account is represented by an account
address, which is a [Crockford base-32](https://en.wikipedia.org/wiki/Base32#Crockford's_Base32)
encoding of the RIPEMD160 hash of the SHA256 hash of one or more keys,
plus a version byte and a 4-byte SHA256 checksum.
Internally, Blockstack account addresses are generated and represented in the
same way as p2pkh and p2sh Bitcoin addresses -- that is, a Blockstack account addresses
are in 1-to-1 correspondance with Bitcoin addresses (Blockstack account addresses
simply use a different encoding alphabet).
We have a [reference library](http://github.com/blockstack/c32check) for
helping developers generate and convert between Bitcoin and Blockstack addresses.

Right now, an account can only own Stacks tokens (designiated in the API
as having a toke type `STACKS`).  However, in the future
Blockstack may be upgraded to support owning many different kinds of
app-specific tokens.  The API presented here is designed to accomodate this
possible development.

## Get account status [GET /v1/accounts/{address}/{tokenType}/status]

Get the status of an account's current token allocation.  The current number of
tokens held by the account's address is equal to the difference between the
`credit_value` and `debit_value`.  These two numbers always increase and are
accounted in the smallest possible unit of the token type (e.g. microStacks for
the `STACKS` token).  Programs that parse these values should be aware of this,
and should use an appropriate numeric representation like `BigInteger` when
parsing them.

The last transaction's ID (`txid`) and transaction offset (`vtxindex`) are given.
If `vtxindex` is 0, then the transaction ID corresponds to a "sentinal" transaction
in Blockstack Core that indicates tokens getting generated or unlocked.  These
transaction IDs will not appear in any block explorer, since they do not correspond
to "real" transactions.

+ Public Endpoint
* Parameters
  + address: SP1T1F14QX4KZYFZH8A5286Z4AK9S7GY93KZ4ZZD7 (string) - address to query.  Can be either a base58check address or a c32check address
  + tokenType: STACKS (string) - type of token to query (only `STACKS` is
    supported right now).
+ Response 200 (application/json)
  + Body

            {
              "address": "1BaqZJqwt2dcdxt6oa3mwSK4DiEyfXCgnZ",
              "block_id": 589689,
              "credit_value": "100000000000",
              "debit_value": "6400000000",
              "lock_transfer_block_id": 0,
              "txid": "65e99765cb332b1026049527ecf297223612a12cd6adec9aeb555105f655428b",
              "type": "STACKS",
              "vtxindex": 1
            }

  + Schema

            {
              'type': 'object',
              'properties': {
                 'address': {
                    'type': 'string',
                    'pattern': "^([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+)$",
                 },
                 'block_id': { 'type': 'integer', 'minimum': 0 },
                 'credit_value': { 'type': 'string', 'pattern': '^[0-9]+$' },
                 'debit_value': { 'type': 'string', 'pattern': '^[0-9]+$' },
                 'lock_transfer_block_id': { 'type': 'integer', 'minimum': 0 },
                 'txid': { 'type': 'string', 'pattern': '^[0-9a-fA-F]{64}$' },
                 'type': { 'type': 'string' },
                 'vtxindex': { 'type': 'integer', 'minimum': 0 }
              },
              'required': [ 'address, 'block_id', 'credit_value', 'debit_value', 
                            'lock_transfer_block_id', 'txid', 'type', 'vtxindex' ]
            }

+ Response 400 (application/json)
  + Body

            { "error": "Invalid address" }

  + Schema

            {
                'type': 'object',
                'properties': {
                    'error': { 'type': 'string' },
                },
            }

+ Response 404 (application/json)
  + Body

            { "error": "Failed to get account record for STACKS ST3S24N1NK9JVGK6T06PR3E6HE7SBAH7VSG6C950F: No such account"}

  + Schema

            {
                'type': 'object',
                'properties': {
                    'error': { 'type': 'string' },
                },
            }

## Get account tokens [GET /v1/accounts/{address}/tokens]

Get the types of tokens held by a particular account, given its address.  For
now, this can only be `STACKS` tokens.

+ Public Endpoint
* Parameters
  + address: SP1T1F14QX4KZYFZH8A5286Z4AK9S7GY93KZ4ZZD7 (string) - address to query.  Can be either a base58check address or a c32check address
+ Response 200 (application/json)
  + Body

            {
              "tokens": [
                  "STACKS"
              ]
            }

  + Schema

            {
              'type': 'object',
              'properties': {
                'tokens': {
                   'type': 'array',
                   'items': { 'type': 'string' }
                },
                'required': [ 'tokens' ]
              }
            }

+ Response 400 (application/json)
  + Body

            { "error": "Invalid address" }

  + Schema

            {
                'type': 'object',
                'properties': {
                    'error': { 'type': 'string' },
                },
            }

## Get account balance [GET /v1/accounts/{address}/{tokenType}/balance]

Get the number of tokens held by a particular account, given the account's
address and the token type.

Note that the value returned by this endpoint can be very large, since the token
balances are integers that represent the number of smallest units of the token
(e.g. microStacks for the `STACKS` token).

This endpoint returns a zero balance for accounts and token types that do not
exist.

+ Public Endpoint
+ Parameters
  + address: SP1T1F14QX4KZYFZH8A5286Z4AK9S7GY93KZ4ZZD7 (string) - address to query.  Can be either a base58check address or a c32check address
  + tokenType: STACKS (string) - type of token to query (only `STACKS` is
    supported right now).
+ Response 200 (application/json)
  + Body

            {
              "balance": "936000000"
            }

  + Schema

            {
              'type': 'object',
              'properties': {
                 'balance' { 'type': 'string', 'pattern': '^[0-9+]$' }
              }
              'required': [ 'balance' ]
            }
     

+ Response 400 (application/json)
  + Body

            { "error": "Invalid address" }

  + Schema

            {
                'type': 'object',
                'properties': {
                    'error': { 'type': 'string' },
                },
            }

## Get account history [GET /v1/accounts/{address}/history?page={pageNum}]

Get a page of an account's transaction history.  Each entry in the history
corresponds to the status of the account at a particular transaction.
The history will be returned in reverse order -- the first item will be the
latest transaction.

Queries on addresses that do not correspond to an existing account will simply
return an empty list.

+ Public Endpoint
+ Parameters
  + address: SP1T1F14QX4KZYFZH8A5286Z4AK9S7GY93KZ4ZZD7 (string) - address to query.  Can be either a base58check address or a c32check address
  + pageNum: 0 (integer) - page of the history to query
+ Response 200 (application/json)
  + Body

            [
              {
                "address": "1BaqZJqwt2dcdxt6oa3mwSK4DiEyfXCgnZ",
                "block_id": 589689,
                "credit_value": "100000000000",
                "debit_value": "6400000000",
                "lock_transfer_block_id": 0,
                "txid": "65e99765cb332b1026049527ecf297223612a12cd6adec9aeb555105f655428b",
                "type": "STACKS",
                "vtxindex": 1
              },
              {
                "address": "1BaqZJqwt2dcdxt6oa3mwSK4DiEyfXCgnZ",
                "block_id": 589688,
                "credit_value": "100000000000",
                "debit_value": "0",
                "lock_transfer_block_id": 0,
                "txid": "c28d44fde97dbe59856fa62a4aa99b49c37291577a3e664621a6f03c77c08f47",
                "type": "STACKS",
                "vtxindex": 0
              }
            ]

  + Schema

            {
              'type': 'array'
              'items': {
                 'type': 'object',
                 'properties': {
                    'address': {
                       'type': 'string',
                       'pattern': "^([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+)$",
                    },
                    'block_id': { 'type': 'integer', 'minimum': 0 },
                    'credit_value': { 'type': 'string', 'pattern': '^[0-9]+$' },
                    'debit_value': { 'type': 'string', 'pattern': '^[0-9]+$' },
                    'lock_transfer_block_id': { 'type': 'integer', 'minimum': 0 },
                    'txid': { 'type': 'string', 'pattern': '^[0-9a-fA-F]{64}$' },
                    'type': { 'type': 'string' },
                    'vtxindex': { 'type': 'integer', 'minimum': 0 }
                 },
                 'required': [ 'address, 'block_id', 'credit_value', 'debit_value', 
                               'lock_transfer_block_id', 'txid', 'type', 'vtxindex' ]
               }
            }

+ Response 400 (application/json)
  + Body

            { "error": "Invalid address" }

  + Schema

            {
                'type': 'object',
                'properties': {
                    'error': { 'type': 'string' },
                },
            }

## Get account statuses at block [GET /v1/accounts/{address}/history/{blockNum}]

Get the status(es) of an account at a particular block height.  If the account
was affected by a transaction at the given block height, the states the
account passed through will be returned (i.e. at least two entries).  If the
account was not affected at this block height, then the last state the account
was in at that block height will be returned.

If there is more than one state, then the states will be listed in reverse order
chronologically, with the latest state as the first entry.

If the account does not exist, then an empty list will be returned.

+ Public Endpoint
+ Parameters
  + address: SP1T1F14QX4KZYFZH8A5286Z4AK9S7GY93KZ4ZZD7 (string) - address to query.  Can be either a base58check address or a c32check address
  + blockNum: 589688 (integer) - page of the history to query
+ Response 200 (application/json)
  + Body

            [
              {
                "address": "1BaqZJqwt2dcdxt6oa3mwSK4DiEyfXCgnZ",
                "block_id": 589688,
                "credit_value": "100000000000",
                "debit_value": "0",
                "lock_transfer_block_id": 0,
                "txid": "c28d44fde97dbe59856fa62a4aa99b49c37291577a3e664621a6f03c77c08f47",
                "type": "STACKS",
                "vtxindex": 0
              }
            ]

  + Schema

            {
              'type': 'array'
              'items': {
                 'type': 'object',
                 'properties': {
                    'address': {
                       'type': 'string',
                       'pattern': "^([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+)$",
                    },
                    'block_id': { 'type': 'integer', 'minimum': 0 },
                    'credit_value': { 'type': 'string', 'pattern': '^[0-9]+$' },
                    'debit_value': { 'type': 'string', 'pattern': '^[0-9]+$' },
                    'lock_transfer_block_id': { 'type': 'integer', 'minimum': 0 },
                    'txid': { 'type': 'string', 'pattern': '^[0-9a-fA-F]{64}$' },
                    'type': { 'type': 'string' },
                    'vtxindex': { 'type': 'integer', 'minimum': 0 }
                 },
                 'required': [ 'address, 'block_id', 'credit_value', 'debit_value', 
                               'lock_transfer_block_id', 'txid', 'type', 'vtxindex' ]
               }
            }

+ Response 400 (application/json)
  + Body

            { "error": "Invalid address" }

  + Schema

            {
                'type': 'object',
                'properties': {
                    'error': { 'type': 'string' },
                },
            }

# Group Resolver Endpoints

## Lookup User [GET /v1/users/{username}]
Lookup and resolve a user's profile. Defaults to the `id` namespace.
Note that [blockstack.js](https://github.com/blockstack/blockstack.js) does
*not* rely on this endpoint.

+ Public Endpoint
+ Subdomain Aware
+ Legacy Endpoint
+ Parameters
  + username: fred (string) - username to lookup
+ Response 200 (application/json)

               {
                 "fred.id": {
                   "owner_address": "1CER5u4QXuqffHjHKrU76iMCsqtJLM5VHu", 
                   "profile": {
                     "@context": "http://schema.org", 
                     "@type": "Person", 
                     "account": [
                       {
                         "@type": "Account", 
                         "identifier": "fredwilson", 
                         "placeholder": false, 
                         "proofType": "http", 
                         "proofUrl": "https://twitter.com/fredwilson/status/943066895422455809", 
                         "service": "twitter"
                       }
                     ], 
                     "description": "I am a VC", 
                     "image": [
                       {
                         "@type": "ImageObject", 
                         "contentUrl": "https://gaia.blockstack.org/hub/1CER5u4QXuqffHjHKrU76iMCsqtJLM5VHu/0/avatar-0", 
                         "name": "avatar"
                       }
                     ], 
                     "name": "Fred Wilson"
                   }, 
                   "public_key": "026c94d1897fa148fa6401247a339b55abd869a3d562fdae8a7fcb9a11f1f846f3", 
                   "verifications": [
                     {
                       "identifier": "fredwilson", 
                       "proof_url": "https://twitter.com/fredwilson/status/943066895422455809", 
                       "service": "twitter", 
                       "valid": true
                     }
                   ], 
                   "zone_file": {
                     "$origin": "fred.id", 
                     "$ttl": 3600, 
                     "uri": [
                       {
                         "name": "_http._tcp", 
                         "priority": 10, 
                         "target": "https://gaia.blockstack.org/hub/1CER5u4QXuqffHjHKrU76iMCsqtJLM5VHu/0/profile.json", 
                         "weight": 1
                       }
                     ]
                   }
                 }
               }

  + Schema

            {
                'type': 'object',
                'patternProperties': {
                    '^([a-z0-9\\-_.+]{3,37})\.([a-z0-9\\-_.+]{3,37})$|^([a-z0-9\\-_.+]){3,37}$': {
                      'type': 'object',
                      'properties': {
                           'owner_address': { 'type': 'string', 'pattern': "^([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+)$" },
                           'profile' : { 'type': 'object' },
                           'public_key': { 'type': 'string', 'pattern': "^([0-9a-fA-F]$" },
                           'verifications: { 
                              'type': 'array', 
                              'items': {
                                 'type': 'object',
                                 'properties': {
                                    'identifier': { 'type': 'string' },
                                    'proof_url': { 'type': 'string' },
                                    'service': { 'type': 'string' },
                                    'valid': { 'type': 'boolean' }
                                 },
                              }
                           },
                           'zone-file': { 'type': 'object' }
                       }
                    }
                 }
            }

+ Response 404 (application/json)
  + Body

            {
              "nope.none": {
                "error": "Name has no user record hash defined"
              }
            }

  + Schema

            {
                'type': 'object',
                'patternProperties': {
                    '^([a-z0-9\\-_.+]{3,37})\.([a-z0-9\\-_.+]{3,37})$|^([a-z0-9\\-_.+]){3,37}$': {
                      'type': 'object',
                      'properties': {
                         'error': { 'type': 'string' }
                       },
                      'required': [ 'error' ]
                    }
                 }
            }

## Profile Search [GET /v1/search?query={query}]
Searches for a profile using a search string.
+ Public Only Endpoint
+ Parameters
  + query: wenger (string) - the search query
+ Response 200 (application/json)
  + Body

               {
                 "results": [
                   {
                     "fullyQualifiedName": "albertwenger.id",
                     "username": "albertwenger",
                     "profile": {
                       "@type": "Person", 
                       "account": [
                         {
                           "@type": "Account", 
                           "identifier": "albertwenger", 
                           "proofType": "http", 
                           "service": "twitter"
                         }, 
                         {
                           "@type": "Account", 
                           "identifier": "albertwenger", 
                           "proofType": "http", 
                           "service": "facebook"
                         }, 
                         {
                           "@type": "Account", 
                           "identifier": "albertwenger", 
                           "proofType": "http", 
                           "service": "github"
                         }, 
                         {
                           "@type": "Account", 
                           "identifier": "1QHDGGLEKK7FZWsBEL78acV9edGCTarqXt", 
                           "role": "payment", 
                           "service": "bitcoin"
                         }
                       ], 
                       "address": {
                         "@type": "PostalAddress", 
                         "addressLocality": "New York"
                       }, 
                       "description": "VC at USV.com", 
                       ...
               }

  + Schema

            {
                'type': 'object',
                'properties': {
                   'results': {
                        'type': 'array',
                        'items': {
                           'fullyQualifiedName': { 'type': 'string', 'pattern': '^([a-z0-9\\-_.+]{3,37})\.([a-z0-9\\-_.+]{3,37})$|^([a-z0-9\\-_.+]){3,37}$' },
                           'username': { 'type': 'string' },
                           'profile' : { 'type': 'object' },
                       }
                    }
                 }
            }

## Resolve DID [GET /v1/dids/{did}]
Resolve a Blockstack DID to its DID document object (DDO).  In practice, the DDO
is stored in the same way as a user profile, but a few extra DDO-specific
fields will be filled in by this endpoint (namely, `@context` and `publicKey`).

Blockstack DIDs correspond to non-revoked, non-expired names.  A DID will not
resolve if its underlying name is revoked or expired, or if the DID does not
correspond to an existing name.

+ Public Endpoint
+ Subdomain Aware
+ Parameters
  + did: `did:stack:v0:15gxXgJyT5tM5A4Cbx99nwccynHYsBouzr-0` (string) - DID to resolve
+ Response 200 (application/json)
  + Body

            {
                "document": {
                    "@context": "https://w3id.org/did/v1",
                    "publicKey": [
                        {
                            "id": "did:stack:v0:15gxXgJyT5tM5A4Cbx99nwccynHYsBouzr-0",
                            "publicKeyHex": "022af593b4449b37899b34244448726aa30e9de13c518f6184a29df40823d82840",
                            "type": "secp256k1"
                        }
                    ],
                    ... omitted for brevity ...
                },
                "public_key": "022af593b4449b37899b34244448726aa30e9de13c518f6184a29df40823d82840"
            }

   + Schema

            {
               "type": "object",
               "properties": {
                  "document": {
                     "type": "object",
                     "properties": {
                        "@context": { "type": "string" },
                        "publicKey": {
                           "type": "array",
                           "items": {
                              "type": "object",
                              "properties": {
                                 "id": { "type": "string" },
                                 "type": { "type": "string" },
                                 "publicKeyHex": { "type": "string", "pattern": "^[0-9a-fA-F]$" },
                              },
                              "required": [ "id", "type", "publicKeyHex" ],
                           },
                        },
                     },
                     "required": [ "@context", "publicKey" ],
                  },
                  "public_key": { "type": "string", "pattern": "^[0-9a-fA-F]$" },
               }
               "required": [ "document", "public_key" ]
            }


+ Response 400 (application/json)
  + Body

            {
               "error": "Invalid DID"
            }

  + Schema

            {
                'type': 'object',
                'properties': { 'error': 'string' },
                'required': [ 'error' ]
            }

+ Response 404 (application/json)
  + Body

            {
               "error": "Failed to get DID record: Failed to resolve DID to a non-revoked name"
            }

  + Schema

            {
                'type': 'object',
                'properties': { 'error': 'string' },
                'required': [ 'error' ]
            }
