# Group Authorization

## Auth Request View [GET /auth?authRequest={authRequestToken}]

This endpoint is accessed internally by
[blockstack.js](https://github.com/blockstack/blockstack.js) to process user
sign-in requests.  Applications use `blockstack.js` to direct users to sign in
or sign up.  Please see the [blockstack.js
documentation](http://blockstack.github.io/blockstack.js/#authentication) on
authentication for details.

When the user clicks the Blockstack login button in an application, the app should
redirect the user to this endpoint (via `blockstack.js`).  If the user already has an
account, they will be redirected along with requested data. If the
user doesn’t have an account, the user will be presented with each of
the app’s requested permissions, then will satisfy or deny them. The
sign-in dashboard will then redirect the user back to the application
with a signed JWT.  This JWT contains a signature and an API
token that the app can use for future authorization of endpoints.

Each application specifies in advance which family of API calls it
will need to make to function properly.  This list is passed along to
this endpoint when creating an application account.  The
account-creation page shows this list of API endpoints and what they
do, and allows the user to line-item approve or deny them.  The list
is stored to the user's profile, and returned to the application
application as part of the session JWT.  The API
server will NACK requests to endpoints in API families absent from the
session JWT.

+ Requires root authorization
+ Parameters
    + authRequestToken: eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJhcHBfZG9tYWluIjoiaGVsbG9ibG9ja3N0YWNrLmNvbSIsIm1ldGhvZHMiOltdLCJhcHBfcHVibGljX2tleSI6IjAyYjk0ZjY4NDgzOGFkMjdmZTE0Nzk1MGMyNjQ1ZjRhYzhjYmU1OTJlYjYzYmQwYTQ5MWQ2YzBlYWZjNjE0YzVjMCJ9.0lLrxt8uGtB2rCKB9sb0jK1DdrrWuuuWM-nsyjvFnmjNx0XfG14Npl72w6hp9W2OHoXdPe7VuXkfvKmVNlQdeA (jwt token) - app token before signing
+ Response 200
  + Body

             {"token": 
              "eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QifQ.eyJhcHBfZG9tYWluIjoiaGVsbG9ibG9ja3N0YWNrLmNvbSIsIm1ldGhvZHMiOltdLCJ0aW1lc3RhbXAiOjE0OTkzNDc4OTUsImV4cGlyZXMiOjE0OTk5NTI2OTUsImFwcF91c2VyX2lkIjoiMUVITmE2UTRKejJ1dk5FeEw0OTdtRTQzaWtYaHdGNmtabSIsImRldmljZV9pZCI6IjAiLCJibG9ja2NoYWluX2lkIjpudWxsLCJzdG9yYWdlIjp7ImNsYXNzZXMiOnsid3JpdGVfcHJpdmF0ZSI6WyJkaXNrIiwiczMiLCJibG9ja3N0YWNrX3NlcnZlciIsImRodCJdLCJyZWFkX2xvY2FsIjpbImRpc2siXSwicmVhZF9wdWJsaWMiOlsiczMiLCJibG9ja3N0YWNrX3Jlc29sdmVyIiwiYmxvY2tzdGFja19zZXJ2ZXIiLCJodHRwIiwiZGh0Il0sIndyaXRlX2xvY2FsIjpbImRpc2siXSwid3JpdGVfcHVibGljIjpbXSwicmVhZF9wcml2YXRlIjpbImRpc2siXX0sInByZWZlcmVuY2VzIjp7fX0sImFwaV9lbmRwb2ludCI6ImxvY2FsaG9zdDo2MjcwIiwiYXBwX3B1YmxpY19rZXlzIjpbXSwidmVyc2lvbiI6MX0.Bhne8wQpPVfkV-VLf2mrsoMmNiE2e04crgLN7OUFKEh_YWeGmqjoZU7JVSzXA5r7LCpZ9Eki5uAWlJSHk-JuCA"
             }

# Group Core Node Administration

Blockstack Core's API module provides a set of API calls for interacting with
the node's configuration.  However, most of this section is **DEPRECATED** in favor
of moving configuration state to the [Blockstack
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
                 'type': 'object',
                 'properties': {
                     'status': {
                         'type': 'string'
                     },
                 },
                 'required': [
                     'status'
                 ]
             }

## Get the node's config [GET /v1/node/config]
Returns the current configuation settings of the Blockstack node.

+ DEPRECATED.  Blockstack clients should use
  [blockstack.js](https://github.com/blockstack/blockstack.js) for querying
client-side configuration state.
+ Requires root authorization
+ Legacy Endpoint
+ Response 200 (application/json)
  + Body

             {
                 "bitcoind": {
                     "passwd": "blockstacksystem",
                     "port": "18332",
                     "regtest": "True",
                     "server": "localhost",
                     "spv_path": "/tmp/.../spv_headers.dat",
                     "use_https": "False",
                     "user": "blockstack"
                 },
                 "blockchain-reader": {
                     "port": "18332",
                     "rpc_password": "blockstacksystem",
                     "rpc_username": "blockstack",
                     "server": "localhost",
                     "use_https": "False",
                     "utxo_provider": "bitcoind_utxo",
                     "version_byte": "0"
                 },
                 "blockchain-writer": {
                     "port": "18332",
                     "rpc_password": "blockstacksystem",
                     "rpc_username": "blockstack",
                     "server": "localhost",
                     "use_https": "False",
                     "utxo_provider": "bitcoind_utxo",
                     "version_byte": "0"
                 },
                 "blockstack-client": {
                     "advanced_mode": "true",
                     "api_endpoint_port": "6270",
                     "api_password": "...",
                     "blockchain_reader": "bitcoind_utxo",
                     "blockchain_writer": "bitcoind_utxo",
                     "client_version": "0.18.0.0",
                     "poll_interval": "300",
                     "port": "16264",
                     "queue_path": "/tmp/.../client/queues.db",
                     "rpc_detach": "True",
                     "server": "localhost",
                     "storage_drivers": "disk",
                     "storage_drivers_required_write": "disk",
                 }
             }
    
  + Schema

             {
                 'type': 'object',
                 'patternProperties': {
                     '.+': {
                         'type': 'string',
                         'pattern': '.+',
                 },
             }
     
## Set config field [POST /v1/node/config/{section}?{key}={value}]
Set one or more config fields in a config section.

+ DEPRECATED.  Blockstack clients should use
  [blockstack.js](https://github.com/blockstack/blockstack.js) for client-side
configuration management.
+ Requires root authorization
+ Legacy Endpoint
+ Parameters
  + section: blockstack-client (string) - configuration section
  + key: server (string) - configuration variable to set
  + value: node.blockstack.org (string) - value to set

+ Response 200 (application/json)
  + Body

             { 'status' : true }

  + Schema

                 {
                   'anyOf': [
                     {
                           'type': 'object',
                           'properties': {
                                'status': {
                                   'type': 'boolean'
                                },
                           },
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
                }

## Delete a config field [DELETE /v1/node/config/{section}/{key}]
Delete a single field from the configuration.

+ DEPRECATED.  Blockstack clients should use
  [blockstack.js](https://github.com/blockstack/blockstack.js) for client-side
configuration management.
+ Requires root authorization
+ Legacy Endpoint
+ Parameters
  + section: blockstack-client (string) - configuration section
  + key: advanced_mode (string) - configuration variable to set

+ Response 200 (application/json)

  + Body

             { 'status' : true }

  + Schema

             {
              'anyOf': [
                {
                      'type': 'object',
                      'properties': {
                           'status': {
                              'type': 'boolean'
                           },
                      },
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
             }

## Delete a config section [DELETE /v1/node/config/{section}]
Deletes a whole section from the node's configuration.

+ DEPRECATED.  Blockstack clients should use
  [blockstack.js](https://github.com/blockstack/blockstack.js) for client-side
configuration management.
+ Requires root authorization
+ Legacy Endpoint
+ Parameters
    + section: blockstack-client (string) - configuration section

+ Response 200 (application/json)
  + Body

             { 'status' : true }

  + Schema

             {
              'anyOf': [
                {
                      'type': 'object',
                      'properties': {
                           'status': {
                              'type': 'boolean'
                           },
                      },
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
             }

## Get registrar state [GET /v1/node/registrar/state]
Gets the current state of the registrar. That is, the Blockstack operations 
that have been submitted to the blockchain but are still waiting for
enough confirmations.

+ DEPRECATED.  Blockstack clients should use 
  [blockstack.js](https://github.com/blockstack/blockstack.js) to query
the status of pending transactions.
+ Requires root authorization
+ Legacy Endpoint
+ Response 200 (application/json)
  + Body

             [
                 {
                     "block_height": 666,
                     "fqu": "bar.test",
                     "owner_address": "myaPViveUWiiZQQTb51KXCDde4iLC3Rf3K",
                     "payment_address": "mv1uqYWZpnap4VBSKTHfKW6noTZcNtxtCW",
                     "profile": {
                         "@type": "Person",
                         "accounts": []
                     },
                     "transfer_address": null,
                     "tx_hash": "b0fa7d4d79bb69cb3eccf40978514dec1620d05fe7822c550c2764c670efcd29",
                     "type": "preorder",
                     "zonefile": "$ORIGIN bar.test\n$TTL 3600\npubkey TXT \"pubkey:data:03ea5d8c2a3ba84eb17625162320bb53440557c71f7977a57d61405e86be7bdcda\"\n_file URI 10 1 \"file:///home/bar/.blockstack/storage-disk/mutable/bar.test\"\n",
                     "zonefile_hash": "cbe11bbbfffe415b915a7f9566748f72a0d8b2bd"
                 }
             ]

  + Schema

            {
                'type': 'array',
                'items': {
                    'type': 'object',
                    'properties': {
                        'block_height': {
                            'type': 'integer',
                            'minimum': 0,
                        },
                        'fqu': {
                            'type': 'string',
                            'pattern': r'^([a-z0-9\\-_.+]{3,37})$',
                        },
                        'owner_address': {
                            'type': 'string',
                            'pattern': r'^([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+)$',
                        },
                        'payment_address': {
                            'type': 'string',
                            'pattern': r'^([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+)$',
                        },
                        'profile': {
                            'type': 'object',
                            'additionalProperties': true, 
                            'properties': {
                                '@context': {
                                    'optional': true, 
                                    'type': 'string'
                                }, 
                                '@id': {
                                    'optional': true, 
                                    'type': 'string'
                                }, 
                                '@type': {
                                    'type': 'string'
                                }, 
                                'account': {
                                    'items': {
                                        'properties': {
                                            '@type': {
                                                'type': 'string'
                                            }, 
                                            'identifier': {
                                                'optional': true, 
                                                'type': 'string'
                                            }, 
                                            'proofMessage': {
                                                'optional': true, 
                                                'type': 'string'
                                            }, 
                                            'proofSignature': {
                                                'optional': true, 
                                                'type': 'string'
                                            }, 
                                            'proofType': {
                                                'optional': true, 
                                                'type': 'string'
                                            }, 
                                            'proofUrl': {
                                                'optional': true, 
                                                'type': 'string'
                                            }, 
                                            'service': {
                                                'optional': true, 
                                                'type': 'string'
                                            }
                                        }, 
                                        'type': 'object'
                                    }, 
                                    'optional': true, 
                                    'type': 'array'
                                }, 
                                'address': {
                                    'optional': true, 
                                    'properties': {
                                        '@type': {
                                            'type': 'string'
                                        }, 
                                        'addressCountry': {
                                            'optional': true, 
                                            'type': 'string'
                                        }, 
                                        'addressLocality': {
                                            'optional': true, 
                                            'type': 'string'
                                        }, 
                                        'postalCode': {
                                            'optional': true, 
                                            'type': 'string'
                                        }, 
                                        'streetAddress': {
                                            'optional': true, 
                                            'type': 'string'
                                        }
                                    }, 
                                    'type': 'object'
                                }, 
                                'birthDate': {
                                    'optional': true, 
                                    'type': 'string'
                                }, 
                                'description': {
                                    'optional': true, 
                                    'type': 'string'
                                }, 
                                'familyName': {
                                    'optional': true, 
                                    'type': 'string'
                                }, 
                                'givenName': {
                                    'optional': true, 
                                    'type': 'string'
                                }, 
                                'image': {
                                    'items': {
                                        'properties': {
                                            '@type': {
                                                'type': 'string'
                                            }, 
                                            'contentUrl': {
                                                'optional': true, 
                                                'type': 'string'
                                            }, 
                                            'name': {
                                                'optional': true, 
                                                'type': 'string'
                                            }
                                        }, 
                                        'type': 'object'
                                    }, 
                                    'optional': true, 
                                    'type': 'array'
                                }, 
                                'knows': {
                                    'items': {
                                        'properties': {
                                            '@id': {
                                                'optional': true, 
                                                'type': 'string'
                                            }, 
                                            '@type': {
                                                'type': 'string'
                                            }
                                        }, 
                                        'type': 'object'
                                    }, 
                                    'optional': true, 
                                    'type': 'array'
                                }, 
                                'name': {
                                    'optional': true, 
                                    'type': 'string'
                                }, 
                                'taxID': {
                                    'optional': true, 
                                    'type': 'string'
                                }, 
                                'website': {
                                    'items': {
                                        'properties': {
                                            '@type': {
                                                'type': 'string'
                                            }, 
                                            'url': {
                                                'optional': true, 
                                                'type': 'string'
                                            }
                                        }, 
                                        'type': 'object'
                                    }, 
                                    'optional': true, 
                                    'type': 'array'
                                }, 
                                'worksFor': {
                                    'items': {
                                        'properties': {
                                            '@id': {
                                                'optional': true, 
                                                'type': 'string'
                                            }, 
                                            '@type': {
                                                'type': 'string'
                                            }
                                        }, 
                                        'type': 'object'
                                    }, 
                                    'optional': true, 
                                    'type': 'array'
                                }
                            }
                        },
                        'transfer_address': r'^([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+)$',
                        'tx_hash': r'^([0-9a-fA-F]+)$',
                        'type': '.+',
                        'zonefile': '.+',
                        'zonefile_hash': r'^([0-9a-fA-F]+)$'
                    }
                }
            }


# Group Core Wallet Management

This entire section is **DEPRECATED** in favor of the wallet software in
[blockstack.js](https://github.com/blockstack/blockstack.js).  Names registered
with this API will need to be transferred to the Blockstack Browser.

The Blockstack Core node manages its own wallet -- this has three keys
for payment, name ownership, and signing data (e.g., user profiles). This
wallet can be managed through these endpoints.

## Get balance via mock-insight API [GET /insight-api/addr/{address}/balance]
Returns the integer satoshi balance of the given address, with mininum
of 1 confirmation.

+ DEPRECATED.  Blockstack clients should use 
  [blockstack.js](https://github.com/blockstack/blockstack.js) to query
balances.
+ Authorization: `wallet_read`
+ Legacy Endpoint
+ Response 200 (application/json)
  + Body

             2104

  + Schema

             { 'type' : 'integer' }

## Get unconfirmed balance via mock-insight API [GET /insight-api/addr/{address}/unconfirmedBalance]
Returns the integer *unconfirmed* satoshi balance of the given address
(only the 0-confirmation balance). To get the min_conf=0 balance of an
address, you want *unconfirmedBalance* + *balance*. The unconfirmed
balance may be negative (if there is an unconfirmed spend). This
specification is strange, I know, but it replicates the interface of
insight-api.

+ DEPRECATED.  Blockstack clients should use 
  [blockstack.js](https://github.com/blockstack/blockstack.js) to query
balances.
+ Authorization: `wallet_read`
+ Legacy Endpoint
+ Response 200 (application/json)
  + Body

             -1000

  + Schema

             { 'type' : 'integer' }

## Get wallet payment address [GET /v1/wallet/payment_address]

Returns core node's payment address.

+ DEPRECATED.  Blockstack clients should use 
  [blockstack.js](https://github.com/blockstack/blockstack.js) to manage keys
and query UTXOs.
+ Authorization: `wallet_read`
+ Legacy Endpoint
+ Response 200 (application/json)
  + Body

             {
                 "address": "mv1uqYWZpnap4VBSKTHfKW6noTZcNtxtCW"
             }

  + Schema

             {
                 'type': 'object',
                 'properties': {
                     'type': 'string',
                     'pattern': r'^([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+)$',
                 }
             }

## Set a specific wallet key [PUT /v1/wallet/keys/{keyname}]
This call instructs the blockstack core node to use a particular key
instead of the core node's configured wallet key. The setting of this
key is *temporary* by default, meaning that it is not written to
`~/.blockstack/wallet.json`, and on a subsequent restart, the key will
return to the original key.  However, the core registrar *tracks* the
owner key used for each `PREORDER`, and stores that private key
encrypted (with `scrypt` and the core wallet password) in the
queue. When the registrar detects that the key being used for a
particular name has changed, it will recover by submitting further
transactions with the stored key.

However, for blockstack core >= 0.14.5, the `persist_change` keyword
will instruct the core node to write the changed key to
`~/.blockstack/wallet.json`. In this mode, the node will backup the
previous wallet to `~/.blockstack/wallet.json.prior.<timestamp>`

+ DEPRECATED.  Blockstack clients should use 
  [blockstack.js](https://github.com/blockstack/blockstack.js) to manage keys.
+ Requires root authorization
+ Legacy Endpoint
+ Parameters
    + keyname: owner (string) - which key to set (one of 'owner', 'data', 'payment')

+ Request (application/json)
  + Body

              "cPo24qGYz76xSbUCug6e8LzmzLGJPZoowQC7fCVPLN2tzCUJgfcW"

+ Request (application/json)
  + Schema

              {
                "type" : "object",
                "properties" : {
                  "private_key" : {
                     "anyOf": [
                         {
                             "anyOf": [
                                 {
                                     "pattern": "^([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+)$",
                                     "type": "string"
                                 },
                                 {
                                     "pattern": "^([0-9a-fA-F]+)$",
                                     "type": "string"
                                 }
                             ]
                         },
                         {
                             "properties": {
                                 "address": {
                                     "pattern": "^([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+)$",
                                     "type": "string"
                                 },
                                 "private_keys": {
                                     "items": {
                                         "anyOf": [
                                             {
                                                 "pattern": "^([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+)$", 
                                                 "type": "string"
                                             },
                                             {
                                                 "pattern": "^([0-9a-fA-F]+)$",
                                                 "type": "string"
                                             }
                                         ]
                                     },
                                     "type": "array"
                                 },
                                 "redeem_script": {
                                     "pattern": "^([0-9a-fA-F]+)$",
                                     "type": "string"
                                 }
                             },
                             "required": [
                                 "address",
                                 "redeem_script",
                                 "private_keys"
                             ],
                             "type": "object"
                         }
                     ]
                    },
                  "persist_change" : {"type" : "boolean"}
              },
              "required" : [ "private_key" ]
             }

+ Request (application/json)
  + Schema

              {
                "anyOf": [
                    {
                        "anyOf": [
                            {
                                "pattern": "^([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+)$",
                                "type": "string"
                            },
                            {
                                "pattern": "^([0-9a-fA-F]+)$",
                                "type": "string"
                            }
                        ]
                    },
                    {
                        "properties": {
                            "address": {
                                "pattern": "^([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+)$",
                                "type": "string"
                            },
                            "private_keys": {
                                "items": {
                                    "anyOf": [
                                        {
                                            "pattern": "^([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+)$", 
                                            "type": "string"
                                        },
                                        {
                                            "pattern": "^([0-9a-fA-F]+)$",
                                            "type": "string"
                                        }
                                    ]
                                },
                                "type": "array"
                            },
                            "redeem_script": {
                                "pattern": "^([0-9a-fA-F]+)$",
                                "type": "string"
                            }
                        },
                        "required": [
                            "address",
                            "redeem_script",
                            "private_keys"
                        ],
                        "type": "object"
                    }
                ]
              }

+ Response 200 (application/json)
  + Body

              {"status": true}

  + Schema

             {
              'anyOf': [
                {
                      'type': 'object',
                      'properties': {
                           'status': {
                              'type': 'boolean'
                           },
                      },
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
             }

## Get payment wallet balance [GET /v1/wallet/balance/{minconfs}]

Fetches wallet balance, including UTXOs from transactions with at
least a specified number of confirmations.

+ DEPRECATED.  Blockstack clients should use 
  [blockstack.js](https://github.com/blockstack/blockstack.js) to manage keys
and query UTXOs.
+ Authorization: `wallet_read`
+ Legacy Endpoint
+ Parameters
  + minconfs: 0 (number, optional) - the minimum confs of transactions to include in balance
+ Response 200 (application/json)
  + Body

             {
                 "balance": {
                     "bitcoin": 49.931727,
                     "satoshis": 4993172700
                 }
             }

  + Schema

              {
                 'type': 'object',
                 'properties': {
                     'balance': {
                         'type': 'object',
                             'properties': {
                                 'bitcoin': {
                                     'type': 'number',
                                     'minimum': 0,
                                 },
                                 'satoshis': {
                                     'type': 'integer',
                                     'minimum': 0,
                                 },
                             },
                         },
                   },
                }

## Withdraw payment wallet funds [POST /v1/wallet/balance]
Withdraw an amount (given in satoshis) from the core payment
wallet, to a particular address.

+ DEPRECATED.  Blockstack clients should use 
  [blockstack.js](https://github.com/blockstack/blockstack.js) to manage keys,
generate transactions, and send transactions.
+ Authorization: `wallet_write`
+ Legacy Endpoint
+ Request (application/json)
  + Body

            {'address' : 'mibZW6EBpXSTWQNQ9E4fi9hhGKYSMkjyg9',
               'amount' : 100,
               'min_confs' : 6,
               'tx_only' : false}

  + Schema

            {
                'type': 'object',
                'properties': {
                    'address': {
                        'type': 'string',
                        'pattern': r"^([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+)$",
                    },
                    'amount': {
                        'type': 'integer',
                        'minimum': 0,
                    },
                    'message': {
                        'type': 'string',
                        'pattern': '^.{1,80}$',
                    }
                    'min_confs': {
                        'type': 'integer',
                        'minimum': 0,
                    },
                    'tx_only': {
                        'type': 'boolean'
                    },
                    'payment_key': {
                        'anyOf': [
                            {
                                'anyOf': [
                                    {
                                        'pattern': '^([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+)$',
                                        'type': 'string'
                                    },
                                    {
                                        'pattern': '^([0-9a-fA-F]+)$',
                                        'type': 'string'
                                    }
                                ]
                            },
                            {
                                'properties': {
                                    'address': {
                                        'pattern': '^([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+)$',
                                        'type': 'string'
                                    },
                                    'private_keys': {
                                        'items': {
                                            'anyOf': [
                                                {
                                                    'pattern': '^([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+)$',
                                                    'type': 'string'
                                                },
                                                {
                                                    'pattern': '^([0-9a-fA-F]+)$',
                                                    'type': 'string'
                                                }
                                            ]
                                        },
                                        'type': 'array'
                                    },
                                    'redeem_script': {
                                        'pattern': '^([0-9a-fA-F]+)$',
                                        'type': 'string'
                                    }
                                },
                                'required': [
                                    'owner'
                                ],
                                'type': 'object'
                            }
                        ]
                    }
                },
                'required': [
                    'address'
                ],
            }

+ Response 200 (application/json)
  + Body

             {
              "status": true, 
              "transaction_hash": "c4ee8d1993794487e6b5aca802a1793530bdff35c763ca051fbaa4b998780822",
              "success": true
             }
  + Schema

            {
              'anyOf': [
                {
                      'type': 'object',
                      'properties': {
                           'success': {
                              'type': 'boolean'
                           },
                           'transaction_hash': {
                               'type': 'string',
                               'pattern': r'^([0-9a-fA-F]+)$',
                           },
                      },
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
            }
                

## Get wallet owner address [GET /v1/wallet/owner_address]
Returns core node's owner address.

+ DEPRECATED.  Blockstack clients should use 
  [blockstack.js](https://github.com/blockstack/blockstack.js) to manage keys.
+ Authorization: `wallet_read`
+ Legacy Endpoint
+ Response 200 (application/json)
  + Body

             {
                 "address": "myaPViveUWiiZQQTb51KXCDde4iLC3Rf3K"
             }
  + Schema

            {
              'anyOf': [
                {
                      'type': 'object',
                      'properties': {
                           'address': {
                              'type': 'string',
                              'pattern': r"^([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+)$",
                           },
                      },
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
            }


## Get wallet data public key [GET /v1/wallet/data_pubkey]
Returns the public key the core node uses for signing user data

+ DEPRECATED.  Blockstack clients should use 
  [blockstack.js](https://github.com/blockstack/blockstack.js) to manage keys.
+ Authorization: `wallet_read`
+ Legacy Endpoint
+ Response 200 (application/json)
  + Body

             {
                 "public_key": "03ea5d8c2a3ba84eb17625162320bb53440557c71f7977a57d61405e86be7bdcda"
             }
  + Schema

            {
              'anyOf': [
                {
                      'type': 'object',
                      'properties': {
                           'public_key': {
                              'type': 'string',
                              'pattern': r'^([0-9a-fA-F]+)$',
                           },
                      },
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
            }

## Change wallet password [PUT /v1/wallet/password]
This will change the password for core's wallet. Currently not working endpoint.

+ DEPRECATED.  Blockstack clients should use 
  [blockstack.js](https://github.com/blockstack/blockstack.js) to encrypt keys.
+ Authorization: `wallet_write`
+ Legacy Endpoint
+ Request (application/json)
  + Body
  
              {'password' : '"0123456789abcdef"',
               'new_password' : "abcdef0123456789"'}
  + Schema

            {
              'anyOf': [
                {
                      'type': 'object',
                      'properties': {
                           'password': {
                              'type': 'string',
                           },
                           'new_password': {
                              'type': 'string',
                           },
                      },
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
            }

## Set all wallet keys [PUT /v1/wallet/keys]

+ DEPRECATED.  Blockstack clients should use 
  [blockstack.js](https://github.com/blockstack/blockstack.js) to manage keys
in a client wallet.
+ Legacy Endpoint
+ Requires root authorization

## Get all wallet keys [GET /v1/wallet/keys]

+ DEPRECATED.  Blockstack clients should use 
  [blockstack.js](https://github.com/blockstack/blockstack.js) to interact with
a client wallet.
+ Legacy Endpoint
+ Requires root authorization

# Group Managing Names

All POST, PUT, and DELETE routes in this section are **DEPRECATED** in favor of using either the [Blockstack
Browser](https://github.com/blockstack/blockstack-browser) or 
[blockstack.js](https://github.com/blockstack/blockstack.js) to register and
manage names.

All GET routes are still valid.

## Register a name [POST /v1/names]
Registers a name, optionally to a given owner key and optionally using
a given payment key to pay for the name and transaction fees.

This method takes a JSON blob with the following fields:

* `name`: (required) the fully-qualified name to register.
* `zonefile`: (optional) the zone file to associate with this name.  If one is
  not given, a default one will be generated.
* `owner_address`: (optional) the recipient of this name.  See below.
* `min_confs`: (optional) this is the minimum number of confirmations for UTXOs
  that will be used for payments for this name registration.  Lower values speed
up the name registration time, at the risk of blockchain reorgs or frontrunners
invalidating your name's registration.
* `tx_fee`: (optional) use this transaction fee (in satoshis) instead of
  estimating one.
* `cost_satoshis`: (optional) how much to pay for this name.  This value will be
  sent to the name's namespace's designated burn address.  If not given, the
precise value will be looked up automatically.
* `unsafe`: (optional) ignore internal safety checks when generating and sending
  transactions.  See below.
* `owner_key`: (optional) if given, this is the *private key* of the owner
that will receive the name.  Useful for when you want to use your *personal*
node to register names to a different key, without having to bother with the
extra `NAME_TRANSFER` transaction required by passing `owner_address`.
DO NOT USE IN PUBLIC SETTINGS.
* `payment_key`: (optional) if given, this is the *private key* used to pay for
  the name registration fee and transaction fees.  Useful for when you want to
use your *personal* node to register names with a different payment key.  DO NOT
USE IN PUBLIC SETTINGS.

If no `owner_address` is supplied in the POSTed JSON
object, the node will register a name for the `owner_key` given in the
JSON blob.  If no `owner_key` is given, then the node's current owner address
in its wallet will be used.

If an `owner_address` is supplied, a `TRANSFER` transaction will be
broadcasted to send the name to appropriate owner.  If you intend to register
many names to different addresses, it is recommended that you use one of the
wallet endpoints to set the node's owner keys to save yourself the extra
`TRANSFER` transactions (or pass `owner_key`).  However, you should *ONLY* do
this if you trust the node (i.e. only do this for personal nodes).

The `min_confs` keyword controls the minimum number of confirmations for
UTXOs used as payments for name registration.

The `unsafe` keyword instructs the node's registrar to ignore certain
safety checks while registering the name (in particular, the registrar
will not verify that the user own's the name before issuing a
`REGISTER` and `UPDATE`). This allows the registrar to submit
operations before they have been confirmed on remote resolvers or
indexers, in this mode, the registrar will wait for 4 confirmations on
a `PREORDER`, 1 confirmation on a `REGISTER` and 1 confirmation on an
`UPDATE`. `node.blockstack.org` will correctly detect the registration
after the `UPDATE` has 6 confirmations.

+ DEPRECATED.  Registering names is now performed by [Blockstack
  Browser](https://github.com/blockstack/blocktack-browser) and
[blockstack.js](https://github.com/blockstack/blockstack.js).
+ Authorization: `register`
+ Legacy Endpoint
+ Request (application/json)
  + Body

             {
               'name' : 'bar.test'
             }

+ Request (application/json)
  + Schema

              {
                        'type': 'object',
                        'properties': {
                            "name": {
                                'type': 'string',
                                'pattern': OP_NAME_PATTERN
                            },
                            "zonefile": {
                                'type': 'string',
                                'maxLength': RPC_MAX_ZONEFILE_LEN,
                            },
                            "owner_address": {
                                'type': 'string',
                                'pattern': OP_BASE58CHECK_PATTERN,
                            },
                            'min_confs': {
                                'type': 'integer',
                                'minimum': 0,
                            },
                            'tx_fee': {
                                'type': 'integer',
                                'minimum': 0,
                                'maximum': TX_MAX_FEE,
                            },
                            'cost_satoshis': {
                                'type': 'integer',
                                'minimum': 0,
                            },
                            'unsafe': {
                                'type': 'boolean'
                            },
                            'owner_key': {
                                'anyOf': [
                                    {
                                        'anyOf': [
                                            {
                                                'pattern': '^([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+)$',
                                                'type': 'string'
                                            },
                                            {
                                                'pattern': '^([0-9a-fA-F]+)$',
                                                'type': 'string'
                                            }
                                        ]
                                    },
                                    {
                                        'properties': {
                                            'address': {
                                                'pattern': '^([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+)$',
                                                'type': 'string'
                                            },
                                            'private_keys': {
                                                'items': {
                                                    'anyOf': [
                                                        {
                                                            'pattern': '^([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+)$',
                                                            'type': 'string'
                                                        },
                                                        {
                                                            'pattern': '^([0-9a-fA-F]+)$',
                                                            'type': 'string'
                                                        }
                                                    ]
                                                },
                                                'type': 'array'
                                            },
                                            'redeem_script': {
                                                'pattern': '^([0-9a-fA-F]+)$',
                                                'type': 'string'
                                            }
                                        },
                                        'required': [
                                            'owner'
                                        ],
                                        'type': 'object'
                                    }
                                ]
                            },
                            'payment_key': {
                                'anyOf': [
                                    {
                                        'anyOf': [
                                            {
                                                'pattern': '^([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+)$',
                                                'type': 'string'
                                            },
                                            {
                                                'pattern': '^([0-9a-fA-F]+)$',
                                                'type': 'string'
                                            }
                                        ]
                                    },
                                    {
                                        'properties': {
                                            'address': {
                                                'pattern': '^([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+)$',
                                                'type': 'string'
                                            },
                                            'private_keys': {
                                                'items': {
                                                    'anyOf': [
                                                        {
                                                            'pattern': '^([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+)$',
                                                            'type': 'string'
                                                        },
                                                        {
                                                            'pattern': '^([0-9a-fA-F]+)$',
                                                            'type': 'string'
                                                        }
                                                    ]
                                                },
                                                'type': 'array'
                                            },
                                            'redeem_script': {
                                                'pattern': '^([0-9a-fA-F]+)$',
                                                'type': 'string'
                                            }
                                        },
                                        'required': [
                                            'owner'
                                        ],
                                        'type': 'object'
                                    }
                                ]
                            }
                        },
                        'required': [
                            'name'
                        ],
                        'additionalProperties': False,
                    }

+ Response 200 (application/json)
  + Body

             {
                 "message": "Name queued for registration.  The process takes several hours.  You can check the status with `blockstack info`.",
                 "success": true,
                 "transaction_hash": "6cdb9722f72875b30e1ab3de463e3960aced951f674be942b302581a9a9469a5"
             }

  + Schema

            {
              'anyOf': [
                {
                      'type': 'object',
                      'properties': {
                           'success': {
                              'type': 'boolean'
                           },
                           'transaction_hash': {
                               'type': 'string',
                               'pattern': r'^([0-9a-fA-F]+)$',
                           },
                      },
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
            }


## Revoke name [DELETE /v1/names/{name}]
Revokes the name from Blockstack.  This renders
the name unusable until it expires.  Use this method if your private keys 
are compromised.

+ DEPRECATED.  Blockstack clients should use
  [blockstack.js](https://github.com/blockstack/blockstack.js) for generating
transactions.
+ Authorization: `revoke`
+ Legacy Endpoint
+ Parameters
  + name: bar.test (string) - fully-qualified name
+ Response 200 (application/json)
  + Body

             {
                 "message": "Name queued for revocation.  The process takes ~1 hour.  You can check the status with `blockstack info`.",
                 "success": true,
                 "transaction_hash": "b2745b706d7a14ce652265de103d7eaefb44a75eb658d7bb1db8868da08768b2"
             }

  + Schema

            {
              'anyOf': [
                {
                      'type': 'object',
                      'properties': {
                           'success': {
                              'type': 'boolean'
                           },
                           'transaction_hash': {
                               'type': 'string',
                               'pattern': r'^([0-9a-fA-F]+)$',
                           },
                      },
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
            }


## Transfer name [PUT /v1/names/{name}/owner]
Transfers a name to a different owner.

+ DEPRECATED.  Blockstack clients should use
  [blockstack.js](https://github.com/blockstack/blockstack.js) for generating
transactions.
+ Authorization: `transfer`
+ Legacy Endpoint
+ Parameters
  + name: bar.test (string) - name to transfer
+ Request (application/json)
  + Body

             { "owner" : "mjZicz7GSJBZuGeCMEgpzr8U9w6d41DfXm" }

+ Request (application/json)
  + Schema


                      {
                        'type': 'object',
                        'properties': {
                            'owner': {
                                'type': 'string',
                                'pattern': OP_BASE58CHECK_PATTERN,
                            },
                            'tx_fee': {
                                'type': 'integer',
                                'minimum': 0,
                                'maximum': 500000
                            },
                            'owner_key': {
                                'anyOf': [
                                    {
                                        'anyOf': [
                                            {
                                                'pattern': '^([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+)$',
                                                'type': 'string'
                                            },
                                            {
                                                'pattern': '^([0-9a-fA-F]+)$',
                                                'type': 'string'
                                            }
                                        ]
                                    },
                                    {
                                        'properties': {
                                            'address': {
                                                'pattern': '^([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+)$',
                                                'type': 'string'
                                            },
                                            'private_keys': {
                                                'items': {
                                                    'anyOf': [
                                                        {
                                                            'pattern': '^([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+)$',
                                                            'type': 'string'
                                                        },
                                                        {
                                                            'pattern': '^([0-9a-fA-F]+)$',
                                                            'type': 'string'
                                                        }
                                                    ]
                                                },
                                                'type': 'array'
                                            },
                                            'redeem_script': {
                                                'pattern': '^([0-9a-fA-F]+)$',
                                                'type': 'string'
                                            }
                                        },
                                        'required': [
                                            'owner'
                                        ],
                                        'type': 'object'
                                    }
                                ]
                            },
                            'payment_key': {
                                'anyOf': [
                                    {
                                        'anyOf': [
                                            {
                                                'pattern': '^([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+)$',
                                                'type': 'string'
                                            },
                                            {
                                                'pattern': '^([0-9a-fA-F]+)$',
                                                'type': 'string'
                                            }
                                        ]
                                    },
                                    {
                                        'properties': {
                                            'address': {
                                                'pattern': '^([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+)$',
                                                'type': 'string'
                                            },
                                            'private_keys': {
                                                'items': {
                                                    'anyOf': [
                                                        {
                                                            'pattern': '^([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+)$',
                                                            'type': 'string'
                                                        },
                                                        {
                                                            'pattern': '^([0-9a-fA-F]+)$',
                                                            'type': 'string'
                                                        }
                                                    ]
                                                },
                                                'type': 'array'
                                            },
                                            'redeem_script': {
                                                'pattern': '^([0-9a-fA-F]+)$',
                                                'type': 'string'
                                            }
                                        },
                                        'required': [
                                            'owner'
                                        ],
                                        'type': 'object'
                                    }
                                ]
                            }
                        },
                        'additionalProperties': False,
                    }


+ Response 202 (application/json)
  + Body

             {
                 "message": "Name queued for transfer.  The process takes ~1 hour.  You can check the status with `blockstack info`.",
                 "success": true,
                 "transaction_hash": "c0d677f9ee681abbed8ca6d231bc4ece517c8c6695ce883e5e196b5395402779"
             }

  + Schema

            {
              'anyOf': [
                {
                      'type': 'object',
                      'properties': {
                           'success': {
                              'type': 'boolean'
                           },
                           'transaction_hash': {
                               'type': 'string',
                               'pattern': r'^([0-9a-fA-F]+)$',
                           },
                      },
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
            }

## Publish zone file [POST /v1/names/zonefile]
Publish the zonefile which has _already_ been announced.
Submit either as a string with the 'zonefile' property, or
as a base64 encoded blob with the 'zonefile_b64' property.
We recommend base64-encoding your zone files in order to guarantee that they
will be JSON-encodable. 

+ DEPRECATED.
+ Request (application/json)
  + Schema

                      {
                        'type': 'object',
                        'properties': {
                            "zonefile": {
                                'type': 'string',
                            },
                            "zonefile_b64": {
                                'type': 'string',
                            }
                        },
                        'additionalProperties': False,
                       }

+ Response 200 (application/json)
  + Body

                {'success': true, 'servers' : ['...']}


## Set zone file [PUT /v1/names/{name}/zonefile]
Sets the user's zonefile hash, and, if supplied, propagates the
zonefile. If you supply the zonefile, the hash will be calculated from
that. Ultimately, your requests should only supply one of `zonefile`,
`zonefile_b64`, or `zonefile_hash`.

The value for `zonefile_b64` is a base64-encoded string.
New clients _should_ use the `zonefile_b64` field when specifying a zone file.
The `zonefile` field is preserved for legacy compatibility.

This API call issues a `NAME_UPDATE` transaction for a name that is owned by
this node's wallet.  That is, you can only call this API method if your node
owns the name you're updating.

+ DEPRECATED.  Blockstack clients should use
  [blockstack.js](https://github.com/blockstack/blockstack.js) for generating
transactions.
+ Authorization: `update`
+ Legacy Endpoint
+ Parameters
  + name: bar.test (string) - fully-qualified name
+ Request (application/json)
  + Schema

                      {
                        'type': 'object',
                        'properties': {
                            "zonefile": {
                                'type': 'string',
                            },
                            'zonefile_b64': {
                                'type': 'string',
                                'pattern': r'^((?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4}))$'
                            },
                            'zonefile_hash': {
                                'type': 'string',
                                'pattern': '^([0-9a-fA-F]{20})$'
                            },
                            'tx_fee': {
                                'type': 'integer',
                                'minimum': 0,
                                'maximum': 500000
                            },
                            'owner_key': {
                                'anyOf': [
                                    {
                                        'anyOf': [
                                            {
                                                'pattern': '^([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+)$',
                                                'type': 'string'
                                            },
                                            {
                                                'pattern': '^([0-9a-fA-F]+)$',
                                                'type': 'string'
                                            }
                                        ]
                                    },
                                    {
                                        'properties': {
                                            'address': {
                                                'pattern': '^([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+)$',
                                                'type': 'string'
                                            },
                                            'private_keys': {
                                                'items': {
                                                    'anyOf': [
                                                        {
                                                            'pattern': '^([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+)$',
                                                            'type': 'string'
                                                        },
                                                        {
                                                            'pattern': '^([0-9a-fA-F]+)$',
                                                            'type': 'string'
                                                        }
                                                    ]
                                                },
                                                'type': 'array'
                                            },
                                            'redeem_script': {
                                                'pattern': '^([0-9a-fA-F]+)$',
                                                'type': 'string'
                                            }
                                        },
                                        'required': [
                                            'owner'
                                        ],
                                        'type': 'object'
                                    }
                                ]
                            },
                            'payment_key': {
                                'anyOf': [
                                    {
                                        'anyOf': [
                                            {
                                                'pattern': '^([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+)$',
                                                'type': 'string'
                                            },
                                            {
                                                'pattern': '^([0-9a-fA-F]+)$',
                                                'type': 'string'
                                            }
                                        ]
                                    },
                                    {
                                        'properties': {
                                            'address': {
                                                'pattern': '^([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+)$',
                                                'type': 'string'
                                            },
                                            'private_keys': {
                                                'items': {
                                                    'anyOf': [
                                                        {
                                                            'pattern': '^([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+)$',
                                                            'type': 'string'
                                                        },
                                                        {
                                                            'pattern': '^([0-9a-fA-F]+)$',
                                                            'type': 'string'
                                                        }
                                                    ]
                                                },
                                                'type': 'array'
                                            },
                                            'redeem_script': {
                                                'pattern': '^([0-9a-fA-F]+)$',
                                                'type': 'string'
                                            }
                                        },
                                        'required': [
                                            'owner'
                                        ],
                                        'type': 'object'
                                    }
                                ]
                            }
                        },
                        'additionalProperties': False,
                    }

+ Response 202 (application/json)
  + Body

                {'success': true, 'transaction_hash' : '...'}
  + Schema

            {
              'anyOf': [
                {
                      'type': 'object',
                      'properties': {
                           'success': {
                              'type': 'boolean'
                           },
                           'transaction_hash': {
                               'type': 'string',
                               'pattern': r'^([0-9a-fA-F]+)$',
                           },
                      },
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
            }

## Fetch zone file [GET /v1/names/{name}/zonefile]
Fetch a user's raw zone file.  This only works for RFC-compliant zone files.
This method returns an error for names that have non-standard zone files.

+ Parameters
  + name: bar.test (string) - fully-qualified name
+ Response 200 (application/json)
  + Body

               {
                   "zonefile": "$ORIGIN bar.test\n$TTL 3600\n_https._tcp URI 10 1 \"https://blockstack.s3.amazonaws.com/bar.test\"\n"
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
                       'pattern': r'^([a-z0-9\\-_.+]{3,37})$',
                 }
              }
 
## Get name info [GET /v1/names/{name}]
+ Public Endpoint
+ Subdomain Aware
+ Parameters
  + name: muneeb.id (string) - fully-qualified name
+ Response 200 (application/json)
  + Body

              {
              "address": "1QJQxDas5JhdiXhEbNS14iNjr8auFT96GP", 
              "blockchain": "bitcoin", 
              "expire_block": 489247, 
              "last_txid": "1edfa419f7b83f33e00830bc9409210da6c6d1db60f99eda10c835aa339cad6b", 
              "status": "registered", 
              "zonefile": "$ORIGIN muneeb.id\n$TTL 3600\n_http._tcp IN URI 10 1 \"https://blockstack.s3.amazonaws.com/muneeb.id\"\n", 
              "zonefile_hash": "b100a68235244b012854a95f9114695679002af9"
              }

  + Schema

               {
                 'type': 'object',
                 'properties': {
                   'address': {
                       'type': 'string',
                       'pattern': r"^([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+)$", 
                   },
                   'blockchain': {
                       'type': 'string',
                       'pattern': '^bitcoin$',
                   },
                   'expire_block': {
                       'type': 'integer',
                       'minimum': 0,
                   },
                   'last_txid': {
                       'type': 'string',
                       'pattern': '^[0-9a-fA-F]+$',
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
                
## Name history [GET /v1/names/{name}/history]
Get a history of all blockchain records of a registered name.
+ Public Endpoint
+ Subdomain aware
+ Parameters
  + name: muneeb.id (string) - name to query
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
                            'pattern': r"^([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+)$", 
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
                                    'pattern': r'^76[aA]914[0-9a-fA-F]{40}88[aA][cC]$',
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
                                    'pattern': r"^([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+)$", 
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
                        'op',
                        'opcode',
                        'txid',
                        'vtxindex'
                    ],
                  }
               }
              }
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
               "zonefile": 
               "$ORIGIN muneeb.id\n$TTL 3600\n_http._tcp IN URI 10 1 \"https://blockstack.s3.amazonaws.com/muneeb.id\"\n"
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
                           },
                       },
                   },
               }

# Group Price Checks
## Get namespace price [GET /v1/prices/namespaces/{tld}]

This endpoint is used to get the price of a namespace.  Anyone can create a
namespace by following [this
tutorial](https://github.com/blockstack/blockstack-core/blob/master/docs/namespace_creation.md).

+ Public Endpoint
+ Parameters
  + tld: id (string) - namespace to query price for
+ Response 200 (application/json)
  + Body

             {
               "satoshis": 4000000000
             }

  + Schema

            {
                'type': 'object',
                'properties': {
                    'satoshis': {
                        'type': 'integer',
                        'minimum': 0,
                    },
                },
            }

## Get name price [GET /v1/prices/names/{name}]

This endpoint is used to get the price of a name.  If you are using
a public endpoint, you should *only* rely on the `name_price` field in the
returned JSON blob.  Other fields are **DEPRECATED**, since they are relevant
only for estimating the cost of registering a name (which should be done via
[blockstack.js](https://github.com/blockstack/blockstack.js) or the [Blockstack
Browser](https://github.com/blockstack/blockstack-browser)).

+ Public Endpoint
+ Parameters
    + name: muneeb.id (string) - name to query price information for
+ Response 200 (application/json)
  + Body

               {
                        "name_price": {
                          "satoshis": 100000, 
                          "btc": 0.001
                        }, 
                        "total_tx_fees": 519209, 
                        "register_tx_fee": {
                          "satoshis": 159110, 
                          "btc": 0.0015911
                        }, 
                        "preorder_tx_fee": {
                          "satoshis": 163703, 
                          "btc": 0.00163703
                        }, 
                        "warnings": [
                          "Insufficient funds; fees are rough estimates."
                        ], 
                        "total_estimated_cost": {
                          "satoshis": 619209, 
                          "btc": 0.00619209
                        }, 
                        "update_tx_fee": {
                          "satoshis": 196396, 
                          "btc": 0.00196396
                        }
               }

    + Schema

               {
                   'type': 'object',
                   'properties': {
                       'name_price': {
                           'type': 'object',
                           'properties': {
                               'btc': { 'type': 'number', 'minimum': 0 },
                               'satoshis': { 'type': 'integer', 'minimum': 0 }
                           }
                       },
                       'preorder_tx_fee': {
                           'type': 'object',
                           'properties': {
                               'btc': { 'type': 'number', 'minimum': 0 },
                               'satoshis': { 'type': 'integer', 'minimum': 0 }
                           }
                       },
                       'register_tx_fee': {
                           'type': 'object',
                           'properties': {
                               'btc': { 'type': 'number', 'minimum': 0 },
                               'satoshis': { 'type': 'integer', 'minimum': 0 }
                           }
                       },
                       'update_tx_fee': {
                           'type': 'object',
                           'properties': {
                               'btc': { 'type': 'number', 'minimum': 0 },
                               'satoshis': { 'type': 'integer', 'minimum': 0 }
                           }
                       },
                       'total_estimated_cost': {
                           'type': 'object',
                           'properties': {
                               'btc': { 'type': 'number', 'minimum': 0 },
                               'satoshis': { 'type': 'integer', 'minimum': 0 }
                           }
                       },
                       'total_tx_fees': {
                           'type': 'integer',
                           'minimum': 0,
                       }
                       'name_price': {
                           'type': 'object',
                           'properties': {
                               'btc': { 'type': 'number', 'minimum': 0 },
                               'satoshis': { 'type': 'integer', 'minimum': 0 }
                           }
                       },
                       'warnings': {
                           'type': 'array',
                           'items': {
                               'type': 'string',
                           },
                       },
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

## Get number of names on blockchain [GET /v1/blockchains/{blockchainName}/name_count{?all}]
Get the number of names on a blockchain.
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

+ Response 401 (application/json)
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

## Get pending transactions [GET /v1/blockchains/{blockchainName}/pending]
Get the current transactions that the node has issued and are still pending.
+ DEPRECATED.  Blockstack clients should use
  [blockstack.js](https://github.com/blockstack/blockstack.js) to query the
blockchain.
+ Public Endpoint
+ Parameters
  + blockchainName : bitcoin (string) - the given blockchain
+ Response 200 (application/json)
  + Body

               {
                          "queues": {}
               }

  + Schema

            {
                'type': 'object',
                'properties': {
                    'preorder': {
                        'type': 'array',
                        'items': {
                            'type': 'object',
                            'properties': {
                                'name': { 'type': 'string', 'pattern': '^([a-z0-9\-_.+]{3,37})$' },
                                'tx_hash': { 'type': 'string', 'pattern': '^[0-9a-fA-F]+$' },
                                'confirmations': { 'type': 'integer', 'minimum': 0 },
                            },
                        },
                    },
                    'register': {
                        'type': 'array',
                        'items': {
                            'type': 'object',
                            'properties': {
                                'name': { 'type': 'string', 'pattern': '^([a-z0-9\-_.+]{3,37})$' },
                                'tx_hash': { 'type': 'string', 'pattern': '^[0-9a-fA-F]+$' },
                                'confirmations': { 'type': 'integer', 'minimum': 0 },
                            },
                        },
                    },
                    'update': {
                        'type': 'array',
                        'items': {
                            'type': 'object',
                            'properties': {
                                'name': { 'type': 'string', 'pattern': '^([a-z0-9\-_.+]{3,37})$' },
                                'tx_hash': { 'type': 'string', 'pattern': '^[0-9a-fA-F]+$' },
                                'confirmations': { 'type': 'integer', 'minimum': 0 },
                            },
                        },
                    },
                    'transfer': {
                        'type': 'array',
                        'items': {
                            'type': 'object',
                            'properties': {
                                'name': { 'type': 'string', 'pattern': '^([a-z0-9\-_.+]{3,37})$' },
                                'tx_hash': { 'type': 'string', 'pattern': '^[0-9a-fA-F]+$' },
                                'confirmations': { 'type': 'integer', 'minimum': 0 },
                            },
                        },
                    },
                    'renew': {
                        'type': 'array',
                        'items': {
                            'type': 'object',
                            'properties': {
                                'name': { 'type': 'string', 'pattern': '^([a-z0-9\-_.+]{3,37})$' },
                                'tx_hash': { 'type': 'string', 'pattern': '^[0-9a-fA-F]+$' },
                                'confirmations': { 'type': 'integer', 'minimum': 0 },
                            },
                        },
                    },
                    'revoke': {
                        'type': 'array',
                        'items': {
                            'type': 'object',
                            'properties': {
                                'name': { 'type': 'string', 'pattern': '^([a-z0-9\-_.+]{3,37})$' },
                                'tx_hash': { 'type': 'string', 'pattern': '^[0-9a-fA-F]+$' },
                                'confirmations': { 'type': 'integer', 'minimum': 0 },
                            },
                        },
                    },
                    'name_import': {
                        'type': 'array',
                        'items': {
                            'type': 'object',
                            'properties': {
                                'name': { 'type': 'string', 'pattern': '^([a-z0-9\-_.+]{3,37})$' },
                                'tx_hash': { 'type': 'string', 'pattern': '^[0-9a-fA-F]+$' },
                                'confirmations': { 'type': 'integer', 'minimum': 0 },
                            },
                        },
                    },
                }
            }

## Get unspent outputs [GET /v1/blockchains/{blockchainName}/{address}/unspent]
+ DEPRECATED.  Blockstack clients should use
  [blockstack.js](https://github.com/blockstack/blockstack.js) to query the
blockchain.
+ Authorization: `blockchain`
+ Parameters
  + blockchainName : bitcoin (string) - the given blockchain
  + address :  1GuKR3nJi2VH3E1ZSPvuX8nAu3jNnr7xzq (string) - the address to get unspents for
+ Response 200 (application/json)
  + Body

               [
                          {
                              "confirmations": 18,
                              "out_script": "76a914ae6ee3760fccb8225541ca89f08c927930adf97b88ac",
                              "outpoint": {
                                  "hash": "977d3a025790e2cbdb50f63761872f36e78fbb9c53d515cb4c53155a1964932d",
                                  "index": 1
                              },
                              "transaction_hash": "977d3a025790e2cbdb50f63761872f36e78fbb9c53d515cb4c53155a1964932d",
                              "value": 76779
                          }
               ]

   + Schema

               {
                   'type': 'array',
                   'items': {
                       'type': 'object',
                       'properties': {
                           'confirmations': { 'type': 'integer', 'minimum': 0 },
                           'out_script': { 'type': 'string', 'pattern': '^[0-9a-fA-F]+$' },
                           'outpoint': {
                               'type': 'object',
                               'properties': {
                                   'hash': { 'type': 'string', 'pattern': '^[0-9a-fA-F]+$' },
                                   'index': { 'type': 'integer', 'minimum': 0 },
                               },
                           },
                           'transaction_hash': { 'type': 'string', 'pattern': '^[0-9a-fA-F]+$' },
                           'value': { 'type': 'integer', 'minimum': 0 },
                       },
                   },
               }

## Broadcast transaction [POST /v1/blockchains/{blockchainName}/txs]
+ DEPRECATED.  Blockstack clients should use
  [blockstack.js](https://github.com/blockstack/blockstack.js) to broadcast
transactions.
+ Authorization: `blockchain`
+ Parameters
  + blockchainName : bitcoin (string) - the blockchain to broadcast on
+ Request (application/json)
  + Schema
        
                              {
                                  'type': 'object',
                                  'properties': {
                                      'tx': {
                                          'type': 'string',
                                          'pattern': OP_HEX_PATTERN,
                                      },
                                  },
                                  'additionalProperties': False,
                                  'required': [
                                      'tx'
                                  ],
                              }

+ Response 200 (application/json)
  + Body
  
               { 'status' : True, 'tx_hash' : '...' }

 + Schema

               {
                   'anyOf': [
                       {
                           'type': 'object',
                           'properties': {
                               'status': { 'type': 'boolean' },
                               'tx_hash': { 'type': 'string', 'pattern': '^[0-9a-fA-F]+$' },
                           },
                       },
                       {
                           'type': 'object',
                           'properties': {
                               'error': { 'type': 'string' },
                           },
                       },
                   ]
               }

# Group Namespace Operations
## Get all namespaces [GET /v1/namespaces]
+ Public Endpoint
+ Response 200 (application/json)
  + Body

               {
                 "namespaces": [
                   ".id"
                 ] 
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

# Group Resolver Endpoints
## Lookup User [GET /v1/users/{username}]
Lookup and resolver a user's profile. Defaults to the `id` namespace.
Note that [blockstack.js](https://github.com/blockstack/blockstack.js) does
*not* rely on this endpoint.

+ Public Only Endpoint
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

