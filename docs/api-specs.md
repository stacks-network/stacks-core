# Group Authorization

## Auth Request View [GET /auth?authRequest={authRequestToken}]

When the user clicks “login” in an application, the app should
redirect the user to this endpoint. If the user already has an
account, they will be redirected along with requested data. If the
user doesn’t have an account, the user will be presented with each of
the app’s requested permissions, then will satisfy or deny them. The
dashboard will then redirect the user back with a JWT. The response
JWT contains a signature and an API token that the app can use for
future authorization of endpoints.

Each application specifies in advance which family of API calls it
will need to make to function properly.  This list is passed along to
the dashboard endpoint when creating an application account.  The
account-creation page shows this list of API endpoints and what they
do, and allows the user to line-item approve or deny them.  The list
is stored by the API server in the local account structure, and the
list is given to the application as part of the session JWT.  The API
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
## Ping the node [GET /v1/node/ping]
Ping the blockstack node to see if it's alive.
+ Public Endpoint
+ Response 200 (application/json)
  + Body
  
            {
             "status": "alive", 
             "version": "0.14.2"
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
Returns the current configuation settings of the blockstack node.

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
                     "accounts": "/tmp/.../client/app_accounts",
                     "advanced_mode": "true",
                     "anonymous_statistics": false,
                     "api_endpoint_port": "16268",
                     "api_password": "blockstack_integration_test_api_password",
                     "blockchain_reader": "bitcoind_utxo",
                     "blockchain_writer": "bitcoind_utxo",
                     "client_version": "0.14.3.0",
                     "datastores": "/tmp/.../client/datastores",
                     "email": "",
                     "metadata": "/tmp/.../client/metadata",
                     "poll_interval": "1",
                     "port": "16264",
                     "queue_path": "/tmp/.../client/queues.db",
                     "rpc_detach": "True",
                     "server": "localhost",
                     "storage_drivers": "disk",
                     "storage_drivers_required_write": "disk",
                     "users": "/tmp/.../client/users"
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
Gets the current state of the registrar. That is, the blockstack operations 
that have been submitted that are still waiting on confirmations.

+ Requires root authorization
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
The blockstack core node manages its own wallet -- this has three keys
for payment, name ownership, and signing data (e.g., user profiles). This
wallet can be managed through these endpoints.

## Get wallet payment address [GET /v1/wallet/payment_address]
Returns core node's payment address.
+ Authorization: `wallet_read`
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
key is *temporary*. It is not written to `~/.blockstack/wallet.json`,
and on a subsequent restart, the key will return to the original key.
However, the core registrar *tracks* the owner key used for each `PREORDER`,
and stores that private key encrypted (with `scrypt` and the core wallet
password) in the queue. When the registrar detects that the key being used
for a particular name has changed, it will recover by submitting further
transactions with the stored key.

+ Requires root authorization
+ Parameters
    + keyname: owner (string) - which key to set (one of 'owner', 'data', 'payment')

+ Request (application/json)
  + Body

              "cPo24qGYz76xSbUCug6e8LzmzLGJPZoowQC7fCVPLN2tzCUJgfcW"

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

+ Authorization: `wallet_read`
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
+ Authorization: `wallet_write`
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
+ Authorization: `wallet_read`
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
+ Authorization: `wallet_read`
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
+ Authorization: `wallet_write`
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
+ Requires root authorization
## Get all wallet keys [GET /v1/wallet/keys]
+ Requires root authorization

# Group Managing Names

## Register a name [POST /v1/names]
Registers a name. If no `owner_address` is supplied in the POSTed JSON
object, core will register a name for the current owner address in core's
wallet. If an `owner_address` is supplied, a `TRANSFER` operation will be
called to send the name to appropriate owner.

The `min_confs` keyword controls the minimum number of confirmations for
UTXOs used as payments for name registration.

The `unsafe` keyword instructs core's registrar to ignore certain
safety checks while registering the name (in particular, the registrar
will not verify that the user own's the name before issuing a
`REGISTER` and `UPDATE`). This allows the registrar to submit
operations before they have been confirmed on remote resolvers or
indexers, in this mode, the registrar will wait for 4 confirmations on
a `PREORDER`, 1 confirmation on a `REGISTER` and 1 confirmation on an
`UPDATE`. `node.blockstack.org` will correctly detect the registration
after the `UPDATE` has 6 confirmations.

+ Authorization: `register`
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
Revokes the name from blockstack.
+ Authorization: `revoke`
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
+ Authorization: `transfer`
+ Parameters
  + name: bar.test (string) - name to transfer
+ Request (application/json)
  + Body

             { "owner" : "mjZicz7GSJBZuGeCMEgpzr8U9w6d41DfXm" }
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


## Set zone file [PUT /v1/names/{name}/zonefile]
Sets the user's zonefile hash, and, if supplied, propagates the
zonefile. If you supply the zonefile, the hash will be calculated from
that. Ultimately, your requests should only supply one of `zonefile`,
`zonefile_b64`, or `zonefile_hash`.

The value for `zonefile_b64` is a base64-encoded string.
New clients _should_ use the `zonefile_b64` field when specifying a zone file.
The `zonefile` field is preserved for legacy compatibility.

+ Authorization: `update`
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
                                            'address',
                                            'redeem_script',
                                            'private_keys'
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

## Get pending transactions [GET /v1/blockchains/{blockchainName}/pending]
Get the current transactions that the node has issued and are still pending.
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

## Get raw name history [GET /v1/blockchains/{blockchainName}/names/{nameID}/history]
Not implemented

+ Response 405 (application/json)
  + Body

             { 'error' : 'Unimplemented' }

# Group Gaia Endpoints
The Gaia endpoints interface with `blockstack-storage.js` to provide
storage to blockstack applications.

## Create "store" for this session [POST /v1/stores]
## Get "store" metadata [GET /v1/stores/{storeID}]
+ Parameters
  + storeID : (string)
## Delete "store" [DELETE /v1/stores/{storeID}]
+ Parameters
  + storeID : (string)
## Get inode info [GET /v1/stores/{storeID}/inodes?path={path}]
+ Parameters
  + storeID : (string)
  + path : (string) - path of inode
## Get directory files [GET /v1/stores/{storeID}/directories?path={path}]
+ Parameters
  + storeID : (string)
  + path : (string) - path of inode
## Create directory [POST /v1/stores/{storeID}/directories?path={path}]
+ Parameters
  + storeID : (string)
  + path : (string) - path of inode
## Delete directory [DELETE /v1/stores/{storeID}/directories?path={path}]
+ Parameters
  + storeID : (string)
  + path : (string) - path of inode
## Get file data [GET /v1/stores/{storeID}/files?path={path}]
+ Parameters
  + storeID : (string)
  + path : (string) - path of inode
## Create file [POST /v1/stores/{storeID}/files?path={path}]
+ Parameters
  + storeID : (string)
  + path : (string) - path of inode
## Update file [PUT /v1/stores/{storeID}/files?path={path}]
+ Parameters
  + storeID : (string)
  + path : (string) - path of inode
## Delete file [DELETE /v1/stores/{storeID}/files?path={path}]
+ Parameters
  + storeID : (string)
  + path : (string) - path of inode

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

## Create namespace [POST /v1/namespaces]
Not implemented.
## Pre-register a name [POST /v1/namespaces/{tld}/names]
Not implemented.
+ Parameters
  + tld: id (string) - the namespace to fetch names from
## Update pre-registered name [POST /v1/namespaces/{tld}/names/{name}]
Not implemented.
+ Parameters
  + tld: id (string) - the namespace to fetch names from
  + name: muneeb (string) - the name to update
## Launch namespace [PUT /v1/namespaces/{tld}]
Not implemented.
+ Parameters
  + tld: id (string) - the namespace to fetch names from
# Group Resolver Endpoints
## Lookup User [GET /v2/users/{username}]
Lookup and resolver a user's profile. Defaults to the `id` namespace.
+ Public Only Endpoint
+ Subdomain Aware
+ Legacy Endpoint
+ Parameters
  + username: fredwilson (string) - username to lookup
+ Response 200 (application/json)

               {
                 "fredwilson": {
                   "profile": {
                     "avatar": {
                       "url": "https://s3.amazonaws.com/kd4/fredwilson1"
                     },
                     "bio": "I am a VC",
                     "bitcoin": {
                       "address": "1Fbi3WDPEK6FxKppCXReCPFTgr9KhWhNB7"
                     },
                     "cover": {
                       "url": "https://s3.amazonaws.com/dx3/fredwilson"
                     },
                     "facebook": {
                       "proof": {
                         "url": "https://facebook.com/fred.wilson.963871/posts/10100401430876108"
                       },
                       "username": "fred.wilson.963871"
                     },
                     "graph": {
                       "url": "https://s3.amazonaws.com/grph/fredwilson"
                     },
                     "location": {
                       "formatted": "New York City"
                     },
                     "name": {
                       "formatted": "Fred Wilson"
                     },
                     "twitter": {
                       "proof": {
                         "url": "https://twitter.com/fredwilson/status/533040726146162689"
                       },
                       "username": "fredwilson"
                     },
                     "v": "0.2",
                     "website": "http://avc.com"
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

