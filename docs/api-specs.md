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
    + authRequestToken: a jwt token (TODO: describe better)

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

## Get the node's config [GET /v1/node/config]
## Set config field [POST /v1/node/config/{section}?{key}={value}]
Set one or more config fields in a config section.

+ Parameters
  + section: blockstack-client (string) - configuration section
  + key: server (string) - configuration variable to set
  + value: node.blockstack.org (string) - value to set

## Delete a config field [DELETE /v1/node/config/{section}/{key}]

+ Parameters
  + section: blockstack-client (string) - configuration section
  + key: server (string) - configuration variable to set

## Delete a config section [DELETE /v1/node/config/{section}]
Deletes a whole section from the node's config
+ Parameters
    + section: blockstack-client (string) - configuration section

## Get registrar state [GET /v1/node/registrar/state]

# Group Core Wallet Management

## Get wallet payment address [GET /v1/wallet/payment_address]
Returns core node's payment address.
+ Authorization: `wallet_read`
## Set all wallet keys [PUT /v1/wallet/keys]
+ Requires root authorization
## Get all wallet keys [GET /v1/wallet/keys]
+ Requires root authorization
## Set a specific wallet key [PUT /v1/wallet/keys/{keyname}]
+ Requires root authorization
+ Parameters
    + keyname: owner (string) - which key to set (one of 'owner', 'data', 'payment')

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

## Get payment wallet balance [GET /v1/wallet/balance/{minconfs}]

Fetches wallet balance, including UTXOs from transactions with at
least a specified number of confirmations.

+ Authorization: `wallet_read`
+ Parameters
  + minconfs: 0 (number, optional) - the minimum confs of transactions to include in balance
## Change wallet password [PUT /v1/wallet/password]
+ Authorization: `wallet_write`
+ Request (application/json)
  + Body
  
              {'password' : 'foobarbar',
               'new_password' : 'barfoobar'}

## Withdraw payment wallet funds [POST /v1/wallet/balance]
+ Authorization: `wallet_write`
+ Request (application/json)
  + Body
  
            {'address' : 'mF12..',
               'amount' : 100,
               'min_confs' : 6,
               'tx_only' : false}

## Get wallet owner address [GET /v1/wallet/owner_address]
Returns core node's owner address.
+ Authorization: `wallet_read`
## Get wallet data public key [GET /v1/wallet/data_pubkey]
Returns the public key the core node uses for signing user data
+ Authorization: `wallet_read`

# Group Managing Names

## Register a name [POST /v1/names]
+ Authorization: `register`
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

## Revoke name [DELETE /v1/names/{name}]
Revokes the name from blockstack.
+ Parameters
  + name: muneeb.id (string) - fully-qualified name
+ Authorization: `revoke`

## Transfer name [PUT /v1/names/{name}/owner]
Transfers a name to a different owner.
+ Authorization: `transfer`
+ Parameters
  + name: user.id (string) - name to transfer

## Set zone file [PUT /v1/names/{name}/zonefile]
Sets the user's zonefile hash, and, if supplied, propagates the
zonefile. If you supply the zonefile, the hash will be calculated from
that. Ultimately, your requests should only supply one of `zonefile`,
`zonefile_b64`, or `zonefile_hash`.

+ Authorization: `update`
+ Request (application/json)
  + Schema

                      request_schema = {
                        'type': 'object',
                        'properties': {
                            "zonefile": {
                                'type': 'string',
                                'maxLength': RPC_MAX_ZONEFILE_LEN,
                            },
                            'zonefile_b64': {
                                'type': 'string',
                                'maxLength': (RPC_MAX_ZONEFILE_LEN * 4) / 3 + 1,
                            },
                            'zonefile_hash': {
                                'type': 'string',
                                'pattern': OP_ZONEFILE_HASH_PATTERN,
                            },
                            'tx_fee': {
                                'type': 'integer',
                                'minimum': 0,
                                'maximum': TX_MAX_FEE
                            },
                        },
                        'additionalProperties': False,
                    }

+ Response 202 (application/json)
  + Body

                {'transaction_hash' : '...'}

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

## Get name info [GET /v1/names/{name}]
+ Public Endpoint
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

## Get names owned by address [GET /v1/addresses/{blockchain}/{address}]
Retrieves a list of names owned by the address provided.
+ Public Endpoint
+ Parameters
  + blockchain: bitcoin (string) - the layer-1 blockchain for the address
  + address: 1QJQxDas5JhdiXhEbNS14iNjr8auFT96GP (string) - the address to lookup

+ Response 200 (application/json)
  + Body

                {
                    "names": ["muneeb.id"]
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

# Get block operations [GET /v1/blockchains/{blockchainName}/block/{blockHeight}]
Not implemented
## Get raw name history [GET /v1/blockchains/{blockchainName}/names/{nameID}/history]
Not implemented

# Group Gaia Endpoints
## Create "store" for this session [POST /v1/stores]
## "Store" operations [/v1/stores/{storeID}]
### Get "store" metadata [GET]
### Delete "store" [DELETE]
## Get inode info (stat) [GET /v1/stores/{storeID}/inodes?path={path}]
## Directory operations [/v1/stores/{storeID}/directories?path={path}]
### Get directory files (ls) [GET]
### Create directory (mkdir) [POST]
### Delete directory (rmdir) [DELETE]
## File Operations [/v1/stores/{storeID}/files?path={path}]
### Get file data (cat) [GET]
### Create file [POST]
### Update file [PUT]
### Delete file (rm) [DELETE]

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
Not yet implemented.
## Pre-register a name [POST /v1/namespaces/{tld}/names]
Not implemented.
## Update pre-registered name [POST /v1/namespaces/{tld}/names/{name}]
Not implemented.
## Launch namespace [PUT /v1/namespaces/{tld}]
Not implemented.

# Group Proposed Collection APIs
## Create collection [POST /v1/collections]
## Get all collection items [GET /v1/collections/{collectionID}]
## Create collection item [POST /v1/collections/{collectionID}]
## Get collection item [GET /v1/collections/{collectionID}/{itemID}]
