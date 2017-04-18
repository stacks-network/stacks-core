# API Documentation

## Dashboard Home

#### grouping:
Dashboard Endpoints

#### subgrouping


#### anchor_tag:
dashboard_home

#### description
Serves the identity management panel

#### response_description


#### notes:
Serves the identity management panel

#### family:
identity

#### method:
GET

#### path_template:
/

#### private:
True

_end_

## Auth Request View

#### grouping:
Dashboard Endpoints

#### subgrouping


#### anchor_tag:
auth_request_view

#### description


#### response_description


#### notes:
Serves the auth request view

#### family:
identity

#### method:
GET

#### path_template:
/auth?authRequest={authRequestToken}

#### private:
True

#### grouping_note:
Explanation of the auth request view:

When the user clicks “login” in an application, the app should redirect the user to this endpoint. If the user already has an account, they will be redirected along with requested data. If the user doesn’t have an account, the user will be presented with each of the app’s requested permissions, then will satisfy or deny them. The dashboard will then redirect the user back with a JWT. The response JWT contains a signature and an API token that the app can use for future authorization of endpoints.

Each application specifies in advance which family of API calls it will need to make to function properly.  This list is passed along to the dashboard endpoint when creating an application account.  The account-creation page shows this list of API endpoints and what they do, and allows the user to line-item approve or deny them.  The list is stored by the API server in the local account structure, and the list is given to the application as part of the session JWT.  The API server will NACK requests to endpoints in API families absent from the session JWT.

_end_

## Ping the node

#### grouping:
Administrative API

#### subgrouping:
Node

#### anchor_tag:
ping__node

#### description:
Ping the node to check if the node is alive.

#### response_description:
Returns the status of the node.

#### notes:
Requires pre-shared secret in the `Authorization:` header

#### family:
-

#### method:
GET

#### path_template:
/v1/node/ping

#### tryit_pathname:
/v1/node/ping

#### example_request_bash:
/v1/node/ping

#### example_response:
{
  "status": "alive", 
  "version": "0.14.2"
}

_end_

## Get the node's config

#### grouping:
Administrative API

#### subgrouping:
Node

#### anchor_tag:
get__nodes_config

#### description


#### response_description


#### notes:
Requires pre-shared secret in the `Authorization:` header. Returns a dict with the config file

#### family:
-

#### method:
GET

#### path_template:
/v1/node/config

#### private:
True

_end_

## Set one or more config fields in a config section

#### grouping:
Administrative API

#### subgrouping:
Node

#### anchor_tag:
set_one_or_more_conf

#### description


#### response_description


#### notes:
Requires pre-shared secret in the `Authorization:` header.

#### family:
-

#### method:
POST

#### path_template:
/v1/node/config/{section}?{key}={value}

#### private:
True

_end_

## Delete a config field

#### grouping:
Administrative API

#### subgrouping:
Node

#### anchor_tag:
delete_a_config_fiel

#### description


#### response_description


#### notes:
Requires pre-shared secret in the `Authorization:` header.

#### family:
-

#### method:
DELETE

#### path_template:
/v1/node/config/{section}/{key}

#### private:
True

_end_

## Delete a config section

#### grouping:
Administrative API

#### subgrouping:
Node

#### anchor_tag:
delete_a_config_sect

#### description


#### response_description


#### notes:
Requires pre-shared secret in the `Authorization:` header.

#### family:
-

#### method:
DELETE

#### path_template:
/v1/node/config/{section}

#### private:
True

_end_

## Get registrar state

#### grouping:
Administrative API

#### subgrouping:
Node

#### anchor_tag:
get_registrar_state

#### description


#### response_description


#### notes:
Requires pre-shared secret in the `Authorization:` header.

#### family:
-

#### method:
GET

#### path_template:
/v1/node/registrar/state

#### private:
True

_end_

## Get wallet payment address

#### grouping:
Administrative API

#### subgrouping:
Wallet

#### anchor_tag:
get_wallet_payment_a

#### description:


#### response_description:


#### notes:
-

#### family:
wallet_read

#### method:
GET

#### path_template:
/v1/wallet/payment_address

#### private:
True

_end_

## Get wallet owner address

#### grouping:
Administrative API

#### subgrouping:
Wallet

#### anchor_tag:
get_wallet_owner_add

#### description:


#### response_description:


#### notes:
-

#### family:
wallet_read

#### method:
GET

#### path_template:
/v1/wallet/owner_address

#### private:
True

_end_

## Get wallet data public key

#### grouping:
Administrative API

#### subgrouping:
Wallet

#### anchor_tag:
get_wallet_data_publ

#### description:


#### response_description:


#### notes:
-

#### family:
wallet_read

#### method:
GET

#### path_template:
/v1/wallet/data_pubkey

#### private:
True

_end_

## Set the wallet

#### grouping:
Administrative API

#### subgrouping:
Wallet

#### anchor_tag:
set__wallet

#### description:


#### response_description:


#### notes:
Requires a pre-shared secret in the `Authorization:` header

#### family:
-

#### method:
PUT

#### path_template:
/v1/wallet/keys

#### private:
True

_end_

## Get the wallet

#### grouping:
Administrative API

#### subgrouping:
Wallet

#### anchor_tag:
get__wallet

#### description:


#### response_description:


#### notes:
Requires a pre-shared secret in the `Authorization:` header

#### family:
-

#### method:
GET

#### path_template:
/v1/wallet/keys

#### private:
True

_end_

## Get the wallet balance

#### grouping:
Administrative API

#### subgrouping:
Wallet

#### anchor_tag:
get__wallet_balance

#### description:


#### response_description:


#### notes:
-

#### family:
wallet_read

#### method:
GET

#### path_template:
/v1/wallet/balance

#### private:
True

_end_

## Withdraw funds from the wallet

#### grouping:
Administrative API

#### subgrouping:
Wallet

#### anchor_tag:
withdraw_funds_from_

#### description:


#### response_description:


#### notes:
Payload: `{'address': str, 'amount': int, 'min_confs': int, 'tx_only':  bool}

#### family:
wallet_write

#### method:
POST

#### path_template:
/v1/wallet/balance

#### private:
True

_end_

## Change wallet password

#### grouping:
Administrative API

#### subgrouping:
Wallet

#### anchor_tag:
change_wallet_passwo

#### description:


#### response_description:


#### notes:
Payload: `{'password': ..., 'new_password': ...}`

#### family:
wallet_write

#### method:
PUT

#### path_template:
/v1/wallet/password

#### private:
True

_end_

## Create an authorization token

#### grouping:
Administrative API

#### subgrouping:
Authorization

#### anchor_tag:
create_an_authorizat

#### description:


#### response_description:


#### notes:
Requires a pre-shared secret in the `Authorization:` header. TODO: describe authRequestToken format.

#### family:
-

#### method:
GET

#### path_template:
/v1/auth?authRequest={authRequestToken}

#### private:
True

_end_

## Get all names

#### grouping:
Naming API

#### subgrouping:
Names

#### anchor_tag:
get_all_names

#### description:
Fetch a page from the list of all registered names.

#### response_description:
Array of registered names.

#### notes:
-

#### family:
names

#### method:
GET

#### parameters[]:
{"name": "page", "description": "the page number to fetch"}

#### path_template:
/v1/names?page={page}

#### tryit_pathname:
/v1/names?page=0

#### example_request_bash:
/v1/names?page=0

#### example_response:
[ "judecn.id", "3.id", "4.id", "8.id", 
  "e.id", "h.id", "5.id", "9.id", "i.id" ]

_end_

## Register name

#### grouping:
Naming API

#### subgrouping:
Names

#### anchor_tag:
register_name

#### description:


#### response_description:


#### notes:
Payload: {"name": NAME}

#### family:
register

#### method:
POST

#### path_template:
/v1/names

#### private:
True

_end_

## Get name info

#### grouping:
Naming API

#### subgrouping:
Names

#### anchor_tag:
get_name_info

#### description:
Get the latest blockchain registration record of a name.

#### response_description:
Returns the owner address, status, expiry block and other name info.

#### notes:
-

#### family:
names

#### method:
GET

#### path_template:
/v1/names/{name}

#### tryit_pathname:
/v1/names/muneeb.id

#### example_request_bash:
/v1/names/muneeb.id

#### example_response:
{
  "status": "registered", 
  "zonefile": "$ORIGIN muneeb.id\n$TTL 3600\n_http._tcp IN URI 10 1 \"https://blockstack.s3.amazonaws.com/muneeb.id\"\n", 
  "expire_block": 489247, 
  "blockchain": "bitcoin", 
  "last_txid": "1edfa419f7b83f33e00830bc9409210da6c6d1db60f99eda10c835aa339cad6b", 
  "address": "1QJQxDas5JhdiXhEbNS14iNjr8auFT96GP", 
  "zonefile_hash": "b100a68235244b012854a95f9114695679002af9"
}

_end_

## Get name history

#### grouping:
Naming API

#### subgrouping:
Names

#### anchor_tag:
get_name_history

#### description:
Get a history of all blockchain records of a registered name.

#### response_description:
Returns the owner address, status, expiry block and other name info.

#### notes:
-

#### family:
names

#### method:
GET

#### path_template:
/v1/names/{name}/history

#### tryit_pathname:
/v1/names/muneeb.id/history

#### example_request_bash:
/v1/names/muneeb.id/history

#### example_response:
{
  "379904": [
    {
      "block_number": 373821, 
      "namespace_id": "id", 
      "importer_address": "16firc3qZU97D1pWkyL6ZYwPX5UVnWc82V", 
      "value_hash": "bfb725b1f550347dbcc8ba998bbcb2992eeccd46", 
      "consensus_hash": null, 
      "txid": "4747b7b3e1222f1ed0c69b8de87e3d1764c547c04112ae56605646b45635151a", 
      "importer": "76a9143e2b5fdd12db7580fb4d3434b31d4fe9124bd9f088ac", 
      "name_hash128": "deb7fe99776122b77925cbf0a24ab6f8", 
      "transfer_send_block_id": null, 
      "preorder_hash": "e58b193cfe867020ed84cc74edde2487889f28fe", 
      "first_registered": 373821, 
      "last_creation_op": ";", 
      "namespace_block_number": 373601, 
      "address": "1QJQxDas5JhdiXhEbNS14iNjr8auFT96GP", 
      "op_fee": 100000.0, 
      "revoked": false, 
      "last_renewed": 373821, 
      "sender": "76a914ff95f5612a26a81e919e4b6e63fdd929fd115d6d88ac", 
      "name": "muneeb.id", 
      "preorder_block_number": 373821, 
      "opcode": "NAME_IMPORT", 
      "vtxindex": 308, 
      "op": ";",
      ...
    }
  ], 
  "402804": [
    {
    ...
    }
  ],
  ...
}

_end_

## Get zone file

#### grouping:
Naming API

#### subgrouping:
Names

#### anchor_tag:
get_historical_zone

#### description:
Fetches the historical zonefile specified by the username and zone hash.

#### response_description:
Zonefile object.

#### notes:
-

#### family:
zonefiles

#### method:
GET

#### path_template:
/v1/names/{name}/zonefile/{zoneFileHash}

#### tryit_pathname:
/v1/names/muneeb.id/zonefile/b100a68235244b012854a95f9114695679002af9

#### example_request_bash:
/v1/names/muneeb.id/zonefile/b100a68235244b012854a95f9114695679002af9

#### example_response:
{
  "zonefile": 
  "$ORIGIN muneeb.id\n$TTL 3600\n_http._tcp IN URI 10 1 \"https://blockstack.s3.amazonaws.com/muneeb.id\"\n"
}

_end_

## Revoke name

#### grouping:
Naming API

#### subgrouping:
Names

#### anchor_tag:
revoke_name

#### description:


#### response_description:


#### notes:
-

#### family:
revoke

#### method:
DELETE

#### path_template:
/v1/names/{name}

#### private:
True

_end_

## Transfer name

#### grouping:
Naming API

#### subgrouping:
Names

#### anchor_tag:
transfer_name

#### description:


#### response_description:


#### notes:
Payload: {"owner": OWNER }

#### family:
transfer

#### method:
PUT

#### path_template:
/v1/names/{name}/owner

#### private:
True

_end_

## Set zone file

#### grouping:
Naming API

#### subgrouping:
Names

#### anchor_tag:
set_zone_file

#### description:


#### response_description:


#### notes:
Payload: {"zonefile": ZONE_FILE }

#### family:
update

#### method:
PUT

#### path_template:
/v1/names/{name}/zonefile

#### private:
True

_end_

## Set zone file hash

#### grouping:
Naming API

#### subgrouping:
Names

#### anchor_tag:
set_zone_file_hash

#### description:


#### response_description:


#### notes:
Payload: {"zonefile_hash": ZONE_FILE_HASH }

#### family:
update

#### method:
PUT

#### path_template:
/v1/names/{name}/zonefile

#### private:
True

_end_

## Get names owned

#### grouping:
Naming API

#### subgrouping:
Addresses

#### anchor_tag:
get_names_owned_by_a

#### description:
Retrieves a list of names owned by the address provided.

#### response_description:
Returns an array of the names that the address owns.

#### notes:
-

#### family:
names

#### method:
GET

#### path_template:
/v1/addresses/{blockain}/{address}

#### tryit_pathname:
/v1/addresses/bitcoin/1Q3K7ymNVycu3TQoTDUaty8Q5fUVB3feEQ

#### example_request_bash:
/v1/addresses/bitcoin/1Q3K7ymNVycu3TQoTDUaty8Q5fUVB3feEQ

#### example_response:
{
  "names": [
    "ryanshea.id"
  ]
}

_end_

## Get all namespaces

#### grouping:
Naming API

#### subgrouping:
Namespaces

#### anchor_tag:
get_all_namespaces

#### description:
Retrieves a list of all namespaces on all blockchains.

#### response_description:
Returns an array of all namespaces.

#### notes:
-

#### family:
namespaces

#### method:
GET

#### path_template:
/v1/namespaces

#### tryit_pathname:
/v1/namespaces

#### example_request_bash:
/v1/namespaces

#### example_response:
[
  "id"
]

_end_

## Create namespace

#### grouping:
Naming API

#### subgrouping:
Namespaces

#### anchor_tag:
create_namespace

#### description:


#### response_description:


#### notes:
NOT IMPLEMENTED

#### family:
namespace_registration

#### method:
POST

#### path_template:
/v1/namespaces

#### private:
True

_end_

## Launch namespace

#### grouping:
Naming API

#### subgrouping:
Namespaces

#### anchor_tag:
launch_namespace

#### description:


#### response_description:


#### notes:
NOT IMPLEMENTED

#### family:
namespace_registration

#### method:
PUT

#### path_template:
/v1/namespaces/{tld}

#### private:
True

_end_

## Get namespace names

#### grouping:
Naming API

#### subgrouping:
Namespaces

#### anchor_tag:
get_namespace_names

#### description:
Fetch a page from the list of all names registered in a namespace.

#### response_description:
Array of registered names.

#### notes:
-

#### family:
namespaces

#### method:
GET

#### parameters[]:
{"name": "page", "description": "the page number to fetch"}

#### path_template:
/v1/namespaces/{tld}/names?page={page}

#### tryit_pathname:
/v1/namespaces/id/names?page=23

#### example_request_bash:
/v1/namespaces/id/names?page=23

#### example_response:

[ "aldenquimby.id", "aldeoryn.id", 
  "alderete.id", "aldert.id", 
  "aldi.id", "aldighieri.id", ... ]

_end_

## Pre-register a name

#### grouping:
Naming API

#### subgrouping:
Namespaces

#### anchor_tag:
pre-register_a_name

#### description:


#### response_description:


#### notes:
NOT IMPLEMENTED

#### family:
namespace_registration

#### method:
POST

#### path_template:
/v1/namespaces/{tld}/names

#### private:
True

_end_

## Update pre-registered name

#### grouping:
Naming API

#### subgrouping:
Namespaces

#### anchor_tag:
update_pre-registere

#### description:


#### response_description:


#### notes:
NOT IMPLEMENTED

#### family:
namespace_registration

#### method:
PUT

#### path_template:
/v1/namespaces/{tld}/names/{name}

#### private:
True

_end_

## Get namespace price

#### grouping:
Naming API

#### subgrouping:
Prices

#### anchor_tag:
get_namespace_price

#### description:
Get the registration price for a namespace.

#### response_description:
Returns price information for the namespace.

#### notes:
May return a warning if the wallet does not have enough funds

#### family:
prices

#### method:
GET

#### path_template:
/v1/prices/namespaces/{tld}

#### tryit_pathname:
/v1/prices/namespaces/id

#### example_request_bash:
/v1/prices/namespaces/id

#### example_response:
{
  "satoshis": 4000000000
}

_end_

## Get name price

#### grouping:
Naming API

#### subgrouping:
Prices

#### anchor_tag:
get_name_price

#### description:
Get the registration price of a name.

#### response_description:
Returns an array of name price info.

#### notes:
May return a warning if the wallet does not have enough funds

#### family:
prices

#### method:
GET

#### path_template:
/v1/prices/names/{name}

#### tryit_pathname:
/v1/prices/names/muneeb.id

#### example_request_bash:
/v1/prices/names/muneeb.id

#### example_response:
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

_end_

## Get block operations

#### grouping:
Naming API

#### subgrouping:
Blockchains

#### anchor_tag:
get_block_operations

#### description:


#### response_description:


#### notes:
- NOT IMPLEMENTED

#### family:
blockchain

#### method:
GET

#### path_template:
/v1/blockchains/{blockchainName}/block/{blockHeight}

#### tryit_pathname:
/v1/blockchains/bitcoin/block/462449

#### example_request_bash:
/v1/blockchains/bitcoin/block/462449

#### example_response:

#### private:
True

_end_

## Get raw name history

#### grouping:
Naming API

#### subgrouping:
Blockchains

#### anchor_tag:
get_raw_name_history

#### description:


#### response_description:


#### notes:
ERROR IN IMPLEMENTATION

#### family:
blockchain

#### method:
GET

#### path_template:
/v1/blockchains/{blockchainName}/names/{nameID}/history

#### tryit_pathname:
/v1/blockchains/bitcoin/names/ryanshea.id/history

#### path_template:
/v1/blockchains/{blockchainName}/names/{nameID}/history

#### private:
True

_end_

## Get consensus hash

#### grouping:
Naming API

#### subgrouping:
Blockchains

#### anchor_tag:
get_consensus_hash

#### description:
Get the current Blockstack consensus hash of a blockchain.

#### response_description:
Returns an array with the current consensus hash.

#### notes:
-

#### family:
blockchain

#### method:
GET

#### path_template:
/v1/blockchains/{blockchainName}/consensus

#### tryit_pathname:
/v1/blockchains/bitcoin/consensus

#### example_request_bash:
/v1/blockchains/bitcoin/consensus

#### example_response:
{
  "consensus_hash": "f435a51026f06d8e4af5223f2acd5546"
}

_end_

## Get pending transactions

#### grouping:
Naming API

#### subgrouping:
Blockchains

#### anchor_tag:
get_pending_transact

#### description:
Gets a list of transactions pending on this node for a specific blockchain.

#### response_description:
Array of pending transactions.

#### notes:
-

#### family:
blockchain

#### method:
GET

#### path_template:
/v1/blockchains/{blockchainName}/pending

#### example_request_bash:
/v1/blockchains/bitcoin/pending

#### tryit_pathname:
/v1/blockchains/bitcoin/pending

#### example_response:
{
  "queues": {}
}

_end_

## Get unspent outputs

#### grouping:
Naming API

#### subgrouping:
Blockchains

#### anchor_tag:
get_unspent_outputs

#### description:


#### response_description:


#### notes:
Returns `{"transaction_hash": str, "output_index": int, "value": int (satoshis), "script_hex": str, "confirmations": int}`

#### family:
blockchain

#### method:
GET

#### path_template:
/v1/blockchains/{blockchainName}/{address}/unspent

#### tryit_pathname:
/v1/blockchains/bitcoin/16EMaNw3pkn3v6f2BgnSSs53zAKH4Q8YJg/unspent

#### example_request_bash:
/v1/blockchains/bitcoin/16EMaNw3pkn3v6f2BgnSSs53zAKH4Q8YJg/unspent

#### example_response:
[
    {
        "confirmations": 8710,
        "output_index": 1,
        "script_hex": "76a914395f3643cea07ec4eec73b4d9a973dcce56b9bf188ac",
        "transaction_hash": "93824630a2afa2da6279322f42118bec14f300a6993b5787d550b783ec456953",
        "value": 16500
    }
]

#### private:
True

_end_

## Broadcast transaction

#### grouping:
Naming API

#### subgrouping:
Blockchains

#### anchor_tag:
broadcast_transactio

#### description:


#### response_description:


#### notes:
Takes `{"tx": str}` as its payload

#### family:
blockchain

#### method:
POST

#### path_template:
/v1/blockchains/{blockchainName}/txs

#### private:
True

_end_

## Create profile

#### grouping:
Identity API

#### subgrouping:
Profiles

#### anchor_tag:
create_profile

#### description:
Registers a new profile. Wallet on the node must own the name and POST requests 
should be enabled on the node.

#### response_description:
Returns an object with a status that is either "success" or "error".

#### notes:
Payload: `{"name": NAME, "profile": PROFILE}`.  Wallet must own the name.

#### family:
profile_write

#### method:
POST

#### path_template:
/v1/profiles

#### path_template:
/v1/profiles

#### example_request_bash:
/v1/profiles \
    -d '{"name": "fredwilson",
         "profile": {"bio": "I am a VC"}}' \
    -H 'Content-type: application/json' \
    -X POST

#### example_response:
{
    "status": "success"
}

#### private:
True

_end_

## Get profile

#### grouping:
Identity API

#### subgrouping:
Profiles

#### anchor_tag:
identity_get_deprecated

#### description:
Looks up the data for a profile. 
Note that this is a legacy endpoint and will be phased out in the future.

#### response_description:
Returns an object with profile data.

#### notes:
Legacy endpoint

#### family:
profile_read

#### method:
GET

#### path_template:
/v2/users/{username}

#### tryit_pathname:
/v2/users/fredwilson

#### example_request_bash:
/v2/users/fredwilson

#### example_response:
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

_end_

## Get profile

#### grouping:
Identity API

#### subgrouping:
Profiles

#### anchor_tag:
get_profile

#### description:


#### response_description:


#### notes:
- This doesn't appear to be implemented yet...

#### family:
profile_read

#### method:
GET

#### path_template:
/v1/profiles/{name}

#### private:
True

_end_

## Delete profile

#### grouping:
Identity API

#### subgrouping:
Profiles

#### anchor_tag:
delete_profile

#### description:


#### response_description:


#### notes:
Wallet must own {name}

#### family:
profile_write

#### method:
DELETE

#### path_template:
/v1/profiles/{name}

#### private:
True

_end_

## Update profile

#### grouping:
Identity API

#### subgrouping:
Profiles

#### anchor_tag:
update_profile

#### description: 
Update a profile. Wallet on the node must own the name and POST requests 
should be enabled on the node.

#### response_description:
Returns an object with a status that is either "success" or "error".

#### notes:
Payload: `{"blockchain_id": NAME, "profile": PROFILE }`.  Wallet must own the name

#### family:
profile_write

#### method:
PATCH

#### path_template:
/v1/profiles/{name}

#### example_request_bash:
/v1/profile/fredwilson \
    -d '{"profile": {"bio": "I am a VC"}, 
         "blockchain_id": "fredwilson"}' \
    -H 'Content-type: application/json' \
    -X PATCH

#### example_response:
{
    "status": "success"
}

#### private:
True

_end_

## Create store for this session

#### grouping:
Identity API

#### subgrouping:
Datastores

#### anchor_tag:
create_store_for_thi

#### description:


#### response_description:


#### notes:
Creates a datastore for the application indicated by the session

#### family:
store_write

#### method:
POST

#### path_template:
/v1/stores

#### private:
True

_end_

## Get store metadata

#### grouping:
Identity API

#### subgrouping:
Datastores

#### anchor_tag:
get_store_metadata

#### description:


#### response_description:


#### notes:
-

#### family:
store_admin

#### method:
GET

#### path_template:
/v1/stores/{storeID}

#### private:
True

_end_

## Delete store

#### grouping:
Identity API

#### subgrouping:
Datastores

#### anchor_tag:
delete_store

#### description:


#### response_description:


#### notes:
Deletes all files and directories in the store as well

#### family:
store_write

#### method:
DELETE

#### path_template:
/v1/stores/{storeID}

#### private:
True

_end_

## Get inode info (stat)

#### grouping:
Identity API

#### subgrouping:
Datastores

#### anchor_tag:
get_inode_info__stat

#### description:


#### response_description:


#### notes:
-

#### family:
store_read

#### method:
GET

#### path_template:
/v1/stores/{storeID}/inodes?path={path}

#### private:
True

_end_

## Get directory files (ls)

#### grouping:
Identity API

#### subgrouping:
Datastores

#### anchor_tag:
get_directory_files_

#### description:


#### response_description:


#### notes:
Returns structured inode data

#### family:
store_read

#### method:
GET

#### path_template:
/v1/stores/{storeID}/directories?path={path}

#### private:
True

_end_

## Create directory (mkdir)

#### grouping:
Identity API

#### subgrouping:
Datastores

#### anchor_tag:
create_directory__mk

#### description:


#### response_description:


#### notes:
Only works on the datastore for the application indicated by the session

#### family:
store_write

#### method:
POST

#### path_template:
/v1/stores/{storeID}/directories?path={path}

#### private:
True

_end_

## Delete directory (rmdir)

#### grouping:
Identity API

#### subgrouping:
Datastores

#### anchor_tag:
delete_directory__rm

#### description:


#### response_description:


#### notes:
Only works on the datastore for the application indicated by the session

#### family:
store_write

#### method:
DELETE

#### path_template:
/v1/stores/{storeID}/directories?path={path}

#### private:
True

_end_

## Get file data (cat)

#### grouping:
Identity API

#### subgrouping:
Datastores

#### anchor_tag:
get_file_data__cat_

#### description:


#### response_description:


#### notes:
Returns `application/octet-stream` data

#### family:
store_read

#### method:
GET

#### path_template:
/v1/stores/{storeID}/files?path={path}

#### private:
True

_end_

## Create file

#### grouping:
Identity API

#### subgrouping:
Datastores

#### anchor_tag:
create_file

#### description:


#### response_description:


#### notes:
Uploads `application/octet-stream` raw file data.  Only works on the datastore for the application indicated by the session.

#### family:
store_write

#### method:
POST

#### path_template:
/v1/stores/{storeID}/files?path={path}

#### private:
True

_end_

## Update file

#### grouping:
Identity API

#### subgrouping:
Datastores

#### anchor_tag:
update_file

#### description:


#### response_description:


#### notes:
Uploads `application/octet-stream` raw file data.  Only works on the datastore for the application indicated by the session.

#### family:
store_write

#### method:
PUT

#### path_template:
/v1/stores/{storeID}/files?path={path}

#### private:
True

_end_

## Delete file (rm)

#### grouping:
Identity API

#### subgrouping:
Datastores

#### anchor_tag:
delete_file__rm_

#### description:


#### response_description:


#### notes:
Only works on the datastore for the application indicated by the session

#### family:
store_write

#### method:
DELETE

#### path_template:
/v1/stores/{storeID}/files?path={path}

#### private:
True

_end_

## Create collection

#### grouping:
Identity API

#### subgrouping:
Collections

#### anchor_tag:
create_collection

#### description:


#### response_description:


#### notes:
NOT IMPLEMENTED

#### family:
collection_admin

#### method:
POST

#### path_template:
/v1/collections

#### private:
True

_end_

## Get all collection items

#### grouping:
Identity API

#### subgrouping:
Collections

#### anchor_tag:
get_all_collection_i

#### description:


#### response_description:


#### notes:
NOT IMPLEMENTED

#### family:
collection_read

#### method:
GET

#### path_template:
/v1/collections/{collectionID}

#### private:
True

_end_

## Create collection item

#### grouping:
Identity API

#### subgrouping:
Collections

#### anchor_tag:
create_collection_it

#### description:


#### response_description:


#### notes:
NOT IMPLEMENTED

#### family:
collection_write

#### method:
POST

#### path_template:
/v1/collections/{collectionID}

#### private:
True

_end_

## Get collection item

#### grouping:
Identity API

#### subgrouping:
Collections

#### anchor_tag:
get_collection_item

#### description:


#### response_description:


#### notes:
NOT IMPLEMENTED

#### family:
collection_read

#### method:
GET

#### path_template:
/v1/{collectionID}/{itemID}

#### private:
True

_end_

## Search users

#### grouping:
Identity API

#### subgrouping:
Profiles

#### anchor_tag:
search_users

#### description:
Takes in a search query and returns a list of results that match the search. 
The query is matched against usernames, full names, and twitter handles.

#### response_description:
Returns an array of results, where each result has a \"profile\" object.

#### method:
GET

#### notes:

#### family:
-

#### path_template:
/v1/search

#### parameters[]:
{"name": "query", "description": "The text to search for."}

#### tryit_pathname:
/v1/search?query=wenger

#### example_request_bash:
/v1/search?query=wenger

#### example_response:
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

_end_
