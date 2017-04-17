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

#### description


#### response_description


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

_end_

## Get wallet payment address

#### grouping:
Administrative API

#### subgrouping:
Wallet

#### anchor_tag:
get_wallet_payment_a

#### description


#### response_description


#### notes:
-

#### family:
wallet_read

#### method:
GET

#### path_template:
/v1/wallet/payment_address

_end_

## Get wallet owner address

#### grouping:
Administrative API

#### subgrouping:
Wallet

#### anchor_tag:
get_wallet_owner_add

#### description


#### response_description


#### notes:
-

#### family:
wallet_read

#### method:
GET

#### path_template:
/v1/wallet/owner_address

_end_

## Get wallet data public key

#### grouping:
Administrative API

#### subgrouping:
Wallet

#### anchor_tag:
get_wallet_data_publ

#### description


#### response_description


#### notes:
-

#### family:
wallet_read

#### method:
GET

#### path_template:
/v1/wallet/data_pubkey

_end_

## Set the wallet

#### grouping:
Administrative API

#### subgrouping:
Wallet

#### anchor_tag:
set__wallet

#### description


#### response_description


#### notes:
Requires a pre-shared secret in the `Authorization:` header

#### family:
-

#### method:
PUT

#### path_template:
/v1/wallet/keys

_end_

## Get the wallet

#### grouping:
Administrative API

#### subgrouping:
Wallet

#### anchor_tag:
get__wallet

#### description


#### response_description


#### notes:
Requires a pre-shared secret in the `Authorization:` header

#### family:
-

#### method:
GET

#### path_template:
/v1/wallet/keys

_end_

## Get the wallet balance

#### grouping:
Administrative API

#### subgrouping:
Wallet

#### anchor_tag:
get__wallet_balance

#### description


#### response_description


#### notes:
-

#### family:
wallet_read

#### method:
GET

#### path_template:
/v1/wallet/balance

_end_

## Withdraw funds from the wallet

#### grouping:
Administrative API

#### subgrouping:
Wallet

#### anchor_tag:
withdraw_funds_from_

#### description


#### response_description


#### notes:
Payload: `{'address': str, 'amount': int, 'min_confs': int, 'tx_only':  bool}

#### family:
wallet_write

#### method:
POST

#### path_template:
/v1/wallet/balance

_end_

## Change wallet password

#### grouping:
Administrative API

#### subgrouping:
Wallet

#### anchor_tag:
change_wallet_passwo

#### description


#### response_description


#### notes:
Payload: `{'password': ..., 'new_password': ...}`

#### family:
wallet_write

#### method:
PUT

#### path_template:
/v1/wallet/password

_end_

## Create an authorization token

#### grouping:
Administrative API

#### subgrouping:
Authorization

#### anchor_tag:
create_an_authorizat

#### description


#### response_description


#### notes:
Requires a pre-shared secret in the `Authorization:` header.

#### family:
-

#### method:
GET

#### path_template:
/v1/auth?authRequest={authRequestToken}

_end_

## Get all names

#### grouping:
Naming API

#### subgrouping:
Names

#### anchor_tag:
get_all_names

#### description


#### response_description


#### notes:
-

#### family:
names

#### method:
GET

#### path_template:
/v1/names

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

#### description


#### response_description


#### notes:
Payload: {"name": NAME}

#### family:
register

#### method:
POST

#### path_template:
/v1/names

_end_

## Get name info

#### grouping:
Naming API

#### subgrouping:
Names

#### anchor_tag:
get_name_info

#### description


#### response_description


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

#### description


#### response_description


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
      "sender_pubkey": "0411d88aa37a0eea476a5b63ca4b1cd392ded830865824c27dacef6bde9f9bc53fa13a0926533ef4d20397207e212c2086cbe13db5470fd29616abd35326d33090", 
      "preorder_block_number": 373821, 
      "opcode": "NAME_IMPORT", 
      "vtxindex": 308, 
      "op": ";"
    }
  ], 
  "402804": [
    {
      "block_number": 373821, 
      "namespace_id": "id", 
      "importer_address": "16firc3qZU97D1pWkyL6ZYwPX5UVnWc82V", 
      "value_hash": "3085137b19ce56092f5cb91b7f78d073c815dbc1", 
      "consensus_hash": "63c434864743c944782553996d6819a0", 
      "txid": "904c5f187ab143d187e26afaddaa6061059451407193fbfc4c4a9b0baa24dbd7", 
      "importer": "76a9143e2b5fdd12db7580fb4d3434b31d4fe9124bd9f088ac", 
      "name_hash128": "deb7fe99776122b77925cbf0a24ab6f8", 
      "transfer_send_block_id": null, 
      "preorder_hash": "e58b193cfe867020ed84cc74edde2487889f28fe", 
      "first_registered": 373821, 
      "last_creation_op": ";", 
      "namespace_block_number": 373601, 
      "address": "1QJQxDas5JhdiXhEbNS14iNjr8auFT96GP", 
      "op_fee": 100000, 
      "revoked": false, 
      "last_renewed": 373821, 
      "sender": "76a914ff95f5612a26a81e919e4b6e63fdd929fd115d6d88ac", 
      "name": "muneeb.id", 
      "sender_pubkey": "0411d88aa37a0eea476a5b63ca4b1cd392ded830865824c27dacef6bde9f9bc53fa13a0926533ef4d20397207e212c2086cbe13db5470fd29616abd35326d33090", 
      "preorder_block_number": 373821, 
      "opcode": "NAME_UPDATE", 
      "vtxindex": 948, 
      "op": "+"
    }
  ], 
  "424744": [
    {
      "block_number": 373821, 
      "namespace_id": "id", 
      "importer_address": "16firc3qZU97D1pWkyL6ZYwPX5UVnWc82V", 
      "value_hash": "97710672cd3cb335d4f7cf0493efb48cb5275c45", 
      "consensus_hash": "93ff7f9ced2b9c0061552f7e14396dde", 
      "txid": "8a68d52d70cf06d819eb72a9a58f4dceda942db792ceb35dd333f43f55fa8713", 
      "importer": "76a9143e2b5fdd12db7580fb4d3434b31d4fe9124bd9f088ac", 
      "name_hash128": "deb7fe99776122b77925cbf0a24ab6f8", 
      "transfer_send_block_id": null, 
      "preorder_hash": "e58b193cfe867020ed84cc74edde2487889f28fe", 
      "first_registered": 373821, 
      "last_creation_op": ";", 
      "namespace_block_number": 373601, 
      "address": "1QJQxDas5JhdiXhEbNS14iNjr8auFT96GP", 
      "op_fee": 100000, 
      "revoked": false, 
      "last_renewed": 373821, 
      "sender": "76a914ff95f5612a26a81e919e4b6e63fdd929fd115d6d88ac", 
      "name": "muneeb.id", 
      "sender_pubkey": "0411d88aa37a0eea476a5b63ca4b1cd392ded830865824c27dacef6bde9f9bc53fa13a0926533ef4d20397207e212c2086cbe13db5470fd29616abd35326d33090", 
      "preorder_block_number": 373821, 
      "opcode": "NAME_UPDATE", 
      "vtxindex": 2240, 
      "op": "+"
    }
  ], 
  "381287": [
    {
      "block_number": 373821, 
      "namespace_id": "id", 
      "importer_address": "16firc3qZU97D1pWkyL6ZYwPX5UVnWc82V", 
      "value_hash": "15b4b06e55ba469c2bcac929635a4e56679c6cc6", 
      "consensus_hash": null, 
      "txid": "a6a954b9ad0af2d08ffa64d8691e93a2c4e860d7daa630872acff76d13c517f7", 
      "importer": "76a9143e2b5fdd12db7580fb4d3434b31d4fe9124bd9f088ac", 
      "name_hash128": "deb7fe99776122b77925cbf0a24ab6f8", 
      "transfer_send_block_id": null, 
      "preorder_hash": "e58b193cfe867020ed84cc74edde2487889f28fe", 
      "first_registered": 373821, 
      "last_creation_op": ";", 
      "namespace_block_number": 373601, 
      "address": "1QJQxDas5JhdiXhEbNS14iNjr8auFT96GP", 
      "op_fee": 100000, 
      "revoked": false, 
      "last_renewed": 373821, 
      "sender": "76a914ff95f5612a26a81e919e4b6e63fdd929fd115d6d88ac", 
      "name": "muneeb.id", 
      "sender_pubkey": "0411d88aa37a0eea476a5b63ca4b1cd392ded830865824c27dacef6bde9f9bc53fa13a0926533ef4d20397207e212c2086cbe13db5470fd29616abd35326d33090", 
      "preorder_block_number": 373821, 
      "opcode": "NAME_IMPORT", 
      "vtxindex": 1362, 
      "op": ";"
    }
  ], 
  "373821": [
    {
      "block_number": 373821, 
      "namespace_id": "id", 
      "importer_address": "16firc3qZU97D1pWkyL6ZYwPX5UVnWc82V", 
      "value_hash": "f15528d0831d2beffed5d609d469cf4064bd0b51", 
      "consensus_hash": null, 
      "txid": "f75f58329714fd0455e1283e40cf27b07b933b75f06286874c8328ccedde21f7", 
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
      "sender_pubkey": "0411d88aa37a0eea476a5b63ca4b1cd392ded830865824c27dacef6bde9f9bc53fa13a0926533ef4d20397207e212c2086cbe13db5470fd29616abd35326d33090", 
      "preorder_block_number": 373821, 
      "opcode": "NAME_IMPORT", 
      "vtxindex": 232, 
      "op": ";"
    }
  ], 
  "456383": [
    {
      "block_number": 373821, 
      "namespace_id": "id", 
      "importer_address": "16firc3qZU97D1pWkyL6ZYwPX5UVnWc82V", 
      "value_hash": "b100a68235244b012854a95f9114695679002af9", 
      "consensus_hash": "36dc9bd59e9ee00370349d0af898144c", 
      "txid": "1edfa419f7b83f33e00830bc9409210da6c6d1db60f99eda10c835aa339cad6b", 
      "importer": "76a9143e2b5fdd12db7580fb4d3434b31d4fe9124bd9f088ac", 
      "name_hash128": "deb7fe99776122b77925cbf0a24ab6f8", 
      "transfer_send_block_id": null, 
      "preorder_hash": "e58b193cfe867020ed84cc74edde2487889f28fe", 
      "first_registered": 373821, 
      "last_creation_op": ";", 
      "namespace_block_number": 373601, 
      "address": "1QJQxDas5JhdiXhEbNS14iNjr8auFT96GP", 
      "op_fee": 100000, 
      "revoked": false, 
      "last_renewed": 373821, 
      "sender": "76a914ff95f5612a26a81e919e4b6e63fdd929fd115d6d88ac", 
      "name": "muneeb.id", 
      "sender_pubkey": "0411d88aa37a0eea476a5b63ca4b1cd392ded830865824c27dacef6bde9f9bc53fa13a0926533ef4d20397207e212c2086cbe13db5470fd29616abd35326d33090", 
      "preorder_block_number": 373821, 
      "opcode": "NAME_UPDATE", 
      "vtxindex": 53, 
      "op": "+"
    }
  ]
}

_end_

## Get historical zone file

#### grouping:
Naming API

#### subgrouping:
Names

#### anchor_tag:
get_historical_zone_

#### description


#### response_description


#### notes:
-

#### family:
zonefiles

#### method:
GET

#### path_template:
/names/{name}/zonefile/{zoneFileHash}

_end_

## Revoke name

#### grouping:
Naming API

#### subgrouping:
Names

#### anchor_tag:
revoke_name

#### description


#### response_description


#### notes:
-

#### family:
revoke

#### method:
DELETE

#### path_template:
/v1/names/{name}

_end_

## Transfer name

#### grouping:
Naming API

#### subgrouping:
Names

#### anchor_tag:
transfer_name

#### description


#### response_description


#### notes:
Payload: {"owner": OWNER }

#### family:
transfer

#### method:
PUT

#### path_template:
/v1/names/{name}/owner

_end_

## Set zone file

#### grouping:
Naming API

#### subgrouping:
Names

#### anchor_tag:
set_zone_file

#### description


#### response_description


#### notes:
Payload: {"zonefile": ZONE_FILE }

#### family:
update

#### method:
PUT

#### path_template:
/v1/names/{name}/zonefile

_end_

## Set zone file hash

#### grouping:
Naming API

#### subgrouping:
Names

#### anchor_tag:
set_zone_file_hash

#### description


#### response_description


#### notes:
Payload: {"zonefile_hash": ZONE_FILE_HASH }

#### family:
update

#### method:
PUT

#### path_template:
/v1/names/{name}/zonefile

_end_

## Get names owned by address

#### grouping:
Naming API

#### subgrouping:
Addresses

#### anchor_tag:
get_names_owned_by_a

#### description


#### response_description


#### notes:
-

#### family:
names

#### method:
GET

#### path_template:
/v1/addresses/{address}

_end_

## Get all namespaces

#### grouping:
Naming API

#### subgrouping:
Namespaces

#### anchor_tag:
get_all_namespaces

#### description


#### response_description


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

#### description


#### response_description


#### notes:
NOT IMPLEMENTED

#### family:
namespace_registration

#### method:
POST

#### path_template:
/v1/namespaces

_end_

## Launch namespace

#### grouping:
Naming API

#### subgrouping:
Namespaces

#### anchor_tag:
launch_namespace

#### description


#### response_description


#### notes:
NOT IMPLEMENTED

#### family:
namespace_registration

#### method:
PUT

#### path_template:
/v1/namespaces/{tld}

_end_

## Get namespace names

#### grouping:
Naming API

#### subgrouping:
Namespaces

#### anchor_tag:
get_namespace_names

#### description


#### response_description


#### notes:
-

#### family:
namespaces

#### method:
GET

#### path_template:
/v1/namespaces/{tld}/names

_end_

## Pre-register a name

#### grouping:
Naming API

#### subgrouping:
Namespaces

#### anchor_tag:
pre-register_a_name

#### description


#### response_description


#### notes:
NOT IMPLEMENTED

#### family:
namespace_registration

#### method:
POST

#### path_template:
/v1/namespaces/{tld}/names

_end_

## Update pre-registered name

#### grouping:
Naming API

#### subgrouping:
Namespaces

#### anchor_tag:
update_pre-registere

#### description


#### response_description


#### notes:
NOT IMPLEMENTED

#### family:
namespace_registration

#### method:
PUT

#### path_template:
/v1/namespaces/{tld}/names/{name}

_end_

## Get namespace price

#### grouping:
Naming API

#### subgrouping:
Prices

#### anchor_tag:
get_namespace_price

#### description


#### response_description


#### notes:
May return a warning if the wallet does not have enough funds

#### family:
prices

#### method:
GET

#### path_template:
/v1/prices/namespaces/{tld}

_end_

## Get name price

#### grouping:
Naming API

#### subgrouping:
Prices

#### anchor_tag:
get_name_price

#### description


#### response_description


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

#### description


#### response_description


#### notes:
-

#### family:
blockchain

#### method:
GET

#### path_template:
/v1/blockchains/{blockchainName}/block/{blockHeight}

_end_

## Get raw name history

#### grouping:
Naming API

#### subgrouping:
Blockchains

#### anchor_tag:
get_raw_name_history

#### description


#### response_description


#### notes:
-

#### family:
blockchain

#### method:
GET

#### path_template:
/v1/blockchains/{blockchainName}/names/{nameID}/history

_end_

## Get consensus hash

#### grouping:
Naming API

#### subgrouping:
Blockchains

#### anchor_tag:
get_consensus_hash

#### description


#### response_description


#### notes:
-

#### family:
blockchain

#### method:
GET

#### path_template:
/v1/blockchains/{blockchainName}/consensusHash

_end_

## Get pending transactions

#### grouping:
Naming API

#### subgrouping:
Blockchains

#### anchor_tag:
get_pending_transact

#### description


#### response_description


#### notes:
-

#### family:
blockchain

#### method:
GET

#### path_template:
/v1/blockchains/{blockchainName}/pending

_end_

## Get unspent outputs

#### grouping:
Naming API

#### subgrouping:
Blockchains

#### anchor_tag:
get_unspent_outputs

#### description


#### response_description


#### notes:
Returns `{"transaction_hash": str, "output_index": int, "value": int (satoshis), "script_hex": str, "confirmations": int}`

#### family:
blockchain

#### method:
GET

#### path_template:
/v1/blockchains/{blockchainName}/{address}/unspent

_end_

## Broadcast transaction

#### grouping:
Naming API

#### subgrouping:
Blockchains

#### anchor_tag:
broadcast_transactio

#### description


#### response_description


#### notes:
Takes `{"tx": str}` as its payload

#### family:
blockchain

#### method:
POST

#### path_template:
/v1/blockchains/{blockchainName}/txs

_end_

## Create profile

#### grouping:
Identity API

#### subgrouping:
Profiles

#### anchor_tag:
create_profile

#### description


#### response_description


#### notes:
Payload: `{"name": NAME, "profile": PROFILE}`.  Wallet must own the name.

#### family:
profile_write

#### method:
POST

#### path_template:
/v1/profiles

_end_

## Get profile

#### grouping:
Identity API

#### subgrouping:
Profiles

#### anchor_tag:
get_profile

#### description


#### response_description


#### notes:
-

#### family:
profile_read

#### method:
GET

#### path_template:
/v1/profiles/{name}

_end_

## Delete profile

#### grouping:
Identity API

#### subgrouping:
Profiles

#### anchor_tag:
delete_profile

#### description


#### response_description


#### notes:
Wallet must own {name}

#### family:
profile_write

#### method:
DELETE

#### path_template:
/v1/profiles/{name}

_end_

## Update profile

#### grouping:
Identity API

#### subgrouping:
Profiles

#### anchor_tag:
update_profile

#### description


#### response_description


#### notes:
Payload: `{"blockchain_id": NAME, "profile": PROFILE }`.  Wallet must own the name

#### family:
profile_write

#### method:
PATCH

#### path_template:
/v1/profiles/{name}

_end_

## Create store for this session

#### grouping:
Identity API

#### subgrouping:
Datastores

#### anchor_tag:
create_store_for_thi

#### description


#### response_description


#### notes:
Creates a datastore for the application indicated by the session

#### family:
store_write

#### method:
POST

#### path_template:
/v1/stores

_end_

## Get store metadata

#### grouping:
Identity API

#### subgrouping:
Datastores

#### anchor_tag:
get_store_metadata

#### description


#### response_description


#### notes:
-

#### family:
store_admin

#### method:
GET

#### path_template:
/v1/stores/{storeID}

_end_

## Delete store

#### grouping:
Identity API

#### subgrouping:
Datastores

#### anchor_tag:
delete_store

#### description


#### response_description


#### notes:
Deletes all files and directories in the store as well

#### family:
store_write

#### method:
DELETE

#### path_template:
/v1/stores/{storeID}

_end_

## Get inode info (stat)

#### grouping:
Identity API

#### subgrouping:
Datastores

#### anchor_tag:
get_inode_info__stat

#### description


#### response_description


#### notes:
-

#### family:
store_read

#### method:
GET

#### path_template:
/v1/stores/{storeID}/inodes?path={path}

_end_

## Get directory files (ls)

#### grouping:
Identity API

#### subgrouping:
Datastores

#### anchor_tag:
get_directory_files_

#### description


#### response_description


#### notes:
Returns structured inode data

#### family:
store_read

#### method:
GET

#### path_template:
/v1/stores/{storeID}/directories?path={path}

_end_

## Create directory (mkdir)

#### grouping:
Identity API

#### subgrouping:
Datastores

#### anchor_tag:
create_directory__mk

#### description


#### response_description


#### notes:
Only works on the datastore for the application indicated by the session

#### family:
store_write

#### method:
POST

#### path_template:
/v1/stores/{storeID}/directories?path={path}

_end_

## Delete directory (rmdir)

#### grouping:
Identity API

#### subgrouping:
Datastores

#### anchor_tag:
delete_directory__rm

#### description


#### response_description


#### notes:
Only works on the datastore for the application indicated by the session

#### family:
store_write

#### method:
DELETE

#### path_template:
/v1/stores/{storeID}/directories?path={path}

_end_

## Get file data (cat)

#### grouping:
Identity API

#### subgrouping:
Datastores

#### anchor_tag:
get_file_data__cat_

#### description


#### response_description


#### notes:
Returns `application/octet-stream` data

#### family:
store_read

#### method:
GET

#### path_template:
/v1/stores/{storeID}/files?path={path}

_end_

## Create file

#### grouping:
Identity API

#### subgrouping:
Datastores

#### anchor_tag:
create_file

#### description


#### response_description


#### notes:
Uploads `application/octet-stream` raw file data.  Only works on the datastore for the application indicated by the session.

#### family:
store_write

#### method:
POST

#### path_template:
/v1/stores/{storeID}/files?path={path}

_end_

## Update file

#### grouping:
Identity API

#### subgrouping:
Datastores

#### anchor_tag:
update_file

#### description


#### response_description


#### notes:
Uploads `application/octet-stream` raw file data.  Only works on the datastore for the application indicated by the session.

#### family:
store_write

#### method:
PUT

#### path_template:
/v1/stores/{storeID}/files?path={path}

_end_

## Delete file (rm)

#### grouping:
Identity API

#### subgrouping:
Datastores

#### anchor_tag:
delete_file__rm_

#### description


#### response_description


#### notes:
Only works on the datastore for the application indicated by the session

#### family:
store_write

#### method:
DELETE

#### path_template:
/v1/stores/{storeID}/files?path={path}

_end_

## Create collection

#### grouping:
Identity API

#### subgrouping:
Collections

#### anchor_tag:
create_collection

#### description


#### response_description


#### notes:
NOT IMPLEMENTED

#### family:
collection_admin

#### method:
POST

#### path_template:
/v1/collections

_end_

## Get all collection items

#### grouping:
Identity API

#### subgrouping:
Collections

#### anchor_tag:
get_all_collection_i

#### description


#### response_description


#### notes:
NOT IMPLEMENTED

#### family:
collection_read

#### method:
GET

#### path_template:
/v1/collections/{collectionID}

_end_

## Create collection item

#### grouping:
Identity API

#### subgrouping:
Collections

#### anchor_tag:
create_collection_it

#### description


#### response_description


#### notes:
NOT IMPLEMENTED

#### family:
collection_write

#### method:
POST

#### path_template:
/v1/collections/{collectionID}

_end_

## Get collection item

#### grouping:
Identity API

#### subgrouping:
Collections

#### anchor_tag:
get_collection_item

#### description


#### response_description


#### notes:
NOT IMPLEMENTED

#### family:
collection_read

#### method:
GET

#### path_template:
/v1/{collectionID}/{itemID}

_end_

