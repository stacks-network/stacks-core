# API Documentation

## Ping the node

#### anchor_tag:
node_ping

#### description:
Ping the node to check if the node is alive.

#### response_description:
Returns the status of the node.

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
  "status": "alive"
}

_end_

## Get name info

#### anchor_tag:
naming_name_info

#### description:
Get the latest blockchain registration record of a name.

#### response_description:
Returns the owner address, status, expiry block and other name info.

#### method:
GET

#### path_template:
/v1/names/<name>

#### tryit_pathname:
/v1/names/muneeb.id

#### example_request_bash:
/v1/names/muneeb.id

#### example_response:
{
  "address": "1QJQxDas5JhdiXhEbNS14iNjr8auFT96GP", 
  "blockchain": "bitcoin", 
  "expire_block": 489247, 
  "last_txid": "1edfa419f7b83f33e00830bc9409210da6c6d1db60f99eda10c835aa339cad6b", 
  "status": "registered", 
  "zonefile": "$ORIGIN muneeb.id\n$TTL 3600\n_http._tcp IN URI 10 1 \"https://blockstack.s3.amazonaws.com/muneeb.id\"\n", 
  "zonefile_hash": "b100a68235244b012854a95f9114695679002af9"
}

_end_

## Get name history

#### anchor_tag:
naming_name_history

#### description:
Get a history of all blockchain records of a registered name.

#### response_description:
Returns the owner address, status, expiry block and other name info.

#### method:
GET

#### path_template:
/v1/names/<name>/history

#### tryit_pathname:
/v1/names/muneeb.id/history

#### example_request_bash:
/v1/names/muneeb.id/history

#### example_response:
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
      ...

_end_


## Get names owned

#### anchor_tag:
names_owned

#### description:
Retrieves a list of names owned by the address provided.

#### response_description:
Returns an array of the names that the address owns.

#### method:
GET

#### path_template:
/v1/addresses/{blockchain}/{address}

#### tryit_pathname:
/v1/addresses/bitcoin/1QJQxDas5JhdiXhEbNS14iNjr8auFT96GP

#### example_request_bash:
/v1/addresses/bitcoin/1QJQxDas5JhdiXhEbNS14iNjr8auFT96GP

#### example_response:
{
  "names": [
    "muneeb.id"
  ]
}

_end_

## Get all namespaces

#### anchor_tag:
namespaces_all

#### description:
Retrieves a list of all namespaces on all blockchains.

#### response_description:
Returns an array of all namespaces.

#### method:
GET

#### path_template:
/v1/namespaces

#### tryit_pathname:
/v1/namespaces

#### example_request_bash:
/v1/namespaces

#### example_response:
{
  "namespaces": [
    ".id"
  ] 
}

_end_

## Get name price

#### anchor_tag:
price_name

#### description:
Get the registration price of a name.

#### response_description:
Returns an array of name price info.

#### method:
GET

#### path_template:
/v1/prices/names/<name>


#### tryit_pathname:
/v1/prices/names/muneeb.id

#### example_request_bash:
/v1/prices/names/muneeb.id

#### example_response:
{
  "name_price": {
    "btc": 0.001, 
    "satoshis": 100000
  }, 
  "preorder_tx_fee": {
    "btc": 0.00198075, 
    "satoshis": 198075
  }, 
  "register_tx_fee": {
    "btc": 0.00208185, 
    "satoshis": 208185
  }, 
  "total_estimated_cost": {
    "btc": 0.00749965, 
    "satoshis": 749965
  }, 
  "total_tx_fees": 649965, 
  "update_tx_fee": {
    "btc": 0.00243705, 
    "satoshis": 243705
  }, 
 }

_end_

## Get consensus hash

#### anchor_tag:
blockchains_consensus

#### description:
Get the current Blockstack consensus hash of a blockchain.

#### response_description:
Returns an array with the current consensus hash.

#### method:
GET

#### path_template:
/v1/blockchains/<blockchain>/consensus


#### tryit_pathname:
/v1/blockchains/bitcoin/consensus

#### example_request_bash:
/v1/blockchains/bitcoin/consensus

#### example_response:
{
  "consensus_hash": "5bf073b56fec90072a074884392373d4"
}

_end_

## Get profile

#### anchor_tag:
identity_get

#### description:
Looks up the data for a profile. 

#### response_description:
Returns an object with profile data.

#### method:
GET

#### path_template:
/v1/users/{username}

#### tryit_pathname:
/v1/users/fredwilson

#### example_request_bash:
/v1/users/fredwilson 

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

## Create profile

#### anchor_tag:
identity_create

#### description: 
Registers a new profile. Wallet on the node must own the name and POST requests 
should be enabled on the node.

#### parameters[]:

#### response_description:
Returns an object with a status that is either "success" or "error".

#### method:
POST

#### path_template:
/v1/users/<username>

#### example_request_bash:
/v1/users \
    -d '{"name": "fredwilson",
         "profile": {"bio": "I am a VC"}}' \
    -H 'Content-type: application/json' \
    -X POST

#### example_response:
{
    "status": "success"
}

_end_

## Update profile

#### anchor_tag:
identity_update

#### description: 
Update a profile. Wallet on the node must own the name and POST requests 
should be enabled on the node.

#### parameters[]:

#### response_description:
Returns an object with a status that is either "success" or "error".

#### method:
POST

#### path_template:
/v1/users/{username}/update

#### example_request_bash:
/v1/users/fredwilson/update \
    -d '{"profile": {"bio": "I am a VC"}, 
         "blockchain_id": "fredwilson"}' \
    -H 'Content-type: application/json' \
    -X POST

#### example_response:
{
    "status": "success"
}

_end_


## Search users

#### anchor_tag:
search_users

#### description:
Takes in a search query and returns a list of results that match the search. 
The query is matched against +usernames, full names, and twitter handles by default.

It's also possible to explicitly search verified Twitter, Facebook, Github 
accounts, and verified domains. This can be done by using search queries like 
twitter:albertwenger, facebook:g3lepage, github:shea256, domain:muneebali.com


#### response_description:
Returns an array of results, where each result has a \"profile\" object.

#### method:
GET

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

