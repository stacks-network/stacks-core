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
/v1/names/muneeb.id

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
/v1/names/muneeb.id/history

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

## Lookup users

#### anchor_tag:
lookup_users

#### description:
Looks up the data for one or more users by their usernames. In order to perform more than one lookup at once, include a set of comma-separated usernames in the URL in place of the single username.

#### response_description:
Returns an object with a top-level key for each username looked up. Each top-level key contains an sub-object that has a "profile" field and a "verifications" field.

#### method:
GET

#### path_template:
/users/{usernames}

#### tryit_pathname:
/v1/users/fredwilson?app-id=demo-app-id&app-secret=demo-app-secret

#### example_request_bash:
curl https://api.onename.com/v1/users/fredwilson \
    -u 'YOUR-API-ID:YOUR-API-SECRET'

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
    },
    "verifications": [
      {
        "identifier": "fredwilson",
        "proof_url": "https://twitter.com/fredwilson/status/533040726146162689",
        "service": "twitter",
        "valid": true
      },
      {
        "identifier": "fred.wilson.963871",
        "proof_url": "https://facebook.com/fred.wilson.963871/posts/10100401430876108",
        "service": "facebook",
        "valid": true
      }
    ]
  }
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
/search

#### parameters[]:
{"name": "query", "description": "The text to search for."}

#### tryit_pathname:
/v1/search?query=wenger&app-id=demo-1234&app-secret=demo-1234

#### example_request_bash:
curl https://api.onename.com/v1/search?query=wenger \
    -u 'YOUR-API-ID:YOUR-API-SECRET'

#### example_response:
{
  "results": [
    {
      "profile": {
        "avatar": {
          "url": "https://pbs.twimg.com/profile_images/1773890030/aew_artistic_bigger.gif"
        },
        "bio": "VC at USV.com",
        "bitcoin": {
          "address": "1QHDGGLEKK7FZWsBEL78acV9edGCTarqXt"
        },
        "cover": {
          "url": "https://s3.amazonaws.com/dx3/albertwenger"
        },
        "facebook": {
          "proof": {
            "url": "https://www.facebook.com/albertwenger/posts/10152554952070219"
          },
          "username": "albertwenger"
        },
        "github": {
          "proof": {
            "url": "https://gist.github.com/albertwenger/03c1b5db3880998115fa"
          },
          "username": "albertwenger"
        },
        "graph": {
          "url": "https://s3.amazonaws.com/grph/albertwenger"
        },
        "location": {
          "formatted": "New York"
        },
        "name": {
          "formatted": "Albert Wenger"
        },
        "twitter": {
          "proof": {
            "url": "https://twitter.com/albertwenger/status/499594071401197568"
          },
          "username": "albertwenger"
        },
        "v": "0.2",
        "website": "http://continuations.com"
      },
      "username": "albertwenger"
    }
  ]
}

_end_

## Register users

#### anchor_tag:
register_users

#### description: 
Registers a new blockchain ID and transfers the ownership to
a bitcoin address. Takes in a username to be registered along with the address
that will own the blockchain ID. Optionally, takes in the profile data that should
be associated with the blockchain ID being registered. Returns a status object that
shows if the request was successfully received. It takes on the order of hours
to actually complete the registration.

#### parameters[]:
{"name": "username", "description": "The username (blockchain ID username) that is to be registered."}
{"name": "recipient_address", "description": "The bitcoin address that the blockchain ID will be transferred to once it has been registered."}
{"name": "profile", "description": "The data to be associated with the blockchain ID.", "optional": true}

#### response_description:
Returns an object with a status that is either "success" or "error".

#### method:
POST

#### path_template:
/users

#### example_request_bash:
curl https://api.onename.com/v1/users \
    -u 'YOUR-API-ID:YOUR-API-SECRET' \
    -d '{"username": "fredwilson",
         "recipient_address": "152f1muMCNa7goXYhYAQC61hxEgGacmncB",
         "profile": {"bio": "I am a VC"}}' \
    -H 'Content-type: application/json' \
    -X POST

#### example_response:
{
    "status": "success"
}

_end_

## Update users

#### anchor_tag:
update_users

#### description: 
Update a blockchain ID profile on the blockchain. For a given username, takes in
the new profile data and public key of the bitcoin owner address. Returns an unsigned
transaction that needs to be signed client side and broadcasted using the
transaction broadcast endpoint. The unsigned transaction already contains the
signed transaction fee and only name update input needs to be signed. It takes
on the order of hours to update the profile data on the blockchain.

#### parameters[]:
{"name": "profile", "description": "JSON profile data that should be associated with the username."}
{"name": "owner_pubkey", "description": "Public key of the bitcoin address that owns the username."}

#### response_description:
Returns an object with an unsigned transaction "unsigned_tx" in hex format.

#### method:
POST

#### path_template:
/users/{username}/update

#### example_request_bash:
curl https://api.onename.com/v1/users/fredwilson/update \
    -u 'YOUR-API-ID:YOUR-API-SECRET' \
    -d '{"profile": {"bio": "I am a VC"}, 
         "owner_pubkey": "02b262e2bdb4fee2834115aab77..."}' \
    -H 'Content-type: application/json' \
    -X POST

#### example_response:
{
    "unsigned_tx": "01000000027757f96d886019cf8307e3b3c35bee845...."
}

_end_

## Transfer users

#### anchor_tag:
transfer_users

#### description: 
Transfer the ownership of a blockchain ID to a new bitcoin address. For a given username, takes in
the new address that should own the blockchain ID and public key of the current bitcoin owner address.
Returns an unsigned transaction that needs to be signed client side and broadcasted using the
transaction broadcast endpoint. The unsigned transaction already contains the
signed transaction fee and only name transfer input needs to be signed. It takes
on the order of hours to transfer the blockchain ID on the blockchain.

#### parameters[]:
{"name": "transfer_address", "description": "Bitcoin address of the new owner address."}
{"name": "owner_pubkey", "description": "Public key of the bitcoin address that currently owns the username."}

#### response_description:
Returns an object with an unsigned transaction "unsigned_tx" in hex format.

#### method:
POST

#### path_template:
/users/{username}/transfer

#### example_request_bash:
curl https://api.onename.com/v1/users/fredwilson/transfer \
    -u 'YOUR-API-ID:YOUR-API-SECRET' \
    -d '{"transfer_address": "19bXfGsGEXewR6TyAV3b89cSHBtFFewXt6", 
         "owner_pubkey": "02b262e2bdb4fee2834115aab77..."}' \
    -H 'Content-type: application/json' \
    -X POST

#### example_response:
{
    "unsigned_tx": "01000000027757f96d886019cf8307e3b3c35bee845...."
}

_end_

## Get all users

#### anchor_tag:
get_userbase

#### description:
Gets all data for the decentralized namespace, including the total number of users registered.

#### response_description:
Returns an object with "stats", and "usernames". "stats" is a sub-object which in turn contains a "registrations" field that reflects a running count of the total users registered. "usernames" is a list of all usernames in the namespace.

#### tryit_pathname:
/v1/users

#### method:
GET

#### path_template:
/users

#### example_request_bash:
curl https://api.onename.com/v1/users \
    -u 'YOUR-API-ID:YOUR-API-SECRET'

#### example_response:
{
  "stats": {
    "registrations": "37000"
  },
  "usernames": [
    "fredwilson",
    ...
  ]
}

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
/addresses/{address}/names

#### tryit_pathname:
/v1/addresses/1QJQxDas5JhdiXhEbNS14iNjr8auFT96GP/names?app-id=demo-1234&app-secret=demo-1234

#### example_request_bash:
curl https://api.onename.com/v1/addresses/1QJQxDas5JhdiXhEbNS14iNjr8auFT96GP/names \
    -u 'YOUR-API-ID:YOUR-API-SECRET'

#### example_response:
{
  "names": [
    "muneeb.id"
  ]
}

_end_

