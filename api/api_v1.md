# API Documentation

## Lookup users

#### anchor_tag:
lookup_users

#### description:
Looks up the data for one or more users by their passnames. In order to perform more than one lookup at once, include a set of comma-separated passnames in the URL in place of the single passname.

#### response_description:
Returns an object with a top-level key for each passname looked up. Each top-level key contains an sub-object that has a "profile" field and a "verifications" field.

#### method:
GET

#### path_template:
/users/{passnames}

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

## Search for users

#### anchor_tag:
search_users

#### description:
Takes in a search query and returns a list of results that match the search. The query is matched against +passnames, full names, and twitter handles.

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
Takes in a passname to be registered along with the address that will own the passname. Optionally, takes in the passcard data that should be associated with the passname being registered. Returns a status object that shows if the request was successfully received. It takes on the order of hours to actually complete the registration.

#### parameters[]:
{"name": "passname", "description": "The passname (passcard username) that is to be registered."}
{"name": "recipient_address", "description": "The namecoin address that the passcard will be transferred to once it has been registered."}
{"name": "passcard", "description": "The data to be associated with the passcard.", "optional": true}

#### response_description:
Returns an object with a status that is either "success" or "error".

#### method:
POST

#### path_template:
/users

#### example_request_bash:
curl https://api.onename.com/v1/users \
    -u 'YOUR-API-ID:YOUR-API-SECRET' \
    -d '{"passname": "fredwilson",
         "recipient_address": "N6zdUCKq1gJaps76gagBbC5Vc6xBxMdvHc",
         "passcard": {"bio": "I am a VC"}}' \
    -H 'Content-type: application/json' \
    -X POST

#### example_response:
{
    "status": "success"
}

_end_

## Get entire userbase

#### anchor_tag:
get_userbase

#### description:
Gets all data for the decentralized namespace, including the total number of users registered.

#### response_description:
Returns an object with "stats", "usernames" and "profiles". "stats" is a sub-object which in turn contains a "registrations" field that reflects a running count of the total users registered. "usernames" is a list of all usernames in the namespace. "profiles" is a sub-object with data for each profile.

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
    "registrations": "29235"
  },
  "usernames": [
    "fredwilson",
    ...
  ],
  "profiles": {
    "fredwilson": {
       ...
    },
    ...
  }
}

_end_

## Broadcast transactions

#### anchor_tag:
broadcast_transaction

#### description:
Takes in a signed transaction (in hex format) and broadcasts it to the network. If the transaction is successfully broadcasted, the transaction hash is returned in the response.

#### response_description:
Returns an object with a status that is either "success" or "error".

#### method:
POST

#### path_template:
/transactions

#### parameters[]:
{"name": "signed_hex", "description": "A signed transaction in hex format."}

#### example_request_bash:
curl https://api.onename.com/v1/transactions \
    -u 'YOUR-API-ID:YOUR-API-SECRET' \
    -d '{"signed_hex": "00710000015e98119922f0b"}' \
    -H 'Content-Type: application/json' \
    -X POST

#### example_response:
{
    "status": "success"
}

_end_

## Get unspent outputs

#### anchor_tag:
unspent_outputs

#### description:
Retrieves the unspent outputs for a given address so they can be used for building transactions.

#### response_description:
Returns an array of unspent outputs for a provided address.

#### method:
GET

#### path_template:
/addresses/{address}/unspents

#### tryit_pathname:
/v1/addresses/N8PcBQnL4oMuM6aLsQow6iG59yks1AtQX4/unspents?app-id=demo-1234&app-secret=demo-1234

#### example_request_bash:
curl https://api.onename.com/v1/addresses/N8PcBQnL4oMuM6aLsQow6iG59yks1AtQX4/unspents \
    -u 'YOUR-API-ID:YOUR-API-SECRET'

#### example_response:
{
  "unspent_outputs": [
    {
      "amount": 99.995, 
      "scriptPubKey": {
        "addresses": [
          "NBSffD6N6sABDxNooLZxL26jwGetiFHN6H"
        ], 
        "asm": "OP_DUP OP_HASH160 a31521da4d3df0d48a7aa7e1d8dadf0e0e862d8d OP_EQUALVERIFY OP_CHECKSIG", 
        "hex": "76a914a31521da4d3df0d48a7aa7e1d8dadf0e0e862d8d88ac", 
        "reqSigs": 1, 
        "type": "pubkeyhash"
      }, 
      "txid": "e06501a48267c26e0ccf85823531be2301291cf582d1e422a69db5a59033e6e5", 
      "vout": "1"
    }, 
    {
      "amount": 378.26213117, 
      "scriptPubKey": {
        "addresses": [
          "NBSffD6N6sABDxNooLZxL26jwGetiFHN6H"
        ], 
        "asm": "OP_DUP OP_HASH160 a31521da4d3df0d48a7aa7e1d8dadf0e0e862d8d OP_EQUALVERIFY OP_CHECKSIG", 
        "hex": "76a914a31521da4d3df0d48a7aa7e1d8dadf0e0e862d8d88ac", 
        "reqSigs": 1, 
        "type": "pubkeyhash"
      }, 
      "txid": "3e3926dd5dc42a3f2d41139bf650d15becfe77bd2143071b09b9b22ca88ad55d", 
      "vout": "1"
    }
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
/v1/addresses/MyVZe4nwF45jeooXw2v1VtXyNCPczbL2EE/names?app-id=demo-1234&app-secret=demo-1234

#### example_request_bash:
curl https://api.onename.com/v1/addresses/MyVZe4nwF45jeooXw2v1VtXyNCPczbL2EE/names \
    -u 'YOUR-API-ID:YOUR-API-SECRET'

#### example_response:
{
  "names": [
    "u/fredwilson"
  ]
}

_end_