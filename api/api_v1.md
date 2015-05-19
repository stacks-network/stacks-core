---START API CALL---
anchor_tag:
lookup_users

title:
Lookup users

description:
Looks up the data for one or more users by their passnames. In order to perform more than one lookup at once, include a set of comma-separated passnames in the URL in place of the single passname.

response_description:
Returns an object with a top-level key for each passname looked up. Each top-level key contains an sub-object that has a "profile" field and a "verifications" field.

method:
GET

path_template:
/users/{passnames}

tryit_pathname:
/v1/users/fredwilson?app-id=demo-app-id&app-secret=demo-app-secret

example_request_bash:
curl https://api.onename.com/v1/users/fredwilson \
    -u 'YOUR-API-ID:YOUR-API-SECRET'

example_response:
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
---END API CALL---


---START API CALL---
anchor_tag:
register_user

title:
Register a user

description:
Takes in a passname to be registered along with the address that will own the passname. Optionally, takes in the passcard data that should be associated with the passname being registered. Returns a status object that shows if the request was successfully received. It takes on the order of hours to actually complete the registration.

parameters[]:
{"name": "transfer_address", "description": "The namecoin address that the passcard will be transferred to once it has been registered."}
{"name": "passcard", "description": "The data to be associated with the passcard.", "optional": true}

response_description:
Returns an object with a status that is either "success" or "error".

method:
POST

path_template:
/users

example_request_bash:
curl https://api.onename.com/v1/users \
    -u 'YOUR-API-ID:YOUR-API-SECRET' \
    -d '{"passname": "fredwilson",
         "recipient_address": "N6zdUCKq1gJaps76gagBbC5Vc6xBxMdvHc",
         "passcard": {"bio": "I am a VC"}}' \
    -H 'Content-type: application/json' \
    -X POST

example_response:
{
    "status": "success"
}
---END API CALL---

---START API CALL---
anchor_tag:
search_users

title:
Search for a user

description:
Takes in a search query and returns a list of results that match the search. The query is matched against +passnames, full names, and twitter handles.

response_description:
Returns an array of results, where each result has a \"profile\" object.

method:
GET

path_template:
/search

parameters[]:
{"name": "query", "description": "The text to search for."}

tryit_pathname:
/v1/search?query=fred&app-id=demo-1234&app-secret=demo-1234

example_request_bash:
curl https://api.onename.com/v1/search?query=wenger \
    -u 'YOUR-API-ID:YOUR-API-SECRET'

example_response:
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
---END API CALL---

---START API CALL---
anchor_tag:
userbase_stats

title:
Get userbase stats

description:
Gets stats about the decentralized namespace, including the total number of users registered.

response_description:
Returns an object with a "stats" sub-object that in turn contains a "registrations" field that reflects a running count of the total users registered.

method:
GET

path_template:
/users

tryit_pathname:
/v1/users?&app-id=demo-1234&app-secret=demo-1234

example_request_bash:
curl https://api.onename.com/v1/users \
    -u 'YOUR-API-ID:YOUR-API-SECRET'

example_response:
{
  "stats": {
    "registrations": "29235"
  }
}
---END API CALL---

---START API CALL---
anchor_tag:
broadcast_transaction

title:
Broadcast a transaction

description:
Takes in a signed transaction (in hex format) and broadcasts it to the network. If the transaction is successfully broadcasted, the transaction hash is returned in the response.

response_description:
Returns an object with a status that is either "success" or "error".

method:
POST

path_template:
/users/{passnames}

parameters[]:
{"name": "signed_hex", "description": "A signed transaction in hex format."}

example_request_bash:
curl https://api.onename.com/v1/transactions \
    -u 'YOUR-API-ID:YOUR-API-SECRET' \
    -d '{"signed_hex": "00710000015e98119922f0b"}' \
    -H 'Content-Type: application/json' \
    -X POST

example_response:
{
    "status": "success"
}
---END API CALL---

---START API CALL---
anchor_tag:
lookup_address

title:
Lookup an address

description:
Retrieves details on a given address. Unspent outputs are returned, so they can be used for building transactions. In addition, a list of names owned by the address is returned.

response_description:
Returns an array of unspent outputs and an array of the names that the address owns.

method:
GET

path_template:
/users/{passnames}

tryit_pathname:
/v1/addresses/N8PcBQnL4oMuM6aLsQow6iG59yks1AtQX4?&app-id=demo-1234&app-secret=demo-1234

example_request_bash:
curl https://api.onename.com/v1/addresses/N8PcBQnL4oMuM6aLsQow6iG59yks1AtQX4 \
    -u 'YOUR-API-ID:YOUR-API-SECRET'

example_response:
{
  "names_owned": [],
  "unspent_outputs": []
}
---END API CALL---
