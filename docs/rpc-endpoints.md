# RPC Endpoints

### POST /v2/transactions

This endpoint is for posting _raw_ transaction data to the node's mempool.

Rejections result in a 400 error.

### GET /v2/accounts/[Principal]

Get the account data for the provided principal.
The principal string is either a Stacks address or a Contract identifier (e.g., 
`SP31DA6FTSJX2WGTZ69SFY11BH51NZMB0ZW97B5P0.get-info`

Returns JSON data in the form:

```
{
 "balance": 100,
 "nonce": 1,
 "balanceProof": "01fa...",
 "nonceProof": "01ab...",
}
```

Where balance (a u128) and nonce (a u64) are both integers, and the proofs are provided as
hex strings.

For non-existent accounts, this _does not_ 404, rather it returns an
object with balance and nonce of 0.

This endpoint also accepts a querystring parameter `?proof=` which when supplied `0`, will return the
JSON object _without_ the `balanceProof` or `nonceProof` fields.

### POST /v2/map_entry/[Stacks Address]/[Contract Name]/[Map Name]

Attempt to fetch data from a contract data map. The contract is identified with [Stacks Address] and
 [Contract Name] in the URL path. The map is identified with [Map Name].
 
The _key_ to lookup in the map is supplied via the POST body. This should be supplied as the hex string
serialization of the key (which should be a Clarity value). Note, this is a _JSON_ string atom.

Returns JSON data in the form:

```
{
 "data": "01ce...",
 "marfProof": "01ab...",
}
```

Where data is the hex serialization of the map response. Note that map responses are Clarity _option_ types,
for non-existent values, this is a serialized `none`, and for all other responses, it is a serialized `(some ...)`
object.

This endpoint also accepts a querystring parameter `?proof=` which when supplied `0`, will return the
JSON object _without_ the `marfProof` field.

### GET /v2/fees/transfer

Get an estimated fee rate for STX transfer transactions. This a a fee rate / byte, and is returned as a JSON integer.

### GET /v2/contracts/interface/[Stacks Address]/[Contract Name]

Fetch the contract interface for a given contract, identified by [Stacks Address] and [Contract Name].

This returns a JSON object of the form:

```
{
  "functions": [
    {
      "name": "exotic-block-height",
      "access": "private",
      "args": [
        {
          "name": "height",
          "type": "uint128"
        }
      ],
      "outputs": {
        "type": "bool"
      }
    },
    {
      "name": "update-info",
      "access": "public",
      "args": [],
      "outputs": {
        "type": {
          "response": {
            "ok": "bool",
            "error": "none"
          }
        }
      }
    },
    {
      "name": "get-exotic-data-info",
      "access": "read_only",
      "args": [
        {
          "name": "height",
          "type": "uint128"
        }
      ],
      "outputs": {
        "type": {
          "tuple": [
            {
              "name": "btc-hash",
              "type": {
                "buffer": {
                  "length": 32
                }
              }
            },
            {
              "name": "burn-block-time",
              "type": "uint128"
            },
            {
              "name": "id-hash",
              "type": {
                "buffer": {
                  "length": 32
                }
              }
            },
            {
              "name": "stacks-hash",
              "type": {
                "buffer": {
                  "length": 32
                }
              }
            },
            {
              "name": "stacks-miner",
              "type": "principal"
            },
            {
              "name": "vrf-seed",
              "type": {
                "buffer": {
                  "length": 32
                }
              }
            }
          ]
        }
      }
    }
  ],
  "variables": [],
  "maps": [
    {
      "name": "block-data",
      "key": [
        {
          "name": "height",
          "type": "uint128"
        }
      ],
      "value": [
        {
          "name": "btc-hash",
          "type": {
            "buffer": {
              "length": 32
            }
          }
        },
        {
          "name": "burn-block-time",
          "type": "uint128"
        },
        {
          "name": "id-hash",
          "type": {
            "buffer": {
              "length": 32
            }
          }
        },
        {
          "name": "stacks-hash",
          "type": {
            "buffer": {
              "length": 32
            }
          }
        },
        {
          "name": "stacks-miner",
          "type": "principal"
        },
        {
          "name": "vrf-seed",
          "type": {
            "buffer": {
              "length": 32
            }
          }
        }
      ]
    }
  ],
  "fungible_tokens": [],
  "non_fungible_tokens": []
}
```

### GET /v2/contracts/source/[Stacks Address]/[Contract Name]

Fetch the source for a smart contract. Returned as a JSON string.

### POST /v2/contracts/call-read/[Stacks Address]/[Contract Name]/[Function Name]

Call a read-only public function on a given smart contract.

The smart contract and function are specified using the URL path. The arguments and
the simulated `tx-sender` are supplied via the POST body in the following JSON format:

```
{
  "sender": "SP31DA6FTSJX2WGTZ69SFY11BH51NZMB0ZW97B5P0.get-info",
  "arguments": [ "0011...", "00231..." ]
}
```

Where sender is either a Contract identifier or a normal Stacks address, and arguments
is an array of hex serialized Clarity values.

This endpoint returns a JSON object of the following form:

```
{
  "okay": true,
  "result": "0011..."
}
```

Where `"okay"` is `true` if the function executed successfully, and result contains the
hex serialization of the Clarity return value.

If an error occurs in processing the function call, this endpoint returns a 200 response with a JSON
object of the following form:

```
{
  "okay": false,
  "cause": "Unchecked(PublicFunctionNotReadOnly(..."
}
```
