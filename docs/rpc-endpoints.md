# RPC Endpoints

### POST /v2/transactions

This endpoint is for posting _raw_ transaction data to the node's mempool.

Rejections result in a 400 error, with JSON data in the form:

```
{
  "error": "transaction rejected",
  "reason": "BadNonce",
  "reason_data": {
    "actual": 3,
    "expected": 0,
    "is_origin": true,
    "principal": "ST2MVNFYF6H9DCMAV3HVNHTJVVE3CFWT1JYMH1EZB"
  },
  "txid": "0x4068179cb9169b969c80518d83890f8b808a70ab998dd227149221be9480a616"
}
```

Possible values for the "reason" field and "reason_data" field are:

* `Serialization`
   * The `reason_data` field will be an object containing a `message`
     string detailing the serialization error
* `Deserialization`
   * The `reason_data` field will be an object containing a `message`
     string detailing the deserialization error
* `EstimatorError`
   * The `reason_data` field will be an object containing a `message`
     string detailing the error
* `SignatureValidation`
   * The `reason_data` field will be an object containing a `message`
     string detailing the signature validation error
* `BadNonce`
   * The `reason_data` field will be an object containing:
     * `expected` - a number representing the expected nonce,
     * `actual` - a number representing the actual nonce,
     * `is_origin` - a boolean representing whether the nonce error
       occurred on the 'origin' or 'sponsor' of the transaction,
     * `principal` - a string representing the principal address
       that had the bad nonce
* `FeeTooLow`
   * The `reason_data` field will be an object containing:
     * `expected` - a number representing the minimum expected fee,
     * `actual` - a number representing the supplied fee
* `NotEnoughFunds`
   * The `reason_data` field will be an object containing:
     * `expected` - a hex string representing the expected
       number of microstacks
     * `actual` - a hex string representing the actual
       number of microstacks the account possesses
* `NoSuchContract`
* `NoSuchPublicFunction`
* `BadFunctionArgument`
   * The `reason_data` field will be an object containing a `message`
     string detailing why the supplied argument was bad.
* `ContractAlreadyExists`
   * The `reason_data` field will be an object containing a `contract_identifier`
     string representing the contract identifier that would be duplicated.
* `PoisonMicroblocksDoNotConflict`
* `PoisonMicroblockHasUnknownPubKeyHash`
* `PoisonMicroblockIsInvalid`
* `BadAddressVersionByte`
* `NoCoinbaseViaMempool`
* `ServerFailureNoSuchChainTip`
* `ServerFailureDatabase`
   * The `reason_data` field will be an object containing a `message`
     string detailing why the server had a database error
* `ServerFailureOther`
   * The `reason_data` field will be an object containing a `message`
     string providing more detail on the server failure

Reason types without additional information will not have a
`reason_data` field.

### GET /v2/pox

Get current PoX-relevant information. See OpenAPI [spec](./rpc/openapi.yaml) for details.

### GET /v2/headers/[Count]

Get a given number of ancestral Stacks block headers, in order from newest to
oldest.  If the `?tip=` query parameter is given, the headers will be loaded
from the block identified by the tip.  If no `?tip=` query parameter is given,
then the canonical Stacks chain tip will be used.  The first header in the list
is the header of the `?tip=` query parameter (or the canonical tip of the blockchain);
the second header is the parent block's header; the third header is the
grandparent block's header, and so on. [Count] determines how many headers, including this first header, to return.

Up to 2100 headers (one PoX reward cycle) may be returned by this endpoint.
Callers who wish to download more headers will need to issue this query
multiple times, with a `?tip=` query parameter set to the index block hash of
the earliest header received.

Returns a
[SIP-003](https://github.com/stacksgov/sips/blob/main/sips/sip-003/sip-003-peer-network.md)-encoded
vector with length up to [Count] that contains a list of the following SIP-003-encoded
structures:

```
struct ExtendedStacksHeader {
    consensus_hash: ConsensusHash,
    header: StacksBlockHeader,
    parent_block_id: StacksBlockId,
}
```

Where `ConsensusHash` is a 20-byte byte buffer.

Where `StacksBlockId` is a 32-byte byte buffer.

Where `StacksBlockHeader` is the following SIP-003-encoded structure:

```
struct StacksBlockHeader {
    version: u8,
    total_work: StacksWorkScore,
    proof: VRFProof,
    parent_block: BlockHeaderHash,
    parent_microblock: BlockHeaderHash,
    parent_microblock_sequence: u16,
    tx_merkle_root: Sha512Trunc256Sum,
    state_index_root: TrieHash,
    microblock_pubkey_hash: Hash160,
}
```

Where `BlockHeaderHash`, `Sha512Trunc256Sum`, and `TrieHash` are 32-byte byte
buffers.

Where `Hash160` is a 20-byte byte buffer.

Where `StacksWorkScore` and `VRFProof` are the following SIP-003-encoded structures:

```
struct StacksWorkScore {
    burn: u64,
    work: u64,
}
```

```
struct VRFProof {
    Gamma: [u8; 32]
    c: [u8; 16]
    s: [u8; 32]
}
```

The interpretation of most these fields is beyond the scope of this document (please
see
[SIP-005](https://github.com/stacksgov/sips/blob/main/sips/sip-005/sip-005-blocks-and-transactions.md)
for details).  However, it is worth pointing out that `parent_block_id` is a
valid argument to the `?tip=` query parameter.  If the caller of this API
endpoint wants to receive more than 2100 contiguous headers, it would use the
oldest header's `parent_block_id` field from the previous call as the `?tip=`
argument to the next call in order to fetch the next batch of ancestor headers.

This API endpoint may return a list of zero headers if `?tip=` refers to the
hash of the Stacks genesis block.

This API endpoint will return HTTP 404 if the `?tip=` argument is given but
refers to a nonexistent Stacks block, or a Stacks block that has not yet been
processed by the node.

The `?tip=` argument may refer to a Stacks block that is not on the canonical
fork.  In this case, this endpoint behaves as described above, except that
non-canonical headers will be returned instead.

### GET /v2/accounts/[Principal]

Get the account data for the provided principal.
The principal string is either a Stacks address or a Contract identifier (e.g., 
`SP31DA6FTSJX2WGTZ69SFY11BH51NZMB0ZW97B5P0.get-info`

Returns JSON data in the form:

```
{
 "balance": "0x100..",
 "nonce": 1,
 "balance_proof": "0x01fa...",
 "nonce_proof": "0x01ab...",
}
```

Where balance is the hex encoding of a unsigned 128-bit integer
(big-endian), nonce is a unsigned 64-bit integer, and the proofs are
provided as hex strings.

For non-existent accounts, this _does not_ 404, rather it returns an
object with balance and nonce of 0.

This endpoint also accepts a querystring parameter `?proof=` which when supplied `0`, will return the
JSON object _without_ the `balance_proof` or `nonce_proof` fields.

### GET /v2/data_var/[Stacks Address]/[Contract Name]/[Var Name]

Attempt to vetch a data var from a contract. The contract is identified with [Stacks Address] and
 [Contract Name] in the URL path. The variable is identified with [Var Name].
 
Returns JSON data in the form:

```
{
 "data": "0x01ce...",
 "proof": "0x01ab...",
}
```

Where data is the hex serialization of the variable value.

This endpoint also accepts a querystring parameter `?proof=` which when supplied `0`, will return the
JSON object _without_ the `proof` field.

### GET /v2/constant_val/[Stacks Address]/[Contract Name]/[Constant Name]
Attempt to fetch a constant from a contract. The contract is identified with [Stacks Address] and 
 [Contract Name] in the URL path. The constant is identified with [Constant Name].

Returns JSON data in the form:
```
{
  "data": "0x01ce...",
}
```

Where data is the hex serialization of the constant value.

### POST /v2/map_entry/[Stacks Address]/[Contract Name]/[Map Name]

Attempt to fetch data from a contract data map. The contract is identified with [Stacks Address] and
 [Contract Name] in the URL path. The map is identified with [Map Name].
 
The _key_ to lookup in the map is supplied via the POST body. This should be supplied as the hex string
serialization of the key (which should be a Clarity value). Note, this is a _JSON_ string atom.

Returns JSON data in the form:

```
{
 "data": "0x01ce...",
 "proof": "0x01ab...",
}
```

Where data is the hex serialization of the map response. Note that map responses are Clarity _option_ types,
for non-existent values, this is a serialized `none`, and for all other responses, it is a serialized `(some ...)`
object.

This endpoint also accepts a querystring parameter `?proof=` which when supplied `0`, will return the
JSON object _without_ the `proof` field.

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

Fetch the source for a smart contract, along with the block height it was
published in, and the MARF proof for the data.

```
{
 "source": "(define-private ...",
 "publish_height": 1,
 "proof": "0x00213..."
}
```

This endpoint also accepts a querystring parameter `?proof=` which
when supplied `0`, will return the JSON object _without_ the `proof`
field.

### POST /v2/contracts/call-read/[Stacks Address]/[Contract Name]/[Function Name]

Call a read-only public function on a given smart contract.

The smart contract and function are specified using the URL path. The arguments and
the simulated `tx-sender` are supplied via the POST body in the following JSON format:

```
{
  "sender": "SP31DA6FTSJX2WGTZ69SFY11BH51NZMB0ZW97B5P0.get-info",
  "arguments": [ "0x0011...", "0x00231..." ]
}
```

Where sender is either a Contract identifier or a normal Stacks address, and arguments
is an array of hex serialized Clarity values.

This endpoint returns a JSON object of the following form:

```
{
  "okay": true,
  "result": "0x0011..."
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

### GET /v2/traits/[Stacks Address]/[Contract Name]/[Trait Stacks Address]/[Trait Contract Name]/[Trait Name]

Determine whether a given trait is implemented within the specified contract (either explicitly or implicitly).

See OpenAPI [spec](./rpc/openapi.yaml) for details.

### GET /v2/health

Determine whether a node is healthy. A node is considered healthy if its block height
is greater than or equal to the max block height of its initial peers. If there are no valid 
initial peers or data for the node to determine this information, this endpoint 
returns an error. The endpoint also returns an error if the node's height is 
less than the max block height amongst its initial peers, and this error includes
the percent of blocks the node has relative to its most advanced peer. 

See OpenAPI [spec](./rpc/openapi.yaml) for details.