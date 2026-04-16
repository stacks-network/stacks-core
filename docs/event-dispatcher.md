# Event Dispatching / Observer Interface

The `stacks-node` supports a configurable event observer interface, allowing external services to subscribe to various on-chain and node-related events. This is enabled by adding one or more `[[events_observer]]` entries to the node's `config.toml` file.

```toml
...
[[events_observer]]
endpoint = "listener:3700" # The host and port of your listening service
events_keys = ["*"]                     # A list of event keys to subscribe to (see below)
timeout_ms = 5000                       # Optional: Timeout in milliseconds for requests (default: 1000)
disable_retries = false                 # Optional: If true, failed deliveries won't be retried (default: false)

# Example of another observer for specific events
# [[events_observer]]
# endpoint = "another-service:3701"
# events_keys = [
#   "stx",
#   "ST0000000000000000000000000000000000000000.my-contract::my-event"
# ]
...
```

The `stacks-node` will then execute HTTP POST requests with JSON payloads to the configured `endpoint` for the subscribed events.

By default, when sending a payload the event dispatcher will block node operation until it has received a successful response from your observer. Your event observer should therefore be quick to respond, and offload any expensive computation to an asynchronous background task. Alternatively, you can configure the events to be delivered in a non-blocking fashion like this:

```toml
[node]
...
event_dispatcher_blocking = false
# By default, up to 1,000 requests can be held in a queue before the event dispatcher will start blocking
# again. If you expect bigger bursts than that, you can further tweak this value.
#
# event_dispatcher_queue_size = 1_000
```

Note that this is only meant to deal with bursts of events. If your event observer is continuously slower than the stream of incoming events, it will fall behind more and more, and the dispatcher will eventually start blocking again to catch up.

## Important Notes

*   **`/new_microblocks` Endpoint Limitation:** Event delivery via the `/new_microblocks` endpoint (and by extension, events sourced from microblocks delivered to `/new_block`) is **only supported until epoch 2.5**. After this epoch, observers will no longer receive events on this path for new microblocks.
*   **`/attachments/new` Implicit Subscription:** All observers, regardless of their `events_keys` configuration, implicitly receive payloads on the `/attachments/new` endpoint for new AtlasDB attachments.


## Configuring Event Subscriptions (`events_keys`)

The `events_keys` array in the `[[events_observer]]` configuration block is crucial as it determines precisely which events an observer will receive and to which endpoints they are delivered. Providing an invalid key will cause the node to panic on startup.

Below is a comprehensive list of valid keys and their behaviors:

*   `"*"`: Subscribes to a broad set of common events.
    *   **Description**: An observer with `"*"` will receive a wide range of general event types.
    *   **Events delivered to**:
        *   `/new_block`: For blocks containing transactions that generate STX, FT, NFT, or smart contract events.
        *   `/new_microblocks`: For all new microblock streams (subject to epoch 2.5 limitation).
        *   `/new_mempool_tx`: For new mempool transactions.
        *   `/drop_mempool_tx`: For dropped mempool transactions.
        *   `/new_burn_block`: For new burnchain blocks.
    *   **Note**: This key does NOT by itself subscribe to the StackerDB events (`/stackerdb_chunks`), or block proposal responses (`/proposal_response`).

*   `"stx"`: Subscribes to STX token operation events.
    *   **Description**: Captures STX token events like transfers, mints, burns, and locks.
    *   **Events delivered to**: `/new_block`, `/new_microblocks` (subject to epoch 2.5 limitation).
    *   **Payload details**: The "events" array in the delivered payloads will be filtered to include only STX-related events.

*   `"memtx"`: Subscribes to mempool transaction events.
    *   **Description**: Captures new and dropped mempool transaction events.
    *   **Events delivered to**: `/new_mempool_tx`, `/drop_mempool_tx`.

*   `"burn_blocks"`: Subscribes to new burnchain block events.
    *   **Description**: Captures events related to new burnchain blocks being processed.
    *   **Events delivered to**: `/new_burn_block`.

*   `"microblocks"`: Subscribes to new microblock stream events.
    *   **Description**: Captures events for new microblock streams.
    *   **Events delivered to**: `/new_microblocks`.
    *   **Payload details**:
        *   The "transactions" field will contain all transactions from the microblocks.
        *   The "events" field will contain STX, FT, NFT, or specific smart contract events *only if* this observer is also subscribed to those more specific event types (e.g., via `"stx"`, `"*"`, a specific contract event key, or a specific asset identifier key).
    *   **Note**: Microblocks are deprecated since epoch 2.5.

*   `"stackerdb"`: Subscribes to StackerDB chunk update events.
    *   **Description**: Captures events for updates to StackerDB replicas.
    *   **Events delivered to**: `/stackerdb_chunks`.
    *   **Note**: Requires specific subscription; not included in `*`.

*   `"block_proposal"`: Subscribes to block proposal response events.
    *   **Description**: Captures validation responses for block proposals (relevant for Nakamoto consensus).
    *   **Events delivered to**: `/proposal_response`.
    *   **Note**: Requires specific subscription; not included in `*`.

*   **Smart Contract Event**: Subscribes to a specific smart contract event.
    *   **Description**: Allows subscription to events emitted by a particular smart contract.
    *   **Format**: `"{deployer_address}.{contract_name}::{event_name}"`
    *   **Example**: `"ST0000000000000000000000000000000000000000.my-contract::my-custom-event"`
    *   **Events delivered to**: `/new_block`, `/new_microblocks` (subject to epoch 2.5 limitation).
    *   **Payload details**: The "events" array in delivered payloads will be filtered for this specific event.

*   **Asset Identifier for FT/NFT Events**: Subscribes to events for a specific Fungible Token (FT) or Non-Fungible Token (NFT).
    *   **Description**: Captures mint, burn, and transfer events for a specific token asset.
    *   **Format**: `"{deployer_address}.{contract_name}.{asset_name}"`
    *   **Example (FT)**: `"ST0000000000000000000000000000000000000000.my-ft-contract.my-fungible-token"`
    *   **Events delivered to**: `/new_block`, `/new_microblocks` (subject to epoch 2.5 limitation).
    *   **Payload details**: The "events" array in delivered payloads will be filtered for events related to the specified asset.

## Event Endpoints and Payloads

The following endpoints are used to deliver event payloads.

### `POST /new_block`

Delivers data for a newly processed Stacks block, including transactions and associated events. If transactions originated from microblocks, relevant microblock details are included.
*   **Triggered by keys**: `*`, `"stx"`, specific smart contract or asset identifiers.
*   **Payload Summary**: Contains block details, an array of transactions, and an array of filtered events based on subscription.
*   **Note**: If the `raw_tx` field for a transaction is `"0x00"`, it indicates a burnchain operation (see "Burnchain Operations" below).

The section below has example json encodings for each of the burnchain operations.

*Example Payloads:*

```json
{
  "block_hash": "0x4eaabcd105865e471f697eff5dd5bd85d47ecb5a26a3379d74fae0ae87c40904",
  "block_height": 3,
  "burn_block_time": 1591301733,
  "events": [
    {
      "event_index": 1,
      "committed": true,
      "stx_transfer_event": {
        "amount": "1000",
        "recipient": "ST31DA6FTSJX2WGTZ69SFY11BH51NZMB0ZZ239N96",
        "sender": "ST3WM51TCWMJYGZS1QFMC28DH5YP86782YGR113C1"
      },
      "txid": "0x738e4d44636023efa08374033428e44eca490582bd39a6e61f3b6cf749b4214c",
      "type": "stx_transfer_event"
    }
  ],
  "index_block_hash": "0x329efcbcc6daf5ac3f264522e0df50eddb5be85df6ee8a9fc2384c54274d7afc",
  "parent_block_hash": "0xf5d4ce0efe1d42c963d615ce57f0d014f263a985175e4ece766eceff10e0a358",
  "parent_index_block_hash": "0x0c8b38d44d6af72703a4767ff4cea683ec965346d9e9a7ded2d773fb4f257c28",
  "parent_microblock": "0xedd15cf1e697c28df934e259f0f82970a7c9edc2d39bef04bdd0d422116235c6",
  "transactions": [
    {
      "contract_abi": null,
      "burnchain_op": null,
      "raw_result": "0x03",
      "raw_tx": "0x808000000004008bc5147525b8f477f0bc4522a88c8339b2494db50000000000000002000000000000000001015814daf929d8700af344987681f44e913890a12e38550abe8e40f149ef5269f40f4008083a0f2e0ddf65dcd05ecfc151c7ff8a5308ad04c77c0e87b5aeadad31010200000000040000000000000000000000000000000000000000000000000000000000000000",
      "status": "success",
      "tx_index": 0,
      "txid": "0x3e04ada5426332bfef446ba0a06d124aace4ade5c11840f541bf88e2e919faf6",
      "microblock_sequence": "None",
      "microblock_hash": "None",
      "microblock_parent_hash": "None"
    },
    {
      "contract_abi": null,
      "burnchain_op": null,
      "raw_result": "0x03",
      "raw_tx": "0x80800000000400f942874ce525e87f21bbe8c121b12fac831d02f4000000000000000000000000000003e800006ae29867aec4b0e4f776bebdcea7f6d9a24eeff370c8c739defadfcbb52659b30736ad4af021e8fb741520a6c65da419fdec01989fdf0032fc1838f427a9a36102010000000000051ac2d519faccba2e435f3272ff042b89435fd160ff00000000000003e800000000000000000000000000000000000000000000000000000000000000000000",
      "status": "success",
      "tx_index": 1,
      "txid": "0x738e4d44636023efa08374033428e44eca490582bd39a6e61f3b6cf749b4214c",
      "microblock_sequence": "3",
      "microblock_hash": "0x9304fcbcc6daf5ac3f264522e0df50eddb5be85df6ee8a9fc2384c54274daaac",
      "microblock_parent_hash": "0x4893ab44636023efa08374033428e44eca490582bd39a6e61f3b6cf749b474bd"
    },
    {
      "burnchain_op": {
        "transfer_stx": {
          "burn_block_height": 10,
          "burn_header_hash": "1410131010105914101010101013704010101010221010101010101010101010",
          "memo": "0x000102030405",
          "recipient": {
            "address": "SP24ZBZ8ZE6F48JE9G3F3HRTG9FK7E2H6K2QZ3Q1K",
            "address_hash_bytes": "0x89f5fd1f719e4449c980de38e3504be6770a2698",
            "address_version": 22
          },
          "sender": {
            "address": "ST2QKZ4FKHAH1NQKYKYAYZPY440FEPK7GZ1R5HBP2",
            "address_hash_bytes": "0xaf3f91f38aa21ade7e9f95efdbc4201eeb4cf0f8",
            "address_version": 26
          },
          "transfered_ustx": 10,
          "burn_txid": "85aa2106186723f3c4f1d8bb58e3a02746ca9be1be9f4be0c6557079e1f660e6",
          "vtxindex": 10
        }
      },
      "contract_abi": null,
      "execution_cost": {
        "read_count": 0,
        "read_length": 0,
        "runtime": 0,
        "write_count": 0,
        "write_length": 0
      },
      "microblock_hash": null,
      "microblock_parent_hash": null,
      "microblock_sequence": null,
      "raw_result": "0x0703",
      "raw_tx": "0x00",
      "status": "success",
      "tx_index": 2,
      "txid": "0x85aa2106186723f3c4f1d8bb58e3a02746ca9be1be9f4be0c6557079e1f660e6"
    }
  ],
   "matured_miner_rewards": [
    {
      "recipient": "ST31DA6FTSJX2WGTZ69SFY11BH51NZMB0ZZ239N96",
      "coinbase_amount": "1000",
      "tx_fees_anchored": "800",
      "tx_fees_streamed_confirmed": "0",
      "from_stacks_block_hash": "0xf5d4ce0efe1d42c963d615ce57f0d014f263a985175e4ece766eceff10e0a358",
      "from_index_block_hash": "0x329efcbcc6daf5ac3f264522e0df50eddb5be85df6ee8a9fc2384c54274d7afc",
    }
   ],
   "anchored_cost": {
    "runtime": 100,
    "read_count": 10,
    "write_count": 5,
    "read_length": 150,
    "write_length": 75
   },
   "confirmed_microblocks_cost": {
    "runtime": 100,
    "read_count": 10,
    "write_count": 5,
    "read_length": 150,
    "write_length": 75
   }
}
```

## Burnchain Operations
When a transaction in the `/new_block` payload has a `raw_tx` field of `"0x00"`, it signifies a "burnchain operation." These are Stacks operations initiated via the Bitcoin network. The specific operation details are found in the `burnchain_op` field of that transaction object.
More details on burnchain operations can be found in [SIP-007](https://github.com/stacksgov/sips/blob/main/sips/sip-007/sip-007-stacking-consensus.md#stx-operations-on-bitcoin).

#### Example JSON values for `burnchain_op` field:
*   **transfer-stx:**
    ```json
    {
      "transfer_stx": {
        "burn_block_height": 10,
        "burn_header_hash": "1410131010105914101010101013704010101010221010101010101010101010",
        "memo": "0x000102030405",
        "recipient": {
          "address": "SP24ZBZ8ZE6F48JE9G3F3HRTG9FK7E2H6K2QZ3Q1K",
          "address_hash_bytes": "0x89f5fd1f719e4449c980de38e3504be6770a2698",
          "address_version": 22
        },
        "sender": {
          "address": "ST2QKZ4FKHAH1NQKYKYAYZPY440FEPK7GZ1R5HBP2",
          "address_hash_bytes": "0xaf3f91f38aa21ade7e9f95efdbc4201eeb4cf0f8",
          "address_version": 26
        },
        "transfered_ustx": 10,
        "burn_txid": "85aa2106186723f3c4f1d8bb58e3a02746ca9be1be9f4be0c6557079e1f660e6",
        "vtxindex": 10
      }
    }
    ```

*   **stack-stx:**
    ```json
    {
      "stack_stx": {
        "burn_block_height": 10,
        "burn_header_hash": "1010101010101010101010101010101010101010101010101010101010101010",
        "num_cycles": 10,
        "reward_addr": "16Jswqk47s9PUcyCc88MMVwzgvHPvtEpf",
        "sender": {
          "address": "ST2QKZ4FKHAH1NQKYKYAYZPY440FEPK7GZ1R5HBP2",
          "address_hash_bytes": "0xaf3f91f38aa21ade7e9f95efdbc4201eeb4cf0f8",
          "address_version": 26
        },
        "stacked_ustx": 10,
        "burn_txid": "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
        "vtxindex": 10
      }
    }
    ```

*   **delegate-stx:**
    ```json
    {
      "delegate_stx": {
        "burn_block_height": 10,
        "burn_header_hash": "1010101010101010101010101010101010101010101010101010101010101010",
        "delegate_to": {
          "address": "SP24ZBZ8ZE6F48JE9G3F3HRTG9FK7E2H6K2QZ3Q1K",
          "address_hash_bytes": "0x89f5fd1f719e4449c980de38e3504be6770a2698",
          "address_version": 22
        },
        "delegated_ustx": 10,
        "sender": {
          "address": "ST2QKZ4FKHAH1NQKYKYAYZPY440FEPK7GZ1R5HBP2",
          "address_hash_bytes": "0xaf3f91f38aa21ade7e9f95efdbc4201eeb4cf0f8",
          "address_version": 26
        },
        "reward_addr": [10, "16Jswqk47s9PUcyCc88MMVwzgvHPvtEpf"],
        "burn_txid": "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
        "until_burn_height": null,
        "vtxindex": 10
      }
    }
    ```

*   **pre-stx:**
    ```json
    {
      "pre_stx": {
        "burn_block_height": 10,
        "burn_header_hash": "1010101010101010101010101010101010101010101010101010101010101010",
        "output": "ST2QKZ4FKHAH1NQKYKYAYZPY440FEPK7GZ1R5HBP2",
        "burn_txid": "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
        "vtxindex": 10
      }
    }
    ```

*   **vote-for-aggregate-key:**
    ```json
    {
      "vote_for_aggregate_key": {
        "burn_block_height": 10,
        "burn_header_hash": "1010101010101010101010101010101010101010101010101010101010101010",
        "aggregate_key": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "reward_cycle": 10,
        "round": 10,
        "sender": {
          "address": "ST2QKZ4FKHAH1NQKYKYAYZPY440FEPK7GZ1R5HBP2",
          "address_hash_bytes": "0xaf3f91f38aa21ade7e9f95efdbc4201eeb4cf0f8",
          "address_version": 26
        },
        "signer_index": 10,
        "signer_key": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "burn_txid": "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
        "vtxindex": 10
      }
    }
    ```

### `POST /new_burn_block`

Delivers information about burnchain blocks as their sortitions are processed.
*   **Triggered by keys**: `*`, `"burn_blocks"`.
*   **Payload Summary**: Contains burn block hash, height, consensus hash, parent hash, reward recipients, slot holders, and total burn amount.
*   **Note**: In the event of PoX forks, a `new_burn_block` event may be triggered for a burn block previously processed.

*Example Payload:*

```json
{
  "burn_block_hash": "0x4eaabcd105865e471f697eff5dd5bd85d47ecb5a26a3379d74fae0ae87c40904",
  "consensus_hash": "0x53c166a709a9abd64a92a57f928a8b26aad08992",
  "parent_burn_block_hash": "0x6eaebcd105865e471f697eff5dd5bd85d47ecb5a26a3379d74fae0ae87c40904",
  "burn_block_height": 331,
  "reward_recipients": [
    {
      "recipient": "1C56LYirKa3PFXFsvhSESgDy2acEHVAEt6",
      "amt": 5000
    }
  ],
  "reward_slot_holders": [
    "1C56LYirKa3PFXFsvhSESgDy2acEHVAEt6",
    "1C56LYirKa3PFXFsvhSESgDy2acEHVAEt6"
  ],
  "burn_amount": 12000
}
```

* `reward_recipients` is an array of all the rewards received during this burn block. It may
  include recipients who did _not_ have reward slots during the block. This could happen if
  a miner's commitment was included a block or two later than intended. Such commitments would
  not be valid, but the reward recipient would still receive the burn `amt`.
* `reward_slot_holders` is an array of the Bitcoin addresses that would validly receive
  PoX commitments during this block. These addresses may not actually receive rewards during
  this block if the block is faster than miners have an opportunity to commit.

### `POST /new_microblocks`
Delivers data for one or more microblocks, either self-emitted or received from the network.
*   **Triggered by keys**: `*`, `"microblocks"`, `"stx"`, specific smart contract or asset identifiers.
*   **Payload Summary**: Contains parent index block hash, an array of transactions, an array of filtered events, and associated burn block details.
*   **Note**: Microblocks are deprecated since epoch 2.5.

*Example Payload:*

```json
{
  "parent_index_block_hash": "0x999b38d44d6af72703a476dde4cea683ec965346d9e9a7ded2d773fb4f257a3b",
  "events": [
    {
      "event_index": 1,
      "committed": true,
      "stx_transfer_event": {
        "amount": "1000",
        "recipient": "ST31DA6FTSJX2WGTZ69SFY11BH51NZMB0ZZ239N96",
        "sender": "ST3WM51TCWMJYGZS1QFMC28DH5YP86782YGR113C1"
      },
      "txid": "0x738e4d44636023efa08374033428e44eca490582bd39a6e61f3b6cf749b4214c",
      "type": "stx_transfer_event"
    }
  ],
  "transactions": [
    {
      "contract_abi": null,
      "burnchain_op": null,
      "raw_result": "0x03",
      "raw_tx": "0x808000000004008bc5147525b8f477f0bc4522a88c8339b2494db50000000000000002000000000000000001015814daf929d8700af344987681f44e913890a12e38550abe8e40f149ef5269f40f4008083a0f2e0ddf65dcd05ecfc151c7ff8a5308ad04c77c0e87b5aeadad31010200000000040000000000000000000000000000000000000000000000000000000000000000",
      "status": "success",
      "tx_index": 0,
      "txid": "0x3e04ada5426332bfef446ba0a06d124aace4ade5c11840f541bf88e2e919faf6",
      "microblock_sequence": "3",
      "microblock_hash": "0x9304fcbcc6daf5ac3f264522e0df50eddb5be85df6ee8a9fc2384c54274daaac",
      "microblock_parent_hash": "0x4893ab44636023efa08374033428e44eca490582bd39a6e61f3b6cf749b474bd"
    },
    {
      "contract_abi": null,
      "burnchain_op": null,
      "raw_result": "0x03",
      "raw_tx": "0x80800000000400f942874ce525e87f21bbe8c121b12fac831d02f4000000000000000000000000000003e800006ae29867aec4b0e4f776bebdcea7f6d9a24eeff370c8c739defadfcbb52659b30736ad4af021e8fb741520a6c65da419fdec01989fdf0032fc1838f427a9a36102010000000000051ac2d519faccba2e435f3272ff042b89435fd160ff00000000000003e800000000000000000000000000000000000000000000000000000000000000000000",
      "status": "success",
      "tx_index": 1,
      "txid": "0x738e4d44636023efa08374033428e44eca490582bd39a6e61f3b6cf749b4214c",
      "microblock_sequence": "4",
      "microblock_hash": "0xfcd4fc34c6daf5ac3f264522e0df50eddb5be85df6ee8a9fc2384c5427459e43",
      "microblock_parent_hash": "0x9304fcbcc6daf5ac3f264522e0df50eddb5be85df6ee8a9fc2384c54274daaac"
    }
  ],
  "burn_block_hash": "0x4eaabcd105865e471f697eff5dd5bd85d47ecb5a26a3379d74fae0ae87c40904",
  "burn_block_height": 331,
  "burn_block_timestamp": 1651301734
}
```

* `burn_block_{}` are the stats related to the burn block that is associated with the stacks
  block that precedes this microblock stream.
* Each transaction json object includes information about the microblock the transaction was packaged into.

### `POST /new_mempool_tx`

Delivers an array of raw, hex-encoded transactions newly received into the node's mempool.
*   **Triggered by keys**: `*`, `"memtx"`.
*   **Payload Summary**: A JSON array of hex-encoded transaction strings.

*Example Payload:*

```json
[
  "0x80800000000400f942874ce525e87f21bbe8c121b12fac831d02f4000000000000000000000000000003e800006ae29867aec4b0e4f776bebdcea7f6d9a24eeff370c8c739defadfcbb52659b30736ad4af021e8fb741520a6c65da419fdec01989fdf0032fc1838f427a9a36102010000000000051ac2d519faccba2e435f3272ff042b89435fd160ff00000000000003e800000000000000000000000000000000000000000000000000000000000000000000"
]
```

### `POST /drop_mempool_tx`

Delivers information about transactions dropped from the mempool.
*   **Triggered by keys**: `*`, `"memtx"`.
*   **Payload Summary**: Contains an array of dropped transaction IDs, the reason for being dropped, and optionally a new transaction ID if replaced.

*Example Payload:*

```json
{
  "dropped_txids": ["d7b667bb93898b1d3eba4fee86617b06b95772b192f3643256dd0821b476e36f"],
  "reason": "ReplaceByFee"
}
```

Reason can be one of:

* `ReplaceByFee` - replaced by a transaction with the same nonce, but a higher fee
* `ReplaceAcrossFork` - replaced by a transaction with the same nonce but in the canonical fork
* `TooExpensive` - the transaction is too expensive to include in a block
* `StaleGarbageCollect` - transaction was dropped because it became stale

### `POST /stackerdb_chunks`

Delivers data related to mutations in a StackerDB replica this node subscribes to.
*   **Triggered by keys**: `"stackerdb"`.
*   **Payload Summary**: Contains the contract ID and an array of modified StackerDB slots, each with ID, version, signature, and data.
*   **Note**:
    * **Not** included in `*`.
    * The data will only get sent if the corresponding chunk has already been successfully stored.

*Example Payload:*

```json
{
   "contract_id": "STVN97YYA10MY5F6KQJHKNYJNM24C4A1AT39WRW.hello-world",
   "modified_slots": [
      {
         "slot_id": 4,
         "slot_version": 1,
         "signature": "0073feb0a3b8794c95042ac23734eb0db226049665a52a4f7402499256c83d43dd4edf6eb2cb039d7f204b4c4076afde96aca143ea285ff40f10ed68cc6e5fcbc2",
         "data": "68656c6c6f20776f726c64"
      }
   ]
}
```

### `POST /attachments/new`
Delivers information about new AtlasDB attachments processed by the node.
*   **Triggered by**: Implicitly for all observers.
*   **Payload Summary**: A JSON array, where each object represents an attachment and includes its index, block details, content hash, contract ID, metadata, transaction ID, and raw content.

*Example Payload:*
```json
[
  {
    "attachment_index": 123,
    "index_block_hash": "0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
    "block_height": 75000,
    "content_hash": "0x112233445566778899aabbccddeeff0011223344",
    "contract_id": "ST0000000000000000000000000000000000000000.bns",
    "metadata": "0x0c0000000301000000086e616d6573706163650d0000000362746301000000046e616d650d0000000473617473",
    "tx_id": "0xfedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
    "content": "0x48656c6c6f2041746c617321"
  },
  {
    "attachment_index": 124,
    "index_block_hash": "0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
    "block_height": 75000,
    "content_hash": "0xaabbccddeeff00112233445566778899aabbccdd",
    "contract_id": "ST0000000000000000000000000000000000000000.bns",
    "metadata": "0x0c0000000301000000086e616d6573706163650d0000000373747801000000046e616d650d00000005737461636b73",
    "tx_id": "0xfedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
    "content": "0x416e6f74686572204174746163686d656e74"
  }
]

```

### `POST /proposal_response`
Delivers the validation response for a block proposal submitted to this node (relevant for Nakamoto consensus).
*   **Triggered by keys**: `"block_proposal"`.
*   **Payload Summary**: Contains the result of the block validation, which can be an acceptance (`BlockValidateOk`) or rejection (`BlockValidateReject`) with details.
*   **Note**: **Not** included in `*`.

*Example Payload:*
```json
{
    "result": "Ok",
    "block": "00000000000000001f00000000000927c08fb5ae5bf80e39e4168f6a3fddb0407a069d21ee68465e6856393254d2a66194f44bb01070666d5effcfb2436e209a75878fe80a04b4258a8cd34ab97c38a8dde331a2a509dd7e4b90590726866172cc138c18e80567737667f55d3f9817ce4714c91d1adfd36101141829dc0b5ea0c4944668c0005ddb6f9e2718f60014f21932a42a36ffaf58e88e77b217b2af366c15dd59e6b136ca773729832dcfc5875ec0830d04012dd5a4fa77a196646ea2b356289116fd02558c034b62d63f8a65bdd20d7ffc3fec6c266cd974be776a9e92759b90f288dcc2525b6b6bd5622c5f02e0922440e9ad1095c19b4467fd94566caa9755669d8e0000000180800000000400f64081ae6209dce9245753a4f764d6f168aae1af00000000000000000000000000000064000041dbcc7391991c1a18371eb49b879240247a3ec7f281328f53976c1218ffd65421dbb101e59370e2c972b29f48dc674b2de5e1b65acbd41d5d2689124d42c16c01010000000000051a346048df62be3a52bb6236e11394e8600229e27b000000000000271000000000000000000000000000000000000000000000000000000000000000000000",
    "cost": {
        "read_count": 8,
        "read_length":133954,
        "runtime":139720,
        "write_count":2,
        "write_length":114
    },
    "size": 180
}
```
