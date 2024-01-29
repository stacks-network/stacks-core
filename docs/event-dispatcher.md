# Event dispatching / observer interface

The `stacks-node` supports a configurable event observer interface.
This is enabled by adding an entry to the node's `config.toml` file:

```toml
...
[[events_observer]]
endpoint = "listener:3700"
events_keys = [
  "*"
]
...
```

The `stacks-node` will then execute HTTP POSTs to the configured
endpoint in two events:

1. A new Stacks block is processed.
2. New mempool transactions have been received.

These events are sent to the configured endpoint at two URLs:


### `POST /new_block`

This payload includes data related to a newly processed block,
and any events emitted from Stacks transactions during the block.

If the transaction originally comes from the parent microblock stream 
preceding this block, the microblock related fields will be filled in.

If the `raw_tx` field for a particular transaction is "0x00", that indicates
that it is a burnchain operation. A burnchain operation is a transaction that 
is executed on the Stacks network, but was sent through the Bitcoin network.
The Stacks network supports a few specific burnchain operations. You can read 
more about them [here](https://github.com/stacksgov/sips/blob/main/sips/sip-007/sip-007-stacking-consensus.md#stx-operations-on-bitcoin).
The section below has example json encodings for each of the burnchain operations.

Example:

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

#### Example json values for burnchain operations 
- TransferStx 
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

- StackStx
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

- DelegateStx
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

### `POST /new_burn_block`

This payload includes information about burn blocks as their sortitions are processed.
In the event of PoX forks, a `new_burn_block` event may be triggered for a burn block
previously processed.

Example:

```json
{
  "burn_block_hash": "0x4eaabcd105865e471f697eff5dd5bd85d47ecb5a26a3379d74fae0ae87c40904",
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

This payload includes data related to one or more microblocks that are either emmitted by the 
node itself, or received through the network. 

Example:

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

This payload includes raw transactions newly received in the
node's mempool.

Example:

```json
[
  "0x80800000000400f942874ce525e87f21bbe8c121b12fac831d02f4000000000000000000000000000003e800006ae29867aec4b0e4f776bebdcea7f6d9a24eeff370c8c739defadfcbb52659b30736ad4af021e8fb741520a6c65da419fdec01989fdf0032fc1838f427a9a36102010000000000051ac2d519faccba2e435f3272ff042b89435fd160ff00000000000003e800000000000000000000000000000000000000000000000000000000000000000000"
]
```


### `POST /drop_mempool_tx`

This payload includes raw transactions newly received in the
node's mempool.

Example:

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

### `POST /mined_block`

This payload includes data related to block mined by this Stacks node. This
will never be invoked if the node is configured only as a follower. This is invoked
when the miner **assembles** the block; this block may or may not win the sortition.

This endpoint will only broadcast events to observers that explicitly register for
`MinedBlocks` events, `AnyEvent` observers will not receive the events by default.

Example:

```json
{
  "block_hash": "0x4eaabcd105865e471f697eff5dd5bd85d47ecb5a26a3379d74fae0ae87c40904",
  "stacks_height": 3,
  "target_burn_height": 745000,
  "block_size": 145000,
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
  },
  "tx_events": [
    {
      "Success": {
        "txid": "3e04ada5426332bfef446ba0a06d124aace4ade5c11840f541bf88e2e919faf6", 
        "fee": 0, 
        "execution_cost": { 
          "write_length": 0, 
          "write_count": 0, 
          "read_length": 0, 
          "read_count": 0, 
          "runtime": 0
        }, 
        "result": {
          "ResponseData": 
          {
            "committed": true,
            "data": true
          }
        }
    }}, 
    {
      "ProcessingError": {
        "txid": "eef9f46b20fb637bd07ec92ad3ec175a5a4bdf3e8799259fc5b16a272090d4de",
        "error": "Duplicate contract 'ST3BMYNT1DW2QSRZWB6M4S183NK1BXGJ41TEBCCH8.example'"
      }
    }
  ]
}
```

### `POST /mined_microblock`

This payload includes data related to microblocks mined by this Stacks node. This
will never be invoked if the node is configured only as a follower. This is invoked
when the miner **assembles** the microblock; this microblock may or may be incorporated
into the canonical chain.

This endpoint will only broadcast events to observers that explicitly register for
`MinedMicroblocks` events, `AnyEvent` observers will not receive the events by default.

Example:

```json
{
  "block_hash": "0x4eaabcd105865e471f697eff5dd5bd85d47ecb5a26a3379d74fae0ae87c40904",
  "sequence": 3,
  "anchor_block_consensus_hash": "53c166a709a9abd64a92a57f928a8b26aad08992",
  "anchor_block": "43dbf6095c7622db6607d9584c3f65e908ca4eb77d86ee8cc1352aafec5d68b5",
  "tx_events": [
    {
      "Success": {
        "txid": "3e04ada5426332bfef446ba0a06d124aace4ade5c11840f541bf88e2e919faf6", 
        "fee": 0, 
        "execution_cost": { 
          "write_length": 10, 
          "write_count": 10, 
          "read_length": 20, 
          "read_count": 10, 
          "runtime": 1290
        }, 
        "result": {
          "ResponseData": 
          {
            "committed": true,
            "data": true
          }
        }
    }}, 
    {
      "Skipped": {
        "txid": "eef9f46b20fb637bd07ec92ad3ec175a5a4bdf3e8799259fc5b16a272090d4de",
        "reason": "tx.anchor_mode does not support microblocks, anchor_mode=OnChainOnly."
      }
    }
  ]
}
```

### `POST /stackerdb_chunks`

This payload includes data related to a single mutation to a StackerDB replica
that this node subscribes to.  The data will only get sent here if the
corresponding chunk has already been successfully stored.  The data includes the
chunk ID, chunk version, smart contract ID, signature, and data.

This endpoint broadcasts events to `AnyEvent` observers, as well as to
`StackerDBChunks` observers.

Example:

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
