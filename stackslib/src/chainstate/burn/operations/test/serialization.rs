use clarity::vm::types::PrincipalData;
use serde_json::Value;
use stacks_common::address::C32_ADDRESS_VERSION_MAINNET_SINGLESIG;
use stacks_common::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, ConsensusHash, StacksAddress, StacksBlockId, VRFSeed,
};
use stacks_common::types::{Address, StacksPublicKeyBuffer};
use stacks_common::util::hash::Hash160;
use stacks_common::util::secp256k1::MessageSignature;

use crate::burnchains::Txid;
use crate::chainstate::burn::operations::{
    BlockstackOperationType, DelegateStxOp, PreStxOp, StackStxOp, TransferStxOp,
    VoteForAggregateKeyOp,
};
use crate::chainstate::stacks::address::{PoxAddress, PoxAddressType32};

#[test]
fn test_serialization_transfer_stx_op() {
    let sender_addr = "ST2QKZ4FKHAH1NQKYKYAYZPY440FEPK7GZ1R5HBP2";
    let sender = StacksAddress::from_string(sender_addr).unwrap();
    let recipient_addr = "SP24ZBZ8ZE6F48JE9G3F3HRTG9FK7E2H6K2QZ3Q1K";
    let recipient = StacksAddress::from_string(recipient_addr).unwrap();
    let op = TransferStxOp {
        sender,
        recipient,
        transfered_ustx: 10,
        memo: vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05],
        txid: Txid([10u8; 32]),
        vtxindex: 10,
        block_height: 10,
        burn_header_hash: BurnchainHeaderHash([0x10; 32]),
    };
    let serialized_json = BlockstackOperationType::transfer_stx_to_json(&op);
    let constructed_json = serde_json::json!({
        "transfer_stx": {
            "burn_block_height": 10,
            "burn_header_hash": "1010101010101010101010101010101010101010101010101010101010101010",
            "memo": "0x000102030405",
            "recipient": {
                "address": "SP24ZBZ8ZE6F48JE9G3F3HRTG9FK7E2H6K2QZ3Q1K",
                "address_hash_bytes": "0x89f5fd1f719e4449c980de38e3504be6770a2698",
                "address_version": 22,
            },
            "sender": {
                "address": "ST2QKZ4FKHAH1NQKYKYAYZPY440FEPK7GZ1R5HBP2",
                "address_hash_bytes": "0xaf3f91f38aa21ade7e9f95efdbc4201eeb4cf0f8",
                "address_version": 26,
            },
            "transfered_ustx": 10,
            "burn_txid": "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
            "vtxindex": 10,
        }
    });

    assert_json_diff::assert_json_eq!(serialized_json, constructed_json);
}

#[test]
fn test_serialization_stack_stx_op() {
    let sender_addr = "ST2QKZ4FKHAH1NQKYKYAYZPY440FEPK7GZ1R5HBP2";
    let sender = StacksAddress::from_string(sender_addr).unwrap();
    let reward_addr = PoxAddress::Standard(
        StacksAddress {
            version: C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
            bytes: Hash160([0x01; 20]),
        },
        None,
    );

    let op = StackStxOp {
        sender,
        reward_addr,
        stacked_ustx: 10,
        txid: Txid([10u8; 32]),
        vtxindex: 10,
        block_height: 10,
        burn_header_hash: BurnchainHeaderHash([0x10; 32]),
        num_cycles: 10,
        signer_key: None,
        max_amount: None,
        auth_id: None,
    };
    let serialized_json = BlockstackOperationType::stack_stx_to_json(&op);
    let constructed_json = serde_json::json!({
        "stack_stx": {
            "burn_block_height": 10,
            "burn_header_hash": "1010101010101010101010101010101010101010101010101010101010101010",
            "num_cycles": 10,
            "reward_addr": "16Jswqk47s9PUcyCc88MMVwzgvHPvtEpf",
            "sender": {
                "address": "ST2QKZ4FKHAH1NQKYKYAYZPY440FEPK7GZ1R5HBP2",
                "address_hash_bytes": "0xaf3f91f38aa21ade7e9f95efdbc4201eeb4cf0f8",
                "address_version": 26,
            },
            "stacked_ustx": 10,
            "burn_txid": "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
            "vtxindex": 10,
            "signer_key": null,
            "max_amount": null,
            "auth_id": null,
        }
    });

    assert_json_diff::assert_json_eq!(serialized_json, constructed_json);
}

#[test]
fn test_serialization_stack_stx_op_with_signer_key() {
    let sender_addr = "ST2QKZ4FKHAH1NQKYKYAYZPY440FEPK7GZ1R5HBP2";
    let sender = StacksAddress::from_string(sender_addr).unwrap();
    let reward_addr = PoxAddress::Standard(
        StacksAddress {
            version: C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
            bytes: Hash160([0x01; 20]),
        },
        None,
    );

    let op = StackStxOp {
        sender,
        reward_addr,
        stacked_ustx: 10,
        txid: Txid([10u8; 32]),
        vtxindex: 10,
        block_height: 10,
        burn_header_hash: BurnchainHeaderHash([0x10; 32]),
        num_cycles: 10,
        signer_key: Some(StacksPublicKeyBuffer([0x01; 33])),
        max_amount: Some(10),
        auth_id: Some(0u32),
    };
    let serialized_json = BlockstackOperationType::stack_stx_to_json(&op);
    let constructed_json = serde_json::json!({
        "stack_stx": {
            "burn_block_height": 10,
            "burn_header_hash": "1010101010101010101010101010101010101010101010101010101010101010",
            "num_cycles": 10,
            "reward_addr": "16Jswqk47s9PUcyCc88MMVwzgvHPvtEpf",
            "sender": {
                "address": "ST2QKZ4FKHAH1NQKYKYAYZPY440FEPK7GZ1R5HBP2",
                "address_hash_bytes": "0xaf3f91f38aa21ade7e9f95efdbc4201eeb4cf0f8",
                "address_version": 26,
            },
            "stacked_ustx": 10,
            "burn_txid": "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
            "vtxindex": 10,
            "signer_key": "01".repeat(33),
            "max_amount": 10,
            "auth_id": 0,
        }
    });

    assert_json_diff::assert_json_eq!(serialized_json, constructed_json);
}

#[test]
fn test_serialization_pre_stx_op() {
    let output_addr = "ST2QKZ4FKHAH1NQKYKYAYZPY440FEPK7GZ1R5HBP2";
    let output = StacksAddress::from_string(output_addr).unwrap();

    let op = PreStxOp {
        output,
        txid: Txid([10u8; 32]),
        vtxindex: 10,
        block_height: 10,
        burn_header_hash: BurnchainHeaderHash([0x10; 32]),
    };
    let serialized_json = BlockstackOperationType::pre_stx_to_json(&op);
    let constructed_json = serde_json::json!({
        "pre_stx": {
            "burn_block_height": 10,
            "burn_header_hash": "1010101010101010101010101010101010101010101010101010101010101010",
            "output": {
                "address": "ST2QKZ4FKHAH1NQKYKYAYZPY440FEPK7GZ1R5HBP2",
                "address_hash_bytes": "0xaf3f91f38aa21ade7e9f95efdbc4201eeb4cf0f8",
                "address_version": 26,
            },
            "burn_txid": "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
            "vtxindex": 10,
        }
    });

    assert_json_diff::assert_json_eq!(serialized_json, constructed_json);
}

#[test]
fn test_serialization_delegate_stx_op() {
    let sender_addr = "ST2QKZ4FKHAH1NQKYKYAYZPY440FEPK7GZ1R5HBP2";
    let sender = StacksAddress::from_string(sender_addr).unwrap();
    let delegate_to_addr = "SP24ZBZ8ZE6F48JE9G3F3HRTG9FK7E2H6K2QZ3Q1K";
    let delegate_to = StacksAddress::from_string(delegate_to_addr).unwrap();
    let pox_addr = PoxAddress::Standard(
        StacksAddress {
            version: C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
            bytes: Hash160([0x01; 20]),
        },
        None,
    );
    let op = DelegateStxOp {
        sender,
        delegate_to,
        reward_addr: Some((10, pox_addr)),
        delegated_ustx: 10,
        until_burn_height: None,
        txid: Txid([10u8; 32]),
        vtxindex: 10,
        block_height: 10,
        burn_header_hash: BurnchainHeaderHash([0x10; 32]),
    };
    let serialized_json = BlockstackOperationType::delegate_stx_to_json(&op);
    let constructed_json = serde_json::json!({
        "delegate_stx": {
            "burn_block_height": 10,
            "burn_header_hash": "1010101010101010101010101010101010101010101010101010101010101010",
            "delegate_to": {
                "address": "SP24ZBZ8ZE6F48JE9G3F3HRTG9FK7E2H6K2QZ3Q1K",
                "address_hash_bytes": "0x89f5fd1f719e4449c980de38e3504be6770a2698",
                "address_version": 22,
            },
            "delegated_ustx": 10,
            "sender": {
                "address": "ST2QKZ4FKHAH1NQKYKYAYZPY440FEPK7GZ1R5HBP2",
                "address_hash_bytes": "0xaf3f91f38aa21ade7e9f95efdbc4201eeb4cf0f8",
                "address_version": 26,
            },
            "reward_addr": [10, "16Jswqk47s9PUcyCc88MMVwzgvHPvtEpf"],
            "burn_txid": "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
            "until_burn_height": null,
            "vtxindex": 10,
        }
    });

    assert_json_diff::assert_json_eq!(serialized_json, constructed_json);
}

#[test]
fn test_serialization_vote_for_aggregate_key_op() {
    let sender_addr = "ST2QKZ4FKHAH1NQKYKYAYZPY440FEPK7GZ1R5HBP2";
    let sender = StacksAddress::from_string(sender_addr).unwrap();
    let op = VoteForAggregateKeyOp {
        sender,
        reward_cycle: 10,
        round: 1,
        signer_index: 12,
        signer_key: StacksPublicKeyBuffer([0x01; 33]),
        aggregate_key: StacksPublicKeyBuffer([0x02; 33]),
        txid: Txid([10u8; 32]),
        vtxindex: 10,
        block_height: 10,
        burn_header_hash: BurnchainHeaderHash([0x10; 32]),
    };
    // Test both the generic and specific serialization fns
    let serialized_json = BlockstackOperationType::blockstack_op_to_json(
        &BlockstackOperationType::VoteForAggregateKey(op.clone()),
    );
    let specialized_json_fn = BlockstackOperationType::vote_for_aggregate_key_to_json(&op);
    let constructed_json = serde_json::json!({
        "vote_for_aggregate_key": {
            "aggregate_key": "02".repeat(33),
            "burn_block_height": 10,
            "burn_header_hash": "1010101010101010101010101010101010101010101010101010101010101010",
            "reward_cycle": 10,
            "round": 1,
            "sender": {
                "address": "ST2QKZ4FKHAH1NQKYKYAYZPY440FEPK7GZ1R5HBP2",
                "address_hash_bytes": "0xaf3f91f38aa21ade7e9f95efdbc4201eeb4cf0f8",
                "address_version": 26,
            },
            "signer_index": 12,
            "signer_key": "01".repeat(33),
            "burn_txid": "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
            "vtxindex": 10,
        }
    });

    assert_json_diff::assert_json_eq!(specialized_json_fn, constructed_json.clone());
    assert_json_diff::assert_json_eq!(serialized_json, constructed_json);
}
