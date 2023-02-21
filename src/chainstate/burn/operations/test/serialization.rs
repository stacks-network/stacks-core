use crate::burnchains::Txid;
use crate::chainstate::burn::operations::{
    BlockstackOperationType, DelegateStxOp, PegInOp, PreStxOp, StackStxOp, TransferStxOp,
};
use crate::chainstate::stacks::address::{PoxAddress, PoxAddressType32};
use crate::net::BurnchainOps;
use clarity::vm::types::PrincipalData;
use serde_json::Value;
use stacks_common::address::C32_ADDRESS_VERSION_MAINNET_SINGLESIG;
use stacks_common::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, ConsensusHash, StacksAddress, VRFSeed,
};
use stacks_common::types::Address;
use stacks_common::util::hash::Hash160;

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
/// Test the serialization and deserialization of PegIn operations in `BurnchainOps`
///  using JSON string fixtures
fn serialization_peg_in_in_ops() {
    let test_cases = [
        (
            r#"
                {
                    "peg_in": [
                    {
                        "amount": 1337,
                        "block_height": 218,
                        "burn_header_hash": "3292a7d2a7e941499b5c0dcff2a5656c159010718450948a60c2be9e1c221dc4",
                        "memo": "0001020304",
                        "peg_wallet_address": "1111111111111111111114oLvT2",
                        "recipient": "S0000000000000000000002AA028H.awesome_contract",
                        "txid": "d81bec73a0ea0bdcf9bc011f567944eb1eae5889bf002bf7ae641d7096157771",
                        "vtxindex": 2
                    }
                    ]
                }
            "#,
            PegInOp {
                recipient: PrincipalData::parse("S0000000000000000000002AA028H.awesome_contract")
                    .unwrap(),
                peg_wallet_address: PoxAddress::Standard(StacksAddress::burn_address(true), None),
                amount: 1337,
                memo: vec![0, 1, 2, 3, 4],
                txid: Txid::from_hex(
                    "d81bec73a0ea0bdcf9bc011f567944eb1eae5889bf002bf7ae641d7096157771",
                )
                .unwrap(),
                vtxindex: 2,
                block_height: 218,
                burn_header_hash: BurnchainHeaderHash::from_hex(
                    "3292a7d2a7e941499b5c0dcff2a5656c159010718450948a60c2be9e1c221dc4",
                )
                .unwrap(),
            },
        ),
        (
            r#"
                {
                    "peg_in": [
                    {
                        "amount": 1337,
                        "block_height": 218,
                        "burn_header_hash": "3292a7d2a7e941499b5c0dcff2a5656c159010718450948a60c2be9e1c221dc4",
                        "memo": "",
                        "peg_wallet_address": "tb1pqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkgkkf5",
                        "recipient": "S0000000000000000000002AA028H.awesome_contract",
                        "txid": "d81bec73a0ea0bdcf9bc011f567944eb1eae5889bf002bf7ae641d7096157771",
                        "vtxindex": 2
                    }
                    ]
                }
            "#,
            PegInOp {
                recipient: PrincipalData::parse("S0000000000000000000002AA028H.awesome_contract")
                    .unwrap(),
                peg_wallet_address: PoxAddress::Addr32(false, PoxAddressType32::P2TR, [0; 32]),
                amount: 1337,
                memo: vec![],
                txid: Txid::from_hex(
                    "d81bec73a0ea0bdcf9bc011f567944eb1eae5889bf002bf7ae641d7096157771",
                )
                .unwrap(),
                vtxindex: 2,
                block_height: 218,
                burn_header_hash: BurnchainHeaderHash::from_hex(
                    "3292a7d2a7e941499b5c0dcff2a5656c159010718450948a60c2be9e1c221dc4",
                )
                .unwrap(),
            },
        ),
        (
            r#"
                {
                    "peg_in": [
                    {
                        "amount": 1337,
                        "block_height": 218,
                        "burn_header_hash": "3292a7d2a7e941499b5c0dcff2a5656c159010718450948a60c2be9e1c221dc4",
                        "memo": "",
                        "peg_wallet_address": "tb1qqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvps3f3cyq",
                        "recipient": "S0000000000000000000002AA028H",
                        "txid": "d81bec73a0ea0bdcf9bc011f567944eb1eae5889bf002bf7ae641d7096157771",
                        "vtxindex": 2
                    }
                    ]
                }
            "#,
            PegInOp {
                recipient: PrincipalData::parse("S0000000000000000000002AA028H").unwrap(),
                peg_wallet_address: PoxAddress::Addr32(false, PoxAddressType32::P2WSH, [3; 32]),
                amount: 1337,
                memo: vec![],
                txid: Txid::from_hex(
                    "d81bec73a0ea0bdcf9bc011f567944eb1eae5889bf002bf7ae641d7096157771",
                )
                .unwrap(),
                vtxindex: 2,
                block_height: 218,
                burn_header_hash: BurnchainHeaderHash::from_hex(
                    "3292a7d2a7e941499b5c0dcff2a5656c159010718450948a60c2be9e1c221dc4",
                )
                .unwrap(),
            },
        ),
    ];

    for (expected_json, op) in test_cases {
        // Test that op serializes to a JSON value equal to expected_json
        assert_json_diff::assert_json_eq!(
            serde_json::from_str::<Value>(expected_json).unwrap(),
            BurnchainOps::PegIn(vec![op.clone()])
        );

        // Test that expected JSON deserializes into a BurnchainOps that is equal to op
        assert_eq!(
            serde_json::from_str::<BurnchainOps>(expected_json).unwrap(),
            BurnchainOps::PegIn(vec![op])
        );
    }
}

#[test]
/// Test the serialization of PegIn operations via
/// `blockstack_op_to_json()` using JSON string fixtures
fn serialization_peg_in() {
    let test_cases = [
        (
            r#"
            {
                "peg_in":
                {
                    "amount": 1337,
                    "block_height": 218,
                    "burn_header_hash": "3292a7d2a7e941499b5c0dcff2a5656c159010718450948a60c2be9e1c221dc4",
                    "memo": "0001020304",
                    "peg_wallet_address": "1111111111111111111114oLvT2",
                    "recipient": "S0000000000000000000002AA028H.awesome_contract",
                    "txid": "d81bec73a0ea0bdcf9bc011f567944eb1eae5889bf002bf7ae641d7096157771",
                    "vtxindex": 2
                }
            }
        "#,
            PegInOp {
                recipient: PrincipalData::parse("S0000000000000000000002AA028H.awesome_contract")
                    .unwrap(),
                peg_wallet_address: PoxAddress::standard_burn_address(true),
                amount: 1337,
                memo: vec![0, 1, 2, 3, 4],
                txid: Txid::from_hex(
                    "d81bec73a0ea0bdcf9bc011f567944eb1eae5889bf002bf7ae641d7096157771",
                )
                .unwrap(),
                vtxindex: 2,
                block_height: 218,
                burn_header_hash: BurnchainHeaderHash::from_hex(
                    "3292a7d2a7e941499b5c0dcff2a5656c159010718450948a60c2be9e1c221dc4",
                )
                .unwrap(),
            },
        ),
        (
            r#"
            {
                "peg_in":
                {
                    "amount": 1337,
                    "block_height": 218,
                    "burn_header_hash": "3292a7d2a7e941499b5c0dcff2a5656c159010718450948a60c2be9e1c221dc4",
                    "memo": "",
                    "peg_wallet_address": "tb1pqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkgkkf5",
                    "recipient": "S0000000000000000000002AA028H.awesome_contract",
                    "txid": "d81bec73a0ea0bdcf9bc011f567944eb1eae5889bf002bf7ae641d7096157771",
                    "vtxindex": 2
                }
            }
            "#,
            PegInOp {
                recipient: PrincipalData::parse("S0000000000000000000002AA028H.awesome_contract")
                    .unwrap(),
                peg_wallet_address: PoxAddress::Addr32(false, PoxAddressType32::P2TR, [0; 32]),
                amount: 1337,
                memo: vec![],
                txid: Txid::from_hex(
                    "d81bec73a0ea0bdcf9bc011f567944eb1eae5889bf002bf7ae641d7096157771",
                )
                .unwrap(),
                vtxindex: 2,
                block_height: 218,
                burn_header_hash: BurnchainHeaderHash::from_hex(
                    "3292a7d2a7e941499b5c0dcff2a5656c159010718450948a60c2be9e1c221dc4",
                )
                .unwrap(),
            },
        ),
        (
            r#"
            {
                "peg_in":
                {
                    "amount": 1337,
                    "block_height": 218,
                    "burn_header_hash": "3292a7d2a7e941499b5c0dcff2a5656c159010718450948a60c2be9e1c221dc4",
                    "memo": "",
                    "peg_wallet_address": "tb1qqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvps3f3cyq",
                    "recipient": "S0000000000000000000002AA028H",
                    "txid": "d81bec73a0ea0bdcf9bc011f567944eb1eae5889bf002bf7ae641d7096157771",
                    "vtxindex": 2
                }
            }
            "#,
            PegInOp {
                recipient: PrincipalData::parse("S0000000000000000000002AA028H").unwrap(),
                peg_wallet_address: PoxAddress::Addr32(false, PoxAddressType32::P2WSH, [3; 32]),
                amount: 1337,
                memo: vec![],
                txid: Txid::from_hex(
                    "d81bec73a0ea0bdcf9bc011f567944eb1eae5889bf002bf7ae641d7096157771",
                )
                .unwrap(),
                vtxindex: 2,
                block_height: 218,
                burn_header_hash: BurnchainHeaderHash::from_hex(
                    "3292a7d2a7e941499b5c0dcff2a5656c159010718450948a60c2be9e1c221dc4",
                )
                .unwrap(),
            },
        ),
    ];

    for (expected_json, op) in test_cases {
        // Test that op serializes to a JSON value equal to expected_json
        assert_json_diff::assert_json_eq!(
            serde_json::from_str::<Value>(expected_json).unwrap(),
            BlockstackOperationType::PegIn(op).blockstack_op_to_json()
        );
    }
}
