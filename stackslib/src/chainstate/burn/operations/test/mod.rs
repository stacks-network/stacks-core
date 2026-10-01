use clarity::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, ConsensusHash, StacksAddress, VRFSeed,
};
use clarity::types::StacksPublicKeyBuffer;
use clarity::util::vrf::{VRFPrivateKey, VRFPublicKey};
use stacks_common::util::hash::Hash160;

use crate::burnchains::{BurnchainSigner, Txid};
use crate::chainstate::burn::operations::{
    blockstack_op_extended_deserialize, blockstack_op_extended_serialize_opt,
    BlockstackOperationType, DelegateStxOp, LeaderBlockCommitOp, LeaderKeyRegisterOp, PreStxOp,
    StackStxOp, TransferStxOp, VoteForAggregateKeyOp,
};
use crate::chainstate::stacks::address::PoxAddress;

mod serialization;

#[test]
fn serde_blockstack_ops() {
    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    struct TestOpHolder {
        #[serde(
            serialize_with = "blockstack_op_extended_serialize_opt",
            deserialize_with = "blockstack_op_extended_deserialize"
        )]
        burnchain_op: Option<BlockstackOperationType>,
    }
    let holder = TestOpHolder {
        burnchain_op: Some(BlockstackOperationType::PreStx(PreStxOp {
            output: StacksAddress::new(0, Hash160([2u8; 20]))
                .expect("Unable to create StacksAddress"),
            txid: Txid([3u8; 32]),
            vtxindex: 1,
            block_height: 20,
            burn_header_hash: BurnchainHeaderHash([4u8; 32]),
        })),
    };
    let json_str = serde_json::to_string_pretty(&holder).expect("Failed to convert to json string");

    let deserialized: TestOpHolder =
        serde_json::from_str(&json_str).expect("Failed to deserialize PreStxOp");
    assert_eq!(holder, deserialized);

    let holder = TestOpHolder {
        burnchain_op: Some(BlockstackOperationType::DelegateStx(DelegateStxOp {
            sender: StacksAddress::new(0, Hash160([2u8; 20]))
                .expect("Unable to create StacksAddress"),
            delegate_to: StacksAddress::new(1, Hash160([10u8; 20]))
                .expect("Unable ot create StacksAddress"),
            reward_addr: Some((
                30,
                PoxAddress::Standard(StacksAddress::new(22, Hash160([0x01; 20])).unwrap(), None),
            )),
            delegated_ustx: 200,
            until_burn_height: None,
            txid: Txid([3u8; 32]),
            vtxindex: 1,
            block_height: 20,
            burn_header_hash: BurnchainHeaderHash([4u8; 32]),
        })),
    };
    let json_str = serde_json::to_string_pretty(&holder).expect("Failed to convert to json string");

    let deserialized: TestOpHolder =
        serde_json::from_str(&json_str).expect("Failed to deserialize DelegateStxOp");
    assert_eq!(holder, deserialized);

    let holder = TestOpHolder {
        burnchain_op: Some(BlockstackOperationType::StackStx(StackStxOp {
            sender: StacksAddress::new(0, Hash160([2u8; 20]))
                .expect("Unable to create StacksAddress"),
            reward_addr: PoxAddress::Standard(
                StacksAddress::new(22, Hash160([0x01; 20])).unwrap(),
                None,
            ),
            stacked_ustx: 42,
            num_cycles: 3,
            max_amount: None,
            signer_key: None,
            auth_id: None,
            txid: Txid([3u8; 32]),
            vtxindex: 1,
            block_height: 20,
            burn_header_hash: BurnchainHeaderHash([4u8; 32]),
        })),
    };
    let json_str = serde_json::to_string_pretty(&holder).expect("Failed to convert to json string");

    let deserialized: TestOpHolder =
        serde_json::from_str(&json_str).expect("Failed to deserialize json value into StackStxOp");
    assert_eq!(holder, deserialized);

    let holder = TestOpHolder {
        burnchain_op: Some(BlockstackOperationType::TransferStx(TransferStxOp {
            sender: StacksAddress::new(0, Hash160([2u8; 20]))
                .expect("Unable to create StacksAddress"),
            recipient: StacksAddress::new(0, Hash160([6u8; 20]))
                .expect("Unable to create StacksAddress"),
            transfered_ustx: 20,
            memo: vec![],
            txid: Txid([3u8; 32]),
            vtxindex: 1,
            block_height: 20,
            burn_header_hash: BurnchainHeaderHash([4u8; 32]),
        })),
    };
    let json_str = serde_json::to_string_pretty(&holder).expect("Failed to convert to json string");

    let deserialized: TestOpHolder = serde_json::from_str(&json_str)
        .expect("Failed to deserialize json value into TransferStxOp");
    assert_eq!(holder, deserialized);

    let holder = TestOpHolder {
        burnchain_op: Some(BlockstackOperationType::VoteForAggregateKey(
            VoteForAggregateKeyOp {
                sender: StacksAddress::new(0, Hash160([2u8; 20]))
                    .expect("Unable to create StacksAddress"),
                aggregate_key: StacksPublicKeyBuffer([3u8; 33]),
                round: 10,
                signer_index: 11,
                reward_cycle: 2,
                signer_key: StacksPublicKeyBuffer([2u8; 33]),
                txid: Txid([3u8; 32]),
                vtxindex: 1,
                block_height: 20,
                burn_header_hash: BurnchainHeaderHash([4u8; 32]),
            },
        )),
    };
    let json_str = serde_json::to_string_pretty(&holder).expect("Failed to convert to json string");

    let deserialized: TestOpHolder = serde_json::from_str(&json_str)
        .expect("Failed to deserialize json value into VoteForAggregateKeyOp");
    assert_eq!(holder, deserialized);

    let holder = TestOpHolder {
        burnchain_op: Some(BlockstackOperationType::LeaderBlockCommit(
            LeaderBlockCommitOp {
                block_header_hash: BlockHeaderHash([8u8; 32]),
                new_seed: VRFSeed([12u8; 32]),
                txid: Txid([3u8; 32]),
                parent_block_ptr: 1,
                parent_vtxindex: 2,
                key_block_ptr: 3,
                key_vtxindex: 4,
                memo: vec![],
                burn_fee: 5,
                vtxindex: 1,
                input: (Txid([1u8; 32]), 1),
                block_height: 20,
                burn_parent_modulus: 6,
                apparent_sender: BurnchainSigner("Hello there".into()),
                commit_outs: vec![],
                treatment: vec![],
                sunset_burn: 6,
                burn_header_hash: BurnchainHeaderHash([4u8; 32]),
            },
        )),
    };
    let json_str = serde_json::to_string_pretty(&holder).expect("Failed to convert to json string");
    let deserialized: TestOpHolder = serde_json::from_str(&json_str)
        .expect("Failed to deserialize json value into LeaderBlockCommitOp");
    assert!(deserialized.burnchain_op.is_none());

    let holder = TestOpHolder {
        burnchain_op: Some(BlockstackOperationType::LeaderKeyRegister(
            LeaderKeyRegisterOp {
                consensus_hash: ConsensusHash([0u8; 20]),
                public_key: VRFPublicKey::from_private(&VRFPrivateKey::new()),
                memo: vec![],
                txid: Txid([3u8; 32]),
                vtxindex: 0,
                block_height: 1,
                burn_header_hash: BurnchainHeaderHash([9u8; 32]),
            },
        )),
    };
    let json_str = serde_json::to_string_pretty(&holder).expect("Failed to convert to json string");
    let deserialized: TestOpHolder = serde_json::from_str(&json_str)
        .expect("Failed to deserialize json value into LeaderBlockCommitOp");
    assert!(deserialized.burnchain_op.is_none());
}
