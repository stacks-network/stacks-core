use clarity::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, ConsensusHash, StacksAddress, VRFSeed,
};
use clarity::types::StacksPublicKeyBuffer;
use clarity::util::vrf::{VRFPrivateKey, VRFPublicKey};
use rand::rngs::StdRng;
use rand::SeedableRng;
use stacks_common::util::hash::Hash160;

use crate::burnchains::bitcoin::address::{BitcoinAddress, SegwitBitcoinAddress};
use crate::burnchains::bitcoin::{
    BitcoinInputType, BitcoinNetworkType, BitcoinTransaction, BitcoinTxInputStructured,
    BitcoinTxOutput,
};
use crate::burnchains::{BurnchainBlockHeader, BurnchainSigner, BurnchainTransaction, Txid};
use crate::chainstate::burn::operations::{
    blockstack_op_extended_deserialize, blockstack_op_extended_serialize_opt,
    BlockstackOperationType, DelegateStxOp, LeaderBlockCommitOp, LeaderKeyRegisterOp, PreStxOp,
    StackStxOp, TransferStxOp, VoteForAggregateKeyOp,
};
use crate::chainstate::burn::Opcodes;
use crate::chainstate::stacks::address::PoxAddress;

mod serialization;

pub(crate) fn seeded_rng() -> StdRng {
    SeedableRng::from_seed([0; 32])
}

pub(crate) fn random_bytes<Rng: rand::Rng, const N: usize>(rng: &mut Rng) -> [u8; N] {
    [rng.gen(); N]
}

pub(crate) fn burnchain_block_header() -> BurnchainBlockHeader {
    BurnchainBlockHeader {
        block_height: 0,
        block_hash: [0; 32].into(),
        parent_block_hash: [0; 32].into(),
        num_txs: 0,
        timestamp: 0,
    }
}

pub(crate) fn burnchain_transaction(
    data: Vec<u8>,
    outputs: impl IntoIterator<Item = Output>,
    opcode: Opcodes,
) -> BurnchainTransaction {
    BurnchainTransaction::Bitcoin(bitcoin_transaction(data, outputs, opcode))
}

fn bitcoin_transaction(
    data: Vec<u8>,
    outputs: impl IntoIterator<Item = Output>,
    opcode: Opcodes,
) -> BitcoinTransaction {
    BitcoinTransaction {
        txid: Txid([0; 32]),
        vtxindex: 0,
        opcode: opcode as u8,
        data,
        data_amt: 0,
        inputs: vec![BitcoinTxInputStructured {
            keys: vec![],
            num_required: 0,
            in_type: BitcoinInputType::Standard,
            tx_ref: (Txid([0; 32]), 2),
        }
        .into()],
        outputs: outputs
            .into_iter()
            .map(|output2data| output2data.as_bitcoin_tx_output())
            .collect(),
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Output {
    amount: u64,
    address: [u8; 32],
}

impl Output {
    pub(crate) fn new(amount: u64, peg_wallet_address: [u8; 32]) -> Self {
        Self {
            amount,
            address: peg_wallet_address,
        }
    }
    pub(crate) fn as_bitcoin_tx_output(&self) -> BitcoinTxOutput {
        BitcoinTxOutput {
            units: self.amount,
            address: BitcoinAddress::Segwit(SegwitBitcoinAddress::P2TR(
                BitcoinNetworkType::Mainnet,
                self.address,
            )),
        }
    }
}

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
            memo: vec![].into(),
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
                memo: vec![].into(),
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
                memo: vec![].into(),
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
