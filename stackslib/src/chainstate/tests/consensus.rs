// Copyright (C) 2025 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
use std::cell::LazyCell;
use std::collections::HashMap;

use clarity::boot_util::boot_code_addr;
use clarity::codec::StacksMessageCodec;
use clarity::consts::{
    CHAIN_ID_TESTNET, PEER_VERSION_EPOCH_1_0, PEER_VERSION_EPOCH_2_0, PEER_VERSION_EPOCH_2_05,
    PEER_VERSION_EPOCH_2_1, PEER_VERSION_EPOCH_2_2, PEER_VERSION_EPOCH_2_3, PEER_VERSION_EPOCH_2_4,
    PEER_VERSION_EPOCH_2_5, PEER_VERSION_EPOCH_3_0, PEER_VERSION_EPOCH_3_1, PEER_VERSION_EPOCH_3_2,
    PEER_VERSION_EPOCH_3_3, STACKS_EPOCH_MAX,
};
use clarity::types::chainstate::{StacksAddress, StacksPrivateKey, StacksPublicKey, TrieHash};
use clarity::types::{StacksEpoch, StacksEpochId};
use clarity::util::hash::{MerkleTree, Sha512Trunc256Sum};
use clarity::util::secp256k1::MessageSignature;
use clarity::vm::ast::stack_depth_checker::AST_CALL_STACK_DEPTH_BUFFER;
use clarity::vm::costs::ExecutionCost;
use clarity::vm::types::PrincipalData;
use clarity::vm::{Value as ClarityValue, MAX_CALL_STACK_DEPTH};
use serde::{Deserialize, Serialize};
use stacks_common::bitvec::BitVec;

use crate::burnchains::PoxConstants;
use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::nakamoto::{NakamotoBlock, NakamotoBlockHeader, NakamotoChainState};
use crate::chainstate::stacks::boot::RewardSet;
use crate::chainstate::stacks::db::StacksEpochReceipt;
use crate::chainstate::stacks::{Error as ChainstateError, StacksTransaction, TenureChangeCause};
use crate::chainstate::tests::TestChainstate;
use crate::core::test_util::{make_contract_publish, make_stacks_transfer_tx};
use crate::core::{EpochList, BLOCK_LIMIT_MAINNET_21};
use crate::net::tests::NakamotoBootPlan;

pub const SK_1: &str = "a1289f6438855da7decf9b61b852c882c398cff1446b2a0f823538aa2ebef92e01";
pub const SK_2: &str = "4ce9a8f7539ea93753a36405b16e8b57e15a552430410709c2b6d65dca5c02e201";
pub const SK_3: &str = "cb95ddd0fe18ec57f4f3533b95ae564b3f1ae063dbf75b46334bd86245aef78501";

/// The private key for the faucet account.
pub const FAUCET_PRIV_KEY: LazyCell<StacksPrivateKey> = LazyCell::new(|| {
    StacksPrivateKey::from_hex("510f96a8efd0b11e211733c1ac5e3fa6f3d3fcdd62869e376c47decb3e14fea101")
        .expect("Failed to parse private key")
});

fn epoch_3_0_onwards(first_burnchain_height: u64) -> EpochList {
    info!("StacksEpoch unit_test first_burn_height = {first_burnchain_height}");

    EpochList::new(&[
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch10,
            start_height: 0,
            end_height: 0,
            block_limit: ExecutionCost::max_value(),
            network_epoch: PEER_VERSION_EPOCH_1_0,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch20,
            start_height: 0,
            end_height: 0,
            block_limit: ExecutionCost::max_value(),
            network_epoch: PEER_VERSION_EPOCH_2_0,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch2_05,
            start_height: 0,
            end_height: 0,
            block_limit: ExecutionCost::max_value(),
            network_epoch: PEER_VERSION_EPOCH_2_05,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch21,
            start_height: 0,
            end_height: 0,
            block_limit: ExecutionCost::max_value(),
            network_epoch: PEER_VERSION_EPOCH_2_1,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch22,
            start_height: 0,
            end_height: 0,
            block_limit: ExecutionCost::max_value(),
            network_epoch: PEER_VERSION_EPOCH_2_2,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch23,
            start_height: 0,
            end_height: 0,
            block_limit: ExecutionCost::max_value(),
            network_epoch: PEER_VERSION_EPOCH_2_3,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch24,
            start_height: 0,
            end_height: 0,
            block_limit: ExecutionCost::max_value(),
            network_epoch: PEER_VERSION_EPOCH_2_4,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch25,
            start_height: 0,
            end_height: first_burnchain_height,
            block_limit: BLOCK_LIMIT_MAINNET_21.clone(),
            network_epoch: PEER_VERSION_EPOCH_2_5,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch30,
            start_height: first_burnchain_height,
            end_height: first_burnchain_height + 1,
            block_limit: BLOCK_LIMIT_MAINNET_21.clone(),
            network_epoch: PEER_VERSION_EPOCH_3_0,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch31,
            start_height: first_burnchain_height + 1,
            end_height: first_burnchain_height + 2,
            block_limit: BLOCK_LIMIT_MAINNET_21.clone(),
            network_epoch: PEER_VERSION_EPOCH_3_1,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch32,
            start_height: first_burnchain_height + 2,
            end_height: first_burnchain_height + 3,
            block_limit: BLOCK_LIMIT_MAINNET_21.clone(),
            network_epoch: PEER_VERSION_EPOCH_3_2,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch33,
            start_height: first_burnchain_height + 3,
            end_height: STACKS_EPOCH_MAX,
            block_limit: BLOCK_LIMIT_MAINNET_21.clone(),
            network_epoch: PEER_VERSION_EPOCH_3_3,
        },
    ])
}

/// Represents the expected output of a transaction in a test.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ExpectedTransactionOutput {
    /// The expected return value of the transaction.
    pub return_type: ClarityValue,
    /// The expected execution cost of the transaction.
    pub cost: ExecutionCost,
}

/// Represents the expected outputs for a block's execution.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ExpectedBlockOutput {
    /// The expected outputs for each transaction, in input order.
    pub transactions: Vec<ExpectedTransactionOutput>,
    /// The total execution cost of the block.
    pub total_block_cost: ExecutionCost,
}

/// Represents the expected result of a consensus test.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum ExpectedResult {
    /// The test should succeed with the specified outputs.
    Success(ExpectedBlockOutput),
    /// The test should fail with an error matching the specified string
    /// Cannot match on the exact Error directly as they do not implement
    /// Serialize/Deserialize or PartialEq
    Failure(String),
}

impl From<Result<StacksEpochReceipt, ChainstateError>> for ExpectedResult {
    fn from(result: Result<StacksEpochReceipt, ChainstateError>) -> Self {
        match result {
            Ok(epoch_receipt) => {
                let transactions: Vec<ExpectedTransactionOutput> = epoch_receipt
                    .tx_receipts
                    .iter()
                    .map(|r| ExpectedTransactionOutput {
                        return_type: r.result.clone(),
                        cost: r.execution_cost.clone(),
                    })
                    .collect();
                let total_block_cost = epoch_receipt.anchored_block_cost.clone();
                ExpectedResult::Success(ExpectedBlockOutput {
                    transactions,
                    total_block_cost,
                })
            }
            Err(e) => ExpectedResult::Failure(e.to_string()),
        }
    }
}

/// Represents a block to be appended in a test and its expected result.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct TestBlock {
    /// Hex representation of the MARF hash for block construction.
    pub marf_hash: String,
    /// Transactions to include in the block
    pub transactions: Vec<StacksTransaction>,
}

/// Defines a test vector for a consensus test, including chainstate setup and expected outcomes.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ConsensusTestVector {
    /// A mapping of epoch to Blocks that should be applied in that epoch
    pub epoch_blocks: HashMap<StacksEpochId, Vec<TestBlock>>,
}

/// Represents a consensus test with chainstate and test vector.
pub struct ConsensusTest<'a> {
    pub chain: TestChainstate<'a>,
}

impl ConsensusTest<'_> {
    /// Creates a new `ConsensusTest` with the given test name and vector.
    pub fn new(test_name: &str, initial_balances: Vec<(PrincipalData, u64)>) -> Self {
        // Set up chainstate to start at Epoch 3.0
        // We don't really ever want the reward cycle to force a new signer set...
        // so for now just set the cycle length to a high value (100)
        let mut boot_plan = NakamotoBootPlan::new(test_name)
            .with_pox_constants(100, 3)
            .with_initial_balances(initial_balances.clone())
            .with_private_key(FAUCET_PRIV_KEY.clone());
        let epochs = epoch_3_0_onwards(
            (boot_plan.pox_constants.pox_4_activation_height
                + boot_plan.pox_constants.reward_cycle_length
                + 1) as u64,
        );
        boot_plan = boot_plan.with_epochs(epochs);
        let chain = boot_plan.boot_nakamoto_chainstate(None);

        Self { chain }
    }

    /// Advances the chainstate to the specified epoch. Creating a tenure change block per burn block height
    fn advance_to_epoch(&mut self, target_epoch: StacksEpochId) {
        let burn_block_height = self.chain.get_burn_block_height();
        let mut current_epoch =
            SortitionDB::get_stacks_epoch(self.chain.sortdb().conn(), burn_block_height)
                .unwrap()
                .unwrap()
                .epoch_id;
        assert!(current_epoch <= target_epoch, "Chainstate is already at a higher epoch than the target. Current epoch: {current_epoch}. Target epoch: {target_epoch}");
        while current_epoch < target_epoch {
            let (burn_ops, mut tenure_change, miner_key) = self
                .chain
                .begin_nakamoto_tenure(TenureChangeCause::BlockFound);
            let (_, header_hash, consensus_hash) = self.chain.next_burnchain_block(burn_ops);
            let vrf_proof = self.chain.make_nakamoto_vrf_proof(miner_key);

            tenure_change.tenure_consensus_hash = consensus_hash.clone();
            tenure_change.burn_view_consensus_hash = consensus_hash.clone();
            let tenure_change_tx = self.chain.miner.make_nakamoto_tenure_change(tenure_change);
            let coinbase_tx = self.chain.miner.make_nakamoto_coinbase(None, vrf_proof);

            let _blocks_and_sizes =
                self.chain
                    .make_nakamoto_tenure(tenure_change_tx, coinbase_tx, Some(0));
            let burn_block_height = self.chain.get_burn_block_height();
            current_epoch =
                SortitionDB::get_stacks_epoch(self.chain.sortdb().conn(), burn_block_height)
                    .unwrap()
                    .unwrap()
                    .epoch_id;
        }
    }

    /// Runs the consensus test.
    ///
    /// This method constructs a block from the test vector, appends it to the
    /// chain, and returns the result of the block processing.
    pub fn run(mut self, test_vector: ConsensusTestVector) -> Vec<ExpectedResult> {
        // Validate blocks
        for (epoch_id, blocks) in &test_vector.epoch_blocks {
            assert!(
                !matches!(
                    *epoch_id,
                    StacksEpochId::Epoch10
                        | StacksEpochId::Epoch20
                        | StacksEpochId::Epoch2_05
                        | StacksEpochId::Epoch21
                        | StacksEpochId::Epoch22
                        | StacksEpochId::Epoch23
                        | StacksEpochId::Epoch24
                        | StacksEpochId::Epoch25
                ),
                "Pre-Nakamoto Tenures are not Supported"
            );
            assert!(
                !blocks.is_empty(),
                "Each epoch must have at least one block"
            );
        }

        // Get sorted epochs
        let mut epochs: Vec<StacksEpochId> = test_vector.epoch_blocks.keys().cloned().collect();
        epochs.sort();

        let mut results = vec![];
        for epoch in epochs {
            debug!(
                "--------- Processing epoch {epoch:?} with {} blocks ---------",
                test_vector.epoch_blocks[&epoch].len()
            );
            self.advance_to_epoch(epoch);
            for (i, block) in test_vector.epoch_blocks[&epoch].iter().enumerate() {
                debug!("--------- Running block {i} for epoch {epoch:?} ---------");
                let (nakamoto_block, block_size) =
                    self.construct_nakamoto_block(&block.marf_hash, &block.transactions);
                let sortdb = self.chain.sortdb.take().unwrap();
                let chain_tip = NakamotoChainState::get_canonical_block_header(
                    self.chain.stacks_node().chainstate.db(),
                    &sortdb,
                )
                .unwrap()
                .unwrap();
                let pox_constants = PoxConstants::test_default();
                debug!(
                    "--------- Appending block {} ---------",
                    nakamoto_block.header.signer_signature_hash();
                    "block" => ?nakamoto_block
                );
                {
                    let (mut chainstate_tx, clarity_instance) = self
                        .chain
                        .stacks_node()
                        .chainstate
                        .chainstate_tx_begin()
                        .unwrap();

                    let mut burndb_conn = sortdb.index_handle_at_tip();

                    let result = NakamotoChainState::append_block(
                        &mut chainstate_tx,
                        clarity_instance,
                        &mut burndb_conn,
                        &chain_tip.consensus_hash,
                        &pox_constants,
                        &chain_tip,
                        &chain_tip.burn_header_hash,
                        chain_tip.burn_header_height,
                        chain_tip.burn_header_timestamp,
                        &nakamoto_block,
                        block_size.try_into().unwrap(),
                        nakamoto_block.header.burn_spent,
                        1500,
                        &RewardSet::empty(),
                        false,
                    );

                    debug!("--------- Appended block: {} ---------", result.is_ok());
                    results.push(
                        result
                            .map(|(receipt, clarity_commit, _, _)| {
                                clarity_commit.commit();
                                receipt
                            })
                            .into(),
                    );
                    chainstate_tx.commit().unwrap();
                }

                // Restore chainstate for the next block
                self.chain.sortdb = Some(sortdb);
            }
        }
        results
    }

    /// Constructs a Nakamoto block with the given transactions and state index root.
    fn construct_nakamoto_block(
        &self,
        marf_hash: &str,
        transactions: &[StacksTransaction],
    ) -> (NakamotoBlock, usize) {
        let state_index_root = TrieHash::from_hex(marf_hash).unwrap();
        let chain_tip = NakamotoChainState::get_canonical_block_header(
            self.chain.stacks_node.as_ref().unwrap().chainstate.db(),
            self.chain.sortdb.as_ref().unwrap(),
        )
        .unwrap()
        .unwrap();
        let cycle = self.chain.get_reward_cycle();
        let burn_spent = SortitionDB::get_block_snapshot_consensus(
            self.chain.sortdb_ref().conn(),
            &chain_tip.consensus_hash,
        )
        .unwrap()
        .map(|sn| sn.total_burn)
        .unwrap();
        let mut block = NakamotoBlock {
            header: NakamotoBlockHeader {
                version: 1,
                chain_length: chain_tip.stacks_block_height + 1,
                burn_spent,
                consensus_hash: chain_tip.consensus_hash.clone(),
                parent_block_id: chain_tip.index_block_hash(),
                tx_merkle_root: Sha512Trunc256Sum::from_data(&[]),
                state_index_root,
                timestamp: 1,
                miner_signature: MessageSignature::empty(),
                signer_signature: vec![],
                pox_treatment: BitVec::ones(1).unwrap(),
            },
            txs: transactions.to_vec(),
        };

        let tx_merkle_root = {
            let txid_vecs: Vec<_> = block
                .txs
                .iter()
                .map(|tx| tx.txid().as_bytes().to_vec())
                .collect();
            MerkleTree::<Sha512Trunc256Sum>::new(&txid_vecs).root()
        };

        block.header.tx_merkle_root = tx_merkle_root;
        self.chain.miner.sign_nakamoto_block(&mut block);
        let mut signers = self.chain.config.test_signers.clone().unwrap_or_default();
        signers.sign_nakamoto_block(&mut block, cycle);
        let block_len = block.serialize_to_vec().len();
        (block, block_len)
    }
}

#[test]
fn test_append_empty_blocks() {
    let mut epoch_blocks = HashMap::new();
    epoch_blocks.insert(
        StacksEpochId::Epoch30,
        vec![TestBlock {
            marf_hash: "f1934080b22ef0192cfb39710690e7cb0efa9cff950832b33544bde3aa1484a5".into(),
            transactions: vec![],
        }],
    );
    epoch_blocks.insert(
        StacksEpochId::Epoch31,
        vec![TestBlock {
            marf_hash: "a05f1383613215f5789eb977e4c62dfbb789d90964e14865d109375f7f6dc3cf".into(),
            transactions: vec![],
        }],
    );
    epoch_blocks.insert(
        StacksEpochId::Epoch32,
        vec![TestBlock {
            marf_hash: "c17829daff8746329c65ae658f4087519c6a8bd8c7f21e51644ddbc9c010390f".into(),
            transactions: vec![],
        }],
    );
    epoch_blocks.insert(
        StacksEpochId::Epoch33,
        vec![TestBlock {
            marf_hash: "23ecbcb91cac914ba3994a15f3ea7189bcab4e9762530cd0e6c7d237fcd6dc78".into(),
            transactions: vec![],
        }],
    );

    let test_vector = ConsensusTestVector { epoch_blocks };
    let result = ConsensusTest::new(function_name!(), vec![]).run(test_vector);
    insta::assert_ron_snapshot!(result);
}

#[test]
fn test_append_state_index_root_mismatches() {
    let mut epoch_blocks = HashMap::new();
    epoch_blocks.insert(
        StacksEpochId::Epoch30,
        vec![TestBlock {
            marf_hash: "0000000000000000000000000000000000000000000000000000000000000000".into(),
            transactions: vec![],
        }],
    );
    epoch_blocks.insert(
        StacksEpochId::Epoch31,
        vec![TestBlock {
            marf_hash: "0000000000000000000000000000000000000000000000000000000000000000".into(),
            transactions: vec![],
        }],
    );
    epoch_blocks.insert(
        StacksEpochId::Epoch32,
        vec![TestBlock {
            marf_hash: "0000000000000000000000000000000000000000000000000000000000000000".into(),
            transactions: vec![],
        }],
    );
    epoch_blocks.insert(
        StacksEpochId::Epoch33,
        vec![TestBlock {
            marf_hash: "0000000000000000000000000000000000000000000000000000000000000000".into(),
            transactions: vec![],
        }],
    );

    let test_vector = ConsensusTestVector { epoch_blocks };
    let result = ConsensusTest::new(function_name!(), vec![]).run(test_vector);
    insta::assert_ron_snapshot!(result);
}

#[test]
fn test_append_stx_transfers_success() {
    let sender_privks = [
        StacksPrivateKey::from_hex(SK_1).unwrap(),
        StacksPrivateKey::from_hex(SK_2).unwrap(),
        StacksPrivateKey::from_hex(SK_3).unwrap(),
    ];
    let send_amount = 1_000;
    let tx_fee = 180;
    let mut initial_balances = Vec::new();
    let transactions: Vec<_> = sender_privks
        .iter()
        .map(|sender_privk| {
            initial_balances.push((
                StacksAddress::p2pkh(false, &StacksPublicKey::from_private(sender_privk)).into(),
                send_amount + tx_fee,
            ));
            // Interestingly, it doesn't seem to care about nonce...
            make_stacks_transfer_tx(
                sender_privk,
                0,
                tx_fee,
                CHAIN_ID_TESTNET,
                &boot_code_addr(false).into(),
                send_amount,
            )
        })
        .collect();

    let mut epoch_blocks = HashMap::new();
    epoch_blocks.insert(
        StacksEpochId::Epoch30,
        vec![TestBlock {
            marf_hash: "63ea49669d2216ebc7e4f8b5e1cd2c99b8aff9806794adf87dcf709c0a244798".into(),
            transactions: transactions.clone(),
        }],
    );
    epoch_blocks.insert(
        StacksEpochId::Epoch31,
        vec![TestBlock {
            marf_hash: "7fc538e605a4a353871c4a655ae850fe9a70c3875b65f2bb42ea3bef5effed2c".into(),
            transactions: transactions.clone(),
        }],
    );
    epoch_blocks.insert(
        StacksEpochId::Epoch32,
        vec![TestBlock {
            marf_hash: "4d5c9a6d07806ac5006137de22b083de66fff7119143dd5cd92e4a457d66e028".into(),
            transactions: transactions.clone(),
        }],
    );
    epoch_blocks.insert(
        StacksEpochId::Epoch33,
        vec![TestBlock {
            marf_hash: "66eed8c0ab31db111a5adcc83d38a7004c6e464e3b9fb9f52ec589bc6d5f2d32".into(),
            transactions: transactions.clone(),
        }],
    );

    let test_vector = ConsensusTestVector { epoch_blocks };

    let result = ConsensusTest::new(function_name!(), initial_balances).run(test_vector);
    insta::assert_ron_snapshot!(result);
}

#[test]
fn test_append_chainstate_error_expression_stack_depth_too_deep() {
    let exceeds_repeat_factor = AST_CALL_STACK_DEPTH_BUFFER + (MAX_CALL_STACK_DEPTH as u64);
    let tx_exceeds_body_start = "{ a : ".repeat(exceeds_repeat_factor as usize);
    let tx_exceeds_body_end = "} ".repeat(exceeds_repeat_factor as usize);
    let tx_exceeds_body = format!("{tx_exceeds_body_start}u1 {tx_exceeds_body_end}");

    let tx_fee = (tx_exceeds_body.len() * 100) as u64;
    let tx_bytes = make_contract_publish(
        &FAUCET_PRIV_KEY,
        0,
        tx_fee,
        CHAIN_ID_TESTNET,
        "test-exceeds",
        &tx_exceeds_body,
    );

    let tx = StacksTransaction::consensus_deserialize(&mut &tx_bytes[..]).unwrap();

    let mut epoch_blocks = HashMap::new();
    epoch_blocks.insert(
        StacksEpochId::Epoch30,
        vec![TestBlock {
            marf_hash: "0000000000000000000000000000000000000000000000000000000000000000".into(),
            transactions: vec![tx.clone()],
        }],
    );
    epoch_blocks.insert(
        StacksEpochId::Epoch31,
        vec![TestBlock {
            marf_hash: "0000000000000000000000000000000000000000000000000000000000000000".into(),
            transactions: vec![tx.clone()],
        }],
    );
    epoch_blocks.insert(
        StacksEpochId::Epoch32,
        vec![TestBlock {
            marf_hash: "0000000000000000000000000000000000000000000000000000000000000000".into(),
            transactions: vec![tx.clone()],
        }],
    );
    epoch_blocks.insert(
        StacksEpochId::Epoch33,
        vec![TestBlock {
            marf_hash: "0000000000000000000000000000000000000000000000000000000000000000".into(),
            transactions: vec![tx.clone()],
        }],
    );

    let test_vector = ConsensusTestVector { epoch_blocks };
    let result = ConsensusTest::new(function_name!(), vec![]).run(test_vector);
    insta::assert_ron_snapshot!(result);
}

#[test]
fn test_append_block_with_contract_upload_success() {
    let contract_name = "test-contract";
    let contract_content = "(/ 1 1)";
    let tx_fee = (contract_content.len() * 100) as u64;

    let tx_bytes = make_contract_publish(
        &FAUCET_PRIV_KEY,
        0,
        tx_fee,
        CHAIN_ID_TESTNET,
        contract_name,
        &contract_content,
    );
    let tx = StacksTransaction::consensus_deserialize(&mut &tx_bytes[..]).unwrap();

    let mut epoch_blocks = HashMap::new();
    epoch_blocks.insert(
        StacksEpochId::Epoch30,
        vec![TestBlock {
            marf_hash: "b45acd35f4c48a834a2f898ca8bb6c48416ac6bec9d8a3f3662b61ab97b1edde".into(),
            transactions: vec![tx.clone()],
        }],
    );
    epoch_blocks.insert(
        StacksEpochId::Epoch31,
        vec![TestBlock {
            marf_hash: "521d75234ec6c64f68648b6b0f6f385d89b58efb581211a411e0e88aa71f3371".into(),
            transactions: vec![tx.clone()],
        }],
    );
    epoch_blocks.insert(
        StacksEpochId::Epoch32,
        vec![TestBlock {
            marf_hash: "511e1cc37e83ef3de4ea56962574d6ddd2d8840d24d9238f19eee5a35127df6a".into(),
            transactions: vec![tx.clone()],
        }],
    );
    epoch_blocks.insert(
        StacksEpochId::Epoch33,
        vec![TestBlock {
            marf_hash: "3520c2dd96f7d91e179c4dcd00f3c49c16d6ec21434fb16921922558282eab26".into(),
            transactions: vec![tx.clone()],
        }],
    );
    let test_vector = ConsensusTestVector { epoch_blocks };

    let result = ConsensusTest::new(function_name!(), vec![]).run(test_vector);

    insta::assert_ron_snapshot!(result);
}
