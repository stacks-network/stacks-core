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
use clarity::vm::ast::errors::{ParseError, ParseErrors};
use clarity::vm::ast::stack_depth_checker::AST_CALL_STACK_DEPTH_BUFFER;
use clarity::vm::costs::ExecutionCost;
use clarity::vm::events::StacksTransactionEvent;
use clarity::vm::types::{PrincipalData, ResponseData};
use clarity::vm::{Value as ClarityValue, MAX_CALL_STACK_DEPTH};
use serde::{Deserialize, Serialize};
use stacks_common::bitvec::BitVec;

use crate::burnchains::PoxConstants;
use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::nakamoto::{NakamotoBlock, NakamotoBlockHeader, NakamotoChainState};
use crate::chainstate::stacks::boot::{RewardSet, RewardSetData};
use crate::chainstate::stacks::db::{StacksChainState, StacksEpochReceipt};
use crate::chainstate::stacks::{
    Error as ChainstateError, StacksTransaction, TenureChangeCause, MINER_BLOCK_CONSENSUS_HASH,
    MINER_BLOCK_HEADER_HASH,
};
use crate::chainstate::tests::TestChainstate;
use crate::clarity_vm::clarity::{Error as ClarityError, PreCommitClarityBlock};
use crate::core::test_util::{make_contract_publish, make_stacks_transfer_tx};
use crate::core::{EpochList, BLOCK_LIMIT_MAINNET_21};
use crate::net::tests::NakamotoBootPlan;
pub const SK_1: &str = "a1289f6438855da7decf9b61b852c882c398cff1446b2a0f823538aa2ebef92e01";
pub const SK_2: &str = "4ce9a8f7539ea93753a36405b16e8b57e15a552430410709c2b6d65dca5c02e201";
pub const SK_3: &str = "cb95ddd0fe18ec57f4f3533b95ae564b3f1ae063dbf75b46334bd86245aef78501";

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

impl ExpectedResult {
    /// Returns `true` if this result represents a successful outcome.
    pub fn is_success(&self) -> bool {
        matches!(&self, Self::Success(_))
    }
    /// Returns `true` if this result represents a failed outcome.
    pub fn is_failure(&self) -> bool {
        matches!(&self, Self::Failure(_))
    }
}

/// Represents a block to be appended in a test and its expected result.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct TestBlock {
    /// Hex representation of the MARF hash for block construction.
    pub marf_hash: String,
    /// Transactions to include in the block
    pub transactions: Vec<StacksTransaction>,
    /// The expected result after appending the constructed block.
    pub expected_result: ExpectedResult,
}

impl TestBlock {
    /// Returns `true` if the [`ExpectedResult`] variant represents a successful outcome.
    pub fn is_success(&self) -> bool {
        self.expected_result.is_success()
    }

    /// Returns `true` if the [`ExpectedResult`] variant represents a failed outcome.
    pub fn is_failure(&self) -> bool {
        self.expected_result.is_failure()
    }
}

/// Defines a test vector for a consensus test, including chainstate setup and expected outcomes.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ConsensusTestVector {
    /// Initial balances for the provided PrincipalData during chainstate instantiation.
    pub initial_balances: Vec<(PrincipalData, u64)>,
    /// A mapping of epoch to Blocks that should be applied in that epoch
    pub epoch_blocks: HashMap<StacksEpochId, Vec<TestBlock>>,
}

/// Tracks mismatches between actual and expected transaction results.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransactionMismatch {
    /// The index of the transaction with mismatches.
    pub index: u32,
    /// Mismatch between actual and expected return types, if any.
    pub return_type: Option<(ClarityValue, ClarityValue)>,
    /// Mismatch between actual and expected execution costs, if any.
    pub cost: Option<(ExecutionCost, ExecutionCost)>,
}

impl TransactionMismatch {
    /// Creates a new `TransactionMismatch` for the given transaction index.
    fn new(index: u32) -> Self {
        Self {
            index,
            return_type: None,
            cost: None,
        }
    }

    /// Adds a return type mismatch to the transaction.
    fn with_return_type_mismatch(mut self, actual: ClarityValue, expected: ClarityValue) -> Self {
        self.return_type = Some((actual, expected));
        self
    }

    /// Adds an execution cost mismatch to the transaction.
    fn with_cost_mismatch(mut self, actual: ExecutionCost, expected: ExecutionCost) -> Self {
        self.cost = Some((actual, expected));
        self
    }

    /// Returns true if no mismatches are recorded.
    fn is_empty(&self) -> bool {
        self.return_type.is_none() && self.cost.is_none()
    }
}

/// Aggregates all mismatches between actual and expected test results.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct ConsensusMismatch {
    /// Mismatches for individual transactions.
    pub transactions: Vec<TransactionMismatch>,
    /// Mismatch between actual and expected total block costs, if any.
    pub total_block_cost: Option<(ExecutionCost, ExecutionCost)>,
    /// Mismatch between actual and expected error messages, if any.
    pub error: Option<(String, String)>,
}

impl ConsensusMismatch {
    /// Creates a `ConsensusMismatch` from test results, if mismatches exist.
    pub fn from_test_result<'a>(
        append_result: Result<
            (
                StacksEpochReceipt,
                PreCommitClarityBlock<'a>,
                Option<RewardSetData>,
                Vec<StacksTransactionEvent>,
            ),
            ChainstateError,
        >,
        expected_result: ExpectedResult,
    ) -> Option<Self> {
        let mut mismatches = ConsensusMismatch::default();
        match (append_result, expected_result) {
            (Ok((epoch_receipt, clarity_commit, _, _)), ExpectedResult::Success(expected)) => {
                // Convert transaction receipts to `ExpectedTransactionOutput` for comparison.
                let actual_transactions: Vec<_> = epoch_receipt
                    .tx_receipts
                    .iter()
                    .map(|r| {
                        (
                            r.tx_index,
                            ExpectedTransactionOutput {
                                return_type: r.result.clone(),
                                cost: r.execution_cost.clone(),
                            },
                        )
                    })
                    .collect();

                // Compare each transaction's actual vs expected outputs.
                for ((tx_index, actual_tx), expected_tx) in
                    actual_transactions.iter().zip(expected.transactions.iter())
                {
                    let mut tx_mismatch = TransactionMismatch::new(*tx_index);
                    let mut has_mismatch = false;

                    if actual_tx.return_type != expected_tx.return_type {
                        tx_mismatch = tx_mismatch.with_return_type_mismatch(
                            actual_tx.return_type.clone(),
                            expected_tx.return_type.clone(),
                        );
                        has_mismatch = true;
                    }

                    if actual_tx.cost != expected_tx.cost {
                        tx_mismatch = tx_mismatch
                            .with_cost_mismatch(actual_tx.cost.clone(), expected_tx.cost.clone());
                        has_mismatch = true;
                    }

                    if has_mismatch {
                        mismatches.add_transaction_mismatch(tx_mismatch);
                    }
                }

                // Compare total block execution cost.
                if epoch_receipt.anchored_block_cost != expected.total_block_cost {
                    mismatches.add_total_block_cost_mismatch(
                        &epoch_receipt.anchored_block_cost,
                        &expected.total_block_cost,
                    );
                }
                // TODO: add any additional mismatches we might care about?
                clarity_commit.commit();
            }
            (Ok(_), ExpectedResult::Failure(expected_err)) => {
                mismatches.error = Some(("Ok".to_string(), expected_err));
            }
            (Err(actual_err), ExpectedResult::Failure(expected_err)) => {
                let actual_err_str = actual_err.to_string();
                if actual_err_str != expected_err {
                    mismatches.error = Some((actual_err_str, expected_err));
                }
            }
            (Err(actual_err), ExpectedResult::Success(_)) => {
                mismatches.error = Some((actual_err.to_string(), "Success".into()));
            }
        }

        if mismatches.is_empty() {
            None
        } else {
            Some(mismatches)
        }
    }

    /// Adds a transaction mismatch to the collection.
    fn add_transaction_mismatch(&mut self, mismatch: TransactionMismatch) {
        self.transactions.push(mismatch);
    }

    /// Records a total block cost mismatch.
    fn add_total_block_cost_mismatch(&mut self, actual: &ExecutionCost, expected: &ExecutionCost) {
        self.total_block_cost = Some((actual.clone(), expected.clone()));
    }

    /// Returns true if no mismatches are recorded.
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty() && self.total_block_cost.is_none() && self.error.is_none()
    }

    /// Serializes the given `ConsensusMismatch` as pretty-printed JSON,  
    /// or returns an empty string if `None`.
    pub fn to_json_string_pretty(mismatch: &Option<ConsensusMismatch>) -> String {
        mismatch
            .as_ref()
            .map(|m| serde_json::to_string_pretty(m).unwrap())
            .unwrap_or("".into())
    }
}

/// Represents a consensus test with chainstate and test vector.
pub struct ConsensusTest<'a> {
    pub chain: TestChainstate<'a>,
    pub test_vector: ConsensusTestVector,
}

impl ConsensusTest<'_> {
    /// Creates a new `ConsensusTest` with the given test name and vector.
    pub fn new(test_name: &str, test_vector: ConsensusTestVector) -> Self {
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
            for block in blocks {
                if let ExpectedResult::Success(output) = &block.expected_result {
                    assert_eq!(
                        output.transactions.len(),
                        block.transactions.len(),
                        "Test block is invalid. Must specify an expected output per input transaction"
                    );
                }
            }
        }

        let privk = StacksPrivateKey::from_hex(
            "510f96a8efd0b11e211733c1ac5e3fa6f3d3fcdd62869e376c47decb3e14fea101",
        )
        .unwrap();

        // Set up chainstate to start at Epoch 3.0
        // We don't really ever want the reward cycle to force a new signer set...
        // so for now just set the cycle length to a high value (100)
        let mut boot_plan = NakamotoBootPlan::new(test_name)
            .with_pox_constants(100, 3)
            .with_initial_balances(test_vector.initial_balances.clone())
            .with_private_key(privk);
        let epochs = epoch_3_0_onwards(
            (boot_plan.pox_constants.pox_4_activation_height
                + boot_plan.pox_constants.reward_cycle_length
                + 1) as u64,
        );
        boot_plan = boot_plan.with_epochs(epochs);
        let chain = boot_plan.boot_nakamoto_chainstate(None);

        Self { chain, test_vector }
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

    /// Runs the consensus test for the test vector, advancing epochs as needed.
    pub fn run(mut self) {
        // Get sorted epochs
        let mut epochs: Vec<StacksEpochId> =
            self.test_vector.epoch_blocks.keys().cloned().collect();
        epochs.sort();

        for epoch in epochs {
            debug!(
                "--------- Processing epoch {epoch:?} with {} blocks ---------",
                self.test_vector.epoch_blocks[&epoch].len()
            );
            self.advance_to_epoch(epoch);
            let epoch_blocks = self.test_vector.epoch_blocks[&epoch].clone();
            for (i, block) in epoch_blocks.iter().enumerate() {
                debug!("--------- Running block {i} for epoch {epoch:?} ---------");
                let (nakamoto_block, block_size) = self.construct_nakamoto_block(&block);
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

                    // Compare actual vs expected results.
                    let mismatches =
                        ConsensusMismatch::from_test_result(result, block.expected_result.clone());
                    assert!(
                        mismatches.is_none(),
                        "Mismatches found in block {i} for epoch {epoch:?}: {}",
                        ConsensusMismatch::to_json_string_pretty(&mismatches)
                    );
                    chainstate_tx.commit().unwrap();
                }

                // Restore chainstate for the next block
                self.chain.sortdb = Some(sortdb);
            }
        }
    }

    /// Constructs a Nakamoto block with the given [`TestBlock`] configuration.
    fn construct_nakamoto_block(&mut self, test_block: &TestBlock) -> (NakamotoBlock, usize) {
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
                state_index_root: TrieHash::from_empty_data(),
                timestamp: 1,
                miner_signature: MessageSignature::empty(),
                signer_signature: vec![],
                pox_treatment: BitVec::ones(1).unwrap(),
            },
            txs: test_block.transactions.to_vec(),
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

        // Set the MARF root hash: compute it for success cases,
        // or use an all-zero hash for failure cases.
        block.header.state_index_root = if test_block.is_success() {
            self.compute_block_marf_root_hash(block.header.timestamp, &block.txs)
        } else {
            TrieHash::from_bytes(&[0; 32]).unwrap()
        };

        self.chain.miner.sign_nakamoto_block(&mut block);
        let mut signers = self.chain.config.test_signers.clone().unwrap_or_default();
        signers.sign_nakamoto_block(&mut block, cycle);
        let block_len = block.serialize_to_vec().len();
        (block, block_len)
    }

    /// Computes the MARF root hash for a block.
    ///
    /// This function is intended for use in success test cases only, where all
    /// transactions are valid. In other scenarios, the computation may fail.
    ///
    /// The implementation is deliberately minimal: it does not cover every
    /// possible situation (such as new tenure handling), but it should be
    /// sufficient for the scope of our test cases.
    fn compute_block_marf_root_hash(
        &mut self,
        block_time: u64,
        block_txs: &Vec<StacksTransaction>,
    ) -> TrieHash {
        let node = self.chain.stacks_node.as_mut().unwrap();
        let sortdb = self.chain.sortdb.as_ref().unwrap();
        let burndb_conn = sortdb.index_handle_at_tip();
        let chainstate = &mut node.chainstate;

        let chain_tip = NakamotoChainState::get_canonical_block_header(chainstate.db(), &sortdb)
            .unwrap()
            .unwrap();

        let (chainstate_tx, clarity_instance) = chainstate.chainstate_tx_begin().unwrap();
        let burndb_conn = sortdb.index_handle_at_tip();

        let mut clarity_tx = StacksChainState::chainstate_block_begin(
            &chainstate_tx,
            clarity_instance,
            &burndb_conn,
            &chain_tip.consensus_hash,
            &chain_tip.anchored_header.block_hash(),
            &MINER_BLOCK_CONSENSUS_HASH,
            &MINER_BLOCK_HEADER_HASH,
        );

        clarity_tx
            .connection()
            .as_free_transaction(|clarity_tx_conn| {
                clarity_tx_conn.with_clarity_db(|db| {
                    db.setup_block_metadata(Some(block_time))?;
                    Ok(())
                })
            })
            .expect("MARF: Failure on block metadata setup!");

        StacksChainState::process_block_transactions(&mut clarity_tx, block_txs, 0)
            .expect("MARF: Failure on processing block transactions!");

        NakamotoChainState::finish_block(
            &mut clarity_tx,
            None,
            false,
            chain_tip.burn_header_height,
        )
        .expect("MARF: Failure on finishing block!");

        let trie_hash = clarity_tx.seal();
        clarity_tx.rollback_block();
        return trie_hash;
    }
}

#[test]
fn test_append_empty_blocks() {
    let mut epoch_blocks = HashMap::new();
    let expected_result = ExpectedResult::Success(ExpectedBlockOutput {
        transactions: vec![],
        total_block_cost: ExecutionCost::ZERO,
    });
    epoch_blocks.insert(
        StacksEpochId::Epoch30,
        vec![TestBlock {
            marf_hash: "f1934080b22ef0192cfb39710690e7cb0efa9cff950832b33544bde3aa1484a5".into(),
            transactions: vec![],
            expected_result: expected_result.clone(),
        }],
    );
    epoch_blocks.insert(
        StacksEpochId::Epoch31,
        vec![TestBlock {
            marf_hash: "a05f1383613215f5789eb977e4c62dfbb789d90964e14865d109375f7f6dc3cf".into(),
            transactions: vec![],
            expected_result: expected_result.clone(),
        }],
    );
    epoch_blocks.insert(
        StacksEpochId::Epoch32,
        vec![TestBlock {
            marf_hash: "c17829daff8746329c65ae658f4087519c6a8bd8c7f21e51644ddbc9c010390f".into(),
            transactions: vec![],
            expected_result: expected_result.clone(),
        }],
    );
    epoch_blocks.insert(
        StacksEpochId::Epoch33,
        vec![TestBlock {
            marf_hash: "23ecbcb91cac914ba3994a15f3ea7189bcab4e9762530cd0e6c7d237fcd6dc78".into(),
            transactions: vec![],
            expected_result: expected_result.clone(),
        }],
    );

    let test_vector = ConsensusTestVector {
        initial_balances: Vec::new(),
        epoch_blocks,
    };
    ConsensusTest::new(function_name!(), test_vector).run();
}

#[test]
fn test_append_state_index_root_mismatches() {
    let mut epoch_blocks = HashMap::new();
    epoch_blocks.insert(
        StacksEpochId::Epoch30,
        vec![TestBlock {
            marf_hash: "0000000000000000000000000000000000000000000000000000000000000000".into(),
            transactions: vec![],
            expected_result: ExpectedResult::Failure(
                ChainstateError::InvalidStacksBlock(
                    "Block ef45bfa44231d9e7aff094b53cfd48df0456067312f169a499354c4273a66fe3 state root mismatch: expected 0000000000000000000000000000000000000000000000000000000000000000, got f1934080b22ef0192cfb39710690e7cb0efa9cff950832b33544bde3aa1484a5".into(),
                )
                .to_string(),
            ),
        }],
    );
    epoch_blocks.insert(
        StacksEpochId::Epoch31,
        vec![TestBlock {
            marf_hash: "0000000000000000000000000000000000000000000000000000000000000000".into(),
            transactions: vec![],
            expected_result: ExpectedResult::Failure(
                ChainstateError::InvalidStacksBlock(
                    "Block a14d0b5c8d3c49554aeb462a8fe019718195789fa1dcd642059b75e41f0ce9cc state root mismatch: expected 0000000000000000000000000000000000000000000000000000000000000000, got a05f1383613215f5789eb977e4c62dfbb789d90964e14865d109375f7f6dc3cf".into(),
                )
                .to_string(),
            ),
        }],
    );
    epoch_blocks.insert(
        StacksEpochId::Epoch32,
        vec![TestBlock {
            marf_hash: "0000000000000000000000000000000000000000000000000000000000000000".into(),
            transactions: vec![],
            expected_result: ExpectedResult::Failure(
                ChainstateError::InvalidStacksBlock(
                    "Block f8120b4a632ee1d49fbbde3e01289588389cd205cab459a4493a7d58d2dc18ed state root mismatch: expected 0000000000000000000000000000000000000000000000000000000000000000, got c17829daff8746329c65ae658f4087519c6a8bd8c7f21e51644ddbc9c010390f".into(),
                )
                .to_string(),
            ),
        }],
    );
    epoch_blocks.insert(
        StacksEpochId::Epoch33,
        vec![TestBlock {
            marf_hash: "0000000000000000000000000000000000000000000000000000000000000000".into(),
            transactions: vec![],
            expected_result: ExpectedResult::Failure(
                ChainstateError::InvalidStacksBlock(
                    "Block 4dcb48b684d105ff0e0ab8becddd4a2d5623cc8b168aacf9c455e20b3e610e63 state root mismatch: expected 0000000000000000000000000000000000000000000000000000000000000000, got 23ecbcb91cac914ba3994a15f3ea7189bcab4e9762530cd0e6c7d237fcd6dc78".into(),
                )
                .to_string(),
            ),
        }],
    );

    let test_vector = ConsensusTestVector {
        initial_balances: Vec::new(),
        epoch_blocks,
    };
    ConsensusTest::new(function_name!(), test_vector).run();
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
    let transfer_result = ExpectedTransactionOutput {
        return_type: ClarityValue::Response(ResponseData {
            committed: true,
            data: Box::new(ClarityValue::Bool(true)),
        }),
        cost: ExecutionCost {
            write_length: 0,
            write_count: 0,
            read_length: 0,
            read_count: 0,
            runtime: 0,
        },
    };
    let outputs = ExpectedBlockOutput {
        transactions: vec![
            transfer_result.clone(),
            transfer_result.clone(),
            transfer_result,
        ],
        total_block_cost: ExecutionCost::ZERO,
    };
    let mut epoch_blocks = HashMap::new();
    epoch_blocks.insert(
        StacksEpochId::Epoch30,
        vec![TestBlock {
            marf_hash: "63ea49669d2216ebc7e4f8b5e1cd2c99b8aff9806794adf87dcf709c0a244798".into(),
            transactions: transactions.clone(),
            expected_result: ExpectedResult::Success(outputs.clone()),
        }],
    );
    epoch_blocks.insert(
        StacksEpochId::Epoch31,
        vec![TestBlock {
            marf_hash: "7fc538e605a4a353871c4a655ae850fe9a70c3875b65f2bb42ea3bef5effed2c".into(),
            transactions: transactions.clone(),
            expected_result: ExpectedResult::Success(outputs.clone()),
        }],
    );
    epoch_blocks.insert(
        StacksEpochId::Epoch32,
        vec![TestBlock {
            marf_hash: "4d5c9a6d07806ac5006137de22b083de66fff7119143dd5cd92e4a457d66e028".into(),
            transactions: transactions.clone(),
            expected_result: ExpectedResult::Success(outputs.clone()),
        }],
    );
    epoch_blocks.insert(
        StacksEpochId::Epoch33,
        vec![TestBlock {
            marf_hash: "66eed8c0ab31db111a5adcc83d38a7004c6e464e3b9fb9f52ec589bc6d5f2d32".into(),
            transactions: transactions.clone(),
            expected_result: ExpectedResult::Success(outputs.clone()),
        }],
    );

    let test_vector = ConsensusTestVector {
        initial_balances,
        epoch_blocks,
    };
    ConsensusTest::new(function_name!(), test_vector).run();
}

#[test]
fn test_append_chainstate_error_expression_stack_depth_too_deep() {
    let sender_privk = StacksPrivateKey::from_hex(SK_1).unwrap();
    let exceeds_repeat_factor = AST_CALL_STACK_DEPTH_BUFFER + (MAX_CALL_STACK_DEPTH as u64);
    let tx_exceeds_body_start = "{ a : ".repeat(exceeds_repeat_factor as usize);
    let tx_exceeds_body_end = "} ".repeat(exceeds_repeat_factor as usize);
    let tx_exceeds_body = format!("{tx_exceeds_body_start}u1 {tx_exceeds_body_end}");

    let tx_fee = (tx_exceeds_body.len() * 100) as u64;
    let tx_bytes = make_contract_publish(
        &sender_privk,
        0,
        tx_fee,
        CHAIN_ID_TESTNET,
        "test-exceeds",
        &tx_exceeds_body,
    );

    let tx = StacksTransaction::consensus_deserialize(&mut &tx_bytes[..]).unwrap();
    let initial_balances = vec![(
        StacksAddress::p2pkh(false, &StacksPublicKey::from_private(&sender_privk)).into(),
        tx_fee,
    )];
    let e = ChainstateError::ClarityError(ClarityError::Parse(ParseError::new(
        ParseErrors::ExpressionStackDepthTooDeep,
    )));
    let mut epoch_blocks = HashMap::new();
    epoch_blocks.insert(
        StacksEpochId::Epoch30,
        vec![TestBlock {
            marf_hash: "0000000000000000000000000000000000000000000000000000000000000000".into(),
            transactions: vec![tx.clone()],
            expected_result: ExpectedResult::Failure(
                ChainstateError::InvalidStacksBlock(format!(
                    "Invalid Stacks block ff0796f9934d45aad71871f317061acb99dd5ef1237a8747a78624a2824f7d32: {e:?}"
                ))
                .to_string(),
            ),
        }],
    );
    epoch_blocks.insert(
        StacksEpochId::Epoch31,
        vec![TestBlock {
            marf_hash: "0000000000000000000000000000000000000000000000000000000000000000".into(),
            transactions: vec![tx.clone()],
            expected_result: ExpectedResult::Failure(
                ChainstateError::InvalidStacksBlock(format!(
                    "Invalid Stacks block 9da03cdc774989cea30445f1453073b070430867edcecb180d1cc9a6e9738b46: {e:?}"
                ))
                .to_string(),
            ),
        }],
    );
    epoch_blocks.insert(
        StacksEpochId::Epoch32,
        vec![TestBlock {
            marf_hash: "0000000000000000000000000000000000000000000000000000000000000000".into(),
            transactions: vec![tx.clone()],
            expected_result: ExpectedResult::Failure(
                ChainstateError::InvalidStacksBlock(format!(
                    "Invalid Stacks block 76a6d95b3ec273a13f10080b3b18e225cc838044c5e3a3000b7ccdd8b50a5ae1: {e:?}"
                ))
                .to_string(),
            ),
        }],
    );
    epoch_blocks.insert(
        StacksEpochId::Epoch33,
        vec![TestBlock {
            marf_hash: "0000000000000000000000000000000000000000000000000000000000000000".into(),
            transactions: vec![tx.clone()],
            expected_result: ExpectedResult::Failure(
                ChainstateError::InvalidStacksBlock(format!(
                    "Invalid Stacks block de3c507ab60e717275f97f267ec2608c96aaab42a7e32fc2d8129585dff9e74a: {e:?}"
                ))
                .to_string(),
            ),
        }],
    );

    let test_vector = ConsensusTestVector {
        initial_balances,
        epoch_blocks,
    };
    ConsensusTest::new(function_name!(), test_vector).run();
}
