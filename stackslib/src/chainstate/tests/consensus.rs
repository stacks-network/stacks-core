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

use clarity::codec::StacksMessageCodec;
use clarity::types::chainstate::{StacksAddress, StacksPrivateKey, TrieHash};
use clarity::types::{Address, StacksEpochId};
use clarity::util::hash::{MerkleTree, Sha512Trunc256Sum};
use clarity::util::secp256k1::MessageSignature;
use clarity::vm::costs::ExecutionCost;
use clarity::vm::events::StacksTransactionEvent;
use clarity::vm::Value as ClarityValue;
use serde::{Deserialize, Serialize};
use stacks_common::bitvec::BitVec;

use crate::burnchains::PoxConstants;
use crate::chainstate::nakamoto::{NakamotoBlock, NakamotoBlockHeader, NakamotoChainState};
use crate::chainstate::stacks::boot::{RewardSet, RewardSetData};
use crate::chainstate::stacks::db::StacksEpochReceipt;
use crate::chainstate::stacks::{
    Error as ChainstateError, StacksTransaction, TenureChangeCause, TransactionAuth,
    TransactionPayload, TransactionVersion,
};
use crate::chainstate::tests::TestChainstate;
use crate::clarity_vm::clarity::PreCommitClarityBlock;
use crate::net::tests::NakamotoBootPlan;

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

/// Defines a test vector for a consensus test, including chainstate setup and expected outcomes.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ConsensusTestVector {
    /// Initial balances for Stacks addresses during chainstate instantiation.
    pub initial_balances: HashMap<String, u64>,
    /// Hex representation of the MARF hash for block construction.
    pub marf_hash: String,
    /// The epoch ID for the test environment.
    pub epoch_id: u32,
    /// Transaction payloads to include in the block, as serialized strings.
    pub payloads: Vec<String>,
    /// The expected result after appending the constructed block.
    pub expected_result: ExpectedResult,
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
            (Ok((epoch_receipt, _, _, _)), ExpectedResult::Success(expected)) => {
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
}

/// Represents a consensus test with chainstate and test vector.
pub struct ConsensusTest<'a> {
    pub chain: TestChainstate<'a>,
    pub test_vector: ConsensusTestVector,
}

impl ConsensusTest<'_> {
    /// Creates a new `ConsensusTest` with the given test name and vector.
    pub fn new(test_name: &str, test_vector: ConsensusTestVector) -> Self {
        let privk = StacksPrivateKey::from_hex(
            "510f96a8efd0b11e211733c1ac5e3fa6f3d3fcdd62869e376c47decb3e14fea101",
        )
        .unwrap();

        let initial_balances = test_vector
            .initial_balances
            .iter()
            .map(|(addr, amount)| (StacksAddress::from_string(addr).unwrap().into(), *amount))
            .collect();
        let epoch_id = StacksEpochId::try_from(test_vector.epoch_id).unwrap();
        let chain = match epoch_id {
            StacksEpochId::Epoch30
            | StacksEpochId::Epoch31
            | StacksEpochId::Epoch32
            | StacksEpochId::Epoch33 => {
                let mut chain = NakamotoBootPlan::new(test_name)
                    .with_pox_constants(10, 3)
                    .with_initial_balances(initial_balances)
                    .with_private_key(privk)
                    .boot_nakamoto_chainstate(None);
                let (burn_ops, mut tenure_change, miner_key) =
                    chain.begin_nakamoto_tenure(TenureChangeCause::BlockFound);
                let (_, header_hash, consensus_hash) = chain.next_burnchain_block(burn_ops);
                let vrf_proof = chain.make_nakamoto_vrf_proof(miner_key);

                tenure_change.tenure_consensus_hash = consensus_hash.clone();
                tenure_change.burn_view_consensus_hash = consensus_hash.clone();
                let tenure_change_tx = chain.miner.make_nakamoto_tenure_change(tenure_change);
                let coinbase_tx = chain.miner.make_nakamoto_coinbase(None, vrf_proof);

                let blocks_and_sizes =
                    chain.make_nakamoto_tenure(tenure_change_tx, coinbase_tx, Some(0));
                chain
            }
            StacksEpochId::Epoch10
            | StacksEpochId::Epoch20
            | StacksEpochId::Epoch2_05
            | StacksEpochId::Epoch21
            | StacksEpochId::Epoch22
            | StacksEpochId::Epoch23
            | StacksEpochId::Epoch24
            | StacksEpochId::Epoch25 => {
                unimplemented!("Pre-Nakamoto epochs are not supported.");
            }
        };
        Self { chain, test_vector }
    }

    /// Runs the consensus test, validating the results against the expected outcome.
    pub fn run(mut self) {
        debug!("--------- Running test vector ---------");
        let txs: Vec<_> = self
            .test_vector
            .payloads
            .iter()
            .map(|payload_str| {
                let payload: TransactionPayload = serde_json::from_str(payload_str).unwrap();
                StacksTransaction::new(
                    TransactionVersion::Testnet,
                    TransactionAuth::from_p2pkh(&StacksPrivateKey::random()).unwrap(),
                    payload,
                )
            })
            .collect();

        let marf_hash = TrieHash::from_hex(&self.test_vector.marf_hash).unwrap();

        let (block, block_size) = self.construct_nakamoto_block(txs, marf_hash);

        let mut stacks_node = self.chain.stacks_node.take().unwrap();
        let sortdb = self.chain.sortdb.take().unwrap();
        let chain_tip =
            NakamotoChainState::get_canonical_block_header(stacks_node.chainstate.db(), &sortdb)
                .unwrap()
                .unwrap();
        let pox_constants = PoxConstants::test_default();

        let (mut chainstate_tx, clarity_instance) =
            stacks_node.chainstate.chainstate_tx_begin().unwrap();

        let mut burndb_conn = sortdb.index_handle_at_tip();

        debug!("--------- Appending block {} ---------", block.header.signer_signature_hash(); "block" => ?block);
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
            &block,
            block_size.try_into().unwrap(),
            block.header.burn_spent,
            1500,
            &RewardSet::empty(),
            false,
        );

        debug!("--------- Appended block: {} ---------", result.is_ok());
        // Compare actual vs expected results.
        let mismatches =
            ConsensusMismatch::from_test_result(result, self.test_vector.expected_result);
        let mismatch_str = mismatches
            .as_ref()
            .map(|m| serde_json::to_string_pretty(m).unwrap())
            .unwrap_or("".into());
        assert!(mismatches.is_none(), "Mismatches found: {mismatch_str}");
    }

    /// Constructs a Nakamoto block with the given transactions and state index root.
    fn construct_nakamoto_block(
        &self,
        txs: Vec<StacksTransaction>,
        state_index_root: TrieHash,
    ) -> (NakamotoBlock, usize) {
        let chain_tip = NakamotoChainState::get_canonical_block_header(
            self.chain.stacks_node.as_ref().unwrap().chainstate.db(),
            self.chain.sortdb.as_ref().unwrap(),
        )
        .unwrap()
        .unwrap();

        let cycle = self.chain.get_reward_cycle();

        let mut block = NakamotoBlock {
            header: NakamotoBlockHeader {
                version: 1,
                chain_length: chain_tip.stacks_block_height + 1,
                burn_spent: 17000,
                consensus_hash: chain_tip.consensus_hash.clone(),
                parent_block_id: chain_tip.index_block_hash(),
                tx_merkle_root: Sha512Trunc256Sum::from_data(&[]),
                state_index_root,
                timestamp: 1,
                miner_signature: MessageSignature::empty(),
                signer_signature: vec![],
                pox_treatment: BitVec::ones(1).unwrap(),
            },
            txs,
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

/// Creates a default test vector with empty transactions and zero cost.
fn default_test_vector() -> ConsensusTestVector {
    let outputs = ExpectedBlockOutput {
        transactions: vec![],
        total_block_cost: ExecutionCost::ZERO,
    };
    ConsensusTestVector {
        initial_balances: HashMap::new(),
        marf_hash: "6fe3e70b95f5f56c9c7c2c59ba8fc9c19cdfede25d2dcd4d120438bc27dfa88b".into(),
        epoch_id: StacksEpochId::Epoch30 as u32,
        payloads: vec![],
        expected_result: ExpectedResult::Success(outputs),
    }
}

/// Creates a test vector expecting a failure due to a state root mismatch.
fn failing_test_vector() -> ConsensusTestVector {
    ConsensusTestVector {
        initial_balances: HashMap::new(),
        marf_hash: "0000000000000000000000000000000000000000000000000000000000000000".into(),
        epoch_id: StacksEpochId::Epoch30 as u32,
        payloads: vec![],
        expected_result: ExpectedResult::Failure(ChainstateError::InvalidStacksBlock("Block c8eeff18a0b03dec385bfe8268bc87ccf93fc00ff73af600c4e1aaef6e0dfaf5 state root mismatch: expected 0000000000000000000000000000000000000000000000000000000000000000, got 6fe3e70b95f5f56c9c7c2c59ba8fc9c19cdfede25d2dcd4d120438bc27dfa88b".into()).to_string()),
    }
}

#[test]
fn test_append_empty_block() {
    ConsensusTest::new(function_name!(), default_test_vector()).run()
}

#[test]
fn test_append_state_index_root_mismatch() {
    ConsensusTest::new(function_name!(), failing_test_vector()).run()
}
