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
use serde::{Deserialize, Serialize};
use stacks_common::bitvec::BitVec;

use crate::burnchains::PoxConstants;
use crate::chainstate::nakamoto::{NakamotoBlock, NakamotoBlockHeader, NakamotoChainState};
use crate::chainstate::stacks::boot::RewardSet;
use crate::chainstate::stacks::{
    StacksTransaction, TenureChangeCause, TransactionAuth, TransactionPayload, TransactionVersion,
};
use crate::chainstate::tests::TestChainstate;
use crate::net::tests::NakamotoBootPlan;

pub struct ConsensusTest<'a> {
    pub chain: TestChainstate<'a>,
    pub test_vector: ConsensusTestVector,
}

impl ConsensusTest<'_> {
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
                unimplemented!("Not bothering with pre nakamoto tests.");
            }
        };
        Self { chain, test_vector }
    }

    /// Run a single test vector, validating consensus.
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

        let expected_state_index_root =
            TrieHash::from_hex(&self.test_vector.expected_state_index_root).unwrap();

        let (block, block_size) = self.construct_nakamoto_block(txs, expected_state_index_root);
        let test_vector = self.test_vector.clone();

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

        let mut mismatches = Vec::new();

        match (&result, &test_vector.expected_result) {
            (Ok((epoch_receipt, _, _, tx_events)), ExpectedResult::Success(expected_outputs)) => {
                debug!("--------- Appended Block ---------";
                    "epoch_receipt" => ?epoch_receipt,
                    "tx_events" => ?tx_events
                );

                let actual_results = ExpectedOutputs {
                    transaction_return_types: epoch_receipt
                        .tx_receipts
                        .iter()
                        .map(|r| serde_json::to_string(&r.result).unwrap())
                        .collect(),
                    transaction_costs: epoch_receipt
                        .tx_receipts
                        .iter()
                        .map(|r| r.execution_cost.clone())
                        .collect(),
                    total_block_cost: epoch_receipt.anchored_block_cost.clone(),
                    marf_hash: epoch_receipt.header.index_root.to_hex(),
                };

                if actual_results != *expected_outputs {
                    if actual_results.transaction_return_types
                        != expected_outputs.transaction_return_types
                    {
                        mismatches.push(format!(
                            "Tx return types mismatch: actual {:?}, expected {:?}",
                            actual_results.transaction_return_types,
                            expected_outputs.transaction_return_types
                        ));
                    }
                    if actual_results.transaction_costs != expected_outputs.transaction_costs {
                        mismatches.push(format!(
                            "Tx costs mismatch: actual {:?}, expected {:?}",
                            actual_results.transaction_costs, expected_outputs.transaction_costs
                        ));
                    }
                    if actual_results.total_block_cost != expected_outputs.total_block_cost {
                        mismatches.push(format!(
                            "Total block cost mismatch: actual {:?}, expected {:?}",
                            actual_results.total_block_cost, expected_outputs.total_block_cost
                        ));
                    }
                    if actual_results.marf_hash != expected_outputs.marf_hash {
                        mismatches.push(format!(
                            "MARF hash mismatch: actual {}, expected {}",
                            actual_results.marf_hash, expected_outputs.marf_hash
                        ));
                    }
                }
            }
            (Ok(_), ExpectedResult::Failure(_)) => {
                mismatches.push("Expected failure but got success".to_string());
            }
            (Err(e), ExpectedResult::Failure(expected_err)) => {
                debug!("--------- Block Errored: {e} ---------");
                let actual_err = e.to_string();
                if !actual_err.contains(expected_err) {
                    mismatches.push(format!(
                        "Error mismatch: actual '{actual_err}', expected contains '{expected_err}'"
                    ));
                }
            }
            (Err(_), ExpectedResult::Success(_)) => {
                mismatches.push("Expected success but got failure".to_string());
            }
        }
        assert!(mismatches.is_empty(), "Mismatches: {mismatches:?}");
    }

    /// Construct a NakamotoBlock from the test vector.
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
        signers.sign_nakamoto_block(&mut block, self.chain.get_reward_cycle());
        let block_len = block.serialize_to_vec().len();

        (block, block_len)
    }
}

/// Test vector struct for `append_block` consensus testing.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ConsensusTestVector {
    /// A hex stacks address and amount pair for populating initial balances
    pub initial_balances: HashMap<String, u64>,
    /// Desired epoch of chainstate
    pub epoch_id: u32,
    /// Transaction payloads to stuff into the block
    pub payloads: Vec<String>,
    /// Expected state root trie hash
    pub expected_state_index_root: String,
    /// Expected result: success with outputs or failure with error
    pub expected_result: ExpectedResult,
}

/// Enum representing expected result: success with outputs or failure with error
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum ExpectedResult {
    Success(ExpectedOutputs),
    // TODO: should match maybe on actual Error type?
    Failure(String),
}

/// Expected outputs for a successful block append
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ExpectedOutputs {
    pub transaction_return_types: Vec<String>,
    pub transaction_costs: Vec<ExecutionCost>,
    pub total_block_cost: ExecutionCost,
    pub marf_hash: String,
}

fn default_test_vector() -> ConsensusTestVector {
    let outputs = ExpectedOutputs {
        transaction_return_types: vec![],
        transaction_costs: vec![],
        total_block_cost: ExecutionCost::ZERO,
        marf_hash: "f86c9ceaf2a17a4d9e502af73b6f00f89c18e5b58be501b3840f707f7b372dea".into(),
    };
    ConsensusTestVector {
        initial_balances: HashMap::new(),
        expected_state_index_root:
            "6fe3e70b95f5f56c9c7c2c59ba8fc9c19cdfede25d2dcd4d120438bc27dfa88b".into(),
        epoch_id: StacksEpochId::Epoch30 as u32,
        payloads: vec![],
        expected_result: ExpectedResult::Success(outputs),
    }
}

fn failing_test_vector() -> ConsensusTestVector {
    ConsensusTestVector {
        initial_balances: HashMap::new(),
        expected_state_index_root:
            "0000000000000000000000000000000000000000000000000000000000000000".into(),
        epoch_id: StacksEpochId::Epoch30 as u32,
        payloads: vec![],
        expected_result: ExpectedResult::Failure("state root mismatch".to_string()),
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
