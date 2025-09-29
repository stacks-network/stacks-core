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
use clarity::boot_util::boot_code_addr;
use clarity::codec::StacksMessageCodec;
use clarity::consts::CHAIN_ID_TESTNET;
use clarity::types::chainstate::{StacksAddress, StacksPrivateKey, StacksPublicKey, TrieHash};
use clarity::types::StacksEpochId;
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
use crate::chainstate::nakamoto::{NakamotoBlock, NakamotoBlockHeader, NakamotoChainState};
use crate::chainstate::stacks::boot::{RewardSet, RewardSetData};
use crate::chainstate::stacks::db::StacksEpochReceipt;
use crate::chainstate::stacks::{Error as ChainstateError, StacksTransaction, TenureChangeCause};
use crate::chainstate::tests::TestChainstate;
use crate::clarity_vm::clarity::{Error as ClarityError, PreCommitClarityBlock};
use crate::core::test_util::{make_contract_publish, make_stacks_transfer_tx};
use crate::net::tests::NakamotoBootPlan;
pub const SK_1: &str = "a1289f6438855da7decf9b61b852c882c398cff1446b2a0f823538aa2ebef92e01";
pub const SK_2: &str = "4ce9a8f7539ea93753a36405b16e8b57e15a552430410709c2b6d65dca5c02e201";
pub const SK_3: &str = "cb95ddd0fe18ec57f4f3533b95ae564b3f1ae063dbf75b46334bd86245aef78501";

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
    /// Initial balances for the provided PrincipalData during chainstate instantiation.
    pub initial_balances: Vec<(PrincipalData, u64)>,
    /// Hex representation of the MARF hash for block construction.
    pub marf_hash: String,
    /// The epoch ID for the test environment.
    pub epoch_id: u32,
    /// Transactions to include in the block
    pub transactions: Vec<StacksTransaction>,
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
        if let ExpectedResult::Success(output) = &test_vector.expected_result {
            assert_eq!(
                output.transactions.len(),
                test_vector.transactions.len(),
                "Test vector is invalid. Must specify an expected output per input transaction"
            );
        }
        let privk = StacksPrivateKey::from_hex(
            "510f96a8efd0b11e211733c1ac5e3fa6f3d3fcdd62869e376c47decb3e14fea101",
        )
        .unwrap();

        let epoch_id = StacksEpochId::try_from(test_vector.epoch_id).unwrap();
        let chain = match epoch_id {
            StacksEpochId::Epoch30
            | StacksEpochId::Epoch31
            | StacksEpochId::Epoch32
            | StacksEpochId::Epoch33 => {
                let mut chain = NakamotoBootPlan::new(test_name)
                    .with_pox_constants(10, 3)
                    .with_initial_balances(test_vector.initial_balances.clone())
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
        let (block, block_size) = self.construct_nakamoto_block();
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
        assert!(
            mismatches.is_none(),
            "Mismatches found: {}",
            ConsensusMismatch::to_json_string_pretty(&mismatches)
        );
    }

    /// Constructs a Nakamoto block with the given transactions and state index root.
    fn construct_nakamoto_block(&self) -> (NakamotoBlock, usize) {
        let state_index_root = TrieHash::from_hex(&self.test_vector.marf_hash).unwrap();
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
            txs: self.test_vector.transactions.clone(),
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
fn test_append_empty_block() {
    let outputs = ExpectedBlockOutput {
        transactions: vec![],
        total_block_cost: ExecutionCost::ZERO,
    };
    let test_vector = ConsensusTestVector {
        initial_balances: Vec::new(),
        marf_hash: "6fe3e70b95f5f56c9c7c2c59ba8fc9c19cdfede25d2dcd4d120438bc27dfa88b".into(),
        epoch_id: StacksEpochId::Epoch30 as u32,
        transactions: vec![],
        expected_result: ExpectedResult::Success(outputs),
    };
    ConsensusTest::new(function_name!(), test_vector).run()
}

#[test]
fn test_append_state_index_root_mismatch() {
    let test_vector = ConsensusTestVector {
        initial_balances: Vec::new(),
        // An invalid MARF. Will result in state root mismatch
        marf_hash: "0000000000000000000000000000000000000000000000000000000000000000".into(),
        epoch_id: StacksEpochId::Epoch30 as u32,
        transactions: vec![],
        expected_result: ExpectedResult::Failure(ChainstateError::InvalidStacksBlock("Block c8eeff18a0b03dec385bfe8268bc87ccf93fc00ff73af600c4e1aaef6e0dfaf5 state root mismatch: expected 0000000000000000000000000000000000000000000000000000000000000000, got 6fe3e70b95f5f56c9c7c2c59ba8fc9c19cdfede25d2dcd4d120438bc27dfa88b".into()).to_string()),
    };
    ConsensusTest::new(function_name!(), test_vector).run()
}

#[test]
fn test_append_stx_transfers() {
    let sender_privks = [
        StacksPrivateKey::from_hex(SK_1).unwrap(),
        StacksPrivateKey::from_hex(SK_2).unwrap(),
        StacksPrivateKey::from_hex(SK_3).unwrap(),
    ];
    let send_amount = 1_000;
    let tx_fee = 180;
    let mut initial_balances = Vec::new();
    let transactions = sender_privks
        .iter()
        .map(|sender_privk| {
            initial_balances.push((
                StacksAddress::p2pkh(false, &StacksPublicKey::from_private(sender_privk)).into(),
                send_amount + tx_fee,
            ));
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
    let test_vector = ConsensusTestVector {
        initial_balances,
        marf_hash: "3838b1ae67f108b10ec7a7afb6c2b18e6468be2423d7183ffa2f7824b619b8be".into(),
        epoch_id: StacksEpochId::Epoch30 as u32,
        transactions,
        expected_result: ExpectedResult::Success(outputs),
    };
    ConsensusTest::new(function_name!(), test_vector).run()
}

#[test]
fn test_append_chainstate_error_expression_stack_depth_too_deep() {
    // something just over the limit of the expression depth
    let exceeds_repeat_factor = AST_CALL_STACK_DEPTH_BUFFER + (MAX_CALL_STACK_DEPTH as u64);
    let tx_exceeds_body_start = "{ a : ".repeat(exceeds_repeat_factor as usize);
    let tx_exceeds_body_end = "} ".repeat(exceeds_repeat_factor as usize);
    let tx_exceeds_body = format!("{tx_exceeds_body_start}u1 {tx_exceeds_body_end}");

    let sender_privk = StacksPrivateKey::from_hex(SK_1).unwrap();
    let tx_fee = (tx_exceeds_body.len() * 100) as u64;
    let initial_balances = vec![(
        StacksAddress::p2pkh(false, &StacksPublicKey::from_private(&sender_privk)).into(),
        tx_fee,
    )];
    let tx_bytes = make_contract_publish(
        &sender_privk,
        0,
        tx_fee,
        CHAIN_ID_TESTNET,
        "test-exceeds",
        &tx_exceeds_body,
    );
    let tx = StacksTransaction::consensus_deserialize(&mut &tx_bytes[..]).unwrap();
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
        transactions: vec![transfer_result],
        total_block_cost: ExecutionCost::ZERO,
    };
    // TODO: should look into append_block. It does weird wrapping of ChainstateError variants inside ChainstateError::StacksInvalidBlock.
    let e = ChainstateError::ClarityError(ClarityError::Parse(ParseError::new(
        ParseErrors::ExpressionStackDepthTooDeep,
    )));
    let msg = format!("Invalid Stacks block 518dfea674b5c4874e025a31e01a522c8269005c0685d12658f0359757de6692: {e:?}");
    let test_vector = ConsensusTestVector {
        initial_balances,
        // Marf hash doesn't matter. It will fail with ExpressionStackDepthTooDeep
        marf_hash: "0000000000000000000000000000000000000000000000000000000000000000".into(),
        epoch_id: StacksEpochId::Epoch30 as u32,
        transactions: vec![tx],
        expected_result: ExpectedResult::Failure(
            ChainstateError::InvalidStacksBlock(msg).to_string(),
        ),
    };
    ConsensusTest::new(function_name!(), test_vector).run()
}
