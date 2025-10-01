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
use clarity::vm::types::PrincipalData;
use clarity::vm::{Value as ClarityValue, MAX_CALL_STACK_DEPTH};
use serde::{Deserialize, Serialize};
use stacks_common::bitvec::BitVec;

use crate::burnchains::PoxConstants;
use crate::chainstate::nakamoto::{NakamotoBlock, NakamotoBlockHeader, NakamotoChainState};
use crate::chainstate::stacks::boot::RewardSet;
use crate::chainstate::stacks::db::StacksEpochReceipt;
use crate::chainstate::stacks::{Error as ChainstateError, StacksTransaction, TenureChangeCause};
use crate::chainstate::tests::TestChainstate;
use crate::clarity_vm::clarity::Error as ClarityError;
use crate::core::test_util::{make_contract_publish, make_stacks_transfer_tx};
use crate::net::tests::NakamotoBootPlan;
pub const SK_1: &str = "a1289f6438855da7decf9b61b852c882c398cff1446b2a0f823538aa2ebef92e01";
pub const SK_2: &str = "4ce9a8f7539ea93753a36405b16e8b57e15a552430410709c2b6d65dca5c02e201";
pub const SK_3: &str = "cb95ddd0fe18ec57f4f3533b95ae564b3f1ae063dbf75b46334bd86245aef78501";

pub const FAUCET_PRIV_KEY: LazyCell<StacksPrivateKey> = LazyCell::new(|| {
    StacksPrivateKey::from_hex("510f96a8efd0b11e211733c1ac5e3fa6f3d3fcdd62869e376c47decb3e14fea101")
        .expect("Failed to parse private key")
});

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
}

/// Represents a consensus test with chainstate and test vector.
pub struct ConsensusTest<'a> {
    pub chain: TestChainstate<'a>,
    pub test_vector: ConsensusTestVector,
}

impl ConsensusTest<'_> {
    /// Creates a new `ConsensusTest` with the given test name and vector.
    pub fn new(test_name: &str, test_vector: ConsensusTestVector) -> Self {
        let epoch_id = StacksEpochId::try_from(test_vector.epoch_id).unwrap();
        let chain = match epoch_id {
            StacksEpochId::Epoch30
            | StacksEpochId::Epoch31
            | StacksEpochId::Epoch32
            | StacksEpochId::Epoch33 => {
                let mut chain = NakamotoBootPlan::new(test_name)
                    .with_pox_constants(10, 3)
                    .with_initial_balances(test_vector.initial_balances.clone())
                    .with_private_key(FAUCET_PRIV_KEY.clone())
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

    /// Runs the consensus test.
    ///
    /// This method constructs a block from the test vector, appends it to the
    /// chain, and returns the result of the block processing.
    pub fn run(mut self) -> ExpectedResult {
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

        result.map(|(receipt, _, _, _)| receipt).into()
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
    let test_vector = ConsensusTestVector {
        initial_balances: Vec::new(),
        marf_hash: "6fe3e70b95f5f56c9c7c2c59ba8fc9c19cdfede25d2dcd4d120438bc27dfa88b".into(),
        epoch_id: StacksEpochId::Epoch30 as u32,
        transactions: vec![],
    };
    let result = ConsensusTest::new(function_name!(), test_vector).run();
    // Example with inline expected result
    insta::assert_ron_snapshot!(result, @r"
    Success(ExpectedBlockOutput(
      transactions: [],
      total_block_cost: ExecutionCost(
        write_length: 0,
        write_count: 0,
        read_length: 0,
        read_count: 0,
        runtime: 0,
      ),
    ))
    ");
}

#[test]
fn test_append_state_index_root_mismatch() {
    let test_vector = ConsensusTestVector {
        initial_balances: Vec::new(),
        // An invalid MARF. Will result in state root mismatch
        marf_hash: "0000000000000000000000000000000000000000000000000000000000000000".into(),
        epoch_id: StacksEpochId::Epoch30 as u32,
        transactions: vec![],
    };

    let result = ConsensusTest::new(function_name!(), test_vector).run();
    insta::assert_ron_snapshot!(result);
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

    let test_vector = ConsensusTestVector {
        initial_balances,
        marf_hash: "3838b1ae67f108b10ec7a7afb6c2b18e6468be2423d7183ffa2f7824b619b8be".into(),
        epoch_id: StacksEpochId::Epoch30 as u32,
        transactions,
    };
    let result = ConsensusTest::new(function_name!(), test_vector).run();
    insta::assert_ron_snapshot!(result);
}

#[test]
fn test_append_chainstate_error_expression_stack_depth_too_deep() {
    // something just over the limit of the expression depth
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

    // TODO: should look into append_block. It does weird wrapping of ChainstateError variants inside ChainstateError::StacksInvalidBlock.
    let e = ChainstateError::ClarityError(ClarityError::Parse(ParseError::new(
        ParseErrors::ExpressionStackDepthTooDeep,
    )));
    let msg = format!("Invalid Stacks block 518dfea674b5c4874e025a31e01a522c8269005c0685d12658f0359757de6692: {e:?}");
    let test_vector = ConsensusTestVector {
        initial_balances: vec![],
        // Marf hash doesn't matter. It will fail with ExpressionStackDepthTooDeep
        marf_hash: "0000000000000000000000000000000000000000000000000000000000000000".into(),
        epoch_id: StacksEpochId::Epoch30 as u32,
        transactions: vec![tx],
    };
    let result = ConsensusTest::new(function_name!(), test_vector).run();
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

    let test_vector = ConsensusTestVector {
        initial_balances: vec![],
        marf_hash: "908f7e3a8c905d5ceabd3bcaced378038aec57e137034e35e29ddaaf738045b5".into(),
        epoch_id: StacksEpochId::Epoch32 as u32,
        transactions: vec![tx],
    };

    let result = ConsensusTest::new(function_name!(), test_vector).run();

    insta::assert_ron_snapshot!(result);
}
