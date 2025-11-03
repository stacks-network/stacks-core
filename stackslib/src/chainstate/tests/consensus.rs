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
use std::collections::{BTreeSet, HashMap};
use std::sync::LazyLock;

use clarity::boot_util::boot_code_addr;
use clarity::codec::StacksMessageCodec;
use clarity::consts::{CHAIN_ID_TESTNET, STACKS_EPOCH_MAX};
use clarity::types::chainstate::{
    StacksAddress, StacksBlockId, StacksPrivateKey, StacksPublicKey, TrieHash,
};
use clarity::types::{EpochList, StacksEpoch, StacksEpochId};
use clarity::util::hash::{MerkleTree, Sha512Trunc256Sum};
use clarity::util::secp256k1::MessageSignature;
use clarity::vm::ast::stack_depth_checker::AST_CALL_STACK_DEPTH_BUFFER;
use clarity::vm::costs::ExecutionCost;
use clarity::vm::types::PrincipalData;
use clarity::vm::{ClarityVersion, Value as ClarityValue, MAX_CALL_STACK_DEPTH};
use serde::{Deserialize, Serialize, Serializer};
use stacks_common::bitvec::BitVec;

use crate::burnchains::PoxConstants;
use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::nakamoto::{NakamotoBlock, NakamotoBlockHeader, NakamotoChainState};
use crate::chainstate::stacks::db::{ClarityTx, StacksChainState, StacksEpochReceipt};
use crate::chainstate::stacks::events::TransactionOrigin;
use crate::chainstate::stacks::tests::TestStacksNode;
use crate::chainstate::stacks::{
    Error as ChainstateError, StacksTransaction, TransactionContractCall, TransactionPayload,
    TransactionSmartContract, MINER_BLOCK_CONSENSUS_HASH, MINER_BLOCK_HEADER_HASH,
};
use crate::chainstate::tests::TestChainstate;
use crate::core::test_util::{
    make_contract_call, make_contract_publish_versioned, make_stacks_transfer_tx, to_addr,
};
use crate::core::BLOCK_LIMIT_MAINNET_21;
use crate::net::tests::NakamotoBootPlan;

/// The epochs to test for consensus are the current and upcoming epochs.
/// This constant must be changed when new epochs are introduced.
/// Note that contract deploys MUST be done in each epoch >= 2.0.
const EPOCHS_TO_TEST: &[StacksEpochId] = &[StacksEpochId::Epoch32, StacksEpochId::Epoch33];

pub const SK_1: &str = "a1289f6438855da7decf9b61b852c882c398cff1446b2a0f823538aa2ebef92e01";
pub const SK_2: &str = "4ce9a8f7539ea93753a36405b16e8b57e15a552430410709c2b6d65dca5c02e201";
pub const SK_3: &str = "cb95ddd0fe18ec57f4f3533b95ae564b3f1ae063dbf75b46334bd86245aef78501";

/// The private key for the faucet account.
pub static FAUCET_PRIV_KEY: LazyLock<StacksPrivateKey> = LazyLock::new(|| {
    StacksPrivateKey::from_hex("510f96a8efd0b11e211733c1ac5e3fa6f3d3fcdd62869e376c47decb3e14fea101")
        .expect("Failed to parse private key")
});

const FOO_CONTRACT: &str = "(define-public (foo) (ok 1))
                                    (define-public (bar (x uint)) (ok x))";

/// Returns the list of Clarity versions that can be used to deploy contracts in the given epoch.
const fn clarity_versions_for_epoch(epoch: StacksEpochId) -> &'static [ClarityVersion] {
    match epoch {
        StacksEpochId::Epoch10 => &[],
        StacksEpochId::Epoch20 | StacksEpochId::Epoch2_05 => &[ClarityVersion::Clarity1],
        StacksEpochId::Epoch21
        | StacksEpochId::Epoch22
        | StacksEpochId::Epoch23
        | StacksEpochId::Epoch24
        | StacksEpochId::Epoch25 => &[ClarityVersion::Clarity1, ClarityVersion::Clarity2],
        StacksEpochId::Epoch30 | StacksEpochId::Epoch31 | StacksEpochId::Epoch32 => &[
            ClarityVersion::Clarity1,
            ClarityVersion::Clarity2,
            ClarityVersion::Clarity3,
        ],
        StacksEpochId::Epoch33 => &[
            ClarityVersion::Clarity1,
            ClarityVersion::Clarity2,
            ClarityVersion::Clarity3,
            ClarityVersion::Clarity4,
        ],
    }
}

/// Custom serializer for `Option<TransactionPayload>` to improve snapshot readability.
/// This avoids large diffs in snapshots due to code body changes and focuses on key fields.
fn serialize_opt_tx_payload<S>(
    value: &Option<TransactionPayload>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let changed = match value {
        None => "BitcoinTx".to_string(),
        Some(TransactionPayload::TokenTransfer(sender, amount, memo)) => {
            format!("TokenTransfer(from: {sender}, amount: {amount}, memo: {memo})")
        }
        Some(TransactionPayload::SmartContract(
            TransactionSmartContract { name, code_body },
            clarity_version,
        )) => {
            format!("SmartContract(name: {name}, code_body: [..], clarity_version: {clarity_version:?})")
        }
        Some(TransactionPayload::ContractCall(TransactionContractCall {
            address,
            contract_name,
            function_name,
            function_args,
        })) => {
            format!("ContractCall(address: {address}, contract_name: {contract_name}, function_name: {function_name}, function_args: [{function_args:?}])")
        }
        Some(payload) => {
            format!("{payload:?}")
        }
    };
    serializer.serialize_str(&changed)
}

/// Serialize an optional string field appending a non-consensus breaking info message.
fn serialize_opt_string_ncb<S>(value: &Option<String>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let original = match value.as_deref() {
        Some(str) => format!("Some({str})"),
        None => "None".to_string(),
    };
    let changed = format!("{original} [NON-CONSENSUS BREAKING]");
    serializer.serialize_str(&changed)
}

/// Represents the expected output of a transaction in a test.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ExpectedTransactionOutput {
    /// The transaction that was executed.
    /// `None` for bitcoin transactions.
    #[serde(serialize_with = "serialize_opt_tx_payload")]
    pub tx: Option<TransactionPayload>,
    /// The possible Clarity VM error message associated to the transaction (non-consensus breaking)
    #[serde(serialize_with = "serialize_opt_string_ncb")]
    pub vm_error: Option<String>,
    /// The expected return value of the transaction.
    pub return_type: ClarityValue,
    /// The expected execution cost of the transaction.
    pub cost: ExecutionCost,
}

/// Represents the expected outputs for a block's execution.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ExpectedBlockOutput {
    /// The expected block marf
    pub marf_hash: TrieHash,
    /// The epoch in which the test block was expected to be evaluated
    pub evaluated_epoch: StacksEpochId,
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
    fn create_from(
        result: Result<StacksEpochReceipt, ChainstateError>,
        marf_hash: TrieHash,
    ) -> Self {
        match result {
            Ok(epoch_receipt) => {
                let transactions: Vec<ExpectedTransactionOutput> = epoch_receipt
                    .tx_receipts
                    .into_iter()
                    .map(|r| {
                        let tx = match r.transaction {
                            TransactionOrigin::Stacks(tx) => Some(tx.payload),
                            TransactionOrigin::Burn(..) => None,
                        };
                        ExpectedTransactionOutput {
                            tx,
                            return_type: r.result,
                            cost: r.execution_cost,
                            vm_error: r.vm_error,
                        }
                    })
                    .collect();
                ExpectedResult::Success(ExpectedBlockOutput {
                    marf_hash,
                    evaluated_epoch: epoch_receipt.evaluated_epoch,
                    transactions,
                    total_block_cost: epoch_receipt.anchored_block_cost,
                })
            }
            Err(e) => ExpectedResult::Failure(e.to_string()),
        }
    }
}

/// Represents a block to be appended in a test and its expected result.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct TestBlock {
    /// Transactions to include in the block
    pub transactions: Vec<StacksTransaction>,
}

/// Manages a `TestChainstate` tailored for consensus-rule verification.
///
/// Initialises the chain with enough burn-chain blocks per epoch to run
/// the requested number of Stacks blocks per epoch.
///
/// Provides high-level helpers for:
/// - Appending Nakamoto or pre-Nakamoto blocks
pub struct ConsensusChain<'a> {
    pub test_chainstate: TestChainstate<'a>,
}

impl ConsensusChain<'_> {
    /// Creates a new `ConsensusChain`.
    ///
    /// # Arguments
    ///
    /// * `test_name` – identifier used for logging / snapshot names / database names
    /// * `initial_balances` – `(principal, amount)` pairs that receive an initial STX balance
    /// * `num_blocks_per_epoch` – how many **Stacks** blocks must fit into each epoch
    ///
    /// # Panics
    ///
    /// * If `Epoch10` is requested (unsupported)
    /// * If any requested epoch is given `0` blocks
    pub fn new(
        test_name: &str,
        initial_balances: Vec<(PrincipalData, u64)>,
        num_blocks_per_epoch: HashMap<StacksEpochId, u64>,
    ) -> Self {
        // Validate blocks
        for (epoch_id, num_blocks) in &num_blocks_per_epoch {
            assert_ne!(
                *epoch_id,
                StacksEpochId::Epoch10,
                "Epoch10 is not supported"
            );
            assert!(
                *num_blocks > 0,
                "Each epoch must have at least one block. {epoch_id} is empty"
            );
        }
        // Set up chainstate to support Naka.
        let mut boot_plan = NakamotoBootPlan::new(test_name)
            .with_pox_constants(7, 1)
            .with_initial_balances(initial_balances)
            .with_private_key(FAUCET_PRIV_KEY.clone());
        let (epochs, first_burnchain_height) =
            Self::calculate_epochs(&boot_plan.pox_constants, num_blocks_per_epoch);
        boot_plan = boot_plan.with_epochs(epochs);
        let test_chainstate = boot_plan.to_chainstate(None, Some(first_burnchain_height));
        Self { test_chainstate }
    }

    /// Calculates a valid [`EpochList`] and starting burnchain height for the test harness.
    ///
    /// The resulting EpochList satisfies the following:
    /// - Each epoch has enough burnchain blocks to accommodate all test blocks.
    /// - Epoch 2.5 → 3.0 transition satisfies the following constraints:
    ///   - 2.5 and 3.0 are in **different reward cycles**.
    ///   - 2.5 starts **before** the prepare phase of the cycle prior to 3.0 activation.
    ///   - 3.0 does not start on a reward cycle boundary.
    /// - All epoch heights are contiguous and correctly ordered.
    ///
    /// The resulting [`EpochList`] is used to initialize the test chainstate with correct
    /// epoch boundaries, enabling accurate simulation of epoch transitions and consensus rules.
    ///
    /// # Arguments
    ///
    /// * `pox_constants` - PoX configuration (reward cycle length, prepare phase, etc.).
    /// * `num_blocks_per_epoch` - Map of epoch IDs to the number of test blocks to run in each.
    ///
    /// # Returns
    ///
    /// `(EpochList<ExecutionCost>, first_burnchain_height)` — the epoch list and the burnchain
    /// height at which the first Stacks block is mined.
    fn calculate_epochs(
        pox_constants: &PoxConstants,
        num_blocks_per_epoch: HashMap<StacksEpochId, u64>,
    ) -> (EpochList<ExecutionCost>, u64) {
        // Helper function to check if a height is at a reward cycle boundary
        let is_reward_cycle_boundary = |height: u64, reward_cycle_length: u64| -> bool {
            height % reward_cycle_length <= 1 // Covers both 0 (end of cycle) and 1 (start of cycle)
        };

        let first_burnchain_height =
            (pox_constants.pox_4_activation_height + pox_constants.reward_cycle_length + 1) as u64;
        info!("StacksEpoch calculate_epochs first_burn_height = {first_burnchain_height}");
        let reward_cycle_length = pox_constants.reward_cycle_length as u64;
        let prepare_length = pox_constants.prepare_length as u64;
        // Initialize heights
        let mut epochs = vec![];
        let mut current_height = 0;
        for epoch_id in StacksEpochId::ALL.iter() {
            let start_height = current_height;
            let end_height = match *epoch_id {
                StacksEpochId::Epoch10 => first_burnchain_height,
                StacksEpochId::Epoch20
                | StacksEpochId::Epoch2_05
                | StacksEpochId::Epoch21
                | StacksEpochId::Epoch22
                | StacksEpochId::Epoch23
                | StacksEpochId::Epoch24 => {
                    // Use test vector block count
                    // Always add 1 so we can ensure we are fully in the epoch before we then execute
                    // the corresponding test blocks in their own blocks
                    let num_blocks = num_blocks_per_epoch
                        .get(epoch_id)
                        .map(|num_blocks| *num_blocks + 1)
                        .unwrap_or(0);
                    start_height + num_blocks
                }
                StacksEpochId::Epoch25 => {
                    // Calculate Epoch 2.5 end height and Epoch 3.0 start height.
                    // Epoch 2.5 must start before the prepare phase of the cycle prior to Epoch 3.0's activation.
                    // Epoch 2.5 end must equal Epoch 3.0 start
                    // Epoch 3.0 must not start at a cycle boundary
                    // Epoch 2.5 and 3.0 cannot be in the same reward cycle.
                    let num_blocks = num_blocks_per_epoch
                        .get(epoch_id)
                        .copied()
                        .unwrap_or(0)
                        .saturating_add(1); // Add one block for pox lockups.

                    let epoch_25_start = current_height;
                    let epoch_30_start = epoch_25_start + num_blocks;

                    let epoch_25_reward_cycle = epoch_25_start / reward_cycle_length;
                    let mut epoch_30_start = epoch_30_start;
                    let mut epoch_30_reward_cycle = epoch_30_start / reward_cycle_length;
                    // Ensure different reward cycles and Epoch 2.5 starts before prior cycle's prepare phase
                    let mut prior_cycle = epoch_30_reward_cycle.saturating_sub(1);
                    let mut prior_prepare_phase_start =
                        prior_cycle * reward_cycle_length + (reward_cycle_length - prepare_length);
                    while epoch_25_start + num_blocks >= prior_prepare_phase_start
                        || epoch_25_reward_cycle >= epoch_30_reward_cycle
                        || is_reward_cycle_boundary(epoch_30_start, reward_cycle_length)
                    {
                        // Advance to 3.0 start so it is not in a reward cycle boundary and to ensure
                        // 2.5 starts prior to the prepare phase of epoch 30 reward cycle activation
                        epoch_30_start += 1;
                        epoch_30_reward_cycle = epoch_30_start / reward_cycle_length;
                        prior_cycle = epoch_30_reward_cycle.saturating_sub(1);
                        prior_prepare_phase_start = prior_cycle * reward_cycle_length
                            + (reward_cycle_length - prepare_length);
                    }
                    current_height = epoch_30_start;
                    epoch_30_start // Epoch 2.5 ends where Epoch 3.0 starts
                }
                StacksEpochId::Epoch30 | StacksEpochId::Epoch31 | StacksEpochId::Epoch32 => {
                    // Only need 1 block per Epoch
                    if num_blocks_per_epoch.contains_key(epoch_id) {
                        start_height + 1
                    } else {
                        // If we don't care to have any blocks in this epoch
                        // don't bother giving it an epoch height
                        start_height
                    }
                }
                StacksEpochId::Epoch33 => {
                    // The last epoch extends to max
                    STACKS_EPOCH_MAX
                }
            };
            // Create epoch
            let block_limit = if *epoch_id == StacksEpochId::Epoch10 {
                ExecutionCost::max_value()
            } else {
                BLOCK_LIMIT_MAINNET_21.clone()
            };
            let network_epoch = StacksEpochId::network_epoch(*epoch_id);
            epochs.push(StacksEpoch {
                epoch_id: *epoch_id,
                start_height,
                end_height,
                block_limit,
                network_epoch,
            });
            current_height = end_height;
        }
        // Validate Epoch 2.5 and 3.0 constraints
        if let Some(epoch_3_0) = epochs.iter().find(|e| e.epoch_id == StacksEpochId::Epoch30) {
            let epoch_2_5 = epochs
                .iter()
                .find(|e| e.epoch_id == StacksEpochId::Epoch25)
                .expect("Epoch 2.5 not found");
            let epoch_2_5_start = epoch_2_5.start_height;
            let epoch_3_0_start = epoch_3_0.start_height;
            let epoch_2_5_end = epoch_2_5.end_height;

            let epoch_2_5_reward_cycle = epoch_2_5_start / reward_cycle_length;
            let epoch_3_0_reward_cycle = epoch_3_0_start / reward_cycle_length;
            let prior_cycle = epoch_3_0_reward_cycle.saturating_sub(1);
            let epoch_3_0_prepare_phase =
                prior_cycle * reward_cycle_length + (reward_cycle_length - prepare_length);
            assert!(
                epoch_2_5_start < epoch_3_0_prepare_phase,
                "Epoch 2.5 must start before the prepare phase of the cycle prior to Epoch 3.0. (Epoch 2.5 activation height: {epoch_2_5_start}. Epoch 3.0 prepare phase start: {epoch_3_0_prepare_phase})"
            );
            assert_eq!(
                epoch_2_5_end, epoch_3_0.start_height,
                "Epoch 2.5 end must equal Epoch 3.0 start (epoch_2_5_end: {epoch_2_5_end}, epoch_3_0_start: {epoch_3_0_start})"
            );
            assert_ne!(
                epoch_2_5_reward_cycle, epoch_3_0_reward_cycle,
                "Epoch 2.5 and Epoch 3.0 must not be in the same reward cycle (epoch_2_5_reward_cycle: {epoch_2_5_reward_cycle}, epoch_3_0_reward_cycle: {epoch_3_0_reward_cycle})"
            );
            assert!(
                !is_reward_cycle_boundary(epoch_3_0_start, reward_cycle_length),
                "Epoch 3.0 must not start at a reward cycle boundary (epoch_3_0_start: {epoch_3_0_start})"
            );
        }
        // Validate test vector block counts
        for (epoch_id, num_blocks) in num_blocks_per_epoch {
            let epoch = epochs
                .iter()
                .find(|e| e.epoch_id == epoch_id)
                .expect("Epoch not found");
            let epoch_length = epoch.end_height - epoch.start_height;
            if epoch_id > StacksEpochId::Epoch25 {
                assert!(
                    epoch_length > 0,
                    "{epoch_id:?} must have at least 1 burn block."
                );
            } else {
                assert!(
                    epoch_length >= num_blocks,
                    "{epoch_id:?} must have at least {num_blocks} burn blocks, got {epoch_length}"
                );
            }
        }
        let epoch_list = EpochList::new(&epochs);
        info!("Calculated EpochList from pox constants with first burnchain height of {first_burnchain_height}.";
            "epochs" => ?epoch_list,
            "first_burnchain_height" => first_burnchain_height
        );
        (epoch_list, first_burnchain_height)
    }

    /// Appends a single block to the chain as a Nakamoto block and returns the result.
    ///
    /// This method takes a [`TestBlock`] containing a list of transactions, constructs
    /// a fully valid [`NakamotoBlock`], processes it against the current chainstate.
    ///
    /// # Arguments
    ///
    /// * `block` - The test block to be processed and appended to the chain.
    ///
    /// # Returns
    ///
    /// A [`ExpectedResult`] with the outcome of the block processing.
    fn append_nakamoto_block(&mut self, block: TestBlock) -> ExpectedResult {
        debug!("--------- Running block {block:?} ---------");
        let (nakamoto_block, _block_size) = self.construct_nakamoto_block(block);
        let mut sortdb = self.test_chainstate.sortdb.take().unwrap();
        let mut stacks_node = self.test_chainstate.stacks_node.take().unwrap();
        let chain_tip =
            NakamotoChainState::get_canonical_block_header(stacks_node.chainstate.db(), &sortdb)
                .unwrap()
                .unwrap();
        let sig_hash = nakamoto_block.header.signer_signature_hash();
        debug!(
            "--------- Processing block {sig_hash} ---------";
            "block" => ?nakamoto_block
        );
        let expected_marf = nakamoto_block.header.state_index_root;
        let res = TestStacksNode::process_pushed_next_ready_block(
            &mut stacks_node,
            &mut sortdb,
            &mut self.test_chainstate.miner,
            &chain_tip.consensus_hash,
            &mut self.test_chainstate.coord,
            nakamoto_block.clone(),
        );
        debug!(
            "--------- Processed block: {sig_hash} ---------";
            "block" => ?nakamoto_block
        );
        let remapped_result = res.map(|receipt| receipt.unwrap());
        // Restore chainstate for the next block
        self.test_chainstate.sortdb = Some(sortdb);
        self.test_chainstate.stacks_node = Some(stacks_node);
        ExpectedResult::create_from(remapped_result, expected_marf)
    }

    /// Appends a single block to the chain as a Pre-Nakamoto block and returns the result.
    ///
    /// This method takes a [`TestBlock`] containing a list of transactions, constructs
    /// a fully valid [`StacksBlock`], processes it against the current chainstate.
    ///
    /// # Arguments
    ///
    /// * `block` - The test block to be processed and appended to the chain.
    /// * `coinbase_nonce` - The coinbase nonce to use and increment
    ///
    /// # Returns
    ///
    /// A [`ExpectedResult`] with the outcome of the block processing.
    fn append_pre_nakamoto_block(&mut self, block: TestBlock) -> ExpectedResult {
        debug!("--------- Running Pre-Nakamoto block {block:?} ---------");
        let (ch, bh) = SortitionDB::get_canonical_stacks_chain_tip_hash(
            self.test_chainstate.sortdb_ref().conn(),
        )
        .unwrap();
        let tip_id = StacksBlockId::new(&ch, &bh);
        let (burn_ops, stacks_block, microblocks) = self
            .test_chainstate
            .make_pre_nakamoto_tenure_with_txs(&block.transactions);
        let (_, _, consensus_hash) = self.test_chainstate.next_burnchain_block(burn_ops);

        debug!(
            "--------- Processing Pre-Nakamoto block ---------";
            "block" => ?stacks_block
        );

        let mut stacks_node = self.test_chainstate.stacks_node.take().unwrap();
        let mut sortdb = self.test_chainstate.sortdb.take().unwrap();
        let expected_marf = stacks_block.header.state_index_root;
        let res = TestStacksNode::process_pre_nakamoto_next_ready_block(
            &mut stacks_node,
            &mut sortdb,
            &mut self.test_chainstate.miner,
            &ch,
            &mut self.test_chainstate.coord,
            &stacks_block,
            &microblocks,
        );
        debug!(
            "--------- Processed Pre-Nakamoto block ---------";
            "block" => ?stacks_block
        );
        let remapped_result = res.map(|receipt| {
            let mut receipt = receipt.unwrap();
            let mut sanitized_receipts = vec![];
            for tx_receipt in &receipt.tx_receipts {
                // Remove any coinbase transactions from the output
                if tx_receipt.is_coinbase_tx() {
                    continue;
                }
                sanitized_receipts.push(tx_receipt.clone());
            }
            receipt.tx_receipts = sanitized_receipts;
            receipt
        });
        // Restore chainstate for the next block
        self.test_chainstate.sortdb = Some(sortdb);
        self.test_chainstate.stacks_node = Some(stacks_node);
        ExpectedResult::create_from(remapped_result, expected_marf)
    }

    /// Appends a single block to the chain and returns the result.
    ///
    /// This method takes a [`TestBlock`] containing a list of transactions, whether the epoch [`is_naka_epoch`] ,
    /// constructing a fully valid [`StacksBlock`] or [`NakamotoBlock`] accordingly, processes it against the current chainstate.
    ///
    /// # Arguments
    ///
    /// * `block` - The test block to be processed and appended to the chain.
    /// * `coinbase_nonce` - The coinbase nonce to use and increment
    ///
    /// # Returns
    ///
    /// A [`ExpectedResult`] with the outcome of the block processing.
    pub fn append_block(&mut self, block: TestBlock, is_naka_epoch: bool) -> ExpectedResult {
        if is_naka_epoch {
            self.append_nakamoto_block(block)
        } else {
            self.append_pre_nakamoto_block(block)
        }
    }

    /// Constructs a Nakamoto block with the given [`TestBlock`] configuration.
    fn construct_nakamoto_block(&mut self, test_block: TestBlock) -> (NakamotoBlock, usize) {
        let chain_tip = NakamotoChainState::get_canonical_block_header(
            self.test_chainstate
                .stacks_node
                .as_ref()
                .unwrap()
                .chainstate
                .db(),
            self.test_chainstate.sortdb.as_ref().unwrap(),
        )
        .unwrap()
        .unwrap();
        let cycle = self.test_chainstate.get_reward_cycle();
        let burn_spent = SortitionDB::get_block_snapshot_consensus(
            self.test_chainstate.sortdb_ref().conn(),
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
            txs: test_block.transactions,
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

        // Set the MARF root hash or use an all-zero hash in case of failure.
        // NOTE: It is expected to fail when trying computing the marf for invalid block/transactions.
        let marf_result = self.compute_block_marf_root_hash(block.header.timestamp, &block.txs);
        block.header.state_index_root = match marf_result {
            Ok(marf) => marf,
            Err(_) => TrieHash::from_bytes(&[0; 32]).unwrap(),
        };

        self.test_chainstate.miner.sign_nakamoto_block(&mut block);
        let mut signers = self
            .test_chainstate
            .config
            .test_signers
            .clone()
            .unwrap_or_default();
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
        block_txs: &[StacksTransaction],
    ) -> Result<TrieHash, String> {
        let node = self.test_chainstate.stacks_node.as_mut().unwrap();
        let sortdb = self.test_chainstate.sortdb.as_ref().unwrap();
        let burndb_conn = sortdb.index_handle_at_tip();
        let chainstate = &mut node.chainstate;

        let chain_tip = NakamotoChainState::get_canonical_block_header(chainstate.db(), sortdb)
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
        let result = Self::inner_compute_block_marf_root_hash(
            &mut clarity_tx,
            block_time,
            block_txs,
            chain_tip.burn_header_height,
        );
        clarity_tx.rollback_block();
        result
    }

    /// This is where the real MARF computation happens.
    /// It is extrapolated into an _inner_ method to simplify rollback handling,
    /// ensuring that rollback can be applied consistently on both success and failure
    /// in the _outer_ method.
    fn inner_compute_block_marf_root_hash(
        clarity_tx: &mut ClarityTx,
        block_time: u64,
        block_txs: &[StacksTransaction],
        burn_header_height: u32,
    ) -> Result<TrieHash, String> {
        clarity_tx
            .connection()
            .as_free_transaction(|clarity_tx_conn| {
                clarity_tx_conn.with_clarity_db(|db| {
                    db.setup_block_metadata(Some(block_time))?;
                    Ok(())
                })
            })
            .map_err(|e| e.to_string())?;

        StacksChainState::process_block_transactions(clarity_tx, block_txs, 0)
            .map_err(|e| e.to_string())?;

        NakamotoChainState::finish_block(clarity_tx, None, false, burn_header_height)
            .map_err(|e| e.to_string())?;

        Ok(clarity_tx.seal())
    }
}

/// A complete consensus test that drives a `ConsensusChain` through a series of epochs.
///
/// It stores the blocks to execute per epoch and runs them in chronological order,
/// producing a vector of `ExpectedResult` suitable for snapshot testing.
pub struct ConsensusTest<'a> {
    pub chain: ConsensusChain<'a>,
    epoch_blocks: HashMap<StacksEpochId, Vec<TestBlock>>,
}

impl ConsensusTest<'_> {
    /// Constructs a `ConsensusTest` from a map of **epoch → blocks**.
    ///
    /// The map is converted into `num_blocks_per_epoch` for chain initialisation.
    pub fn new(
        test_name: &str,
        initial_balances: Vec<(PrincipalData, u64)>,
        epoch_blocks: HashMap<StacksEpochId, Vec<TestBlock>>,
    ) -> Self {
        let mut num_blocks_per_epoch = HashMap::new();
        for (epoch, blocks) in &epoch_blocks {
            num_blocks_per_epoch.insert(*epoch, blocks.len() as u64);
        }
        Self {
            chain: ConsensusChain::new(test_name, initial_balances, num_blocks_per_epoch),
            epoch_blocks,
        }
    }

    /// Executes a full test plan by processing blocks across multiple epochs.
    ///
    /// This function serves as the primary test runner. It iterates through the
    /// provided epochs in chronological order, automatically advancing the
    /// chainstate to the start of each epoch. It then processes all [`TestBlock`]'s
    /// associated with that epoch and collects their results.
    ///
    ///  # Returns
    ///
    /// A `Vec<ExpectedResult>` with the outcome of each block for snapshot testing.
    pub fn run(mut self) -> Vec<ExpectedResult> {
        let mut sorted_epochs: Vec<_> = self.epoch_blocks.clone().into_iter().collect();
        sorted_epochs.sort_by_key(|(epoch_id, _)| *epoch_id);

        let mut results = vec![];

        for (epoch, blocks) in sorted_epochs {
            debug!(
                "--------- Processing epoch {epoch:?} with {} blocks ---------",
                blocks.len()
            );
            // Use the miner key to prevent messing with FAUCET nonces.
            let miner_key = self.chain.test_chainstate.miner.nakamoto_miner_key();
            self.chain
                .test_chainstate
                .advance_into_epoch(&miner_key, epoch);

            for block in blocks {
                results.push(self.chain.append_block(block, epoch.uses_nakamoto_blocks()));
            }
        }
        results
    }
}

/// A high-level test harness for running consensus-critical smart contract tests.
///
/// This struct enables end-to-end testing of Clarity smart contracts under varying epoch conditions,
/// including different Clarity language versions and block rule sets. It automates:
///
/// - Contract deployment in specified epochs (with epoch-appropriate Clarity versions)
/// - Function execution in subsequent or same epochs
/// - Block-by-block execution with precise control over transaction ordering and nonces
/// - Snapshot testing of execution outcomes via [`ExpectedResult`]
///
/// It integrates:
/// - [`ConsensusChain`] for chain simulation and block production
/// - [`TestTxFactory`] for deterministic transaction generation
///
/// NOTE: The **majority of logic and state computation occurs during construction to enable a deterministic TestChainstate** (`new()`):
/// - All contract names are generated and versioned
/// - Block counts per epoch are precomputed
/// - Epoch order is finalized
/// - Transaction sequencing is fully planned
struct ContractConsensusTest<'a> {
    /// Factory for generating signed, nonce-managed transactions.
    tx_factory: TestTxFactory,
    /// Underlying chainstate used for block execution and consensus checks.
    chain: ConsensusChain<'a>,
    /// Address of the contract deployer (the test faucet).
    contract_addr: StacksAddress,
    /// Mapping of epoch → list of `(contract_name, ClarityVersion)` deployed in that epoch.
    /// Multiple versions may exist per epoch (e.g., Clarity 1, 2, 3 in Epoch 3.0).
    contract_deploys_per_epoch: HashMap<StacksEpochId, Vec<(String, ClarityVersion)>>,
    /// Mapping of epoch → list of `contract_names` that should be called in that epoch.
    contract_calls_per_epoch: HashMap<StacksEpochId, Vec<String>>,
    /// Source code of the Clarity contract being deployed and called.
    contract_code: String,
    /// Name of the public function to invoke during the call phase.
    function_name: String,
    /// Arguments to pass to `function_name` on every call.
    function_args: Vec<ClarityValue>,
    /// Sorted, deduplicated set of all epochs involved.
    /// Used to iterate through test phases in chronological order.
    all_epochs: BTreeSet<StacksEpochId>,
}

impl ContractConsensusTest<'_> {
    /// Creates a new [`ContractConsensusTest`] instance.
    ///
    /// Initializes the test environment to:
    /// - Deploy `contract_code` under `contract_name` in each `deploy_epochs`
    /// - Call `function_name` with `function_args` in each `call_epochs`
    /// - Track all contract instances per epoch and Clarity version
    /// - Precompute block counts per epoch for stable chain simulation
    ///
    /// # Arguments
    ///
    /// * `test_name` - Unique identifier for the test run (used in logging and snapshots)
    /// * `initial_balances` - Initial STX balances for principals (e.g., faucet, users)
    /// * `deploy_epochs` - List of epochs where contract deployment should occur
    /// * `call_epochs` - List of epochs where function calls should be executed
    /// * `contract_name` - Base name for deployed contracts (versioned suffixes added automatically)
    /// * `contract_code` - Clarity source code of the contract
    /// * `function_name` - Contract function to test
    /// * `function_args` - Arguments passed to `function_name` on every call
    ///
    /// # Panics
    ///
    /// - If `deploy_epochs` is empty.
    /// - If any `call_epoch` is less than the minimum `deploy_epoch`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        test_name: &str,
        initial_balances: Vec<(PrincipalData, u64)>,
        deploy_epochs: &[StacksEpochId],
        call_epochs: &[StacksEpochId],
        contract_name: &str,
        contract_code: &str,
        function_name: &str,
        function_args: &[ClarityValue],
    ) -> Self {
        assert!(
            !deploy_epochs.is_empty(),
            "At least one deploy epoch is required"
        );
        let min_deploy_epoch = deploy_epochs.iter().min().unwrap();
        assert!(
            call_epochs.iter().all(|e| e >= min_deploy_epoch),
            "All call epochs must be >= the minimum deploy epoch"
        );

        // Build epoch_blocks map based on deploy and call epochs
        let mut num_blocks_per_epoch: HashMap<StacksEpochId, u64> = HashMap::new();
        let mut contract_deploys_per_epoch: HashMap<StacksEpochId, Vec<(String, ClarityVersion)>> =
            HashMap::new();
        let mut contract_calls_per_epoch: HashMap<StacksEpochId, Vec<String>> = HashMap::new();
        let mut contract_names = vec![];

        // Combine and sort unique epochs
        let all_epochs: BTreeSet<StacksEpochId> =
            deploy_epochs.iter().chain(call_epochs).cloned().collect();

        // Precompute contract names and block counts
        for epoch in &all_epochs {
            let mut num_blocks = 0;

            if deploy_epochs.contains(epoch) {
                let clarity_versions = clarity_versions_for_epoch(*epoch);
                let epoch_name = format!("Epoch{}", epoch.to_string().replace('.', "_"));

                // Each deployment is a seperate TestBlock
                for &version in clarity_versions {
                    let version_tag = version.to_string().replace(' ', "");
                    let name = format!("{contract_name}-{epoch_name}-{version_tag}");
                    contract_deploys_per_epoch
                        .entry(*epoch)
                        .or_default()
                        .push((name.clone(), version));
                    contract_names.push(name.clone());
                    num_blocks += 1;
                }
            }

            if call_epochs.contains(epoch) {
                // Each call is a separate TestBlock
                for name in &contract_names {
                    // Each call is a separate TestBlock
                    contract_calls_per_epoch
                        .entry(*epoch)
                        .or_default()
                        .push(name.clone());
                    num_blocks += 1;
                }
            }
            if num_blocks > 0 {
                num_blocks_per_epoch.insert(*epoch, num_blocks);
            }
        }

        Self {
            tx_factory: TestTxFactory::new(CHAIN_ID_TESTNET),
            chain: ConsensusChain::new(test_name, initial_balances, num_blocks_per_epoch),
            contract_addr: to_addr(&FAUCET_PRIV_KEY),
            contract_deploys_per_epoch,
            contract_calls_per_epoch,
            contract_code: contract_code.to_string(),
            function_name: function_name.to_string(),
            function_args: function_args.to_vec(),
            all_epochs,
        }
    }

    /// Generates a transaction, appends it to a new test block, and executes the block.
    ///
    /// If the transaction succeeds, this function automatically increments the sender's
    /// nonce for subsequent transactions.
    ///
    /// # Arguments
    ///
    /// - `tx_spec`: The transaction specification to generate and execute.
    /// - `is_naka_block`: Whether this block is mined under Nakamoto consensus rules.
    ///
    /// # Returns
    ///
    /// The [`ExpectedResult`] of block execution (success/failure with VM output)
    fn append_tx_block(&mut self, tx_spec: &TestTxSpec, is_naka_block: bool) -> ExpectedResult {
        let tx = self.tx_factory.generate_tx(tx_spec);
        let block = TestBlock {
            transactions: vec![tx],
        };

        let result = self.chain.append_block(block, is_naka_block);

        if let ExpectedResult::Success(_) = result {
            self.tx_factory.increase_nonce_for_tx(tx_spec);
        }

        result
    }

    /// Deploys all contract versions scheduled for the given epoch.
    ///
    /// For each Clarity version supported in the epoch:
    /// - Generates a unique contract name (e.g., `my-contract-Epoch30-Clarity3`)
    /// - Deploys in a **separate block**
    /// - Uses `None` for Clarity version in pre-2.1 epochs (behaviour defaults to Clarity 1)
    ///
    /// # Returns
    /// A vector of [`ExpectedResult`] values, one per deployment block.
    fn deploy_contracts(&mut self, epoch: StacksEpochId) -> Vec<ExpectedResult> {
        let Some(contract_names) = self.contract_deploys_per_epoch.get(&epoch) else {
            warn!("No contract deployments found for {epoch}.");
            return vec![];
        };

        let is_naka_block = epoch.uses_nakamoto_blocks();
        contract_names
            .clone()
            .iter()
            .map(|(name, version)| {
                let clarity_version = if epoch < StacksEpochId::Epoch21 {
                    // Old epochs have no concept of clarity version. It defaults to
                    // clarity version 1 behaviour.
                    None
                } else {
                    Some(*version)
                };
                self.append_tx_block(
                    &TestTxSpec::ContractDeploy {
                        sender: &FAUCET_PRIV_KEY,
                        name,
                        code: &self.contract_code.clone(),
                        clarity_version,
                    },
                    is_naka_block,
                )
            })
            .collect()
    }

    /// Executes the test function on **all** contracts deployed in the given epoch.
    ///
    /// Each call occurs in a **separate block** to isolate side effects and enable
    /// fine-grained snapshot assertions. All prior deployments (even from earlier epochs)
    /// are callable if they exist in the chain state.
    ///
    /// # Arguments
    ///
    /// - `epoch`: The epoch in which to perform contract calls.
    ///
    /// # Returns
    ///
    /// A [`Vec<ExpectedResult>`] with one entry per function call
    fn call_contracts(&mut self, epoch: StacksEpochId) -> Vec<ExpectedResult> {
        let Some(contract_names) = self.contract_calls_per_epoch.get(&epoch) else {
            warn!("No contract calls found for {epoch}.");
            return vec![];
        };

        let is_naka_block = epoch.uses_nakamoto_blocks();
        contract_names
            .clone()
            .iter()
            .map(|contract_name| {
                self.append_tx_block(
                    &TestTxSpec::ContractCall {
                        sender: &FAUCET_PRIV_KEY,
                        contract_addr: &self.contract_addr.clone(),
                        contract_name,
                        function_name: &self.function_name.clone(),
                        args: &self.function_args.clone(),
                    },
                    is_naka_block,
                )
            })
            .collect()
    }

    /// Executes the full consensus test: deploy in [`Self::contract_deploys_per_epoch`], call in [`Self::contract_calls_per_epoch`].
    ///
    /// Processes epochs in **sorted order** using [`Self::all_epochs`]. For each epoch:
    /// - Advances the chain into the target epoch
    /// - Deploys contracts (if scheduled)
    /// - Executes function calls (if scheduled)
    ///
    /// # Execution Order Example
    ///
    /// Given at test instantiation:
    /// ```rust
    /// deploy_epochs = [Epoch20, Epoch30]
    /// call_epochs   = [Epoch30, Epoch31]
    /// ```
    ///
    /// The sequence is:
    /// 1. Enter Epoch 2.0 → Deploy `contract-v1`
    /// 2. Enter Epoch 3.0 → Deploy `contract-v1`, `contract-v2`, `contract-v3`
    /// 3. Enter Epoch 3.0 → Call function on all 4 deployed contracts
    /// 4. Enter Epoch 3.1 → Call function on all 4 deployed contracts
    ///
    /// # Returns
    ///
    /// A `Vec<ExpectedResult>` with the outcome of each block for snapshot testing.
    pub fn run(mut self) -> Vec<ExpectedResult> {
        let mut results = Vec::new();

        // Process epochs in order
        for epoch in self.all_epochs.clone() {
            // Use the miner as the sender to prevent messing with the block transaction nonces of the deployer/callers
            let private_key = self.chain.test_chainstate.miner.nakamoto_miner_key();

            // Advance the chain into the target epoch
            self.chain
                .test_chainstate
                .advance_into_epoch(&private_key, epoch);

            results.extend(self.deploy_contracts(epoch));
            results.extend(self.call_contracts(epoch));
        }

        results
    }
}

/// The type of transaction to create.
pub enum TestTxSpec<'a> {
    Transfer {
        from: &'a StacksPrivateKey,
        to: &'a PrincipalData,
        amount: u64,
    },
    ContractDeploy {
        sender: &'a StacksPrivateKey,
        name: &'a str,
        code: &'a str,
        clarity_version: Option<ClarityVersion>,
    },
    ContractCall {
        sender: &'a StacksPrivateKey,
        contract_addr: &'a StacksAddress,
        contract_name: &'a str,
        function_name: &'a str,
        args: &'a [ClarityValue],
    },
}

/// A helper to create transactions with incrementing nonces for each account.
pub struct TestTxFactory {
    /// Map of address to next nonce
    nonce_counter: HashMap<StacksAddress, u64>,
    /// The default chain ID to use for transactions
    default_chain_id: u32,
}

impl TestTxFactory {
    /// Creates a new [`TransactionFactory`] with the specified default chain ID.
    pub fn new(default_chain_id: u32) -> Self {
        Self {
            nonce_counter: HashMap::new(),
            default_chain_id,
        }
    }

    /// Manually increments the nonce for the sender of the specified transaction.
    ///
    /// This method should be called *after* a transaction has been successfully
    /// processed to ensure the factory uses the correct next nonce for subsequent
    /// transactions from the same sender.
    ///
    /// # Arguments
    ///
    /// * `tx_spec` - The original specification of the transaction whose sender's
    ///   nonce should be incremented.
    ///
    /// # Panics
    ///
    /// Panics if the sender's address is not found in the nonce counter map.
    pub fn increase_nonce_for_tx(&mut self, tx_spec: &TestTxSpec) {
        let sender_privk = match tx_spec {
            TestTxSpec::Transfer { from, .. } => from,
            TestTxSpec::ContractDeploy { sender, .. } => sender,
            TestTxSpec::ContractCall { sender, .. } => sender,
        };
        let address = StacksAddress::p2pkh(false, &StacksPublicKey::from_private(sender_privk));
        let nonce = self
            .nonce_counter
            .get_mut(&address)
            .unwrap_or_else(|| panic!("Nonce not found for address {address}"));
        *nonce += 1;
    }

    /// Generates a new transaction of the specified type.
    ///
    /// Arguments:
    /// - `tx_type`: The type of transaction to create.
    ///
    /// Returns:
    /// A [`StacksTransaction`] representing the created transaction.
    pub fn generate_tx(&mut self, tx_spec: &TestTxSpec) -> StacksTransaction {
        match tx_spec {
            TestTxSpec::Transfer { from, to, amount } => self.transfer(from, to, *amount),
            TestTxSpec::ContractDeploy {
                sender,
                name,
                code,
                clarity_version,
            } => self.contract_deploy(sender, name, code, *clarity_version),
            TestTxSpec::ContractCall {
                sender,
                contract_addr,
                contract_name,
                function_name,
                args,
            } => self.contract_call(sender, contract_addr, contract_name, function_name, args),
        }
    }

    /// Create a STX transfer transaction.
    ///
    /// Arguments:
    /// - `from`: The sender's private key.
    /// - `to`: The recipient's principal data.
    /// - `amount`: The amount of STX to transfer.
    ///
    /// Returns:
    /// A [`StacksTransaction`] representing the transfer.
    ///
    /// Note: The transaction fee is set to 180 micro-STX.
    pub fn transfer(
        &mut self,
        from: &StacksPrivateKey,
        to: &PrincipalData,
        amount: u64,
    ) -> StacksTransaction {
        let address = StacksAddress::p2pkh(false, &StacksPublicKey::from_private(from));
        let nonce = self.nonce_counter.entry(address).or_insert(0);
        make_stacks_transfer_tx(from, *nonce, 180, self.default_chain_id, to, amount)
    }

    /// Create a contract deployment transaction.
    ///
    /// Arguments:
    /// `sender`: The sender's private key.
    /// `name`: The name of the contract.
    /// `code`: The contract code as a string.
    ///
    /// Returns:
    /// A [`StacksTransaction`] representing the contract deployment.
    ///
    /// Note: The transaction fee is set based on the contract code length.
    pub fn contract_deploy(
        &mut self,
        sender: &StacksPrivateKey,
        name: &str,
        code: &str,
        clarity_version: Option<ClarityVersion>,
    ) -> StacksTransaction {
        let address = StacksAddress::p2pkh(false, &StacksPublicKey::from_private(sender));
        let nonce = self.nonce_counter.entry(address).or_insert(0);
        let tx_bytes = make_contract_publish_versioned(
            sender,
            *nonce,
            (code.len() * 100) as u64,
            self.default_chain_id,
            name,
            code,
            clarity_version,
        );
        StacksTransaction::consensus_deserialize(&mut tx_bytes.as_slice()).unwrap()
    }

    /// Create a contract call transaction.
    ///
    /// Arguments:
    /// `sender`: The sender's private key.
    /// `contract_addr`: The address of the contract.
    /// `contract_name`: The name of the contract.
    /// `function_name`: The name of the function to call.
    /// `args`: The arguments to pass to the function.
    ///
    /// Returns:
    /// A [`StacksTransaction`] representing the contract call.
    ///
    /// Note: The transaction fee is set to 200 micro-STX.
    pub fn contract_call(
        &mut self,
        sender: &StacksPrivateKey,
        contract_addr: &StacksAddress,
        contract_name: &str,
        function_name: &str,
        args: &[ClarityValue],
    ) -> StacksTransaction {
        let address = StacksAddress::p2pkh(false, &StacksPublicKey::from_private(sender));
        let nonce = self.nonce_counter.entry(address).or_insert(0);
        let tx_bytes = make_contract_call(
            sender,
            *nonce,
            200,
            self.default_chain_id,
            contract_addr,
            contract_name,
            function_name,
            args,
        );
        StacksTransaction::consensus_deserialize(&mut tx_bytes.as_slice()).unwrap()
    }
}

/// Generates a consensus test for executing a contract function across multiple Stacks epochs.
///
/// This macro automates both contract deployment and function invocation across different
/// epochs and Clarity versions.
/// It simplifies the setup of consensus-critical tests involving versioned smart contracts.
///
/// # Behavior
///
/// - **Deployment:** Deploys `contract_code` in each epoch specified in `deploy_epochs`
///   for every applicable [`ClarityVersion`].
/// - **Execution:** Calls `function_name` in each epoch from `call_epochs` on all previously
///   deployed contract instances.
/// - **Structure:** Each deployment and function call is executed in its own block, ensuring
///   clear separation between transactions.
///
/// # Arguments
///
/// * `$name` — Name of the generated test function.
/// * `contract_name` — The name of the contract.
/// * `contract_code` — The Clarity source code for the contract.
/// * `function_name` — The public function to call.
/// * `function_args` — Function arguments, provided as a slice of [`ClarityValue`].
/// * `deploy_epochs` — *(optional)* Epochs in which to deploy the contract. Defaults to all epochs ≥ 2.0.
/// * `call_epochs` — *(optional)* Epochs in which to call the function. Defaults to [`EPOCHS_TO_TEST`].
///
/// # Example
///
/// ```rust,ignore
/// contract_call_consensus_test!(
///     my_test,
///     contract_name: "my-contract",
///     contract_code: "(define-public (get-message) (ok \"hello\"))",
///     function_name: "get-message",
///     function_args: &[],
/// );
/// ```
macro_rules! contract_call_consensus_test {
    (
        $name:ident,
        contract_name: $contract_name:expr,
        contract_code: $contract_code:expr,
        function_name: $function_name:expr,
        function_args: $function_args:expr,
        $(deploy_epochs: $deploy_epochs:expr,)?
        $(call_epochs: $call_epochs:expr,)?
    ) => {
        #[test]
        fn $name() {
            // Handle deploy_epochs parameter (default to all epochs >= 2.0 if not provided)
            let deploy_epochs = &StacksEpochId::ALL[1..];
            $(let deploy_epochs = $deploy_epochs;)?

            // Handle call_epochs parameter (default to EPOCHS_TO_TEST if not provided)
            let call_epochs = EPOCHS_TO_TEST;
            $(let call_epochs = $call_epochs;)?
            let contract_test = ContractConsensusTest::new(
                function_name!(),
                vec![],
                deploy_epochs,
                call_epochs,
                $contract_name,
                $contract_code,
                $function_name,
                $function_args,
            );
            let result = contract_test.run();
            insta::assert_ron_snapshot!(result);
        }
    };
}

/// Generates a consensus test for contract deployment across multiple Stacks epochs.
///
/// This macro automates deploying a contract across different Stacks epochs and
/// Clarity versions. It is primarily used for consensus-critical testing of contract
/// deployment behavior.
///
/// # Behavior
///
/// - **Deployment:** Deploys `contract_code` in each epoch specified by `deploy_epochs`
///   for all applicable [`ClarityVersion`]s.
/// - **Structure:** Each deployment is executed in its own block, ensuring clear
///   separation between transactions.
///
/// # Arguments
///
/// * `$name` — Name of the generated test function.
/// * `contract_name` — Name of the contract being tested.
/// * `contract_code` — The Clarity source code of the contract.
/// * `deploy_epochs` — *(optional)* Epochs in which to deploy the contract. Defaults to [`EPOCHS_TO_TEST`].
///
/// # Example
///
/// ```rust,ignore
/// contract_deploy_consensus_test!(
///     deploy_test,
///     contract_name: "my-contract",
///     contract_code: "(define-public (init) (ok true))",
/// );
/// ```
macro_rules! contract_deploy_consensus_test {
    // Handle the case where deploy_epochs is not provided
    (
        $name:ident,
        contract_name: $contract_name:expr,
        contract_code: $contract_code:expr,
    ) => {
        contract_deploy_consensus_test!(
            $name,
            contract_name: $contract_name,
            contract_code: $contract_code,
            deploy_epochs: EPOCHS_TO_TEST,
        );
    };
    (
        $name:ident,
        contract_name: $contract_name:expr,
        contract_code: $contract_code:expr,
        deploy_epochs: $deploy_epochs:expr,
    ) => {
        contract_call_consensus_test!(
            $name,
            contract_name: $contract_name,
            contract_code: $contract_code,
            function_name: "",   // No function calls, just deploys
            function_args: &[],  // No function calls, just deploys
            deploy_epochs: $deploy_epochs,
            call_epochs: &[],    // No function calls, just deploys
        );
    };
}

#[test]
fn test_append_empty_blocks() {
    let empty_test_blocks = vec![TestBlock {
        transactions: vec![],
    }];
    let mut epoch_blocks = HashMap::new();
    for epoch in EPOCHS_TO_TEST {
        epoch_blocks.insert(*epoch, empty_test_blocks.clone());
    }

    let result = ConsensusTest::new(function_name!(), vec![], epoch_blocks).run();
    insta::assert_ron_snapshot!(result);
}

#[test]
fn test_append_stx_transfers_success() {
    let sender_privks = [
        StacksPrivateKey::from_hex(SK_1).unwrap(),
        StacksPrivateKey::from_hex(SK_2).unwrap(),
        StacksPrivateKey::from_hex(SK_3).unwrap(),
    ];
    let total_epochs = EPOCHS_TO_TEST.len() as u64;
    let send_amount = 1_000;
    let tx_fee = 180;
    // initialize balances
    let mut initial_balances = Vec::new();
    for sender_privk in &sender_privks {
        let sender_addr =
            StacksAddress::p2pkh(false, &StacksPublicKey::from_private(sender_privk)).into();
        // give them enough to cover all transfers across all epochs
        initial_balances.push((sender_addr, (send_amount + tx_fee) * total_epochs));
    }

    // build transactions per epoch, incrementing nonce per sender
    let mut epoch_blocks = HashMap::new();
    let mut nonces = vec![0u64; sender_privks.len()]; // track nonce per sender

    for epoch in EPOCHS_TO_TEST {
        let transactions: Vec<_> = sender_privks
            .iter()
            .enumerate()
            .map(|(i, sender_privk)| {
                let tx = make_stacks_transfer_tx(
                    sender_privk,
                    nonces[i], // use current nonce
                    tx_fee,
                    CHAIN_ID_TESTNET,
                    &boot_code_addr(false).into(),
                    send_amount,
                );
                nonces[i] += 1; // increment for next epoch
                tx
            })
            .collect();
        epoch_blocks.insert(*epoch, vec![TestBlock { transactions }]);
    }

    let result = ConsensusTest::new(function_name!(), initial_balances, epoch_blocks).run();
    insta::assert_ron_snapshot!(result);
}

// Example of using the `contract_call_consensus_test!` macro
// Deploys a contract to each epoch, for each Clarity version,
// then calls a function in that contract and snapshots the results.
contract_call_consensus_test!(
    successfully_deploy_and_call,
    contract_name: "foo_contract",
    contract_code: FOO_CONTRACT,
    function_name: "bar",
    function_args: &[ClarityValue::UInt(1)],
);

// Example of using the `contract_deploy_consensus_test!` macro
// Deploys a contract that exceeds the maximum allowed stack depth
// and verifies that deployment fails with the expected error.
contract_deploy_consensus_test!(
    chainstate_error_expression_stack_depth_too_deep,
    contract_name: "test-exceeds",
    contract_code: &{
        let exceeds_repeat_factor = AST_CALL_STACK_DEPTH_BUFFER + (MAX_CALL_STACK_DEPTH as u64);
        let tx_exceeds_body_start = "{ a : ".repeat(exceeds_repeat_factor as usize);
        let tx_exceeds_body_end = "} ".repeat(exceeds_repeat_factor as usize);
        format!("{tx_exceeds_body_start}u1 {tx_exceeds_body_end}")
    },
);

// Test RuntimeError::
contract_call_consensus_test!(
    runtime_error_arithmetic_overflow_pow,
    contract_name: "overflow-pow",
    contract_code: &{
    r#"
(define-public (overflow-pow-128)
  (ok (pow 2 128))
)
    "#
    },
    function_name: "overflow-pow-128",
    function_args: &[],
);

contract_call_consensus_test!(
    runtime_error_arithmetic_overflow_mul,
    contract_name: "overflow-mul",
    contract_code: &{
    r#"
(define-public (overflow-mul-large)
  (ok (* 10 (pow 2 126)))
)
    "#
    },
    function_name: "overflow-mul-large",
    function_args: &[],
);

contract_call_consensus_test!(
    runtime_error_arithmetic_overflow_add,
    contract_name: "overflow-add",
    contract_code: &{
    r#"
(define-public (overflow-add-large)
  (ok (+ (pow 2 126) (pow 2 126)))
)
    "#
    },
    function_name: "overflow-add-large",
    function_args: &[],
);

contract_call_consensus_test!(
    runtime_error_arithmetic_overflow_to_int,
    contract_name: "overflow-to-int",
    contract_code: &{
    r#"
(define-public (overflow-to-int-large)
  (ok (to-int (pow u2 u127)))
)
    "#
    },
    function_name: "overflow-to-int-large",
    function_args: &[],
);
