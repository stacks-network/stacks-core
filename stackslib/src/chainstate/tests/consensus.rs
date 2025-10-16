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
use std::collections::{BTreeSet, HashMap};

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
    Error as ChainstateError, StacksTransaction, TenureChangeCause, TransactionContractCall,
    TransactionPayload, TransactionSmartContract, MINER_BLOCK_CONSENSUS_HASH,
    MINER_BLOCK_HEADER_HASH,
};
use crate::chainstate::tests::TestChainstate;
use crate::core::test_util::{
    make_contract_call, make_contract_publish_versioned, make_stacks_transfer_tx, to_addr,
};
use crate::core::{EpochList, BLOCK_LIMIT_MAINNET_21};
use crate::net::tests::NakamotoBootPlan;

/// The epochs to test for consensus are the current and upcoming epochs.
/// This constant must be changed when new epochs are introduced.
/// Note that contract deploys MUST be done in each epoch >= 2.0.
const EPOCHS_TO_TEST: &[StacksEpochId] = &[StacksEpochId::Epoch32, StacksEpochId::Epoch33];

pub const SK_1: &str = "a1289f6438855da7decf9b61b852c882c398cff1446b2a0f823538aa2ebef92e01";
pub const SK_2: &str = "4ce9a8f7539ea93753a36405b16e8b57e15a552430410709c2b6d65dca5c02e201";
pub const SK_3: &str = "cb95ddd0fe18ec57f4f3533b95ae564b3f1ae063dbf75b46334bd86245aef78501";

/// The private key for the faucet account.
pub const FAUCET_PRIV_KEY: LazyCell<StacksPrivateKey> = LazyCell::new(|| {
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

/// Executes a consensus test for a contract function across multiple Stacks epochs.
///
/// This helper automates deploying a contract and invoking one of its public functions
/// across different epochs and Clarity versions, ensuring consistent consensus behavior.
///
/// # Behavior
///
/// The function performs two main phases:
/// 1. **Deployment:** Deploys `contract_code` in each epoch listed in `deploy_epochs` for all
///    applicable Clarity versions.
/// 2. **Execution:** Calls `function_name` in each epoch listed in `call_epochs` on every
///    previously deployed contract.
///
/// ## Example
/// If `deploy_epochs` = `[2.0, 3.0]` and `call_epochs` = `[3.1]`, the following sequence occurs:
/// - Deploy contract in epoch 2.0 with Clarity 1.
/// - Deploy contract in epoch 3.0 with Clarity 1, 2, and 3.
/// - Call the function in epoch 3.1 on all four deployed contracts.
///
/// # Arguments
///
/// * `contract_name` - Base name for the contract.
/// * `contract_code` - Clarity source code of the contract.
/// * `function_name` - Public function to invoke.
/// * `function_args` - Arguments to pass to the function call.
/// * `deploy_epochs` - Epochs during which the contract should be deployed.
/// * `call_epochs` - Epochs during which the function should be executed.
/// * `deploy_success` - Whether deployment blocks are expected to succeed.
/// * `call_success` - Whether call blocks are expected to succeed.
///
/// # Returns
///
/// A `Vec<ExpectedResult>` with the outcome of each block for snapshot testing.
///
/// # Panics
///
/// * If `deploy_epochs` is empty.
/// * If any `call_epoch` precedes the earliest `deploy_epoch`.
fn run_contract_consensus_test(
    contract_name: &str,
    contract_code: &str,
    function_name: &str,
    function_args: &[ClarityValue],
    deploy_epochs: &[StacksEpochId],
    call_epochs: &[StacksEpochId],
    deploy_success: bool,
    call_success: bool,
) -> Vec<ExpectedResult> {
    assert!(
        !deploy_epochs.is_empty(),
        "At least one deploy epoch is required"
    );
    let min_deploy_epoch = deploy_epochs.iter().min().unwrap();
    assert!(
        call_epochs.iter().all(|e| e >= min_deploy_epoch),
        "All call epochs must be >= the minimum deploy epoch"
    );

    let all_epochs: BTreeSet<StacksEpochId> =
        deploy_epochs.iter().chain(call_epochs).cloned().collect();

    let mut contract_names = vec![];
    let sender = &FAUCET_PRIV_KEY;
    let contract_addr = to_addr(sender);
    let mut tx_factory = TestTxFactory::new(CHAIN_ID_TESTNET);

    // Create epoch blocks by pairing each epoch with its corresponding transactions
    let epoch_blocks = all_epochs
        .into_iter()
        .map(|epoch| {
            let mut blocks = vec![];
            if deploy_epochs.contains(&epoch) {
                let clarity_versions = clarity_versions_for_epoch(epoch);
                let epoch_name = format!("Epoch{}", epoch.to_string().replace(".", "_"));
                let mut contract_upload_txs: Vec<TestBlock> = clarity_versions
                    .iter()
                    .map(|version| {
                        let name = format!(
                            "{contract_name}-{epoch_name}-{}",
                            version.to_string().replace(" ", "")
                        );
                        contract_names.push(name.clone());
                        TestBlock {
                            transactions: vec![tx_factory.contract_deploy(
                                sender,
                                &name,
                                contract_code,
                                Some(*version),
                                deploy_success, // increase nonce on deploys expected to succeed
                            )],
                        }
                    })
                    .collect();
                blocks.append(&mut contract_upload_txs);
            }
            if call_epochs.contains(&epoch) {
                let mut contract_call_txs: Vec<TestBlock> = contract_names
                    .iter()
                    .map(|contract_name| TestBlock {
                        transactions: vec![tx_factory.contract_call(
                            sender,
                            &contract_addr,
                            contract_name,
                            function_name,
                            function_args,
                            call_success, // increase nonce on calls expected to succeed
                        )],
                    })
                    .collect();
                blocks.append(&mut contract_call_txs);
            }
            (epoch, blocks)
        })
        .collect();

    let test_vector = ConsensusTestVector {
        initial_balances: vec![],
        epoch_blocks,
    };

    ConsensusTest::new(function_name!(), test_vector).run()
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
/// * `call_success` — Whether function call blocks are expected to succeed.
/// * `deploy_success` — *(optional)* Whether deployment blocks are expected to succeed. Defaults to `true`.
/// * `deploy_epochs` — *(optional)* Epochs in which to deploy the contract. Defaults to all epochs ≥ 3.0.
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
///     call_success: true,
/// );
/// ```
macro_rules! contract_call_consensus_test {
    (
        $name:ident,
        contract_name: $contract_name:expr,
        contract_code: $contract_code:expr,
        function_name: $function_name:expr,
        function_args: $function_args:expr,
        call_success: $call_success:expr,
        $(deploy_success: $deploy_success:expr,)?
        $(deploy_epochs: $deploy_epochs:expr,)?
        $(call_epochs: $call_epochs:expr,)?
    ) => {
        #[test]
        fn $name() {
            let contract_name = $contract_name;

            // Handle deploy_epochs parameter (default to all epochs >= 3.0 if not provided)
            let deploy_epochs = StacksEpochId::ALL_GTE_30;
            $(let deploy_epochs = $deploy_epochs;)?

            // Handle call_epochs parameter (default to EPOCHS_TO_TEST if not provided)
            let call_epochs = EPOCHS_TO_TEST;
            $(let call_epochs = $call_epochs;)?

            // Handle deploy_success parameter (default to true if not provided)
            let deploy_success = true;
            $(let deploy_success = $deploy_success;)?

            let result = run_contract_consensus_test(
                contract_name,
                $contract_code,
                $function_name,
                $function_args,
                deploy_epochs,
                call_epochs,
                deploy_success,
                $call_success,
            );

            insta::assert_ron_snapshot!(result);
        }
    };
}

/// Generates a consensus test for contract deployment across multiple Stacks epochs.
///
/// This macro automates deploying a contract across different Stacks epochs and
/// Clarity versions, validating deployment success and ensuring consistent results
/// across protocol upgrades. It is primarily used for consensus-critical testing of
/// contract deployment behavior.
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
/// * `deploy_success` — Whether deployment blocks are expected to succeed.
/// * `deploy_epochs` — *(optional)* Epochs in which to deploy the contract. Defaults to [`EPOCHS_TO_TEST`].
///
/// # Example
///
/// ```rust,ignore
/// contract_deploy_consensus_test!(
///     deploy_test,
///     contract_name: "my-contract",
///     contract_code: "(define-public (init) (ok true))",
///     deploy_success: true,
/// );
/// ```
macro_rules! contract_deploy_consensus_test {
    // Handle the case where deploy_epochs is not provided
    (
        $name:ident,
        contract_name: $contract_name:expr,
        contract_code: $contract_code:expr,
        deploy_success: $deploy_success:expr,
    ) => {
        contract_deploy_consensus_test!(
            $name,
            contract_name: $contract_name,
            contract_code: $contract_code,
            deploy_success: $deploy_success,
            deploy_epochs: EPOCHS_TO_TEST,
        );
    };
    (
        $name:ident,
        contract_name: $contract_name:expr,
        contract_code: $contract_code:expr,
        deploy_success: $deploy_success:expr,
        deploy_epochs: $deploy_epochs:expr,
    ) => {
        contract_call_consensus_test!(
            $name,
            contract_name: $contract_name,
            contract_code: $contract_code,
            function_name: "",   // No function calls, just deploys
            function_args: &[],  // No function calls, just deploys
            call_success: false, // No function calls, so this value is irrelevant
            deploy_success: $deploy_success,
            deploy_epochs: $deploy_epochs,
            call_epochs: &[],    // No function calls, just deploys
        );
    };
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

    /// Generates a new transaction of the specified type.
    ///
    /// Arguments:
    /// - `tx_type`: The type of transaction to create.
    ///
    /// Returns:
    /// A [`StacksTransaction`] representing the created transaction.
    pub fn generate_tx(&mut self, tx_type: &TestTxSpec, increase_nonce: bool) -> StacksTransaction {
        match tx_type {
            TestTxSpec::Transfer { from, to, amount } => {
                self.transfer(from, to, *amount, increase_nonce)
            }
            TestTxSpec::ContractDeploy { sender, name, code } => {
                self.contract_deploy(sender, name, code, None, increase_nonce)
            }
            TestTxSpec::ContractCall {
                sender,
                contract_addr,
                contract_name,
                function_name,
                args,
            } => self.contract_call(
                sender,
                contract_addr,
                contract_name,
                function_name,
                args,
                increase_nonce,
            ),
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
        increase_nonce: bool,
    ) -> StacksTransaction {
        let address = StacksAddress::p2pkh(false, &StacksPublicKey::from_private(from));
        let nonce = self.nonce_counter.entry(address).or_insert(0);
        let tx = make_stacks_transfer_tx(from, *nonce, 180, self.default_chain_id, to, amount);
        if increase_nonce {
            *nonce += 1;
        }
        tx
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
        version: Option<ClarityVersion>,
        increase_nonce: bool,
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
            version,
        );
        if increase_nonce {
            *nonce += 1;
        }
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
        increase_nonce: bool,
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
        if increase_nonce {
            *nonce += 1;
        }
        StacksTransaction::consensus_deserialize(&mut tx_bytes.as_slice()).unwrap()
    }
}

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
                    .iter()
                    .map(|r| {
                        let tx = match &r.transaction {
                            TransactionOrigin::Stacks(tx) => Some(tx.payload.clone()),
                            TransactionOrigin::Burn(..) => None,
                        };
                        ExpectedTransactionOutput {
                            tx,
                            return_type: r.result.clone(),
                            cost: r.execution_cost.clone(),
                            vm_error: r.vm_error.clone(),
                        }
                    })
                    .collect();
                let total_block_cost = epoch_receipt.anchored_block_cost.clone();
                ExpectedResult::Success(ExpectedBlockOutput {
                    marf_hash,
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
    /// Transactions to include in the block
    pub transactions: Vec<StacksTransaction>,
}

/// Defines a test vector for a consensus test, including chainstate setup and expected outcomes.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ConsensusTestVector {
    /// Initial balances for the provided PrincipalData during chainstate instantiation.
    pub initial_balances: Vec<(PrincipalData, u64)>,
    /// A mapping of epoch to Blocks that should be applied in that epoch
    pub epoch_blocks: HashMap<StacksEpochId, Vec<TestBlock>>,
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
            assert!(
                !blocks.is_empty(),
                "Each epoch must have at least one block"
            );
        }

        // Set up chainstate to start at Epoch 3.0
        // We don't really ever want the reward cycle to force a new signer set...
        // so for now just set the cycle length to a high value (100)
        let mut boot_plan = NakamotoBootPlan::new(test_name)
            .with_pox_constants(100, 3)
            .with_initial_balances(test_vector.initial_balances.clone())
            .with_private_key(FAUCET_PRIV_KEY.clone());
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

            let blocks_and_sizes = self
                .chain
                .make_nakamoto_tenure(tenure_change_tx, coinbase_tx, Some(0))
                .unwrap();
            assert_eq!(
                blocks_and_sizes.len(),
                1,
                "Mined more than one Nakamoto block"
            );
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
    pub fn run(mut self) -> Vec<ExpectedResult> {
        // Get sorted epochs
        let mut epochs: Vec<StacksEpochId> =
            self.test_vector.epoch_blocks.keys().cloned().collect();
        epochs.sort();

        let mut results = vec![];
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
                let mut sortdb = self.chain.sortdb.take().unwrap();
                let mut stacks_node = self.chain.stacks_node.take().unwrap();
                let chain_tip = NakamotoChainState::get_canonical_block_header(
                    stacks_node.chainstate.db(),
                    &sortdb,
                )
                .unwrap()
                .unwrap();
                let pox_constants = PoxConstants::test_default();
                let sig_hash = nakamoto_block.header.signer_signature_hash();
                debug!(
                    "--------- Processing block {sig_hash} ---------";
                    "block" => ?nakamoto_block
                );
                let expected_marf = nakamoto_block.header.state_index_root;
                let res = TestStacksNode::process_pushed_next_ready_block(
                    &mut stacks_node,
                    &mut sortdb,
                    &mut self.chain.miner,
                    &chain_tip.consensus_hash,
                    &mut self.chain.coord,
                    nakamoto_block.clone(),
                );
                debug!(
                    "--------- Processed block: {sig_hash} ---------";
                    "block" => ?nakamoto_block
                );
                let remapped_result = res.map(|receipt| receipt.unwrap()).into();
                results.push(ExpectedResult::create_from(remapped_result, expected_marf));
                // Restore chainstate for the next block
                self.chain.sortdb = Some(sortdb);
                self.chain.stacks_node = Some(stacks_node);
            }
        }
        results
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

        // Set the MARF root hash or use an all-zero hash in case of failure.
        // NOTE: It is expected to fail when trying computing the marf for invalid block/transactions.
        let marf_result = self.compute_block_marf_root_hash(block.header.timestamp, &block.txs);
        block.header.state_index_root = match marf_result {
            Ok(marf) => marf,
            Err(_) => TrieHash::from_bytes(&[0; 32]).unwrap(),
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
    ) -> Result<TrieHash, String> {
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
        let result = Self::inner_compute_block_marf_root_hash(
            &mut clarity_tx,
            block_time,
            block_txs,
            chain_tip.burn_header_height,
        );
        clarity_tx.rollback_block();
        return result;
    }

    /// This is where the real MARF computation happens.
    /// It is extrapolated into an _inner_ method to simplify rollback handling,
    /// ensuring that rollback can be applied consistently on both success and failure
    /// in the _outer_ method.
    fn inner_compute_block_marf_root_hash(
        clarity_tx: &mut ClarityTx,
        block_time: u64,
        block_txs: &Vec<StacksTransaction>,
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

#[test]
fn test_append_empty_blocks() {
    let empty_test_blocks = vec![TestBlock {
        transactions: vec![],
    }];
    let mut epoch_blocks = HashMap::new();
    for epoch in EPOCHS_TO_TEST {
        epoch_blocks.insert(*epoch, empty_test_blocks.clone());
    }

    let test_vector = ConsensusTestVector {
        initial_balances: vec![],
        epoch_blocks,
    };
    let result = ConsensusTest::new(function_name!(), test_vector).run();
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

    let test_vector = ConsensusTestVector {
        initial_balances,
        epoch_blocks,
    };

    let result = ConsensusTest::new(function_name!(), test_vector).run();
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
    call_success: true,
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
    deploy_success: false,
);
