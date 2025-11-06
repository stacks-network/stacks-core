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
use clarity::vm::types::{PrincipalData, MAX_TYPE_DEPTH};
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

/// A high-level test harness for running consensus-critical smart contract tests.
///
/// This struct combines a [`ConsensusTest`] instance for chainstate management and a
/// [`TestTxFactory`] for transaction generation. It provides convenience methods to
/// automate test scenarios involving contract deployments and calls across multiple
/// epochs and Clarity versions.
struct ContractConsensusTest<'a> {
    tx_factory: TestTxFactory,
    consensus_test: ConsensusTest<'a>,
}

impl ContractConsensusTest<'_> {
    /// Creates a new `ContractConsensusTest`.
    pub fn new(test_name: &str) -> Self {
        Self {
            tx_factory: TestTxFactory::new(CHAIN_ID_TESTNET),
            consensus_test: ConsensusTest::new(test_name, vec![]),
        }
    }

    /// Generates and executes the given transaction in a new block.
    /// Increases the nonce if the transaction succeeds.
    fn append_tx_block(&mut self, tx_spec: &TestTxSpec) -> ExpectedResult {
        let tx = self.tx_factory.generate_tx(tx_spec);
        let block = TestBlock {
            transactions: vec![tx],
        };

        let result = self.consensus_test.append_block(block);

        if let ExpectedResult::Success(_) = result {
            self.tx_factory.increase_nonce_for_tx(tx_spec);
        }

        result
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
    ///
    /// # Returns
    ///
    /// A `Vec<ExpectedResult>` with the outcome of each block for snapshot testing.
    ///
    /// # Panics
    ///
    /// * If `deploy_epochs` is empty.
    /// * If any `call_epoch` precedes the earliest `deploy_epoch`.
    pub fn run(
        &mut self,
        contract_name: &str,
        contract_code: &str,
        function_name: &str,
        function_args: &[ClarityValue],
        deploy_epochs: &[StacksEpochId],
        call_epochs: &[StacksEpochId],
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
        // Create epoch blocks by pairing each epoch with its corresponding transactions
        let mut results = vec![];
        all_epochs.into_iter().for_each(|epoch| {
            self.consensus_test.advance_to_epoch(epoch);
            if deploy_epochs.contains(&epoch) {
                let clarity_versions = clarity_versions_for_epoch(epoch);
                let epoch_name = format!("Epoch{}", epoch.to_string().replace(".", "_"));
                clarity_versions.iter().for_each(|version| {
                    let name = format!(
                        "{contract_name}-{epoch_name}-{}",
                        version.to_string().replace(" ", "")
                    );
                    contract_names.push(name.clone());
                    let result = self.append_tx_block(&TestTxSpec::ContractDeploy {
                        sender,
                        name: &name,
                        code: contract_code,
                        clarity_version: Some(*version),
                    });
                    results.push(result);
                });
            }
            if call_epochs.contains(&epoch) {
                contract_names.iter().for_each(|contract_name| {
                    let result = self.append_tx_block(&TestTxSpec::ContractCall {
                        sender,
                        contract_addr: &contract_addr,
                        contract_name,
                        function_name,
                        args: function_args,
                    });
                    results.push(result);
                });
            }
        });
        results
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
            let contract_name = $contract_name;

            // Handle deploy_epochs parameter (default to all epochs >= 3.0 if not provided)
            let deploy_epochs = StacksEpochId::ALL_GTE_30;
            $(let deploy_epochs = $deploy_epochs;)?

            // Handle call_epochs parameter (default to EPOCHS_TO_TEST if not provided)
            let call_epochs = EPOCHS_TO_TEST;
            $(let call_epochs = $call_epochs;)?

            let mut contract_test = ContractConsensusTest::new(function_name!());
            let result = contract_test.run(
                contract_name,
                $contract_code,
                $function_name,
                $function_args,
                deploy_epochs,
                call_epochs,
            );

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
            block_limit: BLOCK_LIMIT_MAINNET_21,
            network_epoch: PEER_VERSION_EPOCH_2_5,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch30,
            start_height: first_burnchain_height,
            end_height: first_burnchain_height + 1,
            block_limit: BLOCK_LIMIT_MAINNET_21,
            network_epoch: PEER_VERSION_EPOCH_3_0,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch31,
            start_height: first_burnchain_height + 1,
            end_height: first_burnchain_height + 2,
            block_limit: BLOCK_LIMIT_MAINNET_21,
            network_epoch: PEER_VERSION_EPOCH_3_1,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch32,
            start_height: first_burnchain_height + 2,
            end_height: first_burnchain_height + 3,
            block_limit: BLOCK_LIMIT_MAINNET_21,
            network_epoch: PEER_VERSION_EPOCH_3_2,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch33,
            start_height: first_burnchain_height + 3,
            end_height: STACKS_EPOCH_MAX,
            block_limit: BLOCK_LIMIT_MAINNET_21,
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

/// Represents a consensus test with chainstate.
pub struct ConsensusTest<'a> {
    pub chain: TestChainstate<'a>,
}

impl ConsensusTest<'_> {
    /// Creates a new `ConsensusTest` with the given test name and initial balances.
    pub fn new(test_name: &str, initial_balances: Vec<(PrincipalData, u64)>) -> Self {
        // Set up chainstate to start at Epoch 3.0
        let mut boot_plan = NakamotoBootPlan::new(test_name)
            // These are the minimum values found for the fastest test execution.
            //
            // If changing these values, ensure the following conditions are met:
            // 1. Min 6 reward blocks (test framework limitation).
            // 2. Epoch 3.0 starts in the reward phase.
            // 3. Tests bypass mainnet's prepare_length >= 3 (allowing 1).
            // - Current boot sequence:
            //   - Cycle 3: Signers at height 27 register for 12 reward cycles
            //   - Cycle 4: Epoch 3.0 starts at height 30
            // Tests generate 1 bitcoin block per epoch transition after 3.0
            // staying within the registration window
            .with_pox_constants(7, 1)
            .with_initial_balances(initial_balances)
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
    pub fn advance_to_epoch(&mut self, target_epoch: StacksEpochId) {
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

    /// Appends a single block to the chain and returns the result.
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
    pub fn append_block(&mut self, block: TestBlock) -> ExpectedResult {
        debug!("--------- Running block {block:?} ---------");
        let (nakamoto_block, block_size) = self.construct_nakamoto_block(block);
        let mut sortdb = self.chain.sortdb.take().unwrap();
        let mut stacks_node = self.chain.stacks_node.take().unwrap();
        let chain_tip =
            NakamotoChainState::get_canonical_block_header(stacks_node.chainstate.db(), &sortdb)
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
        let remapped_result = res.map(|receipt| receipt.unwrap());
        // Restore chainstate for the next block
        self.chain.sortdb = Some(sortdb);
        self.chain.stacks_node = Some(stacks_node);
        ExpectedResult::create_from(remapped_result, expected_marf)
    }

    /// Executes a full test plan by processing blocks across multiple epochs.
    ///
    /// This function serves as the primary test runner. It iterates through the
    /// provided epochs in chronological order, automatically advancing the
    /// chainstate to the start of each epoch. It then processes all [`TestBlock`]'s
    /// associated with that epoch and collects their results.
    ///
    /// # Arguments
    ///
    /// * `epoch_blocks` - A map where keys are [`StacksEpochId`]s and values are the
    ///   sequence of blocks to be executed during that epoch.
    ///
    ///  # Returns
    ///
    /// A `Vec<ExpectedResult>` with the outcome of each block for snapshot testing.
    pub fn run(
        mut self,
        epoch_blocks: HashMap<StacksEpochId, Vec<TestBlock>>,
    ) -> Vec<ExpectedResult> {
        // Validate blocks
        for (epoch_id, blocks) in epoch_blocks.iter() {
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

        let mut sorted_epochs: Vec<_> = epoch_blocks.into_iter().collect();
        sorted_epochs.sort_by_key(|(epoch_id, _)| *epoch_id);

        let mut results = vec![];

        for (epoch, blocks) in sorted_epochs {
            debug!(
                "--------- Processing epoch {epoch:?} with {} blocks ---------",
                blocks.len()
            );
            self.advance_to_epoch(epoch);

            for block in blocks {
                results.push(self.append_block(block));
            }
        }
        results
    }

    /// Constructs a Nakamoto block with the given [`TestBlock`] configuration.
    fn construct_nakamoto_block(&mut self, test_block: TestBlock) -> (NakamotoBlock, usize) {
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
        block_txs: &[StacksTransaction],
    ) -> Result<TrieHash, String> {
        let node = self.chain.stacks_node.as_mut().unwrap();
        let sortdb = self.chain.sortdb.as_ref().unwrap();
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

#[test]
fn test_append_empty_blocks() {
    let empty_test_blocks = vec![TestBlock {
        transactions: vec![],
    }];
    let mut epoch_blocks = HashMap::new();
    for epoch in EPOCHS_TO_TEST {
        epoch_blocks.insert(*epoch, empty_test_blocks.clone());
    }

    let result = ConsensusTest::new(function_name!(), vec![]).run(epoch_blocks);
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

    let result = ConsensusTest::new(function_name!(), initial_balances).run(epoch_blocks);
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

// StaticCheckError: [`StaticCheckError::ValueTooLarge`]
// Caused by: Value exceeds the maximum allowed size for type-checking
// Outcome: block accepted.
contract_deploy_consensus_test!(
    static_check_error_value_too_large,
    contract_name: "value-too-large",
    contract_code: "(as-max-len? 0x01 u1048577)",
);

// StaticCheckError: [`StaticCheckError::ValueOutOfBounds`]
// Caused by: Value is outside the acceptable range for its type
// Outcome: block accepted.
contract_deploy_consensus_test!(
    static_check_error_value_out_of_bounds,
    contract_name: "value-out-of-bounds",
    contract_code: "(define-private (func (x (buff -12))) (len x))
        (func 0x00)",
);

// StaticCheckError: [`StaticCheckError::ExpectedName`]
// Caused by:
// Outcome: block accepted.
contract_deploy_consensus_test!(
    static_check_error_expected_name,
    contract_name: "expected-name",
    contract_code: "(match (some 1) 2 (+ 1 1) (+ 3 4))",
);

// StaticCheckError: [`StaticCheckErrorKind::ExpectedResponseType`]
// Caused by:
// Outcome: block accepted.
contract_deploy_consensus_test!(
    static_check_error_expected_response_type,
    contract_name: "expected-response-type",
    contract_code: "(unwrap-err! (some 2) 2)",
);

// StaticCheckError: [`StaticCheckErrorKind::CouldNotDetermineResponseOkType`]
// Caused by:
// Outcome: block accepted.
contract_deploy_consensus_test!(
    static_check_error_could_not_determine_response_ok_type,
    contract_name: "could-not-determine",
    contract_code: "(unwrap! (err 3) 2)",
);

// StaticCheckError: [`StaticCheckErrorKind::CouldNotDetermineResponseErrType`]
// Caused by:
// Outcome: block accepted.
contract_deploy_consensus_test!(
    static_check_error_could_not_determine_response_err_type,
    contract_name: "could-not-determine",
    contract_code: "(unwrap-err-panic (ok 3))",
);

// StaticCheckError: [`StaticCheckErrorKind::CouldNotDetermineMatchTypes`]
// Caused by:
// Outcome: block accepted.
contract_deploy_consensus_test!(
    static_check_error_could_not_determine_match_types,
    contract_name: "could-not-determine",
    contract_code: "(match none inner-value (/ 1 0) (+ 1 8))",
);

// StaticCheckError: [`StaticCheckErrorKind::MatchArmsMustMatch`]
// Caused by:
// Outcome: block accepted.
contract_deploy_consensus_test!(
    static_check_error_match_arms_must_match,
    contract_name: "match-arms-must-match",
    contract_code: "(match (some 1) inner-value (+ 1 inner-value) (> 1 28))",
);

// StaticCheckError: [`StaticCheckErrorKind::BadMatchOptionSyntax`]
// Caused by:
// Outcome: block accepted.
contract_deploy_consensus_test!(
    static_check_error_bad_match_option_syntax,
    contract_name: "bad-match-option",
    contract_code: "(match (some 1) inner-value (+ 1 inner-value))",
);

// StaticCheckError: [`StaticCheckErrorKind::BadMatchResponseSyntax`]
// Caused by:
// Outcome: block accepted.
contract_deploy_consensus_test!(
    static_check_error_bad_match_response_syntax,
    contract_name: "bad-match-response",
    contract_code: "(match (ok 1) inner-value (+ 1 inner-value))",
);

// StaticCheckError: [`StaticCheckErrorKind::RequiresAtLeastArguments`]
// Caused by:
// Outcome: block accepted.
contract_deploy_consensus_test!(
    static_check_error_requires_at_least_arguments,
    contract_name: "requires-at-least",
    contract_code: "(match)",
);

// StaticCheckError: [`StaticCheckErrorKind::RequiresAtMostArguments`]
// Caused by:
// Outcome: block accepted.
contract_deploy_consensus_test!(
    static_check_error_requires_at_most_arguments,
    contract_name: "requires-at-most",
    contract_code: r#"(principal-construct? 0x22 0xfa6bf38ed557fe417333710d6033e9419391a320 "foo" "bar")"#,
);

// StaticCheckError: [`StaticCheckErrorKind::BadMatchInput`]
// Caused by:
// Outcome: block accepted.
contract_deploy_consensus_test!(
    static_check_error_bad_match_input,
    contract_name: "bad-match-input",
    contract_code: "(match 1 ok-val (/ ok-val 0) err-val (+ err-val 7))",
);

// StaticCheckError: [`StaticCheckErrorKind::ExpectedOptionalType`]
// Caused by:
// Outcome: block accepted.
contract_deploy_consensus_test!(
    static_check_error_expected_optional_type,
    contract_name: "expected-optional-type",
    contract_code: "(default-to 3 5)",
);

// StaticCheckError: [`StaticCheckErrorKind::NameAlreadyUsed`]
// Caused by:
// Outcome: block accepted.
contract_deploy_consensus_test!(
    static_check_error_name_already_used,
    contract_name: "name-already-used",
    contract_code: "
        (define-constant foo 10)
        (define-constant foo 20)",
);

// StaticCheckError: [`StaticCheckErrorKind::ReturnTypesMustMatch`]
// Caused by:
// Outcome: block accepted.
contract_deploy_consensus_test!(
    static_check_error_return_types_must_match,
    contract_name: "return-types-must",
    contract_code: "
        (define-map tokens { id: int } { balance: int })
        (define-private (my-get-token-balance)
            (let ((balance (unwrap!
                              (get balance (map-get? tokens (tuple (id 0))))
                              (err 1))))
              (err false)))",
);

// StaticCheckError: [`StaticCheckErrorKind::TypeError`]
// Caused by:
// Outcome: block accepted.
contract_deploy_consensus_test!(
    static_check_error_type_error,
    contract_name: "type-error",
    contract_code: "(define-data-var cursor int true)",
);

// StaticCheckError: [`StaticCheckErrorKind::DefineVariableBadSignature`]
// Caused by:
// Outcome: block accepted.
contract_deploy_consensus_test!(
    static_check_error_define_variable_bad_signature,
    contract_name: "define-variable-bad",
    contract_code: "(define-data-var cursor 0x00)",
);

// StaticCheckError: [`StaticCheckErrorKind::InvalidTypeDescription`]
// Caused by:
// Outcome: block accepted.
contract_deploy_consensus_test!(
    static_check_error_invalid_type_description,
    contract_name: "invalid-type-desc",
    contract_code: "(define-data-var cursor 0x00 true)",
);

// StaticCheckError: [`StaticCheckErrorKind::TypeSignatureTooDeep`]
// Caused by:
// Outcome: block accepted.
contract_deploy_consensus_test!(
    static_check_error_type_signature_too_deep,
    contract_name: "signature-too-deep",
    contract_code: &{
        let depth: usize = MAX_TYPE_DEPTH as usize + 1;
        let mut s = String::from("(define-public (f (x ");
        for _ in 0..depth {
            s.push_str("(optional ");
        }
        s.push_str("uint");
        for _ in 0..depth {
            s.push_str(") ");
        }
        s.push_str(")) (ok x))");
        s
    },
);

// StaticCheckError: [`StaticCheckErrorKind::SupertypeTooLarge`]
// Caused by:
// Outcome: block rejected.
contract_deploy_consensus_test!(
    static_check_error_supertype_too_large,
    contract_name: "supertype-too-large",
    contract_code: "
        (define-data-var big (buff 600000) 0x00)
        (define-data-var small (buff 10) 0x00)
        (define-public (trigger)
            (let ((initial (list (tuple (a (var-get big)) (b (var-get small))))))
                (ok (append initial (tuple (a (var-get small)) (b (var-get big)))))))",
);

// StaticCheckError: [`StaticCheckErrorKind::ConstructedListTooLarge`]
// Caused by:
// Outcome: block accepted.
contract_deploy_consensus_test!(
    static_check_error_constructed_list_too_large,
    contract_name: "constructed-list-large",
    contract_code: "
        (define-data-var ints (list 65535 int) (list 0))
        (define-public (trigger)
            (let ((mapped (map sha512 (var-get ints))))
                (ok mapped)
            )
        )",
);

// StaticCheckError: [`StaticCheckErrorKind::UnknownTypeName`]
// Caused by:
// Outcome: block accepted.
// Note: during analysis, this error can only be triggered by `from-consensus-buff?`
//       which is only available in Clarity 2 and later. So Clarity 1 will not trigger
//       this error.
contract_deploy_consensus_test!(
    static_check_error_unknown_type_name,
    contract_name: "unknown-type-name",
    contract_code: "
        (define-public (trigger)
            (ok (from-consensus-buff? foo 0x00)))",
);

// StaticCheckError: [`StaticCheckErrorKind::UnionTypeError`]
// Caused by:
// Outcome: block accepted.
contract_deploy_consensus_test!(
    static_check_error_union_type_error,
    contract_name: "union-type-error",
    contract_code: "(map - (list true false true false))",
);

// StaticCheckError: [`StaticCheckErrorKind::UndefinedVariable`]
// Caused by:
// Outcome: block accepted.
contract_deploy_consensus_test!(
    static_check_error_undefined_variable,
    contract_name: "undefined-variable",
    contract_code: "(+ x y z)",
);

// StaticCheckError: [`StaticCheckErrorKind::BadMapTypeDefinition`]
// Caused by:
// Outcome: block accepted.
contract_deploy_consensus_test!(
    static_check_error_bad_map_type_definition,
    contract_name: "bad-map-type",
    contract_code: "(define-map lists { name: int } contents)",
);

// StaticCheckError: [`StaticCheckErrorKind::CouldNotDetermineType`]
// Caused by:
// Outcome: block accepted.
contract_deploy_consensus_test!(
    static_check_error_could_not_determine_type,
    contract_name: "could-not-determine",
    contract_code: "(index-of (list) none)",
);

// StaticCheckError: [`StaticCheckErrorKind::ExpectedSequence`]
// Caused by:
// Outcome: block accepted.
contract_deploy_consensus_test!(
    static_check_error_expected_sequence,
    contract_name: "expected-sequence",
    contract_code: r#"(index-of 3 "a")"#,
);

// StaticCheckError: [`StaticCheckErrorKind::CouldNotDetermineSerializationType`]
// Caused by:
// Outcome: block accepted.
// Note: during analysis, this error can only be triggered by `from-consensus-buff?`
//       which is only available in Clarity 2 and later. So Clarity 1 will not trigger
//       this error.
contract_deploy_consensus_test!(
    static_check_error_could_not_determine_serialization_type,
    contract_name: "serialization-type",
    contract_code: "
        (define-trait trait-a ((ping () (response bool bool))))
        (define-trait trait-b ((pong () (response bool bool))))
        (define-public (trigger (first <trait-a>) (second <trait-b>))
            (ok (to-consensus-buff? (list first second))))",
);

// StaticCheckError: [`StaticCheckErrorKind::UncheckedIntermediaryResponses`]
// Caused by: Intermediate `(ok ...)` expressions inside a `begin` block that are not unwrapped.
// Outcome: block accepted.
contract_deploy_consensus_test!(
    static_check_error_unchecked_intermediary_responses,
    contract_name: "unchecked-resp",
    contract_code: "
        (define-public (trigger)
            (begin
                (ok true)
                (ok true)))",
);

// StaticCheckError: [`StaticCheckErrorKind::NoSuchFT`]
// Caused by:
// Outcome: block accepted.
contract_deploy_consensus_test!(
    static_check_error_no_such_ft,
    contract_name: "no-such-ft",
    contract_code: "(ft-get-balance stackoos tx-sender)",
);

// StaticCheckError: [`StaticCheckErrorKind::NoSuchNFT`]
// Caused by:
// Outcome: block accepted.
contract_deploy_consensus_test!(
    static_check_error_no_such_nft,
    contract_name: "no-such-nft",
    contract_code: r#"(nft-get-owner? stackoos "abc")"#,
);

// StaticCheckError: [`StaticCheckErrorKind::DefineNFTBadSignature`]
// Caused by:
// Outcome: block accepted.
contract_deploy_consensus_test!(
    static_check_error_define_nft_bad_signature,
    contract_name: "nft-bad-signature",
    contract_code: "(define-non-fungible-token stackaroos integer)",
);

// StaticCheckError: [`StaticCheckErrorKind::BadTokenName`]
// Caused by:
// Outcome: block accepted.
contract_deploy_consensus_test!(
    static_check_error_bad_token_name,
    contract_name: "bad-token-name",
    contract_code: "(ft-get-balance u1234 tx-sender)",
);

// StaticCheckError: [`StaticCheckErrorKind::EmptyTuplesNotAllowed`]
// Caused by:
// Outcome: block accepted.
contract_deploy_consensus_test!(
    static_check_error_empty_tuples_not_allowed,
    contract_name: "empty-tuples-not",
    contract_code: "
        (define-private (set-cursor (value (tuple)))
            value)",
);

// StaticCheckError: [`StaticCheckErrorKind::NoSuchDataVariable`]
// Caused by:
// Outcome: block accepted.
contract_deploy_consensus_test!(
    static_check_error_no_such_data_variable,
    contract_name: "no-such-data-var",
    contract_code: "
        (define-private (get-cursor)
            (unwrap! (var-get cursor) 0))",
);

// StaticCheckError: [`StaticCheckErrorKind::NonFunctionApplication`]
// Caused by:
// Outcome: block accepted.
contract_deploy_consensus_test!(
    static_check_error_non_function_application,
    contract_name: "non-function-appl",
    contract_code: "((lambda (x y) 1) 2 1)",
);

// StaticCheckError: [`StaticCheckErrorKind::NoSuchContract`]
// Caused by:
// Outcome: block accepted.
contract_deploy_consensus_test!(
    static_check_error_no_such_contract,
    contract_name: "no-such-contract",
    contract_code: "(contract-call? 'S1G2081040G2081040G2081040G208105NK8PE5.contract-name test! u1)",
);

// StaticCheckError: [`StaticCheckErrorKind::ContractCallExpectName`]
// Caused by:
// Outcome: block accepted.
contract_deploy_consensus_test!(
    static_check_error_contract_call_expect_name,
    contract_name: "ccall-expect-name",
    contract_code: "(contract-call? 'S1G2081040G2081040G2081040G208105NK8PE5.contract-name u1)",
);

// StaticCheckError: [`StaticCheckErrorKind::DefaultTypesMustMatch`]
// Caused by:
// Outcome: block accepted.
contract_deploy_consensus_test!(
    static_check_error_default_types_must_match,
    contract_name: "default-types-must",
    contract_code: "
        (define-map tokens { id: int } { balance: int })
        (default-to false (get balance (map-get? tokens (tuple (id 0)))))",
);

// StaticCheckError: [`StaticCheckErrorKind::IfArmsMustMatch`]
// Caused by:
// Outcome: block accepted.
contract_deploy_consensus_test!(
    static_check_error_if_arms_must_match,
    contract_name: "if-arms-must-match",
    contract_code: "(if true true 1)",
);

// StaticCheckError: [`StaticCheckErrorKind::IllegalOrUnknownFunctionApplication`]
// Caused by:
// Outcome: block accepted.
contract_deploy_consensus_test!(
    static_check_error_illegal_or_unknown_function_application,
    contract_name: "illegal-or-unknown",
    contract_code: "(map if (list 1 2 3 4 5))",
);

// StaticCheckError: [`StaticCheckErrorKind::UnknownFunction`]
// Caused by:
// Outcome: block accepted.
contract_deploy_consensus_test!(
    static_check_error_unknown_function,
    contract_name: "unknown-function",
    contract_code: "(ynot 1 2)",
);

// // StaticCheckError: [`StaticCheckErrorKind::UTraitReferenceUnknownnknownFunction`]
// // Caused by:
// // Outcome: block accepted.
// contract_deploy_consensus_test!(
//     static_check_error_trait_reference_unknown,
//     contract_name: "trait-ref-unknown",
//     contract_code: "",
// );

// StaticCheckError: [`StaticCheckErrorKind::IncorrectArgumentCount`]
// Caused by:
// Outcome: block accepted.
contract_deploy_consensus_test!(
    static_check_error_incorrect_argument_count,
    contract_name: "incorrect-arg-count",
    contract_code: "(len (list 1) (list 1))",
);

// StaticCheckError: [`StaticCheckErrorKind::BadSyntaxBinding`]
// Caused by:
// Outcome: block accepted.
contract_deploy_consensus_test!(
    static_check_error_bad_syntax_binding,
    contract_name: "bad-syntax-binding",
    contract_code: "(let ((1)) (+ 1 2))",
);

// StaticCheckError: [`StaticCheckErrorKind::ExpectedOptionalOrResponseType`]
// Caused by:
// Outcome: block accepted.
contract_deploy_consensus_test!(
    static_check_error_expected_optional_or_response_type,
    contract_name: "exp-opt-or-res",
    contract_code: "(try! 3)",
);

// StaticCheckError: [`StaticCheckErrorKind::DefineTraitBadSignature`]
// Caused by:
// Outcome: block accepted.
contract_deploy_consensus_test!(
    static_check_error_define_trait_bad_signature,
    contract_name: "def-trait-bad-sign",
    contract_code: "(define-trait trait-1 ((get-1 uint uint)))",
);

// StaticCheckError: [`StaticCheckErrorKind::DefineTraitDuplicateMethod`]
// Caused by:
// Outcome: block accepted.
// Note: This error was added in Clarity 2. Clarity 1 will accept the contract.
contract_deploy_consensus_test!(
    static_check_error_define_trait_duplicate_method,
    contract_name: "def-trait-dup-method",
    contract_code: "
        (define-trait double-method (
            (foo (uint) (response uint uint))
            (foo (bool) (response bool bool))
        ))",
);

// StaticCheckError: [`StaticCheckErrorKind::UnexpectedTraitOrFieldReference`]
// Caused by:
// Outcome: block accepted.
contract_deploy_consensus_test!(
    static_check_error_unexpected_trait_or_field_reference,
    contract_name: "trait-or-field-ref",
    contract_code: "(+ 1 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR.contract.field)",
);

// StaticCheckError: [`StaticCheckErrorKind::IncompatibleTrait`]
// Caused by: pass a trait to a trait parameter which is not compatible.
// Outcome: block accepted.
contract_deploy_consensus_test!(
    static_check_error_incompatible_trait,
    contract_name: "incompatible-trait",
    contract_code: "
    (define-trait trait-1 (
        (get-1 (uint) (response uint uint))
    ))
    (define-trait trait-2 (
        (get-2 (uint) (response uint uint))
    ))
    (define-public (wrapped-get-2 (contract <trait-1>))
        (internal-get-2 contract))
    (define-public (internal-get-2 (contract <trait-2>))
        (contract-call? contract get-2 u1))",
);

// StaticCheckError: [`StaticCheckErrorKind::ReservedWord`]
// Caused by:
// Outcome: block accepted.
// Note: This error was added in Clarity 3. Clarity 1 and 2
//       will trigger a [`StaticCheckErrorKind::NameAlreadyUsed`].
contract_deploy_consensus_test!(
    static_check_error_reserved_word,
    contract_name: "reserved-word",
    contract_code: "(define-private (block-height) true)",
);

// StaticCheckError: [`StaticCheckErrorKind::NoSuchBlockInfoProperty`]
// Caused by:
// Outcome: block accepted.
contract_deploy_consensus_test!(
    static_check_error_no_such_block_info_property,
    contract_name: "no-such-block-info",
    contract_code: "(get-burn-block-info? none u1)",
);

// pub enum StaticCheckErrorKind {
//     CostOverflow,
//     CostBalanceExceeded(ExecutionCost, ExecutionCost),
//     MemoryBalanceExceeded(u64, u64),
//     CostComputationFailed(String),
//     ExecutionTimeExpired,
//     ValueTooLarge, [`static_check_error_value_too_large`]
//     ValueOutOfBounds, [`static_check_error_value_out_of_bounds`]
//     TypeSignatureTooDeep, [`static_check_error_type_signature_too_deep`]
//     ExpectedName, [`static_check_error_expected_name`]
//     SupertypeTooLarge, [`static_check_error_supertype_too_large`]
//     Expects(String),
//     BadMatchOptionSyntax(Box<StaticCheckErrorKind>), [`static_check_error_bad_match_option_syntax`]
//     BadMatchResponseSyntax(Box<StaticCheckErrorKind>), [`static_check_error_bad_match_response_syntax`]
//     BadMatchInput(Box<TypeSignature>), [`static_check_error_bad_match_input`]
//     ConstructedListTooLarge, [`static_check_error_constructed_list_too_large`]
//     TypeError(Box<TypeSignature>, Box<TypeSignature>),  [`static_check_error_type_error`]
//     InvalidTypeDescription, [`static_check_error_invalid_type_description`]
//     UnknownTypeName(String), [`static_check_error_unknown_type_name`]
//     UnionTypeError(Vec<TypeSignature>, Box<TypeSignature>), [`static_check_error_union_type_error`]
//     ExpectedOptionalType(Box<TypeSignature>), [`static_check_error_expected_optional_type`]
//     ExpectedResponseType(Box<TypeSignature>), [`static_check_error_expected_response_type`]
//     ExpectedOptionalOrResponseType(Box<TypeSignature>), [`static_check_error_expected_optional_or_response_type`]
//     CouldNotDetermineResponseOkType, [`static_check_error_could_not_determine_response_ok_type`]
//     CouldNotDetermineResponseErrType, [`static_check_error_could_not_determine_response_err_type`]
//     CouldNotDetermineSerializationType, [`static_check_error_could_not_determine_serialization_type`]
//     UncheckedIntermediaryResponses, [`static_check_error_unchecked_intermediary_responses`]
//     CouldNotDetermineMatchTypes, [`static_check_error_could_not_determine_match_types`]
//     CouldNotDetermineType, [`static_check_error_could_not_determine_type`]
//     TypeAlreadyAnnotatedFailure,
//     CheckerImplementationFailure,
//     BadTokenName, [`static_check_error_bad_token_name`]
//     DefineNFTBadSignature, [`static_check_error_define_nft_bad_signature`]
//     NoSuchNFT(String), [`static_check_error_no_such_nft`]
//     NoSuchFT(String), [`static_check_error_no_such_ft`]
//     BadTupleFieldName,
//     ExpectedTuple(Box<TypeSignature>),
//     NoSuchTupleField(String, TupleTypeSignature),
//     EmptyTuplesNotAllowed, [`static_check_error_empty_tuples_not_allowed`]
//     BadTupleConstruction(String),
//     NoSuchDataVariable(String), [`static_check_error_no_such_data_variable`]
//     BadMapName,
//     NoSuchMap(String),
//     DefineFunctionBadSignature,
//     BadFunctionName,
//     BadMapTypeDefinition, [`static_check_error_bad_map_type_definition`]
//     PublicFunctionMustReturnResponse(Box<TypeSignature>),
//     DefineVariableBadSignature, [`static_check_error_define_variable_bad_signature`]
//     ReturnTypesMustMatch(Box<TypeSignature>, Box<TypeSignature>), [`static_check_error_return_types_must_match`]
//     NoSuchContract(String), [`static_check_error_no_such_contract`]
//     NoSuchPublicFunction(String, String),
//     ContractAlreadyExists(String),
//     ContractCallExpectName, [`static_check_error_contract_call_expect_name`]
//     ExpectedCallableType(Box<TypeSignature>),
//     NoSuchBlockInfoProperty(String), [`static_check_error_no_such_block_info_property`]
//     NoSuchStacksBlockInfoProperty(String),
//     NoSuchTenureInfoProperty(String),
//     GetBlockInfoExpectPropertyName,
//     GetBurnBlockInfoExpectPropertyName,
//     GetStacksBlockInfoExpectPropertyName,
//     GetTenureInfoExpectPropertyName,
//     NameAlreadyUsed(String), [`static_check_error_name_already_used`]
//     ReservedWord(String),
//     NonFunctionApplication, [`static_check_error_non_function_application`]
//     ExpectedListApplication,
//     ExpectedSequence(Box<TypeSignature>), [`static_check_error_expected_sequence`]
//     MaxLengthOverflow,
//     BadLetSyntax,
//     BadSyntaxBinding(SyntaxBindingError), [`static_check_error_bad_syntax_binding`]
//     MaxContextDepthReached,
//     UndefinedVariable(String), [`static_check_error_undefined_variable`]
//     RequiresAtLeastArguments(usize, usize), [`static_check_error_requires_at_least_arguments`]
//     RequiresAtMostArguments(usize, usize), [`static_check_error_requires_at_most_arguments`]
//     IncorrectArgumentCount(usize, usize), [`static_check_error_incorrect_argument_count`]
//     IfArmsMustMatch(Box<TypeSignature>, Box<TypeSignature>), [`static_check_error_if_arms_must_match`]
//     MatchArmsMustMatch(Box<TypeSignature>, Box<TypeSignature>), [`static_check_error_match_arms_must_match`]
//     DefaultTypesMustMatch(Box<TypeSignature>, Box<TypeSignature>), [`static_check_error_default_types_must_match`]
//     IllegalOrUnknownFunctionApplication(String), [`static_check_error_illegal_or_unknown_function_application`]
//     UnknownFunction(String), [`static_check_error_unknown_function`]
//     NoSuchTrait(String, String),
//     TraitReferenceUnknown(String),
//     TraitMethodUnknown(String, String),
//     ExpectedTraitIdentifier,
//     BadTraitImplementation(String, String),
//     DefineTraitBadSignature, [`static_check_error_define_trait_bad_signature`]
//     DefineTraitDuplicateMethod(String), [`static_check_error_define_trait_duplicate_method`]
//     UnexpectedTraitOrFieldReference, [`static_check_error_unexpected_trait_or_field_reference`]
//     ContractOfExpectsTrait,
//     IncompatibleTrait(Box<TraitIdentifier>, Box<TraitIdentifier>), [`static_check_error_incompatible_trait`]
//     WriteAttemptedInReadOnly,
//     AtBlockClosureMustBeReadOnly,
//     ExpectedListOfAllowances(String, i32),
//     AllowanceExprNotAllowed,
//     ExpectedAllowanceExpr(String),
//     WithAllAllowanceNotAllowed,
//     WithAllAllowanceNotAlone,
//     WithNftExpectedListOfIdentifiers,
//     MaxIdentifierLengthExceeded(u32, u32),
//     TooManyAllowances(usize, usize),
// }
