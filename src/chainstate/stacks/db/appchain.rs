// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2022 Stacks Open Internet Foundation
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
use burnchains::bitcoin::address::BitcoinAddress;
use burnchains::{Address, Burnchain, BurnchainParameters, PoxConstants};
use chainstate::burn::db::sortdb::BlockHeaderCache;
use chainstate::burn::db::sortdb::*;
use chainstate::burn::db::sortdb::{SortitionDB, SortitionDBConn};
use chainstate::burn::ConsensusHash;
use chainstate::stacks::boot::*;
use chainstate::stacks::db::accounts::*;
use chainstate::stacks::db::blocks::*;
use chainstate::stacks::db::unconfirmed::UnconfirmedState;
use chainstate::stacks::events::*;
use chainstate::stacks::index::marf::{
    MarfConnection, BLOCK_HASH_TO_HEIGHT_MAPPING_KEY, BLOCK_HEIGHT_TO_HASH_MAPPING_KEY, MARF,
};
use chainstate::stacks::index::storage::TrieFileStorage;
use chainstate::stacks::index::MarfTrieId;
use chainstate::stacks::Error;
use chainstate::stacks::*;
use chainstate::stacks::{
    C32_ADDRESS_VERSION_MAINNET_MULTISIG, C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
    C32_ADDRESS_VERSION_TESTNET_MULTISIG, C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
};
use clarity_vm::clarity::{
    ClarityBlockConnection, ClarityConnection, ClarityInstance, ClarityReadOnlyConnection,
    Error as clarity_error,
};
use core::*;
use net::atlas::BNS_CHARS_REGEX;
use net::Error as net_error;
use net::MemPoolSyncData;
use util_lib::db::Error as db_error;
use util_lib::db::{
    query_count, query_row, tx_begin_immediate, tx_busy_handler, DBConn, DBTx, FromColumn, FromRow,
    IndexDBConn, IndexDBTx,
};
use stacks_common::util::hash::to_hex;
use vm::analysis::analysis_db::AnalysisDatabase;
use vm::analysis::run_analysis;
use vm::ast::build_ast;
use vm::contexts::OwnedEnvironment;
use vm::costs::{ExecutionCost, LimitedCostTracker};
use vm::database::{
    BurnStateDB, ClarityDatabase, HeadersDB, STXBalance, SqliteConnection, NULL_BURN_STATE_DB,
};
use vm::representations::ClarityName;
use vm::representations::ContractName;
use vm::types::TupleData;
use {monitoring, util};

use crate::clarity_vm::database::marf::MarfedKV;
use stacks_common::types::chainstate::{
    StacksAddress, StacksBlockId,
};
use chainstate::stacks::StacksBlockHeader;
use chainstate::stacks::StacksMicroblockHeader;
use chainstate::stacks::index::MARFValue;
use chainstate::stacks::index::ClarityMarfTrieId;
use stacks_common::types::chainstate::TrieHash;
use crate::util_lib::boot::{boot_code_acc, boot_code_addr, boot_code_id, boot_code_tx_auth};
use chainstate::stacks::db::ChainStateBootData;
use chainstate::stacks::db::ClarityTx;
use chainstate::stacks::db::StacksChainState;
use vm::Value;

use clarity::vm::types::StacksAddressExtensions;

impl StacksChainState {
    /// Get the genesis state root hash, once the burnchain block has been calculated
    pub fn get_genesis_state_index_root(&mut self) -> TrieHash {
        self.clarity_state.with_marf(|marf| {
            let index_block_hash = StacksBlockHeader::make_index_block_hash(
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
            );
            marf.get_root_hash_at(&index_block_hash).unwrap()
        })
    }

    /// Instantiate chainstate for an appchain
    #[cfg(test)]
    pub fn instantiate_appchain_chainstate(
        mainnet: bool,
        chain_id: u32,
        test_name: &str,
        balances: Vec<(StacksAddress, u64)>,
        first_burnchain_block_hash: BurnchainHeaderHash,
        first_burnchain_block_height: u64,
    ) -> StacksChainState {
        use chainstate::stacks::db::test::chainstate_path;
        use std::fs;

        assert!(chain_id != 0 && chain_id != 0x80000000);

        let path = chainstate_path(test_name);
        match fs::metadata(&path) {
            Ok(_) => {
                fs::remove_dir_all(&path).unwrap();
            }
            Err(_) => {}
        };

        let initial_balances = balances
            .into_iter()
            .map(|(addr, balance)| (PrincipalData::from(addr), balance))
            .collect();

        let mut boot_data = ChainStateBootData {
            initial_balances,
            post_flight_callback: None,
            first_burnchain_block_hash: first_burnchain_block_hash,
            first_burnchain_block_height: first_burnchain_block_height as u32,
            first_burnchain_block_timestamp: 0,
            pox_constants: PoxConstants::testnet_default(),
            get_bulk_initial_lockups: None,
            get_bulk_initial_balances: None,
            get_bulk_initial_names: None,
            get_bulk_initial_namespaces: None,
            appchain_genesis_hash: None,
        };

        StacksChainState::open_and_exec(mainnet, chain_id, &path, Some(&mut boot_data))
            .unwrap()
            .0
    }
}

impl ChainStateBootData {
    pub fn new_appchain(
        mainnet: bool,
        burnchain: &Burnchain,
        initial_balances: Vec<(PrincipalData, u64)>,
        additional_contracts: Vec<(ContractName, StacksString)>,
        genesis_hash: TrieHash,
    ) -> ChainStateBootData {
        let post_flight_callback = move |clarity_tx: &mut ClarityTx| {
            let mut receipts = vec![];
            if additional_contracts.len() > 0 {
                clarity_tx.connection().as_transaction(|clarity| {
                    let boot_code_addr = boot_code_addr(mainnet);
                    let mut boot_code_account = StacksChainState::get_account(clarity, &boot_code_addr.to_account_principal());
                    let boot_code_auth = TransactionAuth::Standard(
                        TransactionSpendingCondition::Singlesig(SinglesigSpendingCondition {
                            signer: boot_code_addr.bytes.clone(),
                            hash_mode: SinglesigHashMode::P2PKH,
                            key_encoding: TransactionPublicKeyEncoding::Uncompressed,
                            nonce: boot_code_account.nonce,
                            tx_fee: 0,
                            signature: MessageSignature::empty(),
                        }),
                    );

                    for (contract_name, contract_code) in additional_contracts.into_iter() {
                        debug!(
                            "Instantiate appchain-specific boot code contract '{}.{}' ({} bytes)...",
                            &boot_code_addr.to_string(),
                            &contract_name.as_str(),
                            contract_code.len(),
                        );

                        let smart_contract =
                            TransactionPayload::SmartContract(TransactionSmartContract {
                                name: contract_name.clone(),
                                code_body: contract_code
                            });

                        let boot_code_smart_contract = StacksTransaction::new(
                            if mainnet { TransactionVersion::Mainnet } else { TransactionVersion::Testnet },
                            boot_code_auth.clone(),
                            smart_contract,
                        );
                        let receipt = StacksChainState::process_transaction_payload(
                            clarity,
                            &boot_code_smart_contract,
                            &boot_code_account,
                        )
                        .expect(&format!("BUG: boot code did not run successfully. Failed contract was {}.{}", &boot_code_addr.to_string(), &contract_name.as_str()));

                        receipts.push(receipt);
                        boot_code_account.nonce += 1;
                    }
                });
            }
            receipts
        };
        ChainStateBootData {
            first_burnchain_block_hash: burnchain.first_block_hash.clone(),
            first_burnchain_block_height: burnchain.first_block_height as u32,
            first_burnchain_block_timestamp: burnchain.first_block_timestamp,
            initial_balances,
            pox_constants: burnchain.pox_constants.clone(),
            post_flight_callback: Some(Box::new(post_flight_callback)),
            get_bulk_initial_lockups: None,
            get_bulk_initial_balances: None,
            get_bulk_initial_namespaces: None,
            get_bulk_initial_names: None,
            appchain_genesis_hash: Some(genesis_hash),
        }
    }
}
