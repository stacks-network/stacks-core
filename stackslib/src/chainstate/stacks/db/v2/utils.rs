use std::collections::{BTreeMap, btree_map::Entry, HashMap, HashSet};

use clarity::vm::{
    types::{PrincipalData, TupleData, BuffData, StacksAddressExtensions, QualifiedContractIdentifier, AssetIdentifier, StandardPrincipalData}, 
    database::NULL_BURN_STATE_DB, ContractName, ast::ASTRules, 
    events::{StacksTransactionEvent, STXEventType, STXMintEventData}, 
    Value, costs::ExecutionCost, tests::BurnStateDB, 
    errors::{CheckErrors, Error as InterpreterError}, clarity::TransactionConnection, contexts::{AssetMap, AssetMapEntry}, ClarityVersion
};
use stacks_common::{
    types::{chainstate::{StacksAddress, StacksBlockId, TrieHash, ConsensusHash, BlockHeaderHash}, Address, StacksEpochId}, 
    address::{
        C32_ADDRESS_VERSION_MAINNET_SINGLESIG, C32_ADDRESS_VERSION_MAINNET_MULTISIG, 
        C32_ADDRESS_VERSION_TESTNET_SINGLESIG, C32_ADDRESS_VERSION_TESTNET_MULTISIG
    }, util::hash::Hash160
};

use crate::{
    burnchains::bitcoin::address::LegacyBitcoinAddress, 
    chainstate::stacks::{
            address::StacksAddressExtensions as ChainstateStacksAddressExtensions,
            Error, events::StacksTransactionReceipt, TransactionVersion, boot, TransactionPayload, 
            TransactionSmartContract, StacksTransaction, TokenTransferMemo, StacksBlockHeader, 
            db::StacksHeaderInfo, 
            index::{
                ClarityMarfTrieId, db::DbConnection, trie_db::TrieDb, marf::MARF
            }, TransactionPostCondition, TransactionPostConditionMode
    }, 
    util_lib::{
        boot::{boot_code_addr, boot_code_tx_auth, boot_code_acc, boot_code_id}, 
        strings::{StacksString, VecDisplay}
    }, 
    core::{
        BURNCHAIN_BOOT_CONSENSUS_HASH, BOOT_BLOCK_HASH, FIRST_BURNCHAIN_CONSENSUS_HASH, 
        FIRST_STACKS_BLOCK_HASH, MAINNET_2_0_GENESIS_ROOT_HASH
    }, 
    net::atlas::BNS_CHARS_REGEX, 
    clarity_vm::clarity::{
        ClarityBlockConnection, ClarityConnection, ClarityInstance, ClarityTransactionConnection,
        Error as clarity_error,
    },
};

use super::super::{ChainStateBootData, ClarityTx, DBConfig, CHAINSTATE_VERSION, StacksAccount, transactions::ClarityRuntimeTxError};

pub struct ChainStateUtils {}

impl ChainStateUtils {
    /// Gets the parent index block for the provided parent consensus hash and 
    /// parent block hash combination.
    pub fn get_parent_index_block(
        parent_consensus_hash: &ConsensusHash,
        parent_block: &BlockHeaderHash,
    ) -> StacksBlockId {
        if *parent_block == BOOT_BLOCK_HASH {
            // begin boot block
            StacksBlockId::sentinel()
        } else if *parent_block == FIRST_STACKS_BLOCK_HASH {
            // begin first-ever block
            StacksBlockHeader::make_index_block_hash(
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
            )
        } else {
            // subsequent block
            StacksBlockHeader::make_index_block_hash(parent_consensus_hash, parent_block)
        }
    }

    pub fn handle_clarity_runtime_error(error: clarity_error) -> ClarityRuntimeTxError {
        match error {
            // runtime errors are okay
            clarity_error::Interpreter(InterpreterError::Runtime(_, _)) => {
                ClarityRuntimeTxError::Acceptable {
                    error,
                    err_type: "runtime error",
                }
            }
            clarity_error::Interpreter(InterpreterError::ShortReturn(_)) => {
                ClarityRuntimeTxError::Acceptable {
                    error,
                    err_type: "short return/panic",
                }
            }
            clarity_error::Interpreter(InterpreterError::Unchecked(CheckErrors::SupertypeTooLarge)) => {
                ClarityRuntimeTxError::Rejectable(error)
            }
            clarity_error::Interpreter(InterpreterError::Unchecked(check_error)) => {
                ClarityRuntimeTxError::AnalysisError(check_error)
            }
            clarity_error::AbortedByCallback(val, assets, events) => {
                ClarityRuntimeTxError::AbortedByCallback(val, assets, events)
            }
            clarity_error::CostError(cost, budget) => ClarityRuntimeTxError::CostError(cost, budget),
            unhandled_error => ClarityRuntimeTxError::Rejectable(unhandled_error),
        }
    }

    /// Apply a post-conditions check.
    /// Return true if they all pass.
    /// Return false if at least one fails.
    pub fn check_transaction_postconditions(
        post_conditions: &Vec<TransactionPostCondition>,
        post_condition_mode: &TransactionPostConditionMode,
        origin_account: &StacksAccount,
        asset_map: &AssetMap,
    ) -> bool {
        let mut checked_fungible_assets: HashMap<PrincipalData, HashSet<AssetIdentifier>> =
            HashMap::new();
        let mut checked_nonfungible_assets: HashMap<
            PrincipalData,
            HashMap<AssetIdentifier, HashSet<Value>>,
        > = HashMap::new();
        let allow_unchecked_assets = *post_condition_mode == TransactionPostConditionMode::Allow;

        for postcond in post_conditions {
            match postcond {
                TransactionPostCondition::STX(
                    ref principal,
                    ref condition_code,
                    ref amount_sent_condition,
                ) => {
                    let account_principal = principal.to_principal_data(&origin_account.principal);

                    let amount_transferred = asset_map.get_stx(&account_principal).unwrap_or(0);
                    let amount_burned = asset_map.get_stx_burned(&account_principal).unwrap_or(0);

                    let amount_sent = amount_transferred
                        .checked_add(amount_burned)
                        .expect("FATAL: sent waaaaay too much STX");

                    if !condition_code.check(u128::from(*amount_sent_condition), amount_sent) {
                        info!(
                            "Post-condition check failure on STX owned by {}: {:?} {:?} {}",
                            account_principal, amount_sent_condition, condition_code, amount_sent
                        );
                        return false;
                    }

                    if let Some(ref mut asset_ids) =
                        checked_fungible_assets.get_mut(&account_principal)
                    {
                        if amount_transferred > 0 {
                            asset_ids.insert(AssetIdentifier::STX());
                        }
                        if amount_burned > 0 {
                            asset_ids.insert(AssetIdentifier::STX_burned());
                        }
                    } else {
                        let mut h = HashSet::new();
                        if amount_transferred > 0 {
                            h.insert(AssetIdentifier::STX());
                        }
                        if amount_burned > 0 {
                            h.insert(AssetIdentifier::STX_burned());
                        }
                        checked_fungible_assets.insert(account_principal, h);
                    }
                }
                TransactionPostCondition::Fungible(
                    ref principal,
                    ref asset_info,
                    ref condition_code,
                    ref amount_sent_condition,
                ) => {
                    let account_principal = principal.to_principal_data(&origin_account.principal);
                    let asset_id = AssetIdentifier {
                        contract_identifier: QualifiedContractIdentifier::new(
                            StandardPrincipalData::from(asset_info.contract_address.clone()),
                            asset_info.contract_name.clone(),
                        ),
                        asset_name: asset_info.asset_name.clone(),
                    };

                    let amount_sent = asset_map
                        .get_fungible_tokens(&account_principal, &asset_id)
                        .unwrap_or(0);
                    if !condition_code.check(u128::from(*amount_sent_condition), amount_sent) {
                        info!("Post-condition check failure on fungible asset {} owned by {}: {} {:?} {}", &asset_id, account_principal, amount_sent_condition, condition_code, amount_sent);
                        return false;
                    }

                    if let Some(ref mut asset_ids) =
                        checked_fungible_assets.get_mut(&account_principal)
                    {
                        asset_ids.insert(asset_id);
                    } else {
                        let mut h = HashSet::new();
                        h.insert(asset_id);
                        checked_fungible_assets.insert(account_principal, h);
                    }
                }
                TransactionPostCondition::Nonfungible(
                    ref principal,
                    ref asset_info,
                    ref asset_value,
                    ref condition_code,
                ) => {
                    let account_principal = principal.to_principal_data(&origin_account.principal);
                    let asset_id = AssetIdentifier {
                        contract_identifier: QualifiedContractIdentifier::new(
                            StandardPrincipalData::from(asset_info.contract_address.clone()),
                            asset_info.contract_name.clone(),
                        ),
                        asset_name: asset_info.asset_name.clone(),
                    };

                    let empty_assets = vec![];
                    let assets_sent = asset_map
                        .get_nonfungible_tokens(&account_principal, &asset_id)
                        .unwrap_or(&empty_assets);
                    if !condition_code.check(asset_value, assets_sent) {
                        info!("Post-condition check failure on non-fungible asset {} owned by {}: {:?} {:?}", &asset_id, account_principal, &asset_value, condition_code);
                        return false;
                    }

                    if let Some(ref mut asset_id_map) =
                        checked_nonfungible_assets.get_mut(&account_principal)
                    {
                        if let Some(ref mut asset_values) = asset_id_map.get_mut(&asset_id) {
                            asset_values.insert(asset_value.clone());
                        } else {
                            let mut asset_set = HashSet::new();
                            asset_set.insert(asset_value.clone());
                            asset_id_map.insert(asset_id, asset_set);
                        }
                    } else {
                        let mut asset_id_map = HashMap::new();
                        let mut asset_set = HashSet::new();
                        asset_set.insert(asset_value.clone());
                        asset_id_map.insert(asset_id, asset_set);
                        checked_nonfungible_assets.insert(account_principal, asset_id_map);
                    }
                }
            }
        }

        if !allow_unchecked_assets {
            // make sure every asset transferred is covered by a postcondition
            let asset_map_copy = (*asset_map).clone();
            let mut all_assets_sent = asset_map_copy.to_table();
            for (principal, mut assets) in all_assets_sent.drain() {
                for (asset_identifier, asset_entry) in assets.drain() {
                    match asset_entry {
                        AssetMapEntry::Asset(values) => {
                            // this is a NFT
                            if let Some(ref checked_nft_asset_map) =
                                checked_nonfungible_assets.get(&principal)
                            {
                                if let Some(ref nfts) = checked_nft_asset_map.get(&asset_identifier)
                                {
                                    // each value must be covered
                                    for v in values {
                                        if !nfts.contains(&v) {
                                            info!("Post-condition check failure: Non-fungible asset {} value {:?} was moved by {} but not checked", &asset_identifier, &v, &principal);
                                            return false;
                                        }
                                    }
                                } else {
                                    // no values covered
                                    info!("Post-condition check failure: No checks for non-fungible asset type {} moved by {}", &asset_identifier, &principal);
                                    return false;
                                }
                            } else {
                                // no NFT for this principal
                                info!("Post-condition check failure: No checks for any non-fungible assets, but moved {} by {}", &asset_identifier, &principal);
                                return false;
                            }
                        }
                        _ => {
                            // This is STX or a fungible token
                            if let Some(ref checked_ft_asset_ids) =
                                checked_fungible_assets.get(&principal)
                            {
                                if !checked_ft_asset_ids.contains(&asset_identifier) {
                                    info!("Post-condition check failure: checks did not cover transfer of {} by {}", &asset_identifier, &principal);
                                    return false;
                                }
                            } else {
                                info!("Post-condition check failure: No checks for fungible token type {} moved by {}", &asset_identifier, &principal);
                                return false;
                            }
                        }
                    }
                }
            }
        }
        return true;
    }

    pub fn parse_genesis_address(addr: &str, mainnet: bool) -> PrincipalData {
        // Typical entries are BTC encoded addresses that need converted to STX
        let mut stacks_address = match LegacyBitcoinAddress::from_b58(&addr) {
            Ok(addr) => StacksAddress::from_legacy_bitcoin_address(&addr),
            // A few addresses (from legacy placeholder accounts) are already STX addresses
            _ => match StacksAddress::from_string(addr) {
                Some(addr) => addr,
                None => panic!("Failed to parsed genesis address {}", addr),
            },
        };
        // Convert a given address to the currently running network mode (mainnet vs testnet).
        // All addresses from the Stacks 1.0 import data should be mainnet, but we'll handle either case.
        stacks_address.version = if mainnet {
            match stacks_address.version {
                C32_ADDRESS_VERSION_TESTNET_SINGLESIG => C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
                C32_ADDRESS_VERSION_TESTNET_MULTISIG => C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                _ => stacks_address.version,
            }
        } else {
            match stacks_address.version {
                C32_ADDRESS_VERSION_MAINNET_SINGLESIG => C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
                C32_ADDRESS_VERSION_MAINNET_MULTISIG => C32_ADDRESS_VERSION_TESTNET_MULTISIG,
                _ => stacks_address.version,
            }
        };
        let principal: PrincipalData = stacks_address.into();
        return principal;
    }
}