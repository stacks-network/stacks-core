use std::collections::{HashMap, HashSet};

use clarity::vm::{
    types::{PrincipalData, QualifiedContractIdentifier, AssetIdentifier, StandardPrincipalData}, 
    Value, errors::CheckErrors, contexts::{AssetMap, AssetMapEntry}
};
use stacks_common::{
    types::{chainstate::{StacksAddress, StacksBlockId, ConsensusHash, BlockHeaderHash}, Address}, 
    address::{
        C32_ADDRESS_VERSION_MAINNET_SINGLESIG, C32_ADDRESS_VERSION_MAINNET_MULTISIG, 
        C32_ADDRESS_VERSION_TESTNET_SINGLESIG, C32_ADDRESS_VERSION_TESTNET_MULTISIG
    }
};

use crate::{
    burnchains::bitcoin::address::LegacyBitcoinAddress, 
    chainstate::stacks::{
            address::StacksAddressExtensions as ChainstateStacksAddressExtensions,
            StacksBlockHeader, 
            index::ClarityMarfTrieId, TransactionPostCondition, TransactionPostConditionMode
    }, 
    core::{
        BOOT_BLOCK_HASH, FIRST_BURNCHAIN_CONSENSUS_HASH, 
        FIRST_STACKS_BLOCK_HASH, MICROSTACKS_PER_STACKS
    },
};

use super::super::{StacksAccount, transactions::ClarityRuntimeTxError};

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

    pub fn handle_clarity_runtime_error(error: clarity::vm::clarity::Error) -> ClarityRuntimeTxError {
        use clarity::vm::clarity::Error as clarity_error;
        use clarity::vm::errors::Error as InterpreterError;

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

    /// Get the coinbase at this burn block height, in microSTX
    pub fn get_coinbase_reward(burn_block_height: u64, first_burn_block_height: u64) -> u128 {
        /*
        From https://forum.stacks.org/t/pox-consensus-and-stx-future-supply

        """

        1000 STX for years 0-4
        500 STX for years 4-8
        250 STX for years 8-12
        125 STX in perpetuity


        From the Token Whitepaper:

        We expect that once native mining goes live, approximately 4383 blocks will be pro-
        cessed per month, or approximately 52,596 blocks will be processed per year.

        """
        */
        // this is saturating subtraction for the initial reward calculation
        //   where we are computing the coinbase reward for blocks that occur *before*
        //   the `first_burn_block_height`
        let effective_ht = burn_block_height.saturating_sub(first_burn_block_height);
        let blocks_per_year = 52596;
        let stx_reward = if effective_ht < blocks_per_year * 4 {
            1000
        } else if effective_ht < blocks_per_year * 8 {
            500
        } else if effective_ht < blocks_per_year * 12 {
            250
        } else {
            125
        };

        stx_reward * (u128::from(MICROSTACKS_PER_STACKS))
    }
}