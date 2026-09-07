// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2026 Stacks Open Internet Foundation
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

//! Transaction logic for the Stacks blockchain.
//!
//! This crate holds the parts of transaction handling that are a pure function
//! of the transaction and the effects of executing it: no database, no
//! chainstate, and no interpreter. It reads what a transaction actually moved
//! from an [`AssetMap`], which is independent of the language that produced it,
//! so the crate needs the Clarity *types* but not the Clarity VM. That lets a
//! Wasm SDK run the same consensus-critical code mainnet does.
//!
//! Today that is post-condition verification. Post-conditions constrain the
//! assets a transaction is allowed to move. Two checks define that constraint,
//! and both are required: [`check_post_conditions_supported_in_epoch`] rejects
//! variants and modes not yet activated in the current epoch, before execution;
//! [`check_transaction_postconditions`] compares the declared post-conditions
//! against the [`AssetMap`] of what actually moved, after execution. The latter
//! runs in every epoch, so it does not subsume the former. Together they need
//! only the codec post-condition types, an [`AssetMap`], the origin principal
//! and the epoch.

use std::collections::{HashMap, HashSet};

use clarity_types::Value;
use clarity_types::effects::{AssetMap, AssetMapEntry};
use clarity_types::types::serialization::SerializationError;
use clarity_types::types::{
    AssetIdentifier, BoundedErrorString, PrincipalData, QualifiedContractIdentifier,
    StandardPrincipalData,
};
use stacks_codec::transaction::{
    NonfungibleConditionCode, TransactionPostCondition, TransactionPostConditionMode,
};
use stacks_common::bounded_format;
use stacks_common::types::StacksEpochId;

#[cfg(test)]
mod tests;

/// This is a safe-to-hash Clarity value
#[derive(PartialEq, Eq)]
struct HashableClarityValue(Value);

impl TryFrom<Value> for HashableClarityValue {
    type Error = SerializationError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        // check that serialization _will_ be successful when hashed
        let _bytes = value.serialize_to_vec()?;
        Ok(Self(value))
    }
}

impl std::hash::Hash for HashableClarityValue {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        #[allow(clippy::unwrap_used, clippy::collection_is_never_read)]
        // this unwrap is safe _as long as_ TryFrom<Value> was used as a constructor
        // Also, this function has side effects, which cause Clippy to wrongly think `bytes` is unused
        let bytes = self.0.serialize_to_vec().unwrap();
        bytes.hash(state);
    }
}

/// Why a transaction's post-conditions are not valid in a given epoch. Typed
/// rather than a formatted message so callers keep their own error channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsupportedPostCondition {
    OriginatorMode,
    NftMaybeSent,
    StakingOrPox,
}

impl std::fmt::Display for UnsupportedPostCondition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::OriginatorMode => {
                "Originator post-condition mode is not supported before Stacks 3.4"
            }
            Self::NftMaybeSent => "NFT MaybeSent post-condition is not supported before Stacks 3.4",
            Self::StakingOrPox => "Staking/Pox post-condition is not supported before Stacks 4.0",
        })
    }
}

impl std::error::Error for UnsupportedPostCondition {}

/// Reject post-condition variants and modes not yet activated in `epoch_id`.
///
/// The checks run in a fixed order — post-condition mode, then NFT
/// `MaybeSent`, then `Staking`/`Pox` — and the first failing check is
/// returned. That order, not the order of `post_conditions`, decides which
/// [`UnsupportedPostCondition`] a transaction with several unsupported
/// features reports.
pub fn check_post_conditions_supported_in_epoch(
    post_conditions: &[TransactionPostCondition],
    post_condition_mode: &TransactionPostConditionMode,
    epoch_id: StacksEpochId,
) -> Result<(), UnsupportedPostCondition> {
    if !epoch_id.supports_sip040_post_conditions() {
        if *post_condition_mode == TransactionPostConditionMode::Originator {
            return Err(UnsupportedPostCondition::OriginatorMode);
        }
        if post_conditions.iter().any(|pc| {
            matches!(
                pc,
                TransactionPostCondition::Nonfungible(_, _, _, NonfungibleConditionCode::MaybeSent)
            )
        }) {
            return Err(UnsupportedPostCondition::NftMaybeSent);
        }
    }

    if !epoch_id.supports_staking_post_conditions()
        && post_conditions.iter().any(|pc| {
            matches!(
                pc,
                TransactionPostCondition::Staking(..) | TransactionPostCondition::Pox(..)
            )
        })
    {
        return Err(UnsupportedPostCondition::StakingOrPox);
    }

    Ok(())
}

/// Apply a post-conditions check.
/// Return `Ok(None)` if the check passes.
/// Return `Ok(Some(reason))` if the check fails.
/// Return `Err` if a non-fungible asset value cannot be serialized, which is
/// required in order to hash it for comparison.
///
/// TODO: return a typed reason rather than a formatted message. It becomes
/// `StacksTransactionReceipt::vm_error`, which reaches the `new_block` event
/// payload and the `/v3/blocks/{replay,simulate}` RPC, so changing it is an
/// observable API change.
pub fn check_transaction_postconditions(
    post_conditions: &[TransactionPostCondition],
    post_condition_mode: &TransactionPostConditionMode,
    origin_principal: &PrincipalData,
    asset_map: &AssetMap,
    epoch_id: StacksEpochId,
) -> Result<Option<BoundedErrorString>, SerializationError> {
    let mut checked_fungible_assets: HashMap<PrincipalData, HashSet<AssetIdentifier>> =
        HashMap::new();
    let mut checked_nonfungible_assets: HashMap<
        PrincipalData,
        HashMap<AssetIdentifier, HashSet<HashableClarityValue>>,
    > = HashMap::new();
    // Principals whose staking (STX locked for PoX) was covered by a
    // `Staking` post-condition, and whose position-altering PoX actions
    // (unstake / unstake-sbtc / update-bond-registration /
    // announce-l1-early-exit) were covered by a `Pox` post-condition. Used
    // for the unchecked-asset enforcement below, in epochs that support
    // staking post-conditions.
    let mut checked_staking: HashSet<PrincipalData> = HashSet::new();
    let mut checked_pox: HashSet<PrincipalData> = HashSet::new();
    let enforce_unchecked_assets_for_principal =
        |principal: &PrincipalData| match post_condition_mode {
            TransactionPostConditionMode::Allow => false,
            TransactionPostConditionMode::Deny => true,
            TransactionPostConditionMode::Originator => principal == origin_principal,
        };

    for postcond in post_conditions {
        match postcond {
            TransactionPostCondition::STX(principal, condition_code, amount_sent_condition) => {
                let account_principal = principal.to_principal_data(origin_principal);

                let amount_transferred = asset_map.get_stx(&account_principal).unwrap_or(0);
                let amount_burned = asset_map.get_stx_burned(&account_principal).unwrap_or(0);

                let amount_sent = amount_transferred
                    .checked_add(amount_burned)
                    .expect("FATAL: sent waaaaay too much STX");

                if !condition_code.check(u128::from(*amount_sent_condition), amount_sent) {
                    let reason = bounded_format!(
                        "Post-condition check failure on STX owned by {account_principal}: {amount_sent_condition:?} {condition_code:?} {amount_sent}",
                    );
                    return Ok(Some(reason));
                }

                if let Some(ref mut asset_ids) = checked_fungible_assets.get_mut(&account_principal)
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
                principal,
                asset_info,
                condition_code,
                amount_sent_condition,
            ) => {
                let account_principal = principal.to_principal_data(origin_principal);
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
                    let reason = bounded_format!(
                        "Post-condition check failure on fungible asset {asset_id} owned by {account_principal}: {amount_sent_condition} {condition_code:?} {amount_sent}"
                    );
                    return Ok(Some(reason));
                }

                if let Some(ref mut asset_ids) = checked_fungible_assets.get_mut(&account_principal)
                {
                    asset_ids.insert(asset_id);
                } else {
                    let mut h = HashSet::new();
                    h.insert(asset_id);
                    checked_fungible_assets.insert(account_principal, h);
                }
            }
            TransactionPostCondition::Nonfungible(
                principal,
                asset_info,
                asset_value,
                condition_code,
            ) => {
                let account_principal = principal.to_principal_data(origin_principal);
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
                    let reason = bounded_format!(
                        "Post-condition check failure on non-fungible asset {asset_id} owned by {account_principal}: {} {condition_code:?} (sent {} value(s))",
                        asset_value.to_error_string(),
                        assets_sent.len(),
                    );
                    return Ok(Some(reason));
                }

                if let Some(ref mut asset_id_map) =
                    checked_nonfungible_assets.get_mut(&account_principal)
                {
                    if let Some(ref mut asset_values) = asset_id_map.get_mut(&asset_id) {
                        asset_values.insert(asset_value.clone().try_into()?);
                    } else {
                        let mut asset_set = HashSet::new();
                        asset_set.insert(asset_value.clone().try_into()?);
                        asset_id_map.insert(asset_id, asset_set);
                    }
                } else {
                    let mut asset_id_map = HashMap::new();
                    let mut asset_set = HashSet::new();
                    asset_set.insert(asset_value.clone().try_into()?);
                    asset_id_map.insert(asset_id, asset_set);
                    checked_nonfungible_assets.insert(account_principal, asset_id_map);
                }
            }
            TransactionPostCondition::Staking(
                principal,
                condition_code,
                amount_staked_condition,
            ) => {
                let account_principal = principal.to_principal_data(origin_principal);

                let amount_staked = asset_map.get_stacking(&account_principal).unwrap_or(0);

                if !condition_code.check(u128::from(*amount_staked_condition), amount_staked) {
                    let reason = bounded_format!(
                        "Post-condition check failure on STX staked by {account_principal}: {amount_staked_condition:?} {condition_code:?} {amount_staked}",
                    );
                    return Ok(Some(reason));
                }

                checked_staking.insert(account_principal);
            }
            TransactionPostCondition::Pox(principal, condition_code) => {
                let account_principal = principal.to_principal_data(origin_principal);

                let performed = asset_map.did_pox_action(&account_principal);

                if !condition_code.check(performed) {
                    let reason = bounded_format!(
                        "Post-condition check failure on PoX action by {account_principal}: {condition_code:?} performed={performed}",
                    );
                    return Ok(Some(reason));
                }

                checked_pox.insert(account_principal);
            }
        }
    }

    // make sure every asset transferred is covered by a postcondition, if the current mode
    // requires it.
    let asset_map_copy = (*asset_map).clone();
    let mut all_assets_sent = asset_map_copy.to_table();
    for (principal, mut assets) in all_assets_sent.drain() {
        if !enforce_unchecked_assets_for_principal(&principal) {
            continue;
        }
        for (asset_identifier, asset_entry) in assets.drain() {
            match asset_entry {
                AssetMapEntry::Asset(values) => {
                    // this is a NFT
                    if let Some(checked_nft_asset_map) = checked_nonfungible_assets.get(&principal)
                    {
                        if let Some(nfts) = checked_nft_asset_map.get(&asset_identifier) {
                            // each value must be covered
                            for v in values {
                                if !nfts.contains(&v.clone().try_into()?) {
                                    let reason = bounded_format!(
                                        "Post-condition check failure: Non-fungible asset {asset_identifier} value {} was moved by {principal} but not checked",
                                        v.to_error_string(),
                                    );
                                    return Ok(Some(reason));
                                }
                            }
                        } else {
                            // no values covered
                            let reason = bounded_format!(
                                "Post-condition check failure: Non-fungible asset {asset_identifier} was moved by {principal} but not checked"
                            );
                            return Ok(Some(reason));
                        }
                    } else {
                        // no NFT for this principal
                        let reason = bounded_format!(
                            "Post-condition check failure: No checks for non-fungible asset {asset_identifier} moved by {principal}"
                        );
                        return Ok(Some(reason));
                    }
                }
                _ => {
                    // This is STX or a fungible token
                    if let Some(checked_ft_asset_ids) = checked_fungible_assets.get(&principal) {
                        if !checked_ft_asset_ids.contains(&asset_identifier) {
                            let reason = bounded_format!(
                                "Post-condition check failure: Fungible asset {asset_identifier} was moved by {principal} but not checked"
                            );
                            return Ok(Some(reason));
                        }
                    } else {
                        let reason = bounded_format!(
                            "Post-condition check failure: Fungible asset {asset_identifier} was moved by {principal} but not checked"
                        );
                        return Ok(Some(reason));
                    }
                }
            }
        }
    }

    // make sure every principal that staked STX is covered by a `Staking` post-condition, and
    // every principal that performed a position-altering PoX action is covered by a `Pox`
    // post-condition, if the current mode requires it. The staking map and pox-action set are
    // intentionally excluded from `to_table`, so they are enforced separately here. Only
    // enforced in epochs that support staking post-conditions, since these were previously
    // unchecked at the tx level.
    if epoch_id.supports_staking_post_conditions() {
        for (principal, amount_staked) in asset_map.get_all_stacking() {
            if *amount_staked == 0 {
                continue;
            }
            if !enforce_unchecked_assets_for_principal(principal) {
                continue;
            }
            if !checked_staking.contains(principal) {
                let reason = bounded_format!(
                    "Post-condition check failure: {amount_staked} STX was staked by {principal} but not checked"
                );
                return Ok(Some(reason));
            }
        }

        for principal in asset_map.get_all_pox_actions() {
            if !enforce_unchecked_assets_for_principal(principal) {
                continue;
            }
            if !checked_pox.contains(principal) {
                let reason = bounded_format!(
                    "Post-condition check failure: {principal} performed a PoX action but it was not checked"
                );
                return Ok(Some(reason));
            }
        }
    }

    Ok(None)
}
