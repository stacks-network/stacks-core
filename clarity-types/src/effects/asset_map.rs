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

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::{error, fmt};

#[cfg(feature = "asset-map-json")]
use serde_json::{Map as JsonMap, Value as JsonValue, json};
use stacks_common::types::StacksEpochId;

use crate::types::{AssetIdentifier, PrincipalData, Value};

/// A categorized asset change recorded for a principal.
#[derive(Debug, PartialEq, Eq)]
pub enum AssetMapEntry {
    /// STX transferred by the principal.
    STX(u128),
    /// STX burned by the principal.
    Burn(u128),
    /// Fungible tokens transferred by the principal.
    Token(u128),
    /// Non-fungible asset values transferred by the principal.
    Asset(Vec<Value>),
    /// STX stacked or delegated for stacking by the principal.
    Stacking(u128),
}

/// An error produced while accumulating or merging asset changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssetMapError {
    /// An accumulated asset amount exceeded `u128::MAX`.
    ///
    /// This is defensive in normal Clarity execution: asset amounts are
    /// balance-bounded, and balance arithmetic is checked before effects are
    /// recorded.
    AmountOverflow,
    /// The total burned STX amount exceeded `u128::MAX`.
    BurnTotalOverflow,
    /// A pre-Epoch-4.0 merge would overwrite an existing stacking entry.
    ///
    /// Rejecting the overwrite preserves the pre-Epoch-4.0 soft-fork safety
    /// check represented by `PoxStxAssetMapOverwrite` in the Clarity VM.
    StackingEntryConflict,
}

impl fmt::Display for AssetMapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AmountOverflow => write!(f, "asset amount overflow"),
            Self::BurnTotalOverflow => write!(f, "burn total overflow"),
            Self::StackingEntryConflict => write!(f, "stacking entry conflict"),
        }
    }
}

impl error::Error for AssetMapError {}

/// Asset changes made by principals during a transaction's execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetMap {
    /// Sum of all STX transfers by principal.
    stx_map: HashMap<PrincipalData, u128>,
    /// Sum of all STX burns by principal.
    burn_map: HashMap<PrincipalData, u128>,
    /// Sum of FT transfers by principal, by asset identifier.
    token_map: HashMap<PrincipalData, HashMap<AssetIdentifier, u128>>,
    /// NFT transfers by principal, by asset identifier.
    asset_map: HashMap<PrincipalData, HashMap<AssetIdentifier, Vec<Value>>>,
    /// Amount of STX stacked or delegated for stacking by principal.
    stacking_map: HashMap<PrincipalData, u128>,
    /// Principals that attempted a position-altering PoX action, whether or not
    /// the action succeeded, so post-conditions can gate failed attempts.
    pox_action_set: HashSet<PrincipalData>,
}

impl Default for AssetMap {
    fn default() -> Self {
        Self::new()
    }
}

impl AssetMap {
    /// Creates an empty asset map.
    pub fn new() -> Self {
        Self {
            stx_map: HashMap::new(),
            burn_map: HashMap::new(),
            token_map: HashMap::new(),
            asset_map: HashMap::new(),
            stacking_map: HashMap::new(),
            pox_action_set: HashSet::new(),
        }
    }

    /// Converts the recorded changes into their JSON representation.
    #[cfg(feature = "asset-map-json")]
    pub fn to_json(&self) -> JsonValue {
        let tokens = self
            .token_map
            .iter()
            .map(|(principal, token_map)| {
                let token_json = token_map
                    .iter()
                    .map(|(asset_id, amount)| {
                        (asset_id.to_string(), JsonValue::String(amount.to_string()))
                    })
                    .collect();
                (principal.to_string(), JsonValue::Object(token_json))
            })
            .collect::<JsonMap<_, _>>();

        let assets = self
            .asset_map
            .iter()
            .map(|(principal, nft_map)| {
                let nft_json = nft_map
                    .iter()
                    .map(|(asset_id, nft_values)| {
                        let nft_array = nft_values
                            .iter()
                            .map(|nft_value| JsonValue::String(nft_value.to_string()))
                            .collect();
                        (asset_id.to_string(), JsonValue::Array(nft_array))
                    })
                    .collect();
                (principal.to_string(), JsonValue::Object(nft_json))
            })
            .collect::<JsonMap<_, _>>();

        let pox = self
            .pox_action_set
            .iter()
            .map(|principal| JsonValue::String(principal.to_string()))
            .collect::<Vec<_>>();

        json!({
            "stx": amounts_to_json(&self.stx_map),
            "burns": amounts_to_json(&self.burn_map),
            "tokens": tokens,
            "assets": assets,
            "stacking": amounts_to_json(&self.stacking_map),
            "pox": pox,
        })
    }

    /// Records an STX transfer by `principal`.
    pub fn add_stx_transfer(
        &mut self,
        principal: &PrincipalData,
        amount: u128,
    ) -> Result<(), AssetMapError> {
        let next_amount = next_amount(self.stx_map.get(principal), amount)?;
        self.stx_map.insert(principal.clone(), next_amount);
        Ok(())
    }

    /// Records an STX burn by `principal`.
    pub fn add_stx_burn(
        &mut self,
        principal: &PrincipalData,
        amount: u128,
    ) -> Result<(), AssetMapError> {
        let next_amount = next_amount(self.burn_map.get(principal), amount)?;
        self.burn_map.insert(principal.clone(), next_amount);
        Ok(())
    }

    /// Records a non-fungible asset transfer by `principal`.
    pub fn add_asset_transfer(
        &mut self,
        principal: &PrincipalData,
        asset: AssetIdentifier,
        transferred: Value,
    ) {
        self.asset_map
            .entry(principal.clone())
            .or_default()
            .entry(asset)
            .or_default()
            .push(transferred);
    }

    /// Records a fungible token transfer by `principal`.
    pub fn add_token_transfer(
        &mut self,
        principal: &PrincipalData,
        asset: AssetIdentifier,
        amount: u128,
    ) -> Result<(), AssetMapError> {
        let current_amount = self
            .token_map
            .get(principal)
            .and_then(|principal_map| principal_map.get(&asset));
        let next_amount = next_amount(current_amount, amount)?;
        self.token_map
            .entry(principal.clone())
            .or_default()
            .insert(asset, next_amount);
        Ok(())
    }

    /// Records an amount stacked or delegated for stacking by `principal`.
    ///
    /// Before Epoch 4.0, a later entry replaces an earlier entry. Starting in
    /// Epoch 4.0, entries are accumulated.
    pub fn add_stacking(
        &mut self,
        principal: &PrincipalData,
        amount: u128,
        epoch_id: StacksEpochId,
    ) -> Result<(), AssetMapError> {
        match self.stacking_map.entry(principal.clone()) {
            Entry::Occupied(mut occupied_entry) => {
                let amount = if epoch_id.sums_stacking_assetmap() {
                    occupied_entry
                        .get()
                        .checked_add(amount)
                        .ok_or(AssetMapError::AmountOverflow)?
                } else {
                    amount
                };
                occupied_entry.insert(amount);
            }
            Entry::Vacant(vacant_entry) => {
                vacant_entry.insert(amount);
            }
        }
        Ok(())
    }

    /// Records that `principal` attempted a position-altering PoX action.
    ///
    /// This includes `unstake`, `unstake-sbtc`, `update-bond-registration`, and
    /// `announce-l1-early-exit`, and is recorded whether or not the call succeeds.
    pub fn add_pox_action(&mut self, principal: &PrincipalData) {
        self.pox_action_set.insert(principal.clone());
    }

    /// Merges a nested transaction's asset changes into this map atomically.
    ///
    /// Before Epoch 4.0, colliding stacking entries are rejected as a soft-fork
    /// safety check. Starting in Epoch 4.0, their amounts are accumulated.
    pub fn commit_other(
        &mut self,
        mut other: AssetMap,
        epoch_id: StacksEpochId,
    ) -> Result<(), AssetMapError> {
        let mut tokens_to_add = Vec::new();
        let mut stx_to_add = Vec::with_capacity(other.stx_map.len());
        let mut burns_to_add = Vec::with_capacity(other.burn_map.len());
        let mut stacking_to_add = Vec::with_capacity(other.stacking_map.len());

        for (principal, mut principal_map) in other.token_map.drain() {
            for (asset, amount) in principal_map.drain() {
                let current_amount = self
                    .token_map
                    .get(&principal)
                    .and_then(|current| current.get(&asset));
                let amount = next_amount(current_amount, amount)?;
                tokens_to_add.push((principal.clone(), asset, amount));
            }
        }

        for (principal, amount) in other.stx_map.drain() {
            let amount = next_amount(self.stx_map.get(&principal), amount)?;
            stx_to_add.push((principal, amount));
        }

        for (principal, amount) in other.burn_map.drain() {
            let amount = next_amount(self.burn_map.get(&principal), amount)?;
            burns_to_add.push((principal, amount));
        }

        if epoch_id.sums_stacking_assetmap() {
            // Compute all sums before mutating `self`, so an overflow aborts
            // the entire merge and leaves the parent map unchanged.
            for (principal, amount) in other.stacking_map.drain() {
                let amount = next_amount(self.stacking_map.get(&principal), amount)?;
                stacking_to_add.push((principal, amount));
            }
        } else {
            // Preserve the pre-Epoch-4.0 soft-fork behavior: a nested frame
            // cannot overwrite an existing stacking entry.
            if other
                .stacking_map
                .keys()
                .any(|principal| self.stacking_map.contains_key(principal))
            {
                return Err(AssetMapError::StackingEntryConflict);
            }
            stacking_to_add.extend(other.stacking_map.drain());
        }

        // All fallible work is complete, so mutations below cannot leave a partial merge.
        for (principal, principal_map) in other.asset_map.drain() {
            let destination = self.asset_map.entry(principal).or_default();
            for (asset, mut transfers) in principal_map {
                destination.entry(asset).or_default().append(&mut transfers);
            }
        }

        self.stx_map.extend(stx_to_add);
        self.burn_map.extend(burns_to_add);
        self.stacking_map.extend(stacking_to_add);
        for (principal, asset, amount) in tokens_to_add {
            self.token_map
                .entry(principal)
                .or_default()
                .insert(asset, amount);
        }
        self.pox_action_set.extend(other.pox_action_set.drain());
        Ok(())
    }

    /// Converts this map into the table used for transaction post-condition checks.
    ///
    /// Stacking entries and PoX actions are intentionally excluded and are
    /// available through their dedicated accessors.
    pub fn to_table(mut self) -> HashMap<PrincipalData, HashMap<AssetIdentifier, AssetMapEntry>> {
        let mut table: HashMap<PrincipalData, HashMap<AssetIdentifier, AssetMapEntry>> =
            HashMap::with_capacity(self.token_map.len());
        for (principal, principal_map) in self.token_map.drain() {
            let output = table.entry(principal).or_default();
            output.extend(
                principal_map
                    .into_iter()
                    .map(|(asset, amount)| (asset, AssetMapEntry::Token(amount))),
            );
        }
        for (principal, amount) in self.stx_map.drain() {
            table
                .entry(principal)
                .or_default()
                .insert(AssetIdentifier::STX(), AssetMapEntry::STX(amount));
        }
        for (principal, amount) in self.burn_map.drain() {
            table
                .entry(principal)
                .or_default()
                .insert(AssetIdentifier::STX_burned(), AssetMapEntry::Burn(amount));
        }
        for (principal, principal_map) in self.asset_map.drain() {
            let output = table.entry(principal).or_default();
            output.extend(
                principal_map
                    .into_iter()
                    .map(|(asset, values)| (asset, AssetMapEntry::Asset(values))),
            );
        }
        table
    }

    /// Returns the STX transferred by `principal`.
    pub fn get_stx(&self, principal: &PrincipalData) -> Option<u128> {
        self.stx_map.get(principal).copied()
    }

    /// Returns the STX burned by `principal`.
    pub fn get_stx_burned(&self, principal: &PrincipalData) -> Option<u128> {
        self.burn_map.get(principal).copied()
    }

    /// Returns the total STX burned by all principals.
    pub fn get_stx_burned_total(&self) -> Result<u128, AssetMapError> {
        self.burn_map.values().try_fold(0u128, |total, amount| {
            total
                .checked_add(*amount)
                .ok_or(AssetMapError::BurnTotalOverflow)
        })
    }

    /// Returns the fungible tokens transferred for an asset by `principal`.
    pub fn get_fungible_tokens(
        &self,
        principal: &PrincipalData,
        asset_identifier: &AssetIdentifier,
    ) -> Option<u128> {
        self.token_map
            .get(principal)?
            .get(asset_identifier)
            .copied()
    }

    /// Returns all fungible token transfers by `principal`.
    pub fn get_all_fungible_tokens(
        &self,
        principal: &PrincipalData,
    ) -> Option<&HashMap<AssetIdentifier, u128>> {
        self.token_map.get(principal)
    }

    /// Returns the non-fungible values transferred for an asset by `principal`.
    pub fn get_nonfungible_tokens(
        &self,
        principal: &PrincipalData,
        asset_identifier: &AssetIdentifier,
    ) -> Option<&Vec<Value>> {
        self.asset_map.get(principal)?.get(asset_identifier)
    }

    /// Returns all non-fungible asset transfers by `principal`.
    pub fn get_all_nonfungible_tokens(
        &self,
        principal: &PrincipalData,
    ) -> Option<&HashMap<AssetIdentifier, Vec<Value>>> {
        self.asset_map.get(principal)
    }

    /// Returns the STX stacked or delegated for stacking by `principal`.
    pub fn get_stacking(&self, principal: &PrincipalData) -> Option<u128> {
        self.stacking_map.get(principal).copied()
    }

    /// Returns all STX stacking changes by principal.
    pub fn get_all_stacking(&self) -> &HashMap<PrincipalData, u128> {
        &self.stacking_map
    }

    /// Returns whether `principal` attempted a position-altering PoX action.
    pub fn did_pox_action(&self, principal: &PrincipalData) -> bool {
        self.pox_action_set.contains(principal)
    }

    /// Returns all principals that attempted position-altering PoX actions.
    pub fn get_all_pox_actions(&self) -> &HashSet<PrincipalData> {
        &self.pox_action_set
    }
}

impl fmt::Display for AssetMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[")?;
        for (principal, principal_map) in &self.token_map {
            for (asset, amount) in principal_map {
                writeln!(f, "{principal} spent {amount} {asset}")?;
            }
        }
        for (principal, principal_map) in &self.asset_map {
            for (asset, transfer) in principal_map {
                write!(f, "{principal} transferred [")?;
                for value in transfer {
                    write!(f, "{value}, ")?;
                }
                writeln!(f, "] {asset}")?;
            }
        }
        for (principal, amount) in &self.stx_map {
            writeln!(f, "{principal} spent {amount} microSTX")?;
        }
        for (principal, amount) in &self.burn_map {
            writeln!(f, "{principal} burned {amount} microSTX")?;
        }
        write!(f, "]")
    }
}

/// Calculates an accumulated amount without mutating its asset map.
///
/// `AmountOverflow` is unreachable in normal Clarity execution. STX and
/// stacking amounts are bounded by unlocked balances, which are a subset of
/// the liquid STX supply. Fungible-token and balance updates perform checked
/// arithmetic before their effects are recorded. This check remains as a
/// consensus-safety guard for direct callers and nested-map merges.
fn next_amount(current: Option<&u128>, amount: u128) -> Result<u128, AssetMapError> {
    current
        .copied()
        .unwrap_or_default()
        .checked_add(amount)
        .ok_or(AssetMapError::AmountOverflow)
}

#[cfg(feature = "asset-map-json")]
fn amounts_to_json(amounts: &HashMap<PrincipalData, u128>) -> JsonMap<String, JsonValue> {
    amounts
        .iter()
        .map(|(principal, amount)| (principal.to_string(), JsonValue::String(amount.to_string())))
        .collect()
}
