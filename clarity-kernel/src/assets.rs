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

//! Transaction-scoped asset accounting: the [`AssetMap`] tracks which assets
//! moved (and from whom) during a transaction. It is the data consumed by
//! Stacks post-condition checks, and it crosses the engine ABI, so it lives
//! in the kernel.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::fmt;

use clarity_types::Value;
use clarity_types::types::{AssetIdentifier, PrincipalData};
use serde_json::json;
use stacks_common::types::StacksEpochId;

use crate::errors::{RuntimeCheckErrorKind, RuntimeError, VmExecutionError, VmInternalError};

#[derive(Debug, PartialEq, Eq)]
pub enum AssetMapEntry {
    STX(u128),
    Burn(u128),
    Token(u128),
    Asset(Vec<Value>),
    Stacking(u128),
}

/**
The AssetMap is used to track which assets have been transferred from whom
during the execution of a transaction.
*/
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetMap {
    /// Sum of all STX transfers by principal
    stx_map: HashMap<PrincipalData, u128>,
    /// Sum of all STX burns by principal
    burn_map: HashMap<PrincipalData, u128>,
    /// Sum of FT transfers by principal, by asset identifier
    token_map: HashMap<PrincipalData, HashMap<AssetIdentifier, u128>>,
    /// NFT transfers by principal, by asset identifier
    asset_map: HashMap<PrincipalData, HashMap<AssetIdentifier, Vec<Value>>>,
    /// Amount of STX stacked or delegated for stacking by principal
    stacking_map: HashMap<PrincipalData, u128>,
    /// Principals that attempted a position-altering PoX action (`unstake`,
    /// `unstake-sbtc`, `update-bond-registration`, `announce-l1-early-exit`)
    /// during the transaction -- recorded whether or not the call succeeded, so
    /// a `Pox` post-condition / `with-pox` allowance can gate even a failed
    /// attempt.
    pox_action_set: HashSet<PrincipalData>,
}

impl AssetMap {
    pub fn to_json(&self) -> serde_json::Value {
        let stx: serde_json::map::Map<_, _> = self
            .stx_map
            .iter()
            .map(|(principal, amount)| {
                (
                    format!("{principal}"),
                    serde_json::value::Value::String(format!("{amount}")),
                )
            })
            .collect();

        let burns: serde_json::map::Map<_, _> = self
            .burn_map
            .iter()
            .map(|(principal, amount)| {
                (
                    format!("{principal}"),
                    serde_json::value::Value::String(format!("{amount}")),
                )
            })
            .collect();

        let tokens: serde_json::map::Map<_, _> = self
            .token_map
            .iter()
            .map(|(principal, token_map)| {
                let token_json: serde_json::map::Map<_, _> = token_map
                    .iter()
                    .map(|(asset_id, amount)| {
                        (
                            format!("{asset_id}"),
                            serde_json::value::Value::String(format!("{amount}")),
                        )
                    })
                    .collect();

                (
                    format!("{principal}"),
                    serde_json::value::Value::Object(token_json),
                )
            })
            .collect();

        let assets: serde_json::map::Map<_, _> = self
            .asset_map
            .iter()
            .map(|(principal, nft_map)| {
                let nft_json: serde_json::map::Map<_, _> = nft_map
                    .iter()
                    .map(|(asset_id, nft_values)| {
                        let nft_array = nft_values
                            .iter()
                            .map(|nft_value| {
                                serde_json::value::Value::String(format!("{nft_value}"))
                            })
                            .collect();

                        (
                            format!("{asset_id}"),
                            serde_json::value::Value::Array(nft_array),
                        )
                    })
                    .collect();

                (
                    format!("{principal}"),
                    serde_json::value::Value::Object(nft_json),
                )
            })
            .collect();

        let stacking: serde_json::map::Map<_, _> = self
            .stacking_map
            .iter()
            .map(|(principal, amount)| {
                (
                    format!("{principal}"),
                    serde_json::value::Value::String(format!("{amount}")),
                )
            })
            .collect();

        let pox: Vec<serde_json::value::Value> = self
            .pox_action_set
            .iter()
            .map(|principal| serde_json::value::Value::String(format!("{principal}")))
            .collect();

        json!({
            "stx": stx,
            "burns": burns,
            "tokens": tokens,
            "assets": assets,
            "stacking": stacking,
            "pox": pox,
        })
    }
}

impl Default for AssetMap {
    fn default() -> Self {
        Self::new()
    }
}

impl AssetMap {
    pub fn new() -> AssetMap {
        AssetMap {
            stx_map: HashMap::new(),
            burn_map: HashMap::new(),
            token_map: HashMap::new(),
            asset_map: HashMap::new(),
            stacking_map: HashMap::new(),
            pox_action_set: HashSet::new(),
        }
    }

    /// This will get the next amount for a (principal, stx) entry in the stx table.
    fn get_next_stx_amount(
        &self,
        principal: &PrincipalData,
        amount: u128,
    ) -> Result<u128, VmExecutionError> {
        // `ArithmeticOverflow` in this function is **unreachable** in normal Clarity execution because:
        // - Every `stx-transfer?` or `stx-burn?` is validated against the sender’s
        //   **unlocked balance** before being queued in `AssetMap`.
        // - The unlocked balance is a subset of `stx-liquid-supply`.
        // - All balance updates in Clarity use the `+` operator **before** logging to `AssetMap`.
        // - `+` performs `checked_add` and returns `RuntimeError::ArithmeticOverflow` **first**.
        let current_amount = self.stx_map.get(principal).unwrap_or(&0);
        current_amount
            .checked_add(amount)
            .ok_or(RuntimeError::ArithmeticOverflow.into())
    }

    /// This will get the next amount for a (principal, stx) entry in the burn table.
    fn get_next_stx_burn_amount(
        &self,
        principal: &PrincipalData,
        amount: u128,
    ) -> Result<u128, VmExecutionError> {
        // `ArithmeticOverflow` in this function is **unreachable** in normal Clarity execution because:
        // - Every `stx-burn?` is validated against the sender’s **unlocked balance** first.
        // - Unlocked balance is a subset of `stx-liquid-supply`, which is <= `u128::MAX`.
        // - All balance updates in Clarity use the `+` operator **before** logging to `AssetMap`.
        // - `+` performs `checked_add` and returns `RuntimeError::ArithmeticOverflow` **first**.
        let current_amount = self.burn_map.get(principal).unwrap_or(&0);
        current_amount
            .checked_add(amount)
            .ok_or(RuntimeError::ArithmeticOverflow.into())
    }

    /// This will get the next amount for a (principal, stx) entry in the
    /// stacking table. Used in Epoch 4.0+ (PoX-5), where multiple stacking
    /// entries for the same principal in one transaction are summed rather
    /// than rejected. Overflow returns `ArithmeticOverflow`; it is unreachable
    /// in normal execution because every stacked amount is bounded by the
    /// principal's balance, which is a subset of `stx-liquid-supply`.
    fn get_next_stacking_amount(
        &self,
        principal: &PrincipalData,
        amount: u128,
    ) -> Result<u128, VmExecutionError> {
        let current_amount = self.stacking_map.get(principal).unwrap_or(&0);
        current_amount
            .checked_add(amount)
            .ok_or(RuntimeError::ArithmeticOverflow.into())
    }

    /// This will get the next amount for a (principal, asset) entry in the asset table.
    fn get_next_amount(
        &self,
        principal: &PrincipalData,
        asset: &AssetIdentifier,
        amount: u128,
    ) -> Result<u128, VmExecutionError> {
        // `ArithmeticOverflow` in this function is **unreachable** in normal Clarity execution because:
        // - The inner transaction must have **partially succeeded** to log any assets.
        // - All balance updates in Clarity use the `+` operator **before** logging to `AssetMap`.
        // - `+` performs `checked_add` and returns `RuntimeError::ArithmeticOverflow` **first**.
        let current_amount = self
            .token_map
            .get(principal)
            .and_then(|x| x.get(asset))
            .unwrap_or(&0);
        current_amount
            .checked_add(amount)
            .ok_or(RuntimeError::ArithmeticOverflow.into())
    }

    pub fn add_stx_transfer(
        &mut self,
        principal: &PrincipalData,
        amount: u128,
    ) -> Result<(), VmExecutionError> {
        let next_amount = self.get_next_stx_amount(principal, amount)?;
        self.stx_map.insert(principal.clone(), next_amount);

        Ok(())
    }

    pub fn add_stx_burn(
        &mut self,
        principal: &PrincipalData,
        amount: u128,
    ) -> Result<(), VmExecutionError> {
        let next_amount = self.get_next_stx_burn_amount(principal, amount)?;
        self.burn_map.insert(principal.clone(), next_amount);

        Ok(())
    }

    pub fn add_asset_transfer(
        &mut self,
        principal: &PrincipalData,
        asset: AssetIdentifier,
        transferred: Value,
    ) {
        let principal_map = self.asset_map.entry(principal.clone()).or_default();

        if let Some(map_entry) = principal_map.get_mut(&asset) {
            map_entry.push(transferred);
        } else {
            principal_map.insert(asset, vec![transferred]);
        }
    }

    pub fn add_token_transfer(
        &mut self,
        principal: &PrincipalData,
        asset: AssetIdentifier,
        amount: u128,
    ) -> Result<(), VmExecutionError> {
        let next_amount = self.get_next_amount(principal, &asset, amount)?;

        let principal_map = self.token_map.entry(principal.clone()).or_default();
        principal_map.insert(asset, next_amount);

        Ok(())
    }

    /// Add stacking entry for `principal` of `amount`.  The EpochId
    /// controls whether or not an existing entry is replaced or
    /// accumulated.
    pub fn add_stacking(
        &mut self,
        principal: &PrincipalData,
        amount: u128,
        epoch_id: StacksEpochId,
    ) -> Result<(), VmExecutionError> {
        match self.stacking_map.entry(principal.clone()) {
            Entry::Occupied(mut occupied_entry) => {
                let next_amt = if epoch_id.sums_stacking_assetmap() {
                    occupied_entry
                        .get()
                        .checked_add(amount)
                        .ok_or(RuntimeError::ArithmeticOverflow)?
                } else {
                    amount
                };
                occupied_entry.insert(next_amt);
            }
            Entry::Vacant(vacant_entry) => {
                vacant_entry.insert(amount);
            }
        };
        Ok(())
    }

    /// Record that a principal attempted a position-altering PoX action
    /// (`unstake`, `unstake-sbtc`, `update-bond-registration`,
    /// `announce-l1-early-exit`) during the transaction. Recorded whether or
    /// not the call succeeded.
    pub fn add_pox_action(&mut self, principal: &PrincipalData) {
        self.pox_action_set.insert(principal.clone());
    }

    // This will add any asset transfer data from other to self,
    //   aborting _all_ changes in the event of an error, leaving self unchanged
    //
    // `epoch_id` selects how concurrent stacking entries for the same principal
    // are handled (see the stacking-merge block below): pre-Epoch-4.0, a second
    // entry is rejected (`PoxStxAssetMapOverwrite`, a soft-fork safety net);
    // Epoch-4.0+ (PoX-5) sums the amounts.
    pub fn commit_other(
        &mut self,
        mut other: AssetMap,
        epoch_id: StacksEpochId,
    ) -> Result<(), VmExecutionError> {
        let mut to_add = Vec::new();
        let mut stx_to_add = Vec::with_capacity(other.stx_map.len());
        let mut stx_burn_to_add = Vec::with_capacity(other.burn_map.len());
        let mut stacking_to_add = Vec::with_capacity(other.stacking_map.len());

        for (principal, mut principal_map) in other.token_map.drain() {
            for (asset, amount) in principal_map.drain() {
                let next_amount = self.get_next_amount(&principal, &asset, amount)?;
                to_add.push((principal.clone(), asset, next_amount));
            }
        }

        for (principal, stx_amount) in other.stx_map.drain() {
            let next_amount = self.get_next_stx_amount(&principal, stx_amount)?;
            stx_to_add.push((principal.clone(), next_amount));
        }

        for (principal, stx_burn_amount) in other.burn_map.drain() {
            let next_amount = self.get_next_stx_burn_amount(&principal, stx_burn_amount)?;
            stx_burn_to_add.push((principal.clone(), next_amount));
        }

        if epoch_id.sums_stacking_assetmap() {
            // Epoch 4.0+ (PoX-5): sum a principal's stacking entries, mirroring
            // how STX transfers/burns accumulate. Computed before any mutation
            // so an overflow aborts the whole merge with `self` unchanged.
            for (principal, stacking_amount) in other.stacking_map.drain() {
                let next_amount = self.get_next_stacking_amount(&principal, stacking_amount)?;
                stacking_to_add.push((principal, next_amount));
            }
        } else {
            // Pre-Epoch-4.0 soft-fork behavior: reject any transaction that
            // would overwrite an existing asset-map stacking entry.
            for principal in other.stacking_map.keys() {
                if self.stacking_map.contains_key(principal) {
                    return Err(VmExecutionError::from(
                        RuntimeCheckErrorKind::PoxStxAssetMapOverwrite,
                    ));
                }
            }
            // No collision is possible, so each entry carries its own amount.
            for (principal, stacking_amount) in other.stacking_map.drain() {
                stacking_to_add.push((principal, stacking_amount));
            }
        }

        // After this point, this function will not fail.
        for (principal, mut principal_map) in other.asset_map.drain() {
            for (asset, mut transfers) in principal_map.drain() {
                let landing_map = self.asset_map.entry(principal.clone()).or_default();
                if let Some(landing_vec) = landing_map.get_mut(&asset) {
                    landing_vec.append(&mut transfers);
                } else {
                    landing_map.insert(asset, transfers);
                }
            }
        }

        for (principal, stx_amount) in stx_to_add.into_iter() {
            self.stx_map.insert(principal, stx_amount);
        }

        for (principal, stx_burn_amount) in stx_burn_to_add.into_iter() {
            self.burn_map.insert(principal, stx_burn_amount);
        }

        for (principal, asset, amount) in to_add.into_iter() {
            let principal_map = self.token_map.entry(principal).or_default();
            principal_map.insert(asset, amount);
        }

        for (principal, stacking_amount) in stacking_to_add.into_iter() {
            self.stacking_map.insert(principal, stacking_amount);
        }

        for principal in other.pox_action_set.drain() {
            self.pox_action_set.insert(principal);
        }

        Ok(())
    }

    pub fn to_table(mut self) -> HashMap<PrincipalData, HashMap<AssetIdentifier, AssetMapEntry>> {
        let mut map = HashMap::with_capacity(self.token_map.len());
        for (principal, mut principal_map) in self.token_map.drain() {
            let mut output_map = HashMap::with_capacity(principal_map.len());
            for (asset, amount) in principal_map.drain() {
                output_map.insert(asset, AssetMapEntry::Token(amount));
            }
            map.insert(principal, output_map);
        }

        for (principal, stx_amount) in self.stx_map.drain() {
            let output_map = map.entry(principal.clone()).or_default();
            output_map.insert(AssetIdentifier::STX(), AssetMapEntry::STX(stx_amount));
        }

        for (principal, stx_burned_amount) in self.burn_map.drain() {
            let output_map = map.entry(principal.clone()).or_default();
            output_map.insert(
                AssetIdentifier::STX_burned(),
                AssetMapEntry::Burn(stx_burned_amount),
            );
        }

        for (principal, mut principal_map) in self.asset_map.drain() {
            let output_map = map.entry(principal.clone()).or_default();
            for (asset, transfers) in principal_map.drain() {
                output_map.insert(asset, AssetMapEntry::Asset(transfers));
            }
        }

        map
    }

    pub fn get_stx(&self, principal: &PrincipalData) -> Option<u128> {
        self.stx_map.get(principal).copied()
    }

    pub fn get_stx_burned(&self, principal: &PrincipalData) -> Option<u128> {
        self.burn_map.get(principal).copied()
    }

    pub fn get_stx_burned_total(&self) -> Result<u128, VmExecutionError> {
        let mut total: u128 = 0;
        for principal in self.burn_map.keys() {
            total = total
                .checked_add(*self.burn_map.get(principal).unwrap_or(&0u128))
                .ok_or_else(|| VmInternalError::Expect("BURN OVERFLOW".into()))?;
        }
        Ok(total)
    }

    pub fn get_fungible_tokens(
        &self,
        principal: &PrincipalData,
        asset_identifier: &AssetIdentifier,
    ) -> Option<u128> {
        let assets = self.token_map.get(principal)?;
        assets.get(asset_identifier).copied()
    }

    pub fn get_all_fungible_tokens(
        &self,
        principal: &PrincipalData,
    ) -> Option<&HashMap<AssetIdentifier, u128>> {
        let assets = self.token_map.get(principal)?;
        Some(assets)
    }

    pub fn get_nonfungible_tokens(
        &self,
        principal: &PrincipalData,
        asset_identifier: &AssetIdentifier,
    ) -> Option<&Vec<Value>> {
        let assets = self.asset_map.get(principal)?;
        assets.get(asset_identifier)
    }

    pub fn get_all_nonfungible_tokens(
        &self,
        principal: &PrincipalData,
    ) -> Option<&HashMap<AssetIdentifier, Vec<Value>>> {
        let assets = self.asset_map.get(principal)?;
        Some(assets)
    }

    pub fn get_stacking(&self, principal: &PrincipalData) -> Option<u128> {
        self.stacking_map.get(principal).copied()
    }

    /// Returns the full map of STX stacked (locked for PoX) by each principal
    /// during the transaction. Used to enforce transaction-level `Staking`
    /// post-conditions, since the stacking map is intentionally excluded from
    /// `to_table`.
    pub fn get_all_stacking(&self) -> &HashMap<PrincipalData, u128> {
        &self.stacking_map
    }

    pub fn did_pox_action(&self, principal: &PrincipalData) -> bool {
        self.pox_action_set.contains(principal)
    }

    /// Returns the set of principals that performed a position-altering PoX
    /// action during the transaction. Used to enforce transaction-level `Pox`
    /// post-conditions; like the stacking map it is intentionally excluded from
    /// `to_table`.
    pub fn get_all_pox_actions(&self) -> &HashSet<PrincipalData> {
        &self.pox_action_set
    }
}

impl fmt::Display for AssetMap {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[")?;
        for (principal, principal_map) in self.token_map.iter() {
            for (asset, amount) in principal_map.iter() {
                writeln!(f, "{principal} spent {amount} {asset}")?;
            }
        }
        for (principal, principal_map) in self.asset_map.iter() {
            for (asset, transfer) in principal_map.iter() {
                write!(f, "{principal} transferred [")?;
                for t in transfer {
                    write!(f, "{t}, ")?;
                }
                writeln!(f, "] {asset}")?;
            }
        }
        for (principal, stx_amount) in self.stx_map.iter() {
            writeln!(f, "{principal} spent {stx_amount} microSTX")?;
        }
        for (principal, stx_burn_amount) in self.burn_map.iter() {
            writeln!(f, "{principal} burned {stx_burn_amount} microSTX")?;
        }
        write!(f, "]")
    }
}
