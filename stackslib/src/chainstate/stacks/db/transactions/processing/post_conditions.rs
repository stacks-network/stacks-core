// Copyright (C) 2026 Stacks Open Internet Foundation
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

//! Post-condition evaluation for Stacks transactions.

use clarity::vm::contexts::AssetMap;
use clarity::vm::types::serialization::SerializationError;

use crate::burnchains::Txid;
use crate::chainstate::stacks::db::StacksAccount;
use crate::chainstate::stacks::events::BoundedErrorString;
use crate::chainstate::stacks::{TransactionPostCondition, TransactionPostConditionMode};
use crate::core::StacksEpochId;

/// Project the node's [`StacksAccount`] onto the origin principal that
/// [`stacks_transactions::check_transaction_postconditions`] needs.
/// Returns `Ok(Some(reason))` if the check fails.
pub fn check(
    post_conditions: &[TransactionPostCondition],
    post_condition_mode: &TransactionPostConditionMode,
    origin_account: &StacksAccount,
    asset_map: &AssetMap,
    epoch_id: StacksEpochId,
    txid: Txid,
) -> Result<Option<BoundedErrorString>, SerializationError> {
    let result = stacks_transactions::check_transaction_postconditions(
        post_conditions,
        post_condition_mode,
        &origin_account.principal,
        asset_map,
        epoch_id,
    )?;
    if let Some(reason) = &result {
        info!("{reason}"; "txid" => %txid);
    }
    Ok(result)
}
