// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2023 Stacks Open Internet Foundation
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

//! Special contract-call handling for updating PoX locks on user
//! accounts.
//!
//! This library provides a contract-call special case handler
//! `crate::handle_contract_call_special_cases()` which matches a
//! contract-call result against zero-address published contracts
//! `pox`, `pox-2`, and `pox-3`. For each of those contracts, it
//! checks if the function called requires applying or updating the
//! `STXBalance` struct's locks, and if the function was successfully
//! invoked. If so, it updates the PoX lock.
use clarity::boot_util::boot_code_id;
use clarity::vm::contexts::GlobalContext;
use clarity::vm::errors::{RuntimeError, VmExecutionError};
use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier};
use clarity::vm::Value;
use stacks_common::types::StacksEpochId;
use stacks_common::warn;

mod events;
mod events_24;
mod pox_1;
mod pox_2;
mod pox_3;
mod pox_4;
mod pox_5;

#[cfg(test)]
mod tests;

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum LockingError {
    /// The contract called was a PoX contract, but the function called was not
    /// read-only, and the current burn height is past the unlock height for
    /// that PoX version.
    DefunctPoxContract,
    /// The staker already has a lock.
    PoxAlreadyLocked,
    /// The staker has an insufficient balance to lock the amount specified.
    PoxInsufficientBalance,
    /// An extend was attempted on an account that is not currently locked.
    PoxExtendNotLocked,
    /// An increase was attempted on an account locked in PoX v1.
    PoxIncreaseOnV1,
    /// The increased amount is less than the currently locked amount.
    PoxInvalidIncrease,
    /// An error occurred in the Clarity VM.
    Clarity(VmExecutionError),
    /// An unstake was attempted on an account that is not currently locked.
    PoxUnstakeNotLocked,
    /// Lock amount was zero. The PoX contract is expected to assert this
    /// before producing the stake/lockup response.
    PoxInvalidLockAmount,
    /// Unlock burn height was zero. The PoX contract is expected to
    /// assert this before producing the stake/lockup response.
    PoxInvalidUnlockHeight,
    /// Adding `amount_locked + amount_unlocked` would overflow `u128`.
    PoxBalanceOverflow,
    /// The response value did not match the expected shape.
    /// The string is a short description of which field was missing or
    /// had the wrong type.
    PoxMalformedResponse(String),
}

impl From<VmExecutionError> for LockingError {
    fn from(e: VmExecutionError) -> LockingError {
        LockingError::Clarity(e)
    }
}

#[cfg(test)]
impl LockingError {
    /// A stable, per-variant code for exact-equality assertions in tests.
    ///
    /// `LockingError` can't `derive(PartialEq)` because its
    /// `Clarity(VmExecutionError)` variant wraps a type that isn't
    /// `PartialEq`, so tests compare error codes rather than the errors
    /// themselves. The code identifies the variant only; wrapped contents (the
    /// `Clarity` error, the `PoxMalformedResponse` message) are not compared.
    pub(crate) fn as_error_code(&self) -> u32 {
        match self {
            LockingError::DefunctPoxContract => 0,
            LockingError::PoxAlreadyLocked => 1,
            LockingError::PoxInsufficientBalance => 2,
            LockingError::PoxExtendNotLocked => 3,
            LockingError::PoxIncreaseOnV1 => 4,
            LockingError::PoxInvalidIncrease => 5,
            LockingError::Clarity(_) => 6,
            LockingError::PoxUnstakeNotLocked => 7,
            LockingError::PoxInvalidLockAmount => 8,
            LockingError::PoxInvalidUnlockHeight => 9,
            LockingError::PoxBalanceOverflow => 10,
            LockingError::PoxMalformedResponse(_) => 11,
        }
    }
}

pub const POX_1_NAME: &str = "pox";
pub const POX_2_NAME: &str = "pox-2";
pub const POX_3_NAME: &str = "pox-3";
pub const POX_4_NAME: &str = "pox-4";
pub const POX_5_NAME: &str = "pox-5";

/// Handle special cases of contract-calls -- namely, those into PoX that should lock up STX
pub fn handle_contract_call_special_cases(
    global_context: &mut GlobalContext,
    sender: Option<&PrincipalData>,
    _sponsor: Option<&PrincipalData>,
    contract_id: &QualifiedContractIdentifier,
    function_name: &str,
    args: &[Value],
    result: &Value,
) -> Result<(), VmExecutionError> {
    if *contract_id == boot_code_id(POX_1_NAME, global_context.mainnet) {
        if !pox_1::is_read_only(function_name)
            && global_context.database.get_v1_unlock_height()
                <= global_context
                    .database
                    .get_current_burnchain_block_height()?
        {
            // NOTE: get-pox-info is read-only, so it can call old pox v1 stuff
            warn!("PoX-1 function call attempted on an account after v1 unlock height";
                  "v1_unlock_ht" => global_context.database.get_v1_unlock_height(),
                  "current_burn_ht" => global_context.database.get_current_burnchain_block_height()?,
                  "function_name" => function_name,
                  "contract_id" => %contract_id
            );
            return Err(VmExecutionError::Runtime(
                RuntimeError::DefunctPoxContract,
                None,
            ));
        }
        return pox_1::handle_contract_call(global_context, sender, function_name, result);
    } else if *contract_id == boot_code_id(POX_2_NAME, global_context.mainnet) {
        if !pox_2::is_read_only(function_name) && global_context.epoch_id >= StacksEpochId::Epoch22
        {
            warn!("PoX-2 function call attempted on an account after Epoch 2.2";
                  "v2_unlock_ht" => global_context.database.get_v2_unlock_height()?,
                  "current_burn_ht" => global_context.database.get_current_burnchain_block_height()?,
                  "function_name" => function_name,
                  "contract_id" => %contract_id
            );
            return Err(VmExecutionError::Runtime(
                RuntimeError::DefunctPoxContract,
                None,
            ));
        }

        return pox_2::handle_contract_call(
            global_context,
            sender,
            contract_id,
            function_name,
            args,
            result,
        );
    } else if *contract_id == boot_code_id(POX_3_NAME, global_context.mainnet) {
        if !pox_3::is_read_only(function_name) && global_context.epoch_id >= StacksEpochId::Epoch25
        {
            warn!("PoX-3 function call attempted on an account after Epoch 2.5";
                  "v3_unlock_ht" => global_context.database.get_v3_unlock_height()?,
                  "current_burn_ht" => global_context.database.get_current_burnchain_block_height()?,
                  "function_name" => function_name,
                  "contract_id" => %contract_id
            );
            return Err(VmExecutionError::Runtime(
                RuntimeError::DefunctPoxContract,
                None,
            ));
        }

        return pox_3::handle_contract_call(
            global_context,
            sender,
            contract_id,
            function_name,
            args,
            result,
        );
    } else if *contract_id == boot_code_id(POX_4_NAME, global_context.mainnet) {
        if !pox_4::is_read_only(function_name) && global_context.epoch_id >= StacksEpochId::Epoch40
        {
            warn!("PoX-4 function call attempted on an account after Epoch 4.0";
                  "v4_unlock_ht" => global_context.database.get_v4_unlock_height()?,
                  "current_burn_ht" => global_context.database.get_current_burnchain_block_height()?,
                  "function_name" => function_name,
                  "contract_id" => %contract_id
            );
            return Err(VmExecutionError::Runtime(
                RuntimeError::DefunctPoxContract,
                None,
            ));
        }

        return pox_4::handle_contract_call(
            global_context,
            sender,
            contract_id,
            function_name,
            args,
            result,
        );
    } else if *contract_id == boot_code_id(POX_5_NAME, global_context.mainnet) {
        return pox_5::handle_contract_call(
            global_context,
            sender,
            contract_id,
            function_name,
            args,
            result,
        );
    }

    Ok(())
}
