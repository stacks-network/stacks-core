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
//! contract-call result against the zero-address published PoX contracts
//! listed in [`PoxVersions`]. For each of those contracts, it
//! checks if the function called requires applying or updating the
//! `STXBalance` struct's locks, and if the function was successfully
//! invoked. If so, it updates the PoX lock.
use clarity::boot_util::boot_code_addr;
use clarity::vm::contexts::GlobalContext;
use clarity::vm::errors::{RuntimeError, VmExecutionError};
use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier, StandardPrincipalData};
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

stacks_common::define_named_enum!(
    /// The PoX contracts, by version. Callers compare versions with `<`, so keep the
    /// variants in version order.
    #[derive(PartialOrd, Ord)]
    PoxVersions {
        Pox1("pox"),
        Pox2("pox-2"),
        Pox3("pox-3"),
        Pox4("pox-4"),
        Pox5("pox-5"),
    }
);

pub const POX_1_NAME: &str = PoxVersions::Pox1.get_name_str();
pub const POX_2_NAME: &str = PoxVersions::Pox2.get_name_str();
pub const POX_3_NAME: &str = PoxVersions::Pox3.get_name_str();
pub const POX_4_NAME: &str = PoxVersions::Pox4.get_name_str();
pub const POX_5_NAME: &str = PoxVersions::Pox5.get_name_str();

/// Whether [`handle_contract_call_special_cases`] can act on a call into `contract`.
/// The node asks without knowing its network, so this accepts the PoX contracts of
/// either one, and the handler ignores the other network's.
pub fn has_contract_call_special_cases(contract: &QualifiedContractIdentifier) -> bool {
    contract.is_boot() && PoxVersions::lookup_by_name(contract.name.as_str()).is_some()
}

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
    // The other network's PoX contracts reach here too (see
    // `has_contract_call_special_cases`), but have no special cases.
    if contract_id.issuer != StandardPrincipalData::from(boot_code_addr(global_context.mainnet)) {
        return Ok(());
    }
    let Some(version) = PoxVersions::lookup_by_name(contract_id.name.as_str()) else {
        return Ok(());
    };
    match version {
        PoxVersions::Pox1 => {
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
            pox_1::handle_contract_call(global_context, sender, function_name, result)
        }
        PoxVersions::Pox2 => {
            if !pox_2::is_read_only(function_name)
                && global_context.epoch_id >= StacksEpochId::Epoch22
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

            pox_2::handle_contract_call(
                global_context,
                sender,
                contract_id,
                function_name,
                args,
                result,
            )
        }
        PoxVersions::Pox3 => {
            if !pox_3::is_read_only(function_name)
                && global_context.epoch_id >= StacksEpochId::Epoch25
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

            pox_3::handle_contract_call(
                global_context,
                sender,
                contract_id,
                function_name,
                args,
                result,
            )
        }
        PoxVersions::Pox4 => {
            if !pox_4::is_read_only(function_name)
                && global_context.epoch_id >= StacksEpochId::Epoch40
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

            pox_4::handle_contract_call(
                global_context,
                sender,
                contract_id,
                function_name,
                args,
                result,
            )
        }
        PoxVersions::Pox5 => pox_5::handle_contract_call(
            global_context,
            sender,
            contract_id,
            function_name,
            args,
            result,
        ),
    }
}

#[cfg(test)]
mod special_cases_tests {
    use clarity::boot_util::boot_code_id;
    use clarity::consts::CHAIN_ID_TESTNET;
    use clarity::vm::contexts::GlobalContext;
    use clarity::vm::costs::LimitedCostTracker;
    use clarity::vm::database::MemoryBackingStore;
    use clarity::vm::errors::{RuntimeError, VmExecutionError};
    use clarity::vm::types::QualifiedContractIdentifier;
    use clarity::vm::Value;
    use rstest::rstest;
    use stacks_common::types::StacksEpochId;

    use crate::{handle_contract_call_special_cases, POX_4_NAME};

    /// The handler acts only on the PoX contracts of the network it runs on. On a
    /// testnet node at Epoch 4.0, `stack-stx` into PoX-4 hits PoX-4's defunct-contract
    /// check, so getting `Ok` for the other contracts shows they were not dispatched.
    #[rstest]
    #[case::this_networks_pox_4(boot_code_id(POX_4_NAME, false), true)]
    #[case::other_networks_pox_4(boot_code_id(POX_4_NAME, true), false)]
    #[case::user_contract_named_like_pox_4(QualifiedContractIdentifier::local(POX_4_NAME).unwrap(), false)]
    fn test_handler_acts_only_on_this_networks_pox(
        #[case] contract: QualifiedContractIdentifier,
        #[case] dispatched: bool,
    ) {
        let mut store = MemoryBackingStore::new();
        let mut db = store.as_clarity_db();
        // The defunct-contract check logs reads that need the stored epoch, not only the
        // context's, to be 4.0.
        db.begin();
        db.set_clarity_epoch_version(StacksEpochId::Epoch40)
            .unwrap();
        db.commit().unwrap();
        let mut global_context = GlobalContext::new(
            false,
            CHAIN_ID_TESTNET,
            db,
            LimitedCostTracker::new_free(),
            StacksEpochId::Epoch40,
        );
        // The VM runs the handler inside the call's nested context.
        global_context.begin();

        let result = handle_contract_call_special_cases(
            &mut global_context,
            None,
            None,
            &contract,
            "stack-stx",
            &[],
            &Value::okay_true(),
        );

        if dispatched {
            assert!(matches!(
                result,
                Err(VmExecutionError::Runtime(
                    RuntimeError::DefunctPoxContract,
                    _
                ))
            ));
        } else {
            assert!(result.is_ok());
        }
    }
}
