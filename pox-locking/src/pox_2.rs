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

use clarity::boot_util::boot_code_id;
use clarity::vm::contexts::GlobalContext;
use clarity::vm::costs::cost_functions::ClarityCostFunction;
use clarity::vm::costs::runtime_cost;
use clarity::vm::database::{ClarityDatabase, STXBalance};
use clarity::vm::errors::{Error as ClarityError, RuntimeErrorType};
use clarity::vm::events::{STXEventType, STXLockEventData, StacksTransactionEvent};
use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier};
use clarity::vm::{Environment, Value};
use slog::{slog_debug, slog_error};
use stacks_common::{debug, error};

use crate::events::synthesize_pox_event_info;
use crate::LockingError;

/// is a PoX-2 function call read only?
pub fn is_read_only(func_name: &str) -> bool {
    "get-pox-rejection" == func_name
        || "is-pox-active" == func_name
        || "burn-height-to-reward-cycle" == func_name
        || "reward-cycle-to-burn-height" == func_name
        || "current-pox-reward-cycle" == func_name
        || "get-stacker-info" == func_name
        || "get-check-delegation" == func_name
        || "get-reward-set-size" == func_name
        || "next-cycle-rejection-votes" == func_name
        || "get-total-ustx-stacked" == func_name
        || "get-reward-set-pox-address" == func_name
        || "get-stacking-minimum" == func_name
        || "check-pox-addr-version" == func_name
        || "check-pox-addr-hashbytes" == func_name
        || "check-pox-lock-period" == func_name
        || "can-stack-stx" == func_name
        || "minimal-can-stack-stx" == func_name
        || "get-pox-info" == func_name
        || "get-delegation-info" == func_name
        || "get-allowance-contract-callers" == func_name
        || "get-num-reward-set-pox-addresses" == func_name
        || "get-partial-stacked-by-cycle" == func_name
        || "get-total-pox-rejection" == func_name
}

/// Parse the returned value from PoX `stack-stx` and `delegate-stack-stx` functions
///  from pox-2.clar or pox-3.clar into a format more readily digestible in rust.
/// Panics if the supplied value doesn't match the expected tuple structure
pub fn parse_pox_stacking_result(
    result: &Value,
) -> std::result::Result<(PrincipalData, u128, u64), i128> {
    match result
        .clone()
        .expect_result()
        .expect("FATAL: unexpected clarity value")
    {
        Ok(res) => {
            // should have gotten back (ok { stacker: principal, lock-amount: uint, unlock-burn-height: uint .. } .. })))
            let tuple_data = res.expect_tuple().expect("FATAL: unexpected clarity value");
            let stacker = tuple_data
                .get("stacker")
                .expect("FATAL: no 'stacker'")
                .to_owned()
                .expect_principal()
                .expect("FATAL: unexpected clarity value");

            let lock_amount = tuple_data
                .get("lock-amount")
                .expect("FATAL: no 'lock-amount'")
                .to_owned()
                .expect_u128()
                .expect("FATAL: unexpected clarity value");

            let unlock_burn_height = tuple_data
                .get("unlock-burn-height")
                .expect("FATAL: no 'unlock-burn-height'")
                .to_owned()
                .expect_u128()
                .expect("FATAL: unexpected clarity value")
                .try_into()
                .expect("FATAL: 'unlock-burn-height' overflow");

            Ok((stacker, lock_amount, unlock_burn_height))
        }
        Err(e) => Err(e.expect_i128().expect("FATAL: unexpected clarity value")),
    }
}

/// Parse the returned value from PoX2 or PoX3 `stack-extend` and `delegate-stack-extend` functions
///  into a format more readily digestible in rust.
/// Panics if the supplied value doesn't match the expected tuple structure
pub fn parse_pox_extend_result(result: &Value) -> std::result::Result<(PrincipalData, u64), i128> {
    match result
        .clone()
        .expect_result()
        .expect("FATAL: unexpected clarity value")
    {
        Ok(res) => {
            // should have gotten back (ok { stacker: principal, unlock-burn-height: uint .. } .. })
            let tuple_data = res.expect_tuple().expect("FATAL: unexpected clarity value");
            let stacker = tuple_data
                .get("stacker")
                .expect("FATAL: no 'stacker'")
                .to_owned()
                .expect_principal()
                .expect("FATAL: unexpected clarity value");

            let unlock_burn_height = tuple_data
                .get("unlock-burn-height")
                .expect("FATAL: no 'unlock-burn-height'")
                .to_owned()
                .expect_u128()
                .expect("FATAL: unexpected clarity value")
                .try_into()
                .expect("FATAL: 'unlock-burn-height' overflow");

            Ok((stacker, unlock_burn_height))
        }
        // in the error case, the function should have returned `int` error code
        Err(e) => Err(e.expect_i128().expect("FATAL: unexpected clarity value")),
    }
}

/// Parse the returned value from PoX2 or PoX3 `stack-increase` function
///  into a format more readily digestible in rust.
/// Panics if the supplied value doesn't match the expected tuple structure
pub fn parse_pox_increase(result: &Value) -> std::result::Result<(PrincipalData, u128), i128> {
    match result
        .clone()
        .expect_result()
        .expect("FATAL: unexpected clarity value")
    {
        Ok(res) => {
            // should have gotten back (ok { stacker: principal, total-locked: uint .. } .. })
            let tuple_data = res.expect_tuple().expect("FATAL: unexpected clarity value");
            let stacker = tuple_data
                .get("stacker")
                .expect("FATAL: no 'stacker'")
                .to_owned()
                .expect_principal()
                .expect("FATAL: unexpected clarity value");

            let total_locked = tuple_data
                .get("total-locked")
                .expect("FATAL: no 'total-locked'")
                .to_owned()
                .expect_u128()
                .expect("FATAL: unexpected clarity value");

            Ok((stacker, total_locked))
        }
        // in the error case, the function should have returned `int` error code
        Err(e) => Err(e.expect_i128().expect("FATAL: unexpected clarity value")),
    }
}

/////////////////////// PoX-2 /////////////////////////////////

/// Increase a STX lock up for PoX.  Does NOT touch the account nonce.
/// Returns Ok( account snapshot ) when successful
///
/// # Errors
/// - Returns Error::PoxExtendNotLocked if this function was called on an account
///     which isn't locked. This *should* have been checked by the PoX v2 contract,
///     so this should surface in a panic.
pub fn pox_lock_increase_v2(
    db: &mut ClarityDatabase,
    principal: &PrincipalData,
    new_total_locked: u128,
) -> Result<STXBalance, LockingError> {
    assert!(new_total_locked > 0);

    let mut snapshot = db.get_stx_balance_snapshot(principal)?;

    if !snapshot.has_locked_tokens()? {
        return Err(LockingError::PoxExtendNotLocked);
    }

    if !snapshot.is_v2_locked()? {
        return Err(LockingError::PoxIncreaseOnV1);
    }

    let bal = snapshot.canonical_balance_repr()?;
    let total_amount = bal
        .amount_unlocked()
        .checked_add(bal.amount_locked())
        .expect("STX balance overflowed u128");
    if total_amount < new_total_locked {
        return Err(LockingError::PoxInsufficientBalance);
    }

    if bal.amount_locked() > new_total_locked {
        return Err(LockingError::PoxInvalidIncrease);
    }

    snapshot.increase_lock_v2(new_total_locked)?;

    let out_balance = snapshot.canonical_balance_repr()?;

    debug!(
        "PoX v2 lock increased";
        "pox_locked_ustx" => out_balance.amount_locked(),
        "available_ustx" => out_balance.amount_unlocked(),
        "unlock_burn_height" => out_balance.unlock_height(),
        "account" => %principal,
    );

    snapshot.save()?;
    Ok(out_balance)
}

/// Extend a STX lock up for PoX for a time.  Does NOT touch the account nonce.
/// Returns Ok(lock_amount) when successful
///
/// # Errors
/// - Returns Error::PoxExtendNotLocked if this function was called on an account
///     which isn't locked. This *should* have been checked by the PoX v2 contract,
///     so this should surface in a panic.
pub fn pox_lock_extend_v2(
    db: &mut ClarityDatabase,
    principal: &PrincipalData,
    unlock_burn_height: u64,
) -> Result<u128, LockingError> {
    assert!(unlock_burn_height > 0);

    let mut snapshot = db.get_stx_balance_snapshot(principal)?;

    if !snapshot.has_locked_tokens()? {
        return Err(LockingError::PoxExtendNotLocked);
    }

    snapshot.extend_lock_v2(unlock_burn_height)?;

    let amount_locked = snapshot.balance().amount_locked();

    debug!(
        "PoX v2 lock applied";
        "pox_locked_ustx" => amount_locked,
        "available_ustx" => snapshot.balance().amount_unlocked(),
        "unlock_burn_height" => unlock_burn_height,
        "account" => %principal,
    );

    snapshot.save()?;
    Ok(amount_locked)
}

/// Lock up STX for PoX for a time.  Does NOT touch the account nonce.
fn pox_lock_v2(
    db: &mut ClarityDatabase,
    principal: &PrincipalData,
    lock_amount: u128,
    unlock_burn_height: u64,
) -> Result<(), LockingError> {
    assert!(unlock_burn_height > 0);
    assert!(lock_amount > 0);

    let mut snapshot = db.get_stx_balance_snapshot(principal)?;

    if snapshot.has_locked_tokens()? {
        return Err(LockingError::PoxAlreadyLocked);
    }
    if !snapshot.can_transfer(lock_amount)? {
        return Err(LockingError::PoxInsufficientBalance);
    }
    snapshot.lock_tokens_v2(lock_amount, unlock_burn_height)?;

    debug!(
        "PoX v2 lock applied";
        "pox_locked_ustx" => snapshot.balance().amount_locked(),
        "available_ustx" => snapshot.balance().amount_unlocked(),
        "unlock_burn_height" => unlock_burn_height,
        "account" => %principal,
    );

    snapshot.save()?;
    Ok(())
}

/// Handle responses from stack-stx and delegate-stack-stx -- functions that *lock up* STX
#[allow(clippy::needless_return)]
fn handle_stack_lockup_pox_v2(
    global_context: &mut GlobalContext,
    function_name: &str,
    value: &Value,
) -> Result<Option<StacksTransactionEvent>, ClarityError> {
    debug!(
        "Handle special-case contract-call to {:?} {} (which returned {:?})",
        "PoX-2 contract", function_name, value
    );
    // applying a pox lock at this point is equivalent to evaluating a transfer
    runtime_cost(
        ClarityCostFunction::StxTransfer,
        &mut global_context.cost_track,
        1,
    )?;

    let (stacker, locked_amount, unlock_height) = match parse_pox_stacking_result(value) {
        Ok(x) => x,
        Err(_) => {
            // nothing to do -- the function failed
            return Ok(None);
        }
    };

    match pox_lock_v2(
        &mut global_context.database,
        &stacker,
        locked_amount,
        unlock_height,
    ) {
        Ok(_) => {
            let event =
                StacksTransactionEvent::STXEvent(STXEventType::STXLockEvent(STXLockEventData {
                    locked_amount,
                    unlock_height,
                    locked_address: stacker,
                    contract_identifier: boot_code_id("pox-2", global_context.mainnet),
                }));
            return Ok(Some(event));
        }
        Err(LockingError::DefunctPoxContract) => {
            return Err(ClarityError::Runtime(
                RuntimeErrorType::DefunctPoxContract,
                None,
            ));
        }
        Err(LockingError::PoxAlreadyLocked) => {
            // the caller tried to lock tokens into both pox-1 and pox-2
            return Err(ClarityError::Runtime(
                RuntimeErrorType::PoxAlreadyLocked,
                None,
            ));
        }
        Err(e) => {
            panic!(
                "FATAL: failed to lock {} from {} until {}: '{:?}'",
                locked_amount, stacker, unlock_height, &e
            );
        }
    }
}

/// Handle responses from stack-extend and delegate-stack-extend -- functions that *extend
/// already-locked* STX.
#[allow(clippy::needless_return)]
fn handle_stack_lockup_extension_pox_v2(
    global_context: &mut GlobalContext,
    function_name: &str,
    value: &Value,
) -> Result<Option<StacksTransactionEvent>, ClarityError> {
    // in this branch case, the PoX-2 contract has stored the extension information
    //  and performed the extension checks. Now, the VM needs to update the account locks
    //  (because the locks cannot be applied directly from the Clarity code itself)
    // applying a pox lock at this point is equivalent to evaluating a transfer
    debug!(
        "Handle special-case contract-call to {:?} {} (which returned {:?})",
        boot_code_id("pox-2", global_context.mainnet),
        function_name,
        value
    );

    runtime_cost(
        ClarityCostFunction::StxTransfer,
        &mut global_context.cost_track,
        1,
    )?;

    let (stacker, unlock_height) = match parse_pox_extend_result(value) {
        Ok(x) => x,
        Err(_) => {
            // The stack-extend function returned an error: we do not need to apply a lock
            //  in this case, and can just return and let the normal VM codepath surface the
            //  error response type.
            return Ok(None);
        }
    };

    match pox_lock_extend_v2(&mut global_context.database, &stacker, unlock_height) {
        Ok(locked_amount) => {
            let event =
                StacksTransactionEvent::STXEvent(STXEventType::STXLockEvent(STXLockEventData {
                    locked_amount,
                    unlock_height,
                    locked_address: stacker,
                    contract_identifier: boot_code_id("pox-2", global_context.mainnet),
                }));
            return Ok(Some(event));
        }
        Err(LockingError::DefunctPoxContract) => {
            return Err(ClarityError::Runtime(
                RuntimeErrorType::DefunctPoxContract,
                None,
            ));
        }
        Err(e) => {
            // Error results *other* than a DefunctPoxContract panic, because
            //  those errors should have been caught by the PoX contract before
            //  getting to this code path.
            panic!(
                "FATAL: failed to extend lock from {} until {}: '{:?}'",
                stacker, unlock_height, &e
            );
        }
    }
}

/// Handle responses from stack-increase and delegate-stack-increase -- functions that *increase
/// already-locked* STX amounts.
#[allow(clippy::needless_return)]
fn handle_stack_lockup_increase_pox_v2(
    global_context: &mut GlobalContext,
    function_name: &str,
    value: &Value,
) -> Result<Option<StacksTransactionEvent>, ClarityError> {
    // in this branch case, the PoX-2 contract has stored the increase information
    //  and performed the increase checks. Now, the VM needs to update the account locks
    //  (because the locks cannot be applied directly from the Clarity code itself)
    // applying a pox lock at this point is equivalent to evaluating a transfer
    debug!(
        "Handle special-case contract-call";
        "contract" => ?boot_code_id("pox-2", global_context.mainnet),
        "function" => function_name,
        "return-value" => %value,
    );

    runtime_cost(
        ClarityCostFunction::StxTransfer,
        &mut global_context.cost_track,
        1,
    )?;

    let (stacker, total_locked) = match parse_pox_increase(value) {
        Ok(x) => x,
        Err(_) => {
            // Function failed, do nothing.
            return Ok(None);
        }
    };

    match pox_lock_increase_v2(&mut global_context.database, &stacker, total_locked) {
        Ok(new_balance) => {
            let event =
                StacksTransactionEvent::STXEvent(STXEventType::STXLockEvent(STXLockEventData {
                    locked_amount: new_balance.amount_locked(),
                    unlock_height: new_balance.unlock_height(),
                    locked_address: stacker,
                    contract_identifier: boot_code_id("pox-2", global_context.mainnet),
                }));

            return Ok(Some(event));
        }
        Err(LockingError::DefunctPoxContract) => {
            return Err(ClarityError::Runtime(
                RuntimeErrorType::DefunctPoxContract,
                None,
            ));
        }
        Err(e) => {
            // Error results *other* than a DefunctPoxContract panic, because
            //  those errors should have been caught by the PoX contract before
            //  getting to this code path.
            panic!(
                "FATAL: failed to increase lock from {}: '{:?}'",
                stacker, &e
            );
        }
    }
}

/// Handle special cases when calling into the PoX API contract
pub fn handle_contract_call(
    global_context: &mut GlobalContext,
    sender_opt: Option<&PrincipalData>,
    contract_id: &QualifiedContractIdentifier,
    function_name: &str,
    args: &[Value],
    value: &Value,
) -> Result<(), ClarityError> {
    // Generate a synthetic print event for all functions that alter stacking state
    let print_event_opt = if let Value::Response(response) = value {
        if response.committed {
            // method succeeded.  Synthesize event info, but default to no event report if we fail
            // for some reason.
            // Failure to synthesize an event due to a bug is *NOT* an excuse to crash the whole
            // network!  Event capture is not consensus-critical.
            let event_info_opt = match synthesize_pox_event_info(
                global_context,
                contract_id,
                sender_opt,
                function_name,
                args,
                response,
            ) {
                Ok(Some(event_info)) => Some(event_info),
                Ok(None) => None,
                Err(e) => {
                    error!("Failed to synthesize PoX-3 event info: {:?}", &e);
                    None
                }
            };
            if let Some(event_info) = event_info_opt {
                let event_response =
                    Value::okay(event_info).expect("FATAL: failed to construct (ok event-info)");
                let tx_event =
                    Environment::construct_print_transaction_event(contract_id, &event_response);
                Some(tx_event)
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    // Execute function specific logic to complete the lock-up
    let lock_event_opt = if function_name == "stack-stx" || function_name == "delegate-stack-stx" {
        handle_stack_lockup_pox_v2(global_context, function_name, value)?
    } else if function_name == "stack-extend" || function_name == "delegate-stack-extend" {
        handle_stack_lockup_extension_pox_v2(global_context, function_name, value)?
    } else if function_name == "stack-increase" || function_name == "delegate-stack-increase" {
        handle_stack_lockup_increase_pox_v2(global_context, function_name, value)?
    } else {
        None
    };

    // append the lockup event, so it looks as if the print event happened before the lock-up
    if let Some(batch) = global_context.event_batches.last_mut() {
        if let Some(print_event) = print_event_opt {
            batch.events.push(print_event);
        }
        if let Some(lock_event) = lock_event_opt {
            batch.events.push(lock_event);
        }
    }

    Ok(())
}
