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
// Note: PoX-4 uses the same contract-call result parsing routines as PoX-2
use crate::pox_2::{parse_pox_extend_result, parse_pox_increase, parse_pox_stacking_result};
use crate::{LockingError, POX_4_NAME};

/////////////////////// PoX-4 /////////////////////////////////

/// Lock up STX for PoX for a time.  Does NOT touch the account nonce.
pub fn pox_lock_v4(
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
    snapshot.lock_tokens_v4(lock_amount, unlock_burn_height)?;

    debug!(
        "PoX v4 lock applied";
        "pox_locked_ustx" => snapshot.balance().amount_locked(),
        "available_ustx" => snapshot.balance().amount_unlocked(),
        "unlock_burn_height" => unlock_burn_height,
        "account" => %principal,
    );

    snapshot.save()?;
    Ok(())
}

/// Extend a STX lock up for PoX for a time.  Does NOT touch the account nonce.
/// Returns Ok(lock_amount) when successful
///
/// # Errors
/// - Returns Error::PoxExtendNotLocked if this function was called on an account
///     which isn't locked. This *should* have been checked by the PoX v4 contract,
///     so this should surface in a panic.
pub fn pox_lock_extend_v4(
    db: &mut ClarityDatabase,
    principal: &PrincipalData,
    unlock_burn_height: u64,
) -> Result<u128, LockingError> {
    assert!(unlock_burn_height > 0);

    let mut snapshot = db.get_stx_balance_snapshot(principal)?;

    if !snapshot.has_locked_tokens()? {
        return Err(LockingError::PoxExtendNotLocked);
    }

    snapshot.extend_lock_v4(unlock_burn_height)?;

    let amount_locked = snapshot.balance().amount_locked();

    debug!(
        "PoX v4 lock applied";
        "pox_locked_ustx" => amount_locked,
        "available_ustx" => snapshot.balance().amount_unlocked(),
        "unlock_burn_height" => unlock_burn_height,
        "account" => %principal,
    );

    snapshot.save()?;
    Ok(amount_locked)
}

/// Increase a STX lock up for PoX-4.  Does NOT touch the account nonce.
/// Returns Ok( account snapshot ) when successful
///
/// # Errors
/// - Returns Error::PoxExtendNotLocked if this function was called on an account
///     which isn't locked. This *should* have been checked by the PoX v4 contract,
///     so this should surface in a panic.
pub fn pox_lock_increase_v4(
    db: &mut ClarityDatabase,
    principal: &PrincipalData,
    new_total_locked: u128,
) -> Result<STXBalance, LockingError> {
    assert!(new_total_locked > 0);

    let mut snapshot = db.get_stx_balance_snapshot(principal)?;

    if !snapshot.has_locked_tokens()? {
        return Err(LockingError::PoxExtendNotLocked);
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

    snapshot.increase_lock_v4(new_total_locked)?;

    let out_balance = snapshot.canonical_balance_repr()?;

    debug!(
        "PoX v4 lock increased";
        "pox_locked_ustx" => out_balance.amount_locked(),
        "available_ustx" => out_balance.amount_unlocked(),
        "unlock_burn_height" => out_balance.unlock_height(),
        "account" => %principal,
    );

    snapshot.save()?;
    Ok(out_balance)
}

/// Handle responses from stack-stx and delegate-stack-stx in pox-4 -- functions that *lock up* STX
fn handle_stack_lockup_pox_v4(
    global_context: &mut GlobalContext,
    function_name: &str,
    value: &Value,
) -> Result<Option<StacksTransactionEvent>, ClarityError> {
    debug!(
        "Handle special-case contract-call to {:?} {function_name} (which returned {value:?})",
        boot_code_id(POX_4_NAME, global_context.mainnet)
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

    match pox_lock_v4(
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
                    contract_identifier: boot_code_id(POX_4_NAME, global_context.mainnet),
                }));
            Ok(Some(event))
        }
        Err(LockingError::DefunctPoxContract) => Err(ClarityError::Runtime(
            RuntimeErrorType::DefunctPoxContract,
            None,
        )),
        Err(LockingError::PoxAlreadyLocked) => {
            // the caller tried to lock tokens into multiple pox contracts
            Err(ClarityError::Runtime(
                RuntimeErrorType::PoxAlreadyLocked,
                None,
            ))
        }
        Err(e) => {
            panic!(
                "FATAL: failed to lock {locked_amount} from {stacker} until {unlock_height}: '{e:?}'"
            );
        }
    }
}

/// Handle responses from stack-extend and delegate-stack-extend in pox-4 -- functions that *extend
/// already-locked* STX.
fn handle_stack_lockup_extension_pox_v4(
    global_context: &mut GlobalContext,
    function_name: &str,
    value: &Value,
) -> Result<Option<StacksTransactionEvent>, ClarityError> {
    // in this branch case, the PoX-4 contract has stored the extension information
    //  and performed the extension checks. Now, the VM needs to update the account locks
    //  (because the locks cannot be applied directly from the Clarity code itself)
    // applying a pox lock at this point is equivalent to evaluating a transfer
    debug!(
        "Handle special-case contract-call to {:?} {function_name} (which returned {value:?})",
        boot_code_id("pox-4", global_context.mainnet),
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

    match pox_lock_extend_v4(&mut global_context.database, &stacker, unlock_height) {
        Ok(locked_amount) => {
            let event =
                StacksTransactionEvent::STXEvent(STXEventType::STXLockEvent(STXLockEventData {
                    locked_amount,
                    unlock_height,
                    locked_address: stacker,
                    contract_identifier: boot_code_id(POX_4_NAME, global_context.mainnet),
                }));
            Ok(Some(event))
        }
        Err(LockingError::DefunctPoxContract) => Err(ClarityError::Runtime(
            RuntimeErrorType::DefunctPoxContract,
            None,
        )),
        Err(e) => {
            // Error results *other* than a DefunctPoxContract panic, because
            //  those errors should have been caught by the PoX contract before
            //  getting to this code path.
            panic!("FATAL: failed to extend lock from {stacker} until {unlock_height}: '{e:?}'");
        }
    }
}

/// Handle responses from stack-increase and delegate-stack-increase in PoX-4 -- functions
/// that *increase already-locked* STX amounts.
fn handle_stack_lockup_increase_pox_v4(
    global_context: &mut GlobalContext,
    function_name: &str,
    value: &Value,
) -> Result<Option<StacksTransactionEvent>, ClarityError> {
    // in this branch case, the PoX-4 contract has stored the increase information
    //  and performed the increase checks. Now, the VM needs to update the account locks
    //  (because the locks cannot be applied directly from the Clarity code itself)
    // applying a pox lock at this point is equivalent to evaluating a transfer
    debug!(
        "Handle special-case contract-call";
        "contract" => ?boot_code_id("pox-4", global_context.mainnet),
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
            // nothing to do -- function failed
            return Ok(None);
        }
    };
    match pox_lock_increase_v4(&mut global_context.database, &stacker, total_locked) {
        Ok(new_balance) => {
            let event =
                StacksTransactionEvent::STXEvent(STXEventType::STXLockEvent(STXLockEventData {
                    locked_amount: new_balance.amount_locked(),
                    unlock_height: new_balance.unlock_height(),
                    locked_address: stacker,
                    contract_identifier: boot_code_id(POX_4_NAME, global_context.mainnet),
                }));

            Ok(Some(event))
        }
        Err(LockingError::DefunctPoxContract) => Err(ClarityError::Runtime(
            RuntimeErrorType::DefunctPoxContract,
            None,
        )),
        Err(e) => {
            // Error results *other* than a DefunctPoxContract panic, because
            //  those errors should have been caught by the PoX contract before
            //  getting to this code path.
            panic!("FATAL: failed to increase lock from {stacker}: '{e:?}'");
        }
    }
}

/// Handle special cases when calling into the PoX-4 API contract
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
                    error!("Failed to synthesize PoX-4 event info: {e:?}");
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
        handle_stack_lockup_pox_v4(global_context, function_name, value)?
    } else if function_name == "stack-extend" || function_name == "delegate-stack-extend" {
        handle_stack_lockup_extension_pox_v4(global_context, function_name, value)?
    } else if function_name == "stack-increase" || function_name == "delegate-stack-increase" {
        handle_stack_lockup_increase_pox_v4(global_context, function_name, value)?
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
