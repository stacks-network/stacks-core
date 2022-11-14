// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
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

use clarity::vm::costs::cost_functions::ClarityCostFunction;
use clarity::vm::costs::{CostTracker, MemoryConsumer};
use std::cmp;
use std::convert::{TryFrom, TryInto};

use crate::chainstate::stacks::boot::POX_1_NAME;
use crate::chainstate::stacks::boot::POX_2_NAME;
use crate::chainstate::stacks::db::StacksChainState;
use crate::chainstate::stacks::Error as ChainstateError;
use crate::chainstate::stacks::StacksMicroblockHeader;
use crate::util_lib::boot::boot_code_id;
use clarity::vm::contexts::{Environment, GlobalContext};
use clarity::vm::errors::Error;
use clarity::vm::errors::{
    CheckErrors, InterpreterError, InterpreterResult as Result, RuntimeErrorType,
};
use clarity::vm::representations::{ClarityName, SymbolicExpression, SymbolicExpressionType};
use clarity::vm::types::{
    BuffData, OptionalData, PrincipalData, QualifiedContractIdentifier, SequenceData, TupleData,
    TypeSignature, Value,
};

use clarity::vm::events::{STXEventType, STXLockEventData, StacksTransactionEvent};

use stacks_common::util::hash::Hash160;

use crate::vm::costs::runtime_cost;

/// Parse the returned value from PoX `stack-stx` and `delegate-stack-stx` functions
///  from pox-2.clar into a format more readily digestible in rust.
/// Panics if the supplied value doesn't match the expected tuple structure
fn parse_pox_stacking_result(
    result: &Value,
) -> std::result::Result<(PrincipalData, u128, u64), i128> {
    match result.clone().expect_result() {
        Ok(res) => {
            // should have gotten back (ok { stacker: principal, data: { lock-amount: uint, unlock-burn-height: uint .. } .. })))
            let tuple_data = res.expect_tuple();
            let stacker = tuple_data
                .get("stacker")
                .expect(&format!("FATAL: no 'stacker'"))
                .to_owned()
                .expect_principal();

            let inner_data = tuple_data
                .get("data")
                .expect(&format!("FATAL: no 'data'"))
                .to_owned()
                .expect_tuple();

            let lock_amount = inner_data
                .get("lock-amount")
                .expect(&format!("FATAL: no 'lock-amount'"))
                .to_owned()
                .expect_u128();

            let unlock_burn_height = inner_data
                .get("unlock-burn-height")
                .expect(&format!("FATAL: no 'unlock-burn-height'"))
                .to_owned()
                .expect_u128()
                .try_into()
                .expect("FATAL: 'unlock-burn-height' overflow");

            Ok((stacker, lock_amount, unlock_burn_height))
        }
        Err(e) => Err(e.expect_i128()),
    }
}

/// Parse the returned value from PoX `stack-stx` and `delegate-stack-stx` functions
///  from pox.clar into a format more readily digestible in rust.
/// Panics if the supplied value doesn't match the expected tuple structure
fn parse_pox_stacking_result_v1(
    result: &Value,
) -> std::result::Result<(PrincipalData, u128, u64), i128> {
    match result.clone().expect_result() {
        Ok(res) => {
            // should have gotten back (ok (tuple (stacker principal) (lock-amount uint) (unlock-burn-height uint)))
            let tuple_data = res.expect_tuple();
            let stacker = tuple_data
                .get("stacker")
                .expect(&format!("FATAL: no 'stacker'"))
                .to_owned()
                .expect_principal();

            let lock_amount = tuple_data
                .get("lock-amount")
                .expect(&format!("FATAL: no 'lock-amount'"))
                .to_owned()
                .expect_u128();

            let unlock_burn_height = tuple_data
                .get("unlock-burn-height")
                .expect(&format!("FATAL: no 'unlock-burn-height'"))
                .to_owned()
                .expect_u128()
                .try_into()
                .expect("FATAL: 'unlock-burn-height' overflow");

            Ok((stacker, lock_amount, unlock_burn_height))
        }
        Err(e) => Err(e.expect_i128()),
    }
}

/// Parse the returned value from PoX2 `stack-extend` and `delegate-stack-extend` functions
///  into a format more readily digestible in rust.
/// Panics if the supplied value doesn't match the expected tuple structure
fn parse_pox_extend_result(result: &Value) -> std::result::Result<(PrincipalData, u64), i128> {
    match result.clone().expect_result() {
        Ok(res) => {
            // should have gotten back (ok { stacker: principal, data: { unlock-burn-height: uint .. } .. })
            let tuple_data = res.expect_tuple();
            let stacker = tuple_data
                .get("stacker")
                .expect(&format!("FATAL: no 'stacker'"))
                .to_owned()
                .expect_principal();

            let inner_data = tuple_data
                .get("data")
                .expect(&format!("FATAL: no 'data'"))
                .to_owned()
                .expect_tuple();

            let unlock_burn_height = inner_data
                .get("unlock-burn-height")
                .expect(&format!("FATAL: no 'unlock-burn-height'"))
                .to_owned()
                .expect_u128()
                .try_into()
                .expect("FATAL: 'unlock-burn-height' overflow");

            Ok((stacker, unlock_burn_height))
        }
        // in the error case, the function should have returned `int` error code
        Err(e) => Err(e.expect_i128()),
    }
}

/// Parse the returned value from PoX2 `stack-increase` function
///  into a format more readily digestible in rust.
/// Panics if the supplied value doesn't match the expected tuple structure
fn parse_pox_increase(result: &Value) -> std::result::Result<(PrincipalData, u128), i128> {
    match result.clone().expect_result() {
        Ok(res) => {
            // should have gotten back (ok { stacker: principal, data: { total-locked: uint .. } .. })
            let tuple_data = res.expect_tuple();
            let stacker = tuple_data
                .get("stacker")
                .expect(&format!("FATAL: no 'stacker'"))
                .to_owned()
                .expect_principal();

            let inner_data = tuple_data
                .get("data")
                .expect(&format!("FATAL: no 'data'"))
                .to_owned()
                .expect_tuple();

            let total_locked = inner_data
                .get("total-locked")
                .expect(&format!("FATAL: no 'total-locked'"))
                .to_owned()
                .expect_u128();

            Ok((stacker, total_locked))
        }
        // in the error case, the function should have returned `int` error code
        Err(e) => Err(e.expect_i128()),
    }
}

/// Handle special cases when calling into the PoX API contract
fn handle_pox_v1_api_contract_call(
    global_context: &mut GlobalContext,
    _sender_opt: Option<&PrincipalData>,
    function_name: &str,
    value: &Value,
) -> Result<()> {
    if function_name == "stack-stx" || function_name == "delegate-stack-stx" {
        debug!(
            "Handle special-case contract-call to {:?} {} (which returned {:?})",
            boot_code_id(POX_1_NAME, global_context.mainnet),
            function_name,
            value
        );

        // applying a pox lock at this point is equivalent to evaluating a transfer
        runtime_cost(
            ClarityCostFunction::StxTransfer,
            &mut global_context.cost_track,
            1,
        )?;

        match parse_pox_stacking_result_v1(value) {
            Ok((stacker, locked_amount, unlock_height)) => {
                // in most cases, if this fails, then there's a bug in the contract (since it already does
                // the necessary checks), but with v2 introduction, that's no longer true -- if someone
                // locks on PoX v2, and then tries to lock again in PoX v1, that's not captured by the v1
                // contract.
                match StacksChainState::pox_lock_v1(
                    &mut global_context.database,
                    &stacker,
                    locked_amount,
                    unlock_height as u64,
                ) {
                    Ok(_) => {
                        if let Some(batch) = global_context.event_batches.last_mut() {
                            batch.events.push(StacksTransactionEvent::STXEvent(
                                STXEventType::STXLockEvent(STXLockEventData {
                                    locked_amount,
                                    unlock_height,
                                    locked_address: stacker,
                                }),
                            ));
                        }
                    }
                    Err(ChainstateError::DefunctPoxContract) => {
                        return Err(Error::Runtime(RuntimeErrorType::DefunctPoxContract, None))
                    }
                    Err(e) => {
                        panic!(
                            "FATAL: failed to lock {} from {} until {}: '{:?}'",
                            locked_amount, stacker, unlock_height, &e
                        );
                    }
                }

                return Ok(());
            }
            Err(_) => {
                // nothing to do -- the function failed
                return Ok(());
            }
        }
    }
    // nothing to do
    Ok(())
}

/// Handle special cases when calling into the PoX API contract
fn handle_pox_v2_api_contract_call(
    global_context: &mut GlobalContext,
    _sender_opt: Option<&PrincipalData>,
    contract_id: &QualifiedContractIdentifier,
    function_name: &str,
    value: &Value,
) -> Result<()> {
    // First, generate a synthetic print event for all functions that alter stacking state
    if function_name == "stack-stx"
        || function_name == "delegate-stack-stx"
        || function_name == "stack-extend"
        || function_name == "delegate-stack-extend"
        || function_name == "stack-increase"
        || function_name == "delegate-stack-increase"
        || function_name == "stack-aggregation-commit"
    {
        let tx_event = Environment::construct_print_transaction_event(contract_id, value);
        if let Some(batch) = global_context.event_batches.last_mut() {
            batch.events.push(tx_event);
        }
    }

    // Execute function specific logic
    if function_name == "stack-stx" || function_name == "delegate-stack-stx" {
        debug!(
            "Handle special-case contract-call to {:?} {} (which returned {:?})",
            boot_code_id(POX_2_NAME, global_context.mainnet),
            function_name,
            value
        );
        // applying a pox lock at this point is equivalent to evaluating a transfer
        runtime_cost(
            ClarityCostFunction::StxTransfer,
            &mut global_context.cost_track,
            1,
        )?;

        match parse_pox_stacking_result(value) {
            Ok((stacker, locked_amount, unlock_height)) => {
                match StacksChainState::pox_lock_v2(
                    &mut global_context.database,
                    &stacker,
                    locked_amount,
                    unlock_height as u64,
                ) {
                    Ok(_) => {
                        if let Some(batch) = global_context.event_batches.last_mut() {
                            batch.events.push(StacksTransactionEvent::STXEvent(
                                STXEventType::STXLockEvent(STXLockEventData {
                                    locked_amount,
                                    unlock_height,
                                    locked_address: stacker,
                                }),
                            ));
                        }
                    }
                    Err(ChainstateError::DefunctPoxContract) => {
                        return Err(Error::Runtime(RuntimeErrorType::DefunctPoxContract, None))
                    }
                    Err(e) => {
                        panic!(
                            "FATAL: failed to lock {} from {} until {}: '{:?}'",
                            locked_amount, stacker, unlock_height, &e
                        );
                    }
                }

                return Ok(());
            }
            Err(_) => {
                // nothing to do -- the function failed
                return Ok(());
            }
        }
    } else if function_name == "stack-extend" || function_name == "delegate-stack-extend" {
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

        if let Ok((stacker, unlock_height)) = parse_pox_extend_result(value) {
            match StacksChainState::pox_lock_extend_v2(
                &mut global_context.database,
                &stacker,
                unlock_height as u64,
            ) {
                Ok(locked_amount) => {
                    if let Some(batch) = global_context.event_batches.last_mut() {
                        batch.events.push(StacksTransactionEvent::STXEvent(
                            STXEventType::STXLockEvent(STXLockEventData {
                                locked_amount,
                                unlock_height,
                                locked_address: stacker,
                            }),
                        ));
                    }
                }
                Err(ChainstateError::DefunctPoxContract) => {
                    return Err(Error::Runtime(RuntimeErrorType::DefunctPoxContract, None))
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

            return Ok(());
        } else {
            // The stack-extend function returned an error: we do not need to apply a lock
            //  in this case, and can just return and let the normal VM codepath surface the
            //  error response type.
            return Ok(());
        }
    } else if function_name == "stack-increase" || function_name == "delegate-stack-increase" {
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

        if let Ok((stacker, total_locked)) = parse_pox_increase(value) {
            match StacksChainState::pox_lock_increase_v2(
                &mut global_context.database,
                &stacker,
                total_locked,
            ) {
                Ok(new_balance) => {
                    if let Some(batch) = global_context.event_batches.last_mut() {
                        batch.events.push(StacksTransactionEvent::STXEvent(
                            STXEventType::STXLockEvent(STXLockEventData {
                                locked_amount: new_balance.amount_locked(),
                                unlock_height: new_balance.unlock_height(),
                                locked_address: stacker,
                            }),
                        ));
                    }
                }
                Err(ChainstateError::DefunctPoxContract) => {
                    return Err(Error::Runtime(RuntimeErrorType::DefunctPoxContract, None))
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

        return Ok(());
    }
    // nothing to do
    Ok(())
}

/// Is a PoX-1 function read-only?
/// i.e. can we call it without incurring an error?
fn is_pox_v1_read_only(func_name: &str) -> bool {
    func_name == "get-pox-rejection"
        || func_name == "is-pox-active"
        || func_name == "get-stacker-info"
        || func_name == "get-reward-set-size"
        || func_name == "get-total-ustx-stacked"
        || func_name == "get-reward-set-pox-address"
        || func_name == "get-stacking-minimum"
        || func_name == "can-stack-stx"
        || func_name == "minimal-can-stack-stx"
        || func_name == "get-pox-info"
}

/// Handle special cases of contract-calls -- namely, those into PoX that should lock up STX
pub fn handle_contract_call_special_cases(
    global_context: &mut GlobalContext,
    sender: Option<&PrincipalData>,
    _sponsor: Option<&PrincipalData>,
    contract_id: &QualifiedContractIdentifier,
    function_name: &str,
    result: &Value,
) -> Result<()> {
    if *contract_id == boot_code_id(POX_1_NAME, global_context.mainnet) {
        if !is_pox_v1_read_only(function_name)
            && global_context.database.get_v1_unlock_height()
                <= global_context.database.get_current_burnchain_block_height()
        {
            // NOTE: get-pox-info is read-only, so it can call old pox v1 stuff
            warn!("PoX-1 function call attempted on an account after v1 unlock height";
                  "v1_unlock_ht" => global_context.database.get_v1_unlock_height(),
                  "current_burn_ht" => global_context.database.get_current_burnchain_block_height(),
                  "function_name" => function_name,
                  "contract_id" => %contract_id
            );
            return Err(Error::Runtime(RuntimeErrorType::DefunctPoxContract, None));
        }
        return handle_pox_v1_api_contract_call(global_context, sender, function_name, result);
    } else if *contract_id == boot_code_id(POX_2_NAME, global_context.mainnet) {
        return handle_pox_v2_api_contract_call(
            global_context,
            sender,
            contract_id,
            function_name,
            result,
        );
    }

    // TODO: insert more special cases here, as needed
    Ok(())
}
