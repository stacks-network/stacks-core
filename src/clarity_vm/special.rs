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
use clarity::vm::database::STXBalance;
use std::cmp;
use std::convert::{TryFrom, TryInto};

// use crate::chainstate::stacks::address::PoxAddress;
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

use clarity::vm::events::{StackExtendData, STXEventType, STXLockEventData, STXLockOperation, StacksTransactionEvent};

use stacks_common::util::hash::Hash160;
use stacks_common::types::chainstate::PoxAddress;
use stacks_common::types::chainstate::StacksAddress;
use stacks_common::address::AddressHashMode;

use crate::vm::costs::runtime_cost;

/// Parse the returned value from PoX `stack-stx` and `delegate-stack-stx` functions
///  into a format more readily digestible in rust.
/// Panics if the supplied value doesn't match the expected tuple structure
fn parse_pox_stacking_result(
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

// PTODO - PoxAddress type refactor; this is duplicate code 
/// Try to convert a Clarity value representation of the PoX address into a PoxAddress.
/// `value` must be `{ version: (buff 1), hashbytes: (buff 20) }`
pub fn try_from_pox_tuple(mainnet: bool, value: &Value) -> Option<PoxAddress> {
    let tuple_data = match value {
        Value::Tuple(data) => data.clone(),
        _ => {
            return None;
        }
    };

    let hashmode_value = tuple_data.get("version").ok()?.to_owned();

    let hashmode_u8 = match hashmode_value {
        Value::Sequence(SequenceData::Buffer(data)) => {
            if data.data.len() == 1 {
                data.data[0]
            } else {
                return None;
            }
        }
        _ => {
            return None;
        }
    };

    let hashbytes_value = tuple_data.get("hashbytes").ok()?.to_owned();

    let hashbytes_vec = match hashbytes_value {
        Value::Sequence(SequenceData::Buffer(data)) => {
            if data.data.len() == 20 {
                data.data
            } else {
                return None;
            }
        }
        _ => {
            return None;
        }
    };

    let hashmode: AddressHashMode = hashmode_u8.try_into().ok()?;

    let mut hashbytes_20 = [0u8; 20];
    hashbytes_20.copy_from_slice(&hashbytes_vec[0..20]);
    let bytes = Hash160(hashbytes_20);

    let version = if mainnet {
        hashmode.to_version_mainnet()
    } else {
        hashmode.to_version_testnet()
    };

    Some(PoxAddress::Standard(
        StacksAddress { version, bytes },
        Some(hashmode),
    ))
}

/// Parse the returned value from PoX2 `stack-extend` and `delegate-stack-extend` functions
///  into a format more readily digestible in rust.
/// Panics if the supplied value doesn't match the expected tuple structure
fn parse_pox_extend_result(
    function_name: &str, 
    result: &Value, 
    is_mainnet: bool
) -> std::result::Result<(PrincipalData, u64, STXLockOperation), i128> {
    match result.clone().expect_result() {
        Ok(res) => {
            // should have gotten back (ok { stacker: principal, unlock-burn-height: uint,
            //          pox-addr: { version: (buff 1), hashbytes: (buff 20) }, extend-count: uint })
            // for `delegate-stack-extend`, the field `delegator: principal` is also expected in the tuple.
            let tuple_data = res.expect_tuple();
            let stacker = tuple_data
                .get("stacker")
                .expect(&format!("FATAL: no 'stacker'"))
                .to_owned()
                .expect_principal();

            let unlock_burn_height = tuple_data
                .get("unlock-burn-height")
                .expect(&format!("FATAL: no 'unlock-burn-height'"))
                .to_owned()
                .expect_u128()
                .try_into()
                .expect("FATAL: 'unlock-burn-height' overflow");
            
            let extend_count = tuple_data
                .get("extend-count")
                .expect(&format!("FATAL: no 'extend-count'"))
                .to_owned()
                .expect_u128()
                .try_into()
                .expect("FATAL: 'extend-count' overflow");
            
            let pox_addr_val = tuple_data
                .get("pox-addr")
                .expect(&format!("FATAL: no 'pox-addr'"))
                .to_owned();
            let pox_addr = try_from_pox_tuple(is_mainnet, &pox_addr_val)
                .expect("FATAL: 'pox-addr' value had incorrect type"); 
            
            let stack_extend_data = StackExtendData {
                extend_count, 
                pox_addr,
            };

            let op_data = if function_name == "stack-extend" {
                STXLockOperation::StackExtend(stack_extend_data)
            } else if function_name == "delegate-stack-extend" {
                let delegator = tuple_data
                .get("delegator")
                .expect(&format!("FATAL: no 'delegator'"))
                .to_owned()
                .expect_principal();

                STXLockOperation::DelegateStackExtend(stack_extend_data, delegator)
            } else {
                panic!("FATAL: unexpected function type passed to `parse_pox_extend_result`"); 
            }; 
            
            Ok((stacker, unlock_burn_height, op_data))
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
            // should have gotten back (ok { stacker: principal, total-locked: uint })
            let tuple_data = res.expect_tuple();
            let stacker = tuple_data
                .get("stacker")
                .expect(&format!("FATAL: no 'stacker'"))
                .to_owned()
                .expect_principal();

            let total_locked = tuple_data
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

/// Parse the returned value from PoX2 `stack-aggregation-commit` function
///  into a format more readily digestible in rust.
/// Panics if the supplied value doesn't match the expected tuple structure
fn parse_pox_aggregation(result: &Value) -> std::result::Result<PrincipalData, i128> {
    match result.clone().expect_result() {
        Ok(res) => {
            // should have gotten back (ok { stacker: principal })
            // stacker should be type principal
            let tuple_data = res.expect_tuple();
            let stacker = tuple_data
                .get("stacker")
                .expect(&format!("FATAL: no 'stacker'"))
                .to_owned()
                .expect_principal();

            Ok(stacker)
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

        match parse_pox_stacking_result(value) {
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
                    Ok(total_balance) => {
                        if let Some(batch) = global_context.event_batches.last_mut() {
                            batch.events.push(StacksTransactionEvent::STXEvent(
                                STXEventType::STXLockEvent(STXLockEventData {
                                    locked_amount,
                                    unlock_height,
                                    locked_address: stacker,
                                    locked_addr_balance: total_balance,
                                    operation_data: STXLockOperation::Dummy, 
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
    function_name: &str,
    value: &Value,
) -> Result<()> {
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
                    Ok(total_balance) => {
                        if let Some(batch) = global_context.event_batches.last_mut() {
                            batch.events.push(StacksTransactionEvent::STXEvent(
                                STXEventType::STXLockEvent(STXLockEventData {
                                    locked_amount,
                                    unlock_height,
                                    locked_address: stacker,
                                    locked_addr_balance: total_balance, 
                                    operation_data: STXLockOperation::Dummy, 
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

        if let Ok((stacker, unlock_height, operation_data)) = parse_pox_extend_result(function_name, value, global_context.mainnet) {
            match StacksChainState::pox_lock_extend_v2(
                &mut global_context.database,
                &stacker,
                unlock_height as u64,
            ) {
                Ok((locked_amount, total_balance)) => {
                    if let Some(batch) = global_context.event_batches.last_mut() {
                        batch.events.push(StacksTransactionEvent::STXEvent(
                            STXEventType::STXLockEvent(STXLockEventData {
                                locked_amount,
                                unlock_height,
                                locked_address: stacker,
                                locked_addr_balance: total_balance, 
                                operation_data,
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
                    let total_balance = new_balance.amount_locked()
                        .checked_add(new_balance.amount_unlocked())
                        .expect("STX overflow"); 
                    if let Some(batch) = global_context.event_batches.last_mut() {
                        batch.events.push(StacksTransactionEvent::STXEvent(
                            STXEventType::STXLockEvent(STXLockEventData {
                                locked_amount: new_balance.amount_locked(),
                                unlock_height: new_balance.unlock_height(),
                                locked_address: stacker,
                                locked_addr_balance: total_balance, 
                                operation_data: STXLockOperation::Dummy, 
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
        // The stack-increase function returned an error: we do not need to alter a lock
        //  in this case, and can just return and let the normal VM codepath surface the
        //  error response type.
        return Ok(());
    } else if function_name == "stack-aggregation-commit" {
        // For `stack-aggregation-commit`, we don't need to alter any lock state, 
        // but we do want to emit a STXLockEvent 
        if let Ok(stacker) = parse_pox_aggregation(value) {
            let stacker_balance = global_context.database.get_account_stx_balance(&stacker); 
            let total_balance = stacker_balance.amount_locked()
                        .checked_add(stacker_balance.amount_unlocked())
                        .expect("STX overflow"); 
            if let Some(batch) = global_context.event_batches.last_mut() {
                batch.events.push(StacksTransactionEvent::STXEvent(
                    STXEventType::STXLockEvent(STXLockEventData {
                        locked_amount: stacker_balance.amount_locked(),
                        unlock_height: stacker_balance.unlock_height(),
                        locked_address: stacker,
                        locked_addr_balance: total_balance, 
                        operation_data: STXLockOperation::Dummy, 
                    }),
                ));
            }
        }  else {
            return Ok(())
        }
        
    }

    // nothing to do
    Ok(())
}


// PTODO - parse the result 
pub fn generate_event_for_auto_unlock(
    stacker: PrincipalData, 
    stacker_balance: STXBalance, 
    _result: &Value, 
) -> StacksTransactionEvent {
    let total_balance = stacker_balance.amount_locked()
                        .checked_add(stacker_balance.amount_unlocked())
                        .expect("STX overflow"); 
    StacksTransactionEvent::STXEvent(
        STXEventType::STXLockEvent(STXLockEventData {
            locked_amount: stacker_balance.amount_locked(),
            unlock_height: stacker_balance.unlock_height(),
            locked_address: stacker,
            locked_addr_balance: total_balance, 
            operation_data: STXLockOperation::Dummy, 
        }),
    )
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
            warn!("PoX-1 Lock attempted on an account after v1 unlock height";
                  "v1_unlock_ht" => global_context.database.get_v1_unlock_height(),
                  "current_burn_ht" => global_context.database.get_current_burnchain_block_height(),
                  "function_name" => function_name,
                  "contract_id" => %contract_id
            );
            return Err(Error::Runtime(RuntimeErrorType::DefunctPoxContract, None));
        }
        return handle_pox_v1_api_contract_call(global_context, sender, function_name, result);
    } else if *contract_id == boot_code_id(POX_2_NAME, global_context.mainnet) {
        return handle_pox_v2_api_contract_call(global_context, sender, function_name, result);
    }

    // TODO: insert more special cases here, as needed
    Ok(())
}
