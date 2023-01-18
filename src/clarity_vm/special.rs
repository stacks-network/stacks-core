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

use clarity::vm::ast::ASTRules;
use clarity::vm::costs::cost_functions::ClarityCostFunction;
use clarity::vm::costs::{CostTracker, MemoryConsumer};
use clarity::vm::{ast, eval_all};
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
    BuffData, OptionalData, PrincipalData, QualifiedContractIdentifier, ResponseData, SequenceData,
    TupleData, TypeSignature, Value,
};

use clarity::vm::clarity::Error as clarity_interpreter_error;
use clarity::vm::events::{STXEventType, STXLockEventData, StacksTransactionEvent};
use clarity::vm::ClarityVersion;

use crate::chainstate::stacks::address::PoxAddress;
use crate::core::StacksEpochId;
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
            // should have gotten back (ok { stacker: principal, lock-amount: uint, unlock-burn-height: uint .. } .. })))
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
            // should have gotten back (ok { stacker: principal, unlock-burn-height: uint .. } .. })
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
            // should have gotten back (ok { stacker: principal, total-locked: uint .. } .. })
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
                                    contract_identifier: boot_code_id(
                                        "pox",
                                        global_context.mainnet,
                                    ),
                                }),
                            ));
                        }
                    }
                    Err(ChainstateError::DefunctPoxContract) => {
                        return Err(Error::Runtime(RuntimeErrorType::DefunctPoxContract, None))
                    }
                    Err(ChainstateError::PoxAlreadyLocked) => {
                        // the caller tried to lock tokens into both pox-1 and pox-2
                        return Err(Error::Runtime(RuntimeErrorType::PoxAlreadyLocked, None));
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

/// Determine who the stacker is for a given function.
/// - for non-delegate stacking functions, it's tx-sender
/// - for delegate stacking functions, it's the first argument
fn get_stacker(sender: &PrincipalData, function_name: &str, args: &[Value]) -> Value {
    match function_name {
        "stack-stx" | "stack-increase" | "stack-extend" | "delegate-stx" => Value::Principal(sender.clone()),
        _ => args[0].clone(),
    }
}

/// Craft the code snippet to evaluate an event-info for a stack-* or a delegate-stack-* function
fn create_event_info_stack_or_delegate_code(
    sender: &PrincipalData,
    function_name: &str,
    args: &[Value],
) -> String {
    format!(
        r#"
        (let (
            (stacker '{stacker})
            (func-name "{func_name}")
            (stacker-info (stx-account stacker))
            (total-balance (stx-get-balance stacker))
        )
            {{
                ;; Function name
                name: func-name,
                ;; The principal of the stacker
                stacker: stacker,
                ;; The current available balance
                balance: total-balance,
                ;; The amount of locked STX
                locked: (get locked stacker-info),
                ;; The burnchain block height of when the tokens unlock. Zero if no tokens are locked.
                burnchain-unlock-height: (get unlock-height stacker-info),
            }}
        )
        "#,
        stacker = get_stacker(sender, function_name, args),
        func_name = function_name
    )
}

/// Craft the code snippet to evaluate a stack-aggregation-* function
fn create_event_info_aggregation_code(function_name: &str) -> String {
    format!(
        r#"
        (let (
            (stacker-info (stx-account tx-sender))
        )
            {{
                ;; Function name
                name: "{func_name}",
                ;; who called this
                ;; NOTE: these fields are required by downstream clients.
                ;; Even though tx-sender is *not* a stacker, the field is
                ;; called "stacker" and these clients know to treat it as
                ;; the delegator.
                stacker: tx-sender,
                balance: (stx-get-balance tx-sender),
                locked: (get locked stacker-info),
                burnchain-unlock-height: (get unlock-height stacker-info),

            }}
        )
        "#,
        func_name = function_name
    )
}

/// Craft the code snippet to evaluate an event-info for the delegate-stx function
fn create_event_info_delegation_code(
    sender: &PrincipalData,
    function_name: &str,
    args: &[Value],
) -> String {
    format!(
        r#"
        (let (
            (stacker '{stacker})
            (func-name "{func_name}")
            (stacker-info (stx-account stacker))
            (total-balance (stx-get-balance stacker))
        )
            {{
                ;; Function name
                name: func-name,
                ;; The principal of the stacker
                stacker: stacker,
                ;; The current available balance
                balance: total-balance,
                ;; The amount of locked STX
                locked: (get locked stacker-info),
                ;; The burnchain block height of when the tokens unlock. Zero if no tokens are locked.
                burnchain-unlock-height: (get unlock-height stacker-info),
            }}
        )
        "#,
        stacker = get_stacker(sender, function_name, args),
        func_name = function_name
    )
}

/// Craft the code snippet to generate the method-specific `data` payload
fn create_event_info_data_code(function_name: &str, args: &[Value]) -> String {
    match function_name {
        "stack-stx" => {
            format!(
                r#"
                {{
                    data: {{
                        ;; amount of ustx to lock.
                        ;; equal to args[0]
                        lock-amount: {lock_amount},
                        ;; burnchain height when the unlock finishes.
                        ;; derived from args[3]
                        unlock-burn-height: (reward-cycle-to-burn-height (+ (current-pox-reward-cycle) u1 {lock_period})),
                        ;; PoX address tuple.
                        ;; equal to args[1].
                        pox-addr: {pox_addr},
                        ;; start of lock-up.
                        ;; equal to args[2]
                        start-burn-height: {start_burn_height},
                        ;; how long to lock, in burn blocks
                        ;; equal to args[3]
                        lock-period: {lock_period}
                    }}
                }}
                "#,
                lock_amount = &args[0],
                lock_period = &args[3],
                pox_addr = &args[1],
                start_burn_height = &args[2],
            )
        }
        "delegate-stack-stx" => {
            format!(
                r#"
                {{
                    data: {{
                        ;; amount of ustx to lock.
                        ;; equal to args[1]
                        lock-amount: {lock_amount},
                        ;; burnchain height when the unlock finishes.
                        ;; derived from args[4]
                        unlock-burn-height: (reward-cycle-to-burn-height (+ (current-pox-reward-cycle) u1 {lock_period})),
                        ;; PoX address tuple.
                        ;; equal to args[2]
                        pox-addr: {pox_addr},
                        ;; start of lock-up
                        ;; equal to args[3]
                        start-burn-height: {start_burn_height},
                        ;; how long to lock, in burn blocks
                        ;; equal to args[3]
                        lock-period: {lock_period},
                        ;; delegator
                        delegator: tx-sender,
                        ;; stacker
                        ;; equal to args[0]
                        stacker: '{stacker}
                    }}
                }}
                "#,
                stacker = &args[0],
                lock_amount = &args[1],
                pox_addr = &args[2],
                start_burn_height = &args[3],
                lock_period = &args[4],
            )
        }
        "stack-increase" => {
            format!(
                r#"
                {{
                    data: {{
                        ;; amount to increase by
                        ;; equal to args[0]
                        increase-by: {increase_by},
                        ;; new amount locked
                        ;; NOTE: the lock has not yet been applied!
                        ;; derived from args[0]
                        total-locked: (+ {increase_by} (get locked (stx-account tx-sender))),
                        ;; pox addr increased
                        pox-addr: (get pox-addr (unwrap-panic (map-get? stacking-state {{ stacker: tx-sender }})))
                    }}
                }}
                "#,
                increase_by = &args[0]
            )
        }
        "delegate-stack-increase" => {
            format!(
                r#"
                {{
                    data: {{
                        ;; pox addr
                        ;; equal to args[1]
                        pox-addr: {pox_addr},
                        ;; amount to increase by
                        ;; equal to args[2]
                        increase-by: {increase_by},
                        ;; total amount locked now
                        ;; NOTE: the lock itself has not yet been applied!
                        ;; this is for the stacker, so args[0]
                        total-locked: (+ {increase_by} (get locked (stx-account '{stacker}))),
                        ;; delegator
                        delegator: tx-sender,
                        ;; stacker
                        ;; equal to args[0]
                        stacker: '{stacker}
                    }}
                }}
                "#,
                stacker = &args[0],
                pox_addr = &args[1],
                increase_by = &args[2],
            )
        }
        "stack-extend" => {
            format!(
                r#"
                (let (
                    ;; variable declarations derived from pox-2
                    (cur-cycle (current-pox-reward-cycle))
                    (unlock-height (get unlock-height (stx-account tx-sender)))
                    (unlock-in-cycle (burn-height-to-reward-cycle unlock-height))
                    (first-extend-cycle
                        (if (> (+ cur-cycle u1) unlock-in-cycle)
                            (+ cur-cycle u1)
                            unlock-in-cycle))
                    (last-extend-cycle  (- (+ first-extend-cycle {extend_count}) u1))
                    (new-unlock-ht (reward-cycle-to-burn-height (+ u1 last-extend-cycle)))
                )
                {{
                    data: {{
                        ;; pox addr extended
                        ;; equal to args[1]
                        pox-addr: {pox_addr},
                        ;; number of cycles extended
                        ;; equal to args[0]
                        extend-count: {extend_count},
                        ;; new unlock burnchain block height
                        unlock-burn-height: new-unlock-ht
                    }}
                }})
                "#,
                extend_count = &args[0],
                pox_addr = &args[1],
            )
        }
        "delegate-stack-extend" => {
            format!(
                r#"
                (let (
                    (unlock-height (get unlock-height (stx-account '{stacker})))
                    (unlock-in-cycle (burn-height-to-reward-cycle unlock-height))
                    (cur-cycle (current-pox-reward-cycle))
                    (first-extend-cycle
                        (if (> (+ cur-cycle u1) unlock-in-cycle)
                            (+ cur-cycle u1)
                            unlock-in-cycle))
                    (last-extend-cycle  (- (+ first-extend-cycle {extend_count}) u1))
                    (new-unlock-ht (reward-cycle-to-burn-height (+ u1 last-extend-cycle)))
                )
                {{
                    data: {{
                        ;; pox addr extended
                        ;; equal to args[1]
                        pox-addr: {pox_addr},
                        ;; number of cycles extended
                        ;; equal to args[2]
                        extend-count: {extend_count},
                        ;; new unlock burnchain block height
                        unlock-burn-height: new-unlock-ht,
                        ;; delegator locking this up
                        delegator: tx-sender,
                        ;; stacker
                        ;; equal to args[0]
                        stacker: '{stacker}
                    }}
                }})
                "#,
                stacker = &args[0],
                pox_addr = &args[1],
                extend_count = &args[2]
            )
        }
        "stack-aggregation-commit"
        | "stack-aggregation-commit-indexed"
        | "stack-aggregation-increase" => {
            format!(
                r#"
                {{
                    data: {{
                        ;; pox addr locked up
                        ;; equal to args[0] in all methods
                        pox-addr: {pox_addr},
                        ;; reward cycle locked up
                        ;; equal to args[1] in all methods
                        reward-cycle: {reward_cycle},
                        ;; amount locked behind this PoX address by this method
                        amount-ustx: (get stacked-amount
                                        (unwrap-panic (map-get? logged-partial-stacked-by-cycle
                                            {{ pox-addr: {pox_addr}, sender: tx-sender, reward-cycle: {reward_cycle} }}))),
                        ;; delegator (this is the caller)
                        delegator: tx-sender
                    }}
                }}
                "#,
                pox_addr = &args[0],
                reward_cycle = &args[1]
            )
        }
        "delegate-stx" => {
            format!(
                r#"
                {{
                    data: {{
                        ;; amount of ustx to delegate.
                        ;; equal to args[0]
                        amount-ustx: {amount_ustx},
                        ;; address of delegatee.
                        ;; equal to args[1]
                        delegate-to: '{delegate_to},
                        ;; optional burnchain height when the delegation finishes.
                        ;; derived from args[2]
                        unlock-burn-height: {until_burn_height},
                        ;; optional PoX address tuple.
                        ;; equal to args[3].
                        pox-addr: {pox_addr}
                    }}
                }}
                "#,
                amount_ustx = &args[0],
                delegate_to = &args[1],
                until_burn_height = &args[2],
                pox_addr = &args[3],
            )
        },
        _ => format!("{{ data: {{ unimplemented: true }} }}"),
    }
}

/// Synthesize an events data tuple to return on the successful execution of a pox-2 stacking
/// function.  It runs a series of Clarity queries against the PoX contract's data space (including
/// calling PoX functions).
fn synthesize_pox_2_event_info(
    global_context: &mut GlobalContext,
    contract_id: &QualifiedContractIdentifier,
    sender_opt: Option<&PrincipalData>,
    function_name: &str,
    args: &[Value],
) -> std::result::Result<Option<Value>, ChainstateError> {
    let sender = match sender_opt {
        Some(sender) => sender,
        None => {
            return Ok(None);
        }
    };
    let code_snippet_template_opt = match function_name {
        "stack-stx"
        | "delegate-stack-stx"
        | "stack-extend"
        | "delegate-stack-extend"
        | "stack-increase"
        | "delegate-stack-increase" => Some(create_event_info_stack_or_delegate_code(
            sender,
            function_name,
            args,
        )),
        "stack-aggregation-commit"
        | "stack-aggregation-commit-indexed"
        | "stack-aggregation-increase" => Some(create_event_info_aggregation_code(function_name)),
        "delegate-stx" => Some(create_event_info_delegation_code(sender, function_name, args)),
        // use create_event_info_stack_or_delegate_code
        _ => None,
    };

    if let Some(code_snippet) = code_snippet_template_opt {
        let data_snippet = create_event_info_data_code(function_name, args);

        test_debug!("Evaluate snippet:\n{}", &code_snippet);
        test_debug!("Evaluate data code:\n{}", &data_snippet);

        let pox_2_contract = global_context
            .database
            .get_contract(contract_id)
            .expect("FATAL: could not load PoX-2 contract metadata");

        let event_info = global_context
            .special_cc_handler_execute_read_only(
                sender.clone(),
                None,
                pox_2_contract.contract_context,
                |env| {
                    let base_event_info = env
                        .eval_read_only_with_rules(
                            contract_id,
                            &code_snippet,
                            ASTRules::PrecheckSize,
                        )
                        .map_err(|e| {
                            error!(
                                "Failed to run event-info code snippet for '{}': {:?}",
                                function_name, &e
                            );
                            ChainstateError::ClarityError(clarity_interpreter_error::Interpreter(e))
                        })?;

                    let data_event_info = env
                        .eval_read_only_with_rules(
                            contract_id,
                            &data_snippet,
                            ASTRules::PrecheckSize,
                        )
                        .map_err(|e| {
                            error!(
                                "Failed to run data-info code snippet for '{}': {:?}",
                                function_name, &e
                            );
                            ChainstateError::ClarityError(clarity_interpreter_error::Interpreter(e))
                        })?;

                    // merge them
                    let base_event_tuple = base_event_info.expect_tuple();
                    let data_tuple = data_event_info.expect_tuple();
                    let event_tuple = TupleData::shallow_merge(base_event_tuple, data_tuple)
                        .map_err(|e| {
                            error!("Failed to merge data-info and event-info: {:?}", &e);
                            ChainstateError::ClarityError(clarity_interpreter_error::Interpreter(e))
                        })?;

                    Ok(Value::Tuple(event_tuple))
                },
            )
            .map_err(|e: ChainstateError| {
                error!("Failed to synthesize PoX-2 event: {:?}", &e);
                e
            })?;

        test_debug!(
            "Synthesized PoX-2 event info for '{}''s call to '{}': {:?}",
            sender,
            function_name,
            &event_info
        );
        Ok(Some(event_info))
    } else {
        Ok(None)
    }
}

/// Handle responses from stack-stx and delegate-stack-stx -- functions that *lock up* STX
fn handle_stack_lockup(
    global_context: &mut GlobalContext,
    function_name: &str,
    value: &Value,
) -> Result<Option<StacksTransactionEvent>> {
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
                    let event = StacksTransactionEvent::STXEvent(STXEventType::STXLockEvent(
                        STXLockEventData {
                            locked_amount,
                            unlock_height,
                            locked_address: stacker,
                            contract_identifier: boot_code_id("pox-2", global_context.mainnet),
                        },
                    ));
                    return Ok(Some(event));
                }
                Err(ChainstateError::DefunctPoxContract) => {
                    return Err(Error::Runtime(RuntimeErrorType::DefunctPoxContract, None));
                }
                Err(ChainstateError::PoxAlreadyLocked) => {
                    // the caller tried to lock tokens into both pox-1 and pox-2
                    return Err(Error::Runtime(RuntimeErrorType::PoxAlreadyLocked, None));
                }
                Err(e) => {
                    panic!(
                        "FATAL: failed to lock {} from {} until {}: '{:?}'",
                        locked_amount, stacker, unlock_height, &e
                    );
                }
            }
        }
        Err(_) => {
            // nothing to do -- the function failed
            return Ok(None);
        }
    }
}

/// Handle responses from stack-extend and delegate-stack-extend -- functions that *extend
/// already-locked* STX.
fn handle_stack_lockup_extension(
    global_context: &mut GlobalContext,
    function_name: &str,
    value: &Value,
) -> Result<Option<StacksTransactionEvent>> {
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
                let event = StacksTransactionEvent::STXEvent(STXEventType::STXLockEvent(
                    STXLockEventData {
                        locked_amount,
                        unlock_height,
                        locked_address: stacker,
                        contract_identifier: boot_code_id("pox-2", global_context.mainnet),
                    },
                ));
                return Ok(Some(event));
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
    } else {
        // The stack-extend function returned an error: we do not need to apply a lock
        //  in this case, and can just return and let the normal VM codepath surface the
        //  error response type.
        return Ok(None);
    }
}

/// Handle resposnes from stack-increase and delegate-stack-increase -- functions that *increase
/// already-locked* STX amounts.
fn handle_stack_lockup_increase(
    global_context: &mut GlobalContext,
    function_name: &str,
    value: &Value,
) -> Result<Option<StacksTransactionEvent>> {
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
                let event = StacksTransactionEvent::STXEvent(STXEventType::STXLockEvent(
                    STXLockEventData {
                        locked_amount: new_balance.amount_locked(),
                        unlock_height: new_balance.unlock_height(),
                        locked_address: stacker,
                        contract_identifier: boot_code_id("pox-2", global_context.mainnet),
                    },
                ));

                return Ok(Some(event));
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
    } else {
        Ok(None)
    }
}

/// Handle special cases when calling into the PoX API contract
fn handle_pox_v2_api_contract_call(
    global_context: &mut GlobalContext,
    sender_opt: Option<&PrincipalData>,
    contract_id: &QualifiedContractIdentifier,
    function_name: &str,
    args: &[Value],
    value: &Value,
) -> Result<()> {
    // Generate a synthetic print event for all functions that alter stacking state
    let print_event_opt = if let Value::Response(response) = value {
        if response.committed {
            // method succeeded.  Synthesize event info, but default to no event report if we fail
            // for some reason.
            // Failure to synthesize an event due to a bug is *NOT* an excuse to crash the whole
            // network!  Event capture is not consensus-critical.
            let event_info_opt = match synthesize_pox_2_event_info(
                global_context,
                contract_id,
                sender_opt,
                function_name,
                args,
            ) {
                Ok(Some(event_info)) => Some(event_info),
                Ok(None) => None,
                Err(e) => {
                    error!("Failed to synthesize PoX-2 event info: {:?}", &e);
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
        handle_stack_lockup(global_context, function_name, value)?
    } else if function_name == "stack-extend" || function_name == "delegate-stack-extend" {
        handle_stack_lockup_extension(global_context, function_name, value)?
    } else if function_name == "stack-increase" || function_name == "delegate-stack-increase" {
        handle_stack_lockup_increase(global_context, function_name, value)?
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
    args: &Vec<Value>,
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
            args,
            result,
        );
    }

    // TODO: insert more special cases here, as needed
    Ok(())
}
