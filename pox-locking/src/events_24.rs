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

use clarity::vm::ast::ASTRules;
use clarity::vm::contexts::GlobalContext;
use clarity::vm::errors::Error as ClarityError;
use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier, TupleData};
use clarity::vm::Value;
#[cfg(test)]
use slog::slog_debug;
use slog::slog_error;
#[cfg(test)]
use stacks_common::debug;
use stacks_common::{error, test_debug};

/// Determine who the stacker is for a given function.
/// - for non-delegate stacking functions, it's tx-sender
/// - for delegate stacking functions, it's the first argument
fn get_stacker(sender: &PrincipalData, function_name: &str, args: &[Value]) -> Value {
    match function_name {
        "stack-stx" | "stack-increase" | "stack-extend" | "delegate-stx" => {
            Value::Principal(sender.clone())
        }
        _ => args[0].clone(),
    }
}

/// Craft the code snippet to evaluate an event-info for a stack-* function,
/// a delegate-stack-* function, or for delegate-stx
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
        }
        _ => "{{ data: {{ unimplemented: true }} }}".into(),
    }
}

/// Synthesize an events data tuple to return on the successful execution of a pox-2 or pox-3 stacking
/// function.  It runs a series of Clarity queries against the PoX contract's data space (including
/// calling PoX functions).
pub fn synthesize_pox_2_or_3_event_info(
    global_context: &mut GlobalContext,
    contract_id: &QualifiedContractIdentifier,
    sender_opt: Option<&PrincipalData>,
    function_name: &str,
    args: &[Value],
) -> Result<Option<Value>, ClarityError> {
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
        | "delegate-stack-increase"
        | "delegate-stx" => Some(create_event_info_stack_or_delegate_code(
            sender,
            function_name,
            args,
        )),
        "stack-aggregation-commit"
        | "stack-aggregation-commit-indexed"
        | "stack-aggregation-increase" => Some(create_event_info_aggregation_code(function_name)),
        _ => None,
    };
    let code_snippet = match code_snippet_template_opt {
        Some(x) => x,
        None => return Ok(None),
    };

    let data_snippet = create_event_info_data_code(function_name, args);

    test_debug!("Evaluate snippet:\n{}", &code_snippet);
    test_debug!("Evaluate data code:\n{}", &data_snippet);

    let pox_2_contract = global_context.database.get_contract(contract_id)?;

    let event_info = global_context
        .special_cc_handler_execute_read_only(
            sender.clone(),
            None,
            pox_2_contract.contract_context,
            |env| {
                let base_event_info = env
                    .eval_read_only_with_rules(contract_id, &code_snippet, ASTRules::PrecheckSize)
                    .map_err(|e| {
                        error!(
                            "Failed to run event-info code snippet for '{}': {:?}",
                            function_name, &e
                        );
                        e
                    })?;

                let data_event_info = env
                    .eval_read_only_with_rules(contract_id, &data_snippet, ASTRules::PrecheckSize)
                    .map_err(|e| {
                        error!(
                            "Failed to run data-info code snippet for '{}': {:?}",
                            function_name, &e
                        );
                        e
                    })?;

                // merge them
                let base_event_tuple = base_event_info
                    .expect_tuple()
                    .expect("FATAL: unexpected clarity value");
                let data_tuple = data_event_info
                    .expect_tuple()
                    .expect("FATAL: unexpected clarity value");
                let event_tuple =
                    TupleData::shallow_merge(base_event_tuple, data_tuple).map_err(|e| {
                        error!("Failed to merge data-info and event-info: {:?}", &e);
                        e
                    })?;

                Ok(Value::Tuple(event_tuple))
            },
        )
        .map_err(|e: ClarityError| {
            error!("Failed to synthesize PoX event: {:?}", &e);
            e
        })?;

    test_debug!(
        "Synthesized PoX event info for '{}''s call to '{}': {:?}",
        sender,
        function_name,
        &event_info
    );
    Ok(Some(event_info))
}
