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
use clarity::vm::costs::LimitedCostTracker;
use clarity::vm::errors::Error as ClarityError;
use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier, ResponseData, TupleData};
use clarity::vm::Value;
#[cfg(test)]
use slog::slog_debug;
use slog::slog_error;
#[cfg(test)]
use stacks_common::debug;
use stacks_common::types::StacksEpochId;
use stacks_common::{error, test_debug};

use crate::events_24;

/// Determine who the stacker is for a given function.
/// - for non-delegate stacking functions, it's tx-sender
/// - for delegate stacking functions, it's the first argument
fn get_stacker(sender: &PrincipalData, function_name: &str, args: &[Value]) -> Value {
    match function_name {
        "stack-stx"
        | "stack-increase"
        | "stack-extend"
        | "delegate-stx"
        | "revoke-delegate-stx" => Value::Principal(sender.clone()),
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
fn create_event_info_data_code(
    function_name: &str,
    args: &[Value],
    response: &ResponseData,
) -> String {
    // If a given burn block height is in a prepare phase, then the stacker will be in the _next_ reward cycle, so bump the cycle by 1
    // `prepare_offset` is 1 or 0, depending on whether current execution is in a prepare phase or not
    //
    // "is-in-next-pox-set" == effective-height <= (reward-length - prepare-length)
    // "<=" since the txs of the first block of the prepare phase are considered in the pox-set
    let pox_set_offset = r#"
        (pox-set-offset (if (<=
            (mod (- %height% (var-get first-burnchain-block-height)) (var-get pox-reward-cycle-length))
            (- (var-get pox-reward-cycle-length) (var-get pox-prepare-cycle-length))
        ) u0 u1))
    "#;

    match function_name {
        "stack-stx" => {
            format!(
                r#"
                (let (
                    (unlock-burn-height (reward-cycle-to-burn-height (+ (current-pox-reward-cycle) u1 {lock_period})))
                    {pox_set_offset}
                )
                {{
                    data: {{
                        ;; amount of ustx to lock.
                        ;; equal to args[0]
                        lock-amount: {lock_amount},
                        ;; burnchain height when the unlock finishes.
                        ;; derived from args[3]
                        unlock-burn-height: unlock-burn-height,
                        ;; PoX address tuple.
                        ;; equal to args[1].
                        pox-addr: {pox_addr},
                        ;; start of lock-up.
                        ;; equal to args[2]
                        start-burn-height: {start_burn_height},
                        ;; how long to lock, in burn blocks
                        ;; equal to args[3]
                        lock-period: {lock_period},
                        ;; equal to args[4]
                        signer-sig: {signer_sig},
                        ;; equal to args[5]
                        signer-key: {signer_key},
                        ;; equal to args[6]
                        max-amount: {max_amount},
                        ;; equal to args[7]
                        auth-id: {auth_id},
                        ;; Get end cycle ID
                        end-cycle-id: (some (burn-height-to-reward-cycle unlock-burn-height)),
                        ;; Get start cycle ID
                        start-cycle-id: (+ (current-pox-reward-cycle) u1 pox-set-offset),
                    }}
                }})
                "#,
                lock_amount = &args[0],
                lock_period = &args[3],
                pox_addr = &args[1],
                start_burn_height = &args[2],
                signer_sig = &args.get(4).unwrap_or(&Value::none()),
                signer_key = &args.get(5).unwrap_or(&Value::none()),
                max_amount = &args.get(6).unwrap_or(&Value::none()),
                auth_id = &args.get(7).unwrap_or(&Value::none()),
                pox_set_offset = pox_set_offset.replace("%height%", "burn-block-height"),
            )
        }
        "delegate-stack-stx" => {
            format!(
                r#"
                (let (
                    (unlock-burn-height (reward-cycle-to-burn-height (+ (current-pox-reward-cycle) u1 {lock_period})))
                    {pox_set_offset}
                )
                {{
                    data: {{
                        ;; amount of ustx to lock.
                        ;; equal to args[1]
                        lock-amount: {lock_amount},
                        ;; burnchain height when the unlock finishes.
                        ;; derived from args[4]
                        unlock-burn-height: unlock-burn-height,
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
                        stacker: '{stacker},
                        ;; Get end cycle ID
                        end-cycle-id: (some (burn-height-to-reward-cycle unlock-burn-height)),
                        ;; Get start cycle ID
                        start-cycle-id: (+ (current-pox-reward-cycle) u1 pox-set-offset),
                    }}
                }})
                "#,
                stacker = &args[0],
                lock_amount = &args[1],
                pox_addr = &args[2],
                start_burn_height = &args[3],
                lock_period = &args[4],
                pox_set_offset = pox_set_offset.replace("%height%", "burn-block-height"),
            )
        }
        "stack-increase" => {
            format!(
                r#"
                (let (
                    (unlock-height (get unlock-height (stx-account tx-sender)))
                    {pox_set_offset}
                )
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
                        pox-addr: (get pox-addr (unwrap-panic (map-get? stacking-state {{ stacker: tx-sender }}))),
                        ;; signer sig (args[1])
                        signer-sig: {signer_sig},
                        ;; signer key (args[2])
                        signer-key: {signer_key},
                        ;; equal to args[3]
                        max-amount: {max_amount},
                        ;; equal to args[4]
                        auth-id: {auth_id},
                        ;; Get end cycle ID
                        end-cycle-id: (some (burn-height-to-reward-cycle unlock-height)),
                        ;; Get start cycle ID
                        start-cycle-id: (+ (current-pox-reward-cycle) u1 pox-set-offset),
                    }}
                }})
                "#,
                increase_by = &args[0],
                signer_sig = &args.get(1).unwrap_or(&Value::none()),
                signer_key = &args.get(2).unwrap_or(&Value::none()),
                max_amount = &args.get(3).unwrap_or(&Value::none()),
                auth_id = &args.get(4).unwrap_or(&Value::none()),
                pox_set_offset = pox_set_offset.replace("%height%", "burn-block-height"),
            )
        }
        "delegate-stack-increase" => {
            format!(
                r#"
                (let (
                    (unlock-height (get unlock-height (stx-account '{stacker})))
                    {pox_set_offset}
                )
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
                        stacker: '{stacker},
                        ;; Get end cycle ID
                        end-cycle-id: (some (burn-height-to-reward-cycle unlock-height)),
                        ;; Get start cycle ID
                        start-cycle-id: (+ (current-pox-reward-cycle) u1 pox-set-offset),
                    }}
                }})
                "#,
                stacker = &args[0],
                pox_addr = &args[1],
                increase_by = &args[2],
                pox_set_offset = pox_set_offset.replace("%height%", "burn-block-height"),
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
                    {pox_set_offset}
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
                        unlock-burn-height: new-unlock-ht,
                        ;; equal to args[2]
                        signer-sig: {signer_sig},
                        ;; equal to args[3]
                        signer-key: {signer_key},
                        ;; equal to args[4]
                        max-amount: {max_amount},
                        ;; equal to args[5]
                        auth-id: {auth_id},
                        ;; Get end cycle ID
                        end-cycle-id: (some (burn-height-to-reward-cycle new-unlock-ht)),
                        ;; Get start cycle ID
                        start-cycle-id: (+ (current-pox-reward-cycle) u1 pox-set-offset),
                    }}
                }})
                "#,
                extend_count = &args[0],
                pox_addr = &args[1],
                signer_sig = &args.get(2).unwrap_or(&Value::none()),
                signer_key = &args.get(3).map_or("none".to_string(), |v| v.to_string()),
                max_amount = &args.get(4).unwrap_or(&Value::none()),
                auth_id = &args.get(5).unwrap_or(&Value::none()),
                pox_set_offset = pox_set_offset.replace("%height%", "burn-block-height"),
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
                    {pox_set_offset}
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
                        stacker: '{stacker},
                        ;; Get end cycle ID
                        end-cycle-id: (some (burn-height-to-reward-cycle new-unlock-ht)),
                        ;; Get start cycle ID
                        start-cycle-id: (+ (current-pox-reward-cycle) u1 pox-set-offset),
                    }}
                }})
                "#,
                stacker = &args[0],
                pox_addr = &args[1],
                extend_count = &args[2],
                pox_set_offset = pox_set_offset.replace("%height%", "burn-block-height"),
            )
        }
        "stack-aggregation-commit" | "stack-aggregation-commit-indexed" => {
            format!(
                r#"
                (let (
                    (next-cycle (+ (current-pox-reward-cycle) u1))
                    {pox_set_offset}
                    (start-cycle (if (is-eq {reward_cycle} next-cycle)
                        (+ {reward_cycle} pox-set-offset)
                        {reward_cycle}))
                )
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
                        delegator: tx-sender,
                        ;; equal to args[2]
                        signer-sig: {signer_sig},
                        ;; equal to args[3]
                        signer-key: {signer_key},
                        ;; equal to args[4]
                        max-amount: {max_amount},
                        ;; equal to args[5]
                        auth-id: {auth_id},
                        ;; Get end cycle ID
                        end-cycle-id: (some (+ {reward_cycle} u1)),
                        ;; Get start cycle ID
                        start-cycle-id: start-cycle,
                    }}
                }})
                "#,
                pox_addr = &args[0],
                reward_cycle = &args[1],
                signer_sig = &args.get(2).unwrap_or(&Value::none()),
                signer_key = &args.get(3).unwrap_or(&Value::none()),
                max_amount = &args.get(4).unwrap_or(&Value::none()),
                auth_id = &args.get(5).unwrap_or(&Value::none()),
                pox_set_offset = pox_set_offset.replace("%height%", "burn-block-height"),
            )
        }
        "stack-aggregation-increase" => {
            format!(
                r#"
                (let (
                    (next-cycle (+ (current-pox-reward-cycle) u1))
                    {pox_set_offset}
                    (start-cycle (if (is-eq {reward_cycle} next-cycle)
                        (+ {reward_cycle} pox-set-offset)
                        {reward_cycle}))
                )
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
                        delegator: tx-sender,
                        ;; equal to args[2]
                        reward-cycle-index: {reward_cycle_index},
                        ;; Get end cycle ID
                        end-cycle-id: (some (+ {reward_cycle} u1)),
                        ;; Get start cycle ID
                        start-cycle-id: start-cycle,
                        ;; equal to args[3]
                        signer-sig: {signer_sig},
                        ;; equal to args[4]
                        signer-key: {signer_key},
                        ;; equal to args[5]
                        max-amount: {max_amount},
                        ;; equal to args[6]
                        auth-id: {auth_id},
                    }}
                }})
                "#,
                pox_addr = &args[0],
                reward_cycle = &args[1],
                reward_cycle_index = &args.get(2).unwrap_or(&Value::none()),
                pox_set_offset = pox_set_offset.replace("%height%", "burn-block-height"),
                signer_sig = &args.get(3).unwrap_or(&Value::none()),
                signer_key = &args.get(4).unwrap_or(&Value::none()),
                max_amount = &args.get(5).unwrap_or(&Value::none()),
                auth_id = &args.get(6).unwrap_or(&Value::none()),
            )
        }
        "delegate-stx" => {
            format!(
                r#"
                (let (
                    {pox_set_offset}
                )
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
                        pox-addr: {pox_addr},
                        ;; Get end cycle ID
                        end-cycle-id: (match {until_burn_height}
                            height (some (burn-height-to-reward-cycle height))
                            none
                        ),
                        ;; Get start cycle ID
                        start-cycle-id: (+ (current-pox-reward-cycle) u1 pox-set-offset),
                    }}
                }})
                "#,
                amount_ustx = &args[0],
                delegate_to = &args[1],
                until_burn_height = &args[2],
                pox_addr = &args[3],
                pox_set_offset = pox_set_offset.replace("%height%", "burn-block-height"),
            )
        }
        "revoke-delegate-stx" => {
            if let Value::Optional(opt) = *response.data.clone() {
                eprintln!("Response data in revoke-delegate-stx is: {:?}", opt.data);
                format!(
                    r#"
                    {{
                        data: {{
                            delegate-to: '{delegate_to},
                            ;; Get end cycle ID
                            end-cycle-id: none,
                            ;; Get start cycle ID
                            start-cycle-id: (+ (current-pox-reward-cycle) u1),
                        }},
                    }}
                    "#,
                    delegate_to = opt
                        .data
                        .clone()
                        .map(|boxed_value| *boxed_value)
                        .unwrap()
                        .expect_tuple()
                        .expect("FATAL: unexpected clarity value")
                        .get("delegated-to")
                        .unwrap(),
                )
            } else {
                "{data: {unimplemented: true}}".into()
            }
        }
        _ => "{data: {unimplemented: true}}".into(),
    }
}

/// Synthesize an events data tuple to return on the successful execution of a pox-2 or pox-3 or pox-4 stacking
/// function.  It runs a series of Clarity queries against the PoX contract's data space (including
/// calling PoX functions).
pub fn synthesize_pox_event_info(
    global_context: &mut GlobalContext,
    contract_id: &QualifiedContractIdentifier,
    sender_opt: Option<&PrincipalData>,
    function_name: &str,
    args: &[Value],
    response: &ResponseData,
) -> Result<Option<Value>, ClarityError> {
    // the first thing we do is check the current epoch. In Epochs <= 2.4,
    //  synthesizing PoX events was an assessed cost, so event generation
    //  must remain identical.
    if global_context.epoch_id <= StacksEpochId::Epoch24 {
        return events_24::synthesize_pox_2_or_3_event_info(
            global_context,
            contract_id,
            sender_opt,
            function_name,
            args,
        );
    }
    // Now, we want to set the cost tracker to free
    //
    // IMPORTANT: This function SHOULD NOT early return without
    // replacing the cost tracker. This code snippet is kept short to
    // ensure that there is only one possible control flow here.  DO
    // NOT alter these lines unless you know what you are doing here.
    let original_tracker = std::mem::replace(
        &mut global_context.cost_track,
        LimitedCostTracker::new_free(),
    );
    let result = inner_synthesize_pox_event_info(
        global_context,
        contract_id,
        sender_opt,
        function_name,
        args,
        response,
    );
    // Restore the cost tracker
    global_context.cost_track = original_tracker;
    result
}

/// The actual implementation of Post-2.4 event construction.
/// We use an inner function to simplify the free cost tracking.
fn inner_synthesize_pox_event_info(
    global_context: &mut GlobalContext,
    contract_id: &QualifiedContractIdentifier,
    sender_opt: Option<&PrincipalData>,
    function_name: &str,
    args: &[Value],
    response: &ResponseData,
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
        | "delegate-stx"
        | "revoke-delegate-stx" => Some(create_event_info_stack_or_delegate_code(
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

    let data_snippet = create_event_info_data_code(function_name, args, response);

    test_debug!("Evaluate snippet:\n{}", &code_snippet);
    test_debug!("Evaluate data code:\n{}", &data_snippet);

    let pox_contract = global_context.database.get_contract(contract_id)?;

    let event_info = global_context
        .special_cc_handler_execute_read_only(
            sender.clone(),
            None,
            pox_contract.contract_context,
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
