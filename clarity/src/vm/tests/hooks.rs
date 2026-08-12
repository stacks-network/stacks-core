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

use stacks_common::types::StacksEpochId;

use crate::vm::contexts::OwnedEnvironment;
use crate::vm::database::MemoryBackingStore;
use crate::vm::hooks::ExecutionOutcome;
use crate::vm::hooks::testing::render::print_trace;
use crate::vm::hooks::testing::{
    CallStackCheckingHook, ExecutionLifecycleEvent, ExecutionLifecycleHook, TraceCallKind,
    TraceHook, flatten_calls,
};
use crate::vm::hooks::trace::{CallTraceHook, TracedCallee, TracedResult};
use crate::vm::types::{PrincipalData, QualifiedContractIdentifier};
use crate::vm::{ClarityVersion, ContractContext, SymbolicExpression, Value, eval_all};

/// Verifies that a successful top-level transaction emits one begin notification followed by a
/// successful finish notification.
#[test]
fn eval_hook_captures_top_level_execution_lifecycle() {
    let mut marf = MemoryBackingStore::new();
    let mut env = OwnedEnvironment::new(marf.as_clarity_db(), StacksEpochId::Epoch21);
    let contract_id = QualifiedContractIdentifier::local("trace-lifecycle").unwrap();
    let source = r#"
        (define-public (entry)
          (ok u1))
    "#;

    env.initialize_versioned_contract(contract_id.clone(), ClarityVersion::Clarity2, source, None)
        .unwrap();

    let mut hook = ExecutionLifecycleHook::default();
    env.add_eval_hook(&mut hook);

    let sender = contract_id.issuer.clone().into();
    let (value, _, _) = env
        .execute_transaction(sender, None, contract_id.clone(), "entry", &[])
        .unwrap();

    assert_eq!(value, Value::okay(Value::UInt(1)).unwrap());
    assert_eq!(
        hook.events,
        vec![
            ExecutionLifecycleEvent::Begin,
            ExecutionLifecycleEvent::Finish(ExecutionOutcome::Success)
        ]
    );
}

/// Verifies that a top-level VM error still emits a matching finish notification with a failure
/// outcome.
#[test]
fn eval_hook_captures_failed_top_level_execution_lifecycle() {
    let mut marf = MemoryBackingStore::new();
    let mut env = OwnedEnvironment::new(marf.as_clarity_db(), StacksEpochId::Epoch21);
    let contract_id = QualifiedContractIdentifier::local("trace-lifecycle-failure").unwrap();
    let source = r#"
        (define-public (entry)
          (/ u1 u0))
    "#;

    env.initialize_versioned_contract(contract_id.clone(), ClarityVersion::Clarity2, source, None)
        .unwrap();

    let mut hook = ExecutionLifecycleHook::default();
    env.add_eval_hook(&mut hook);

    let sender = contract_id.issuer.clone().into();
    env.execute_transaction(sender, None, contract_id.clone(), "entry", &[])
        .unwrap_err();

    assert_eq!(
        hook.events,
        vec![
            ExecutionLifecycleEvent::Begin,
            ExecutionLifecycleEvent::Finish(ExecutionOutcome::Failure)
        ]
    );
}

/// Forces a VM error deep in a local call chain and verifies LIFO error unwinding, an empty hook
/// stack at execution boundaries, and clean reuse of the same hook on retry.
#[test]
fn eval_hook_balances_nested_call_stack_after_deep_failure() {
    let mut marf = MemoryBackingStore::new();
    let mut env = OwnedEnvironment::new(marf.as_clarity_db(), StacksEpochId::Epoch21);
    let contract_id = QualifiedContractIdentifier::local("trace-nested-failure").unwrap();
    let source = r#"
        (define-private (leaf (divisor uint))
          (/ u1 divisor))

        (define-private (middle (divisor uint))
          (+ u1 (leaf divisor)))

        (define-private (outer (divisor uint))
          (+ u1 (middle divisor)))

        (define-public (entry (divisor uint))
          (ok (outer divisor)))
    "#;

    env.initialize_versioned_contract(contract_id.clone(), ClarityVersion::Clarity2, source, None)
        .unwrap();

    let mut hook = CallStackCheckingHook::default();
    env.add_eval_hook(&mut hook);

    let sender = contract_id.issuer.clone().into();
    let failing_args = vec![SymbolicExpression::atom_value(Value::UInt(0))];
    env.execute_transaction(sender, None, contract_id.clone(), "entry", &failing_args)
        .unwrap_err();

    // Reuse the same environment and hook after the deep failure. Any leaked call frame would
    // either make this execution start with stale state or corrupt its LIFO pairing.
    let sender = contract_id.issuer.clone().into();
    let successful_args = vec![SymbolicExpression::atom_value(Value::UInt(1))];
    let (value, _, _) = env
        .execute_transaction(sender, None, contract_id, "entry", &successful_args)
        .unwrap();

    assert_eq!(value, Value::okay(Value::UInt(3)).unwrap());
    assert!(
        hook.max_depth >= 5,
        "the fixture must exercise a genuinely nested call chain"
    );
    assert_eq!(hook.executions.len(), 2);

    let failed = &hook.executions[0];
    assert_eq!(failed.outcome, ExecutionOutcome::Failure);
    assert!(
        failed.calls.iter().all(|call| call.failed),
        "every frame unwound from the deep failure must receive the error: {:?}",
        failed.calls
    );
    for expected in [
        "builtin:/",
        "user-private:leaf",
        "user-private:middle",
        "user-private:outer",
        "user-public:entry",
    ] {
        assert!(
            failed.calls.iter().any(|call| call.label == expected),
            "missing failed call frame {expected}: {:?}",
            failed.calls
        );
    }

    let succeeded = &hook.executions[1];
    assert_eq!(succeeded.outcome, ExecutionOutcome::Success);
    assert!(
        succeeded.calls.iter().all(|call| !call.failed),
        "the follow-up execution should close every frame successfully: {:?}",
        succeeded.calls
    );
    assert_eq!(
        failed
            .calls
            .iter()
            .map(|call| &call.label)
            .collect::<Vec<_>>(),
        succeeded
            .calls
            .iter()
            .map(|call| &call.label)
            .collect::<Vec<_>>(),
        "the successful retry should traverse the same call chain without stale frames"
    );
}

/// Confirms that the lower-level `GlobalContext::execute` path does not emit the top-level
/// transaction lifecycle notifications owned by `OwnedEnvironment`.
#[test]
fn eval_hook_lifecycle_is_not_emitted_by_global_context_execute() {
    let mut marf = MemoryBackingStore::new();
    let mut env = OwnedEnvironment::new(marf.as_clarity_db(), StacksEpochId::Epoch21);
    let contract_id = QualifiedContractIdentifier::local("trace-global-context").unwrap();
    let mut contract_context = ContractContext::new(contract_id, ClarityVersion::Clarity2);
    let parsed = vec![SymbolicExpression::atom_value(Value::UInt(1))];

    let mut hook = ExecutionLifecycleHook::default();
    env.add_eval_hook(&mut hook);

    env.context
        .execute(|global_context| eval_all(&parsed, &mut contract_context, global_context, None))
        .unwrap();

    assert!(hook.events.is_empty());
}

/// Exercises nested user calls and a fold to verify that trace hooks report each callable's
/// effective argument values after their producing expressions have evaluated.
#[test]
fn eval_hook_captures_effective_call_arguments() {
    let mut marf = MemoryBackingStore::new();
    let mut env = OwnedEnvironment::new(marf.as_clarity_db(), StacksEpochId::Epoch21);
    let contract_id = QualifiedContractIdentifier::local("trace-test").unwrap();
    let source = r#"
        (define-private (scale (a uint))
          (+ a u41))

        (define-private (foo (a uint) (b uint))
          (+ (scale a) b))

        (define-public (entry (seed uint))
          (ok (foo (+ seed u1) (fold + (list u10 u20 u12) u0))))
    "#;

    env.initialize_versioned_contract(contract_id.clone(), ClarityVersion::Clarity2, source, None)
        .unwrap();

    let mut hook = TraceHook::default();
    env.add_eval_hook(&mut hook);

    let sender = contract_id.issuer.clone().into();
    let args = vec![SymbolicExpression::atom_value(Value::UInt(0))];
    let (value, _, _) = env
        .execute_transaction(sender, None, contract_id, "entry", &args)
        .unwrap();

    print_trace(&hook.events);

    assert_eq!(value, Value::okay(Value::UInt(84)).unwrap());
    hook.assert_user_begin(TraceCallKind::UserPublic, "trace-test", "entry", 1);
    hook.assert_user_argument_value(
        TraceCallKind::UserPublic,
        "trace-test",
        "entry",
        0,
        "seed",
        Value::UInt(0),
    );
    hook.assert_user_begin(TraceCallKind::UserPrivate, "trace-test", "foo", 2);
    hook.assert_user_argument_value(
        TraceCallKind::UserPrivate,
        "trace-test",
        "foo",
        0,
        "a",
        Value::UInt(1),
    );
    hook.assert_user_argument_value(
        TraceCallKind::UserPrivate,
        "trace-test",
        "foo",
        1,
        "b",
        Value::UInt(42),
    );
    hook.assert_user_argument_value(
        TraceCallKind::UserPrivate,
        "trace-test",
        "scale",
        0,
        "a",
        Value::UInt(1),
    );
    hook.assert_builtin_argument_value("+", 0, Value::UInt(10));
    hook.assert_builtin_argument_value("+", 1, Value::UInt(30));
}

/// Verifies lazy special-form tracing by asserting that `if` records only the selected branch and
/// never opens a call frame for the unevaluated error branch.
#[test]
fn eval_hook_captures_lazy_special_form_call_tree() {
    let mut marf = MemoryBackingStore::new();
    let mut env = OwnedEnvironment::new(marf.as_clarity_db(), StacksEpochId::Epoch21);
    let contract_id = QualifiedContractIdentifier::local("trace-specials").unwrap();
    let source = r#"
        (define-public (entry)
          (ok (if true (+ u1 u2) (/ u1 u0))))
    "#;

    env.initialize_versioned_contract(contract_id.clone(), ClarityVersion::Clarity2, source, None)
        .unwrap();

    let mut hook = TraceHook::default();
    env.add_eval_hook(&mut hook);

    let sender = contract_id.issuer.clone().into();
    let (value, _, _) = env
        .execute_transaction(sender, None, contract_id, "entry", &[])
        .unwrap();

    print_trace(&hook.events);

    assert_eq!(value, Value::okay(Value::UInt(3)).unwrap());
    hook.assert_builtin_begin("if", 3);
    hook.assert_builtin_begin("+", 2);
    hook.assert_no_builtin_begin("/");
}

/// Verifies tracing through `fold`'s pre-evaluated step-function calls, including element values,
/// the threaded accumulator, and the final step result.
#[test]
fn eval_hook_captures_fold_with_user_step_function() {
    let mut marf = MemoryBackingStore::new();
    let mut env = OwnedEnvironment::new(marf.as_clarity_db(), StacksEpochId::Epoch21);
    let contract_id = QualifiedContractIdentifier::local("trace-fold").unwrap();
    let source = r#"
        (define-private (accumulate (item uint) (acc uint))
          (+ acc (* item u2)))

        (define-public (entry)
          (ok (fold accumulate (list u1 u2 u3) u0)))
    "#;

    env.initialize_versioned_contract(contract_id.clone(), ClarityVersion::Clarity2, source, None)
        .unwrap();

    let mut hook = TraceHook::default();
    env.add_eval_hook(&mut hook);

    let sender = contract_id.issuer.clone().into();
    let (value, _, _) = env
        .execute_transaction(sender, None, contract_id, "entry", &[])
        .unwrap();

    print_trace(&hook.events);

    // fold applies `accumulate` left-to-right over (list u1 u2 u3) starting at u0:
    //   (+ u0 (* u1 u2)) = u2  ->  (+ u2 (* u2 u2)) = u6  ->  (+ u6 (* u3 u2)) = u12
    assert_eq!(value, Value::okay(Value::UInt(12)).unwrap());
    hook.assert_builtin_begin("fold", 3);
    // First iteration: item is the first list element, acc is the seed.
    hook.assert_user_argument_value(
        TraceCallKind::UserPrivate,
        "trace-fold",
        "accumulate",
        0,
        "item",
        Value::UInt(1),
    );
    hook.assert_user_argument_value(
        TraceCallKind::UserPrivate,
        "trace-fold",
        "accumulate",
        1,
        "acc",
        Value::UInt(0),
    );
    // Final iteration threads the running accumulator: item=u3, acc=u6.
    hook.assert_user_argument_value(
        TraceCallKind::UserPrivate,
        "trace-fold",
        "accumulate",
        0,
        "item",
        Value::UInt(3),
    );
    hook.assert_user_argument_value(
        TraceCallKind::UserPrivate,
        "trace-fold",
        "accumulate",
        1,
        "acc",
        Value::UInt(6),
    );
    hook.assert_user_finish_value(
        TraceCallKind::UserPrivate,
        "trace-fold",
        "accumulate",
        Value::UInt(12),
    );
}

/// Exercises trait-based dynamic `contract-call?` dispatch and verifies that resolved arguments are
/// attributed to both the local helper and remote implementation call.
#[test]
fn eval_hook_captures_trait_dispatched_contract_call_arguments() {
    let mut marf = MemoryBackingStore::new();
    let mut env = OwnedEnvironment::new(marf.as_clarity_db(), StacksEpochId::Epoch21);
    let trait_contract_id = QualifiedContractIdentifier::local("trace-trait").unwrap();
    let impl_contract_id = QualifiedContractIdentifier::local("trace-impl").unwrap();
    let caller_contract_id = QualifiedContractIdentifier::local("trace-caller").unwrap();

    env.initialize_versioned_contract(
        trait_contract_id,
        ClarityVersion::Clarity2,
        r#"
            (define-trait trace-runner
              ((do-it (uint uint) (response uint uint))))
        "#,
        None,
    )
    .unwrap();
    env.initialize_versioned_contract(
        impl_contract_id,
        ClarityVersion::Clarity2,
        r#"
            (impl-trait .trace-trait.trace-runner)

            (define-public (do-it (x uint) (y uint))
              (ok (+ x y)))
        "#,
        None,
    )
    .unwrap();
    env.initialize_versioned_contract(
        caller_contract_id.clone(),
        ClarityVersion::Clarity2,
        r#"
            (use-trait runner .trace-trait.trace-runner)
            (define-data-var runner-contract principal .trace-impl)

            (define-private (call-runner (runner <runner>) (x uint) (y uint))
              (contract-call? runner do-it x y))

            (define-public (entry (seed uint))
              (call-runner (var-get runner-contract) seed (+ seed u10)))
        "#,
        None,
    )
    .unwrap();

    let mut hook = TraceHook::default();
    env.add_eval_hook(&mut hook);
    let args = vec![SymbolicExpression::atom_value(Value::UInt(7))];
    let sender = caller_contract_id.issuer.clone().into();
    let (value, _, _) = env
        .execute_transaction(sender, None, caller_contract_id, "entry", &args)
        .unwrap();
    drop(env);

    print_trace(&hook.events);

    assert_eq!(value, Value::okay(Value::UInt(24)).unwrap());
    hook.assert_user_begin(TraceCallKind::UserPublic, "trace-caller", "entry", 1);
    hook.assert_user_argument_value(
        TraceCallKind::UserPublic,
        "trace-caller",
        "entry",
        0,
        "seed",
        Value::UInt(7),
    );
    hook.assert_user_begin(TraceCallKind::UserPrivate, "trace-caller", "call-runner", 3);
    hook.assert_user_argument_value(
        TraceCallKind::UserPrivate,
        "trace-caller",
        "call-runner",
        0,
        "runner",
        Value::Principal(PrincipalData::Contract(
            QualifiedContractIdentifier::local("trace-impl").unwrap(),
        )),
    );
    hook.assert_user_argument_value(
        TraceCallKind::UserPrivate,
        "trace-caller",
        "call-runner",
        1,
        "x",
        Value::UInt(7),
    );
    hook.assert_user_argument_value(
        TraceCallKind::UserPrivate,
        "trace-caller",
        "call-runner",
        2,
        "y",
        Value::UInt(17),
    );
    hook.assert_user_begin(TraceCallKind::UserPublic, "trace-impl", "do-it", 2);
    hook.assert_user_argument_value(
        TraceCallKind::UserPublic,
        "trace-impl",
        "do-it",
        0,
        "x",
        Value::UInt(7),
    );
    hook.assert_user_argument_value(
        TraceCallKind::UserPublic,
        "trace-impl",
        "do-it",
        1,
        "y",
        Value::UInt(17),
    );
    hook.assert_user_finish_value(
        TraceCallKind::UserPublic,
        "trace-impl",
        "do-it",
        Value::okay(Value::UInt(24)).unwrap(),
    );
}

/// Propagates a real VM error across a trait-dispatched contract boundary and verifies ordered
/// frame unwinding, preserved pre-error successes, and clean hook reuse on retry.
#[test]
fn eval_hook_balances_trait_dispatched_contract_call_after_failure() {
    let mut marf = MemoryBackingStore::new();
    let mut env = OwnedEnvironment::new(marf.as_clarity_db(), StacksEpochId::Epoch21);
    let trait_contract_id = QualifiedContractIdentifier::local("trace-failure-trait").unwrap();
    let impl_contract_id = QualifiedContractIdentifier::local("trace-failure-impl").unwrap();
    let caller_contract_id = QualifiedContractIdentifier::local("trace-failure-caller").unwrap();

    env.initialize_versioned_contract(
        trait_contract_id,
        ClarityVersion::Clarity2,
        r#"
            (define-trait divider
              ((divide (uint) (response uint uint))))
        "#,
        None,
    )
    .unwrap();
    env.initialize_versioned_contract(
        impl_contract_id,
        ClarityVersion::Clarity2,
        r#"
            (impl-trait .trace-failure-trait.divider)

            (define-public (divide (divisor uint))
              (ok (/ u12 divisor)))
        "#,
        None,
    )
    .unwrap();
    env.initialize_versioned_contract(
        caller_contract_id.clone(),
        ClarityVersion::Clarity2,
        r#"
            (use-trait divider .trace-failure-trait.divider)
            (define-data-var divider-contract principal .trace-failure-impl)

            (define-private (call-divider (target <divider>) (divisor uint))
              (contract-call? target divide divisor))

            (define-public (entry (divisor uint))
              (call-divider (var-get divider-contract) divisor))
        "#,
        None,
    )
    .unwrap();

    let mut hook = CallStackCheckingHook::default();
    env.add_eval_hook(&mut hook);

    let sender = caller_contract_id.issuer.clone().into();
    let failing_args = vec![SymbolicExpression::atom_value(Value::UInt(0))];
    env.execute_transaction(
        sender,
        None,
        caller_contract_id.clone(),
        "entry",
        &failing_args,
    )
    .unwrap_err();

    // Retry the same trait-dispatched contract call with a valid divisor. This ensures
    // that crossing the failed callee's transaction boundary left no stale hook frames.
    let sender = caller_contract_id.issuer.clone().into();
    let successful_args = vec![SymbolicExpression::atom_value(Value::UInt(1))];
    let (value, _, _) = env
        .execute_transaction(sender, None, caller_contract_id, "entry", &successful_args)
        .unwrap();

    assert_eq!(value, Value::okay(Value::UInt(12)).unwrap());
    assert!(
        hook.max_depth >= 5,
        "the fixture must cross a genuinely nested contract-call chain"
    );
    assert_eq!(hook.executions.len(), 2);

    let failed = &hook.executions[0];
    assert_eq!(failed.outcome, ExecutionOutcome::Failure);
    let first_failed = failed
        .calls
        .iter()
        .position(|call| call.failed)
        .expect("the callee's runtime error must reach the hook");
    assert!(
        failed.calls[..first_failed]
            .iter()
            .any(|call| call.label == "builtin:var-get"),
        "`var-get` must complete successfully before the runtime error: {:?}",
        failed.calls
    );
    assert!(
        failed.calls[first_failed..].iter().all(|call| call.failed),
        "every active frame must receive the propagated runtime error: {:?}",
        failed.calls
    );
    for expected in [
        "builtin:/",
        "user-public:divide",
        "builtin:contract-call?",
        "user-private:call-divider",
        "user-public:entry",
    ] {
        assert!(
            failed
                .calls
                .iter()
                .any(|call| call.failed && call.label == expected),
            "missing failed call frame {expected}: {:?}",
            failed.calls
        );
    }

    let succeeded = &hook.executions[1];
    assert_eq!(succeeded.outcome, ExecutionOutcome::Success);
    assert!(
        succeeded.calls.iter().all(|call| !call.failed),
        "the retry should close every frame successfully: {:?}",
        succeeded.calls
    );
    assert_eq!(
        failed
            .calls
            .iter()
            .map(|call| &call.label)
            .collect::<Vec<_>>(),
        succeeded
            .calls
            .iter()
            .map(|call| &call.label)
            .collect::<Vec<_>>(),
        "the retry should traverse the same dynamic call chain without stale frames"
    );
}

/// Traces a three-contract flow where `fold` steps perform nested contract calls, verifying
/// call-tree nesting, branch forms, resolved step arguments, and cross-contract results.
#[test]
fn eval_hook_captures_nested_contract_calls_folding_over_contract_calls() {
    let mut marf = MemoryBackingStore::new();
    let mut env = OwnedEnvironment::new(marf.as_clarity_db(), StacksEpochId::Epoch21);

    let math_id = QualifiedContractIdentifier::local("trace-math").unwrap();
    let agg_id = QualifiedContractIdentifier::local("trace-agg").unwrap();
    let top_id = QualifiedContractIdentifier::local("trace-top").unwrap();

    // Leaf contract: doubles a value, guarding against overflow with an `if` whose
    // error branch is never taken for our inputs.
    env.initialize_versioned_contract(
        math_id,
        ClarityVersion::Clarity2,
        r#"
            (define-public (double (n uint))
              (if (> n u100)
                  (err u1)
                  (ok (* n u2))))
        "#,
        None,
    )
    .unwrap();

    // Middle contract: folds over a list. Each step branches on the item with `if`
    // (skipping zero), and `match`es the contract-call response from `.trace-math`.
    env.initialize_versioned_contract(
        agg_id,
        ClarityVersion::Clarity2,
        r#"
            (define-private (add-doubled (item uint) (acc uint))
              (if (> item u0)
                  (match (contract-call? .trace-math double item)
                    doubled (+ acc doubled)
                    err-val acc)
                  acc))

            (define-public (sum-doubled (items (list 3 uint)))
              (ok (fold add-doubled items u0)))
        "#,
        None,
    )
    .unwrap();

    // Top contract: builds a list (with a trailing zero to exercise the skip branch)
    // and contract-calls the middle contract.
    env.initialize_versioned_contract(
        top_id.clone(),
        ClarityVersion::Clarity2,
        r#"
            (define-public (entry (seed uint))
              (contract-call? .trace-agg sum-doubled (list seed (+ seed u1) u0)))
        "#,
        None,
    )
    .unwrap();

    let mut hook = TraceHook::default();
    env.add_eval_hook(&mut hook);

    let args = vec![SymbolicExpression::atom_value(Value::UInt(2))];
    let sender = top_id.issuer.clone().into();
    let (value, _, _) = env
        .execute_transaction(sender, None, top_id, "entry", &args)
        .unwrap();

    print_trace(&hook.events);

    // list = (u2 u3 u0); double(n) = (* n u2) when n <= u100. The fold sums the doubles,
    // skipping the trailing zero via the `if`:
    //   u0 + double(u2)=u4 -> u4 + double(u3)=u6 => u10 -> (item u0 skipped) => u10
    assert_eq!(value, Value::okay(Value::UInt(10)).unwrap());

    // Nested contract-call chain: trace-top.entry -> trace-agg.sum-doubled -> (fold) ->
    // trace-math.double, with `if`/`match` branching in each fold step.
    hook.assert_user_begin(TraceCallKind::UserPublic, "trace-top", "entry", 1);
    hook.assert_user_begin(TraceCallKind::UserPublic, "trace-agg", "sum-doubled", 1);
    hook.assert_builtin_begin("fold", 3);
    hook.assert_user_begin(TraceCallKind::UserPrivate, "trace-agg", "add-doubled", 2);
    // Branching forms are captured as builtin calls.
    hook.assert_builtin_begin("if", 3);
    hook.assert_builtin_begin("match", 5);

    // First fold step: item=u2, acc=u0, contract-calling double(n=u2) ⇒ (ok u4).
    hook.assert_user_argument_value(
        TraceCallKind::UserPrivate,
        "trace-agg",
        "add-doubled",
        0,
        "item",
        Value::UInt(2),
    );
    hook.assert_user_argument_value(
        TraceCallKind::UserPrivate,
        "trace-agg",
        "add-doubled",
        1,
        "acc",
        Value::UInt(0),
    );
    hook.assert_user_begin(TraceCallKind::UserPublic, "trace-math", "double", 1);
    hook.assert_user_argument_value(
        TraceCallKind::UserPublic,
        "trace-math",
        "double",
        0,
        "n",
        Value::UInt(2),
    );
    hook.assert_user_finish_value(
        TraceCallKind::UserPublic,
        "trace-math",
        "double",
        Value::okay(Value::UInt(4)).unwrap(),
    );

    // Final fold step takes the `if` skip branch: item=u0, acc=u10, and simply returns the
    // accumulator (no contract-call is made for this element).
    hook.assert_user_argument_value(
        TraceCallKind::UserPrivate,
        "trace-agg",
        "add-doubled",
        0,
        "item",
        Value::UInt(0),
    );
    hook.assert_user_argument_value(
        TraceCallKind::UserPrivate,
        "trace-agg",
        "add-doubled",
        1,
        "acc",
        Value::UInt(10),
    );
    hook.assert_user_finish_value(
        TraceCallKind::UserPublic,
        "trace-agg",
        "sum-doubled",
        Value::okay(Value::UInt(10)).unwrap(),
    );
}

/// Validates the production `CallTraceHook` call tree, per-call cost accounting, and eval-merge
/// resolution of state-read and state-write arguments.
#[test]
fn call_trace_hook_resolves_state_reads_and_captures_cost() {
    let mut marf = MemoryBackingStore::new();
    // A memory-backed store has no boot cost contracts, so it runs with the free cost tracker and
    // per-call cost deltas are zero here. This test validates the resolved tree, value resolution,
    // and the eval-merge for special-form arguments; non-zero cost magnitude is exercised against a
    // real cost tracker in the replay path.
    let mut env = OwnedEnvironment::new(marf.as_clarity_db(), StacksEpochId::Epoch21);
    let contract_id = QualifiedContractIdentifier::local("trace-collector").unwrap();
    let source = r#"
        (define-map balances principal uint)
        (define-public (run (amount uint))
          (begin
            (map-set balances tx-sender amount)
            (ok (map-get? balances tx-sender))))
    "#;

    env.initialize_versioned_contract(contract_id.clone(), ClarityVersion::Clarity2, source, None)
        .unwrap();

    let mut hook = CallTraceHook::new();
    env.add_eval_hook(&mut hook);

    let args = vec![SymbolicExpression::atom_value(Value::UInt(1000))];
    let sender = contract_id.issuer.clone().into();
    env.execute_transaction(sender, None, contract_id, "run", &args)
        .unwrap();

    let roots = hook.calls();
    assert_eq!(roots.len(), 1, "one top-level call");
    let run = &roots[0];
    assert!(
        matches!(&run.callee, TracedCallee::UserDefined { function, .. } if function == "run"),
        "root is the `run` entry point: {:?}",
        run.callee
    );
    // The root carries the transaction's return value, confirming it finished and its children
    // attached to it (rather than to a stray root).
    assert_eq!(
        run.result,
        Some(TracedResult::Ok(
            Value::okay(Value::some(Value::UInt(1000)).unwrap()).unwrap()
        )),
        "run returned (ok (some u1000)): {:?}",
        run.result
    );

    let calls = flatten_calls(roots);

    // (a) Cost is sampled per call, and the exclusive-of-children subtraction never yields more
    //     than the inclusive cost in any dimension. (Trivially satisfied under the free tracker
    //     where all costs are zero, but it exercises the sampling + subtraction path.)
    for call in &calls {
        assert!(call.cost_inclusive.runtime >= call.cost_exclusive.runtime);
        assert!(call.cost_inclusive.read_count >= call.cost_exclusive.read_count);
        assert!(call.cost_inclusive.read_length >= call.cost_exclusive.read_length);
        assert!(call.cost_inclusive.write_count >= call.cost_exclusive.write_count);
        assert!(call.cost_inclusive.write_length >= call.cost_exclusive.write_length);
    }

    // (b) The `map-get?` key `tx-sender` is a special-form argument (no per-arg value event),
    //     resolved via the eval-hook merge to the concrete principal that was read.
    let map_get = calls
        .iter()
        .find(|call| {
            matches!(&call.callee, TracedCallee::Builtin { clarity_name, .. } if clarity_name == "map-get?")
        })
        .expect("a map-get? call was traced");
    let key_arg = map_get
        .args
        .iter()
        .find(|arg| arg.source == "tx-sender")
        .expect("map-get? has a tx-sender key argument");
    assert!(
        matches!(key_arg.value, Some(Value::Principal(_))),
        "special-form key resolved to a principal via eval-merge, got {:?}",
        key_arg.value
    );
    // The read returned the value written moments earlier in the same call.
    assert_eq!(
        map_get.result,
        Some(TracedResult::Ok(Value::some(Value::UInt(1000)).unwrap())),
        "map-get? returned (some u1000): {:?}",
        map_get.result
    );

    // The `map-set` write is also present, with its value argument resolved.
    let map_set = calls
        .iter()
        .find(|call| {
            matches!(&call.callee, TracedCallee::Builtin { clarity_name, .. } if clarity_name == "map-set")
        })
        .expect("a map-set call was traced");
    assert!(
        map_set
            .args
            .iter()
            .any(|arg| arg.value == Some(Value::UInt(1000))),
        "map-set value argument resolved to u1000: {:?}",
        map_set.args
    );
}
