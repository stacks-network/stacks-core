// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2026 Stacks Open Internet Foundation
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

use crate::vm::contexts::{ExecutionState, InvocationContext, OwnedEnvironment};
use crate::vm::database::MemoryBackingStore;
use crate::vm::errors::VmExecutionError;
use crate::vm::hooks::{CallArguments, CallHook, EvalHook, ExecutionOutcome};
use crate::vm::types::{PrincipalData, QualifiedContractIdentifier};
use crate::vm::{ClarityVersion, ContractContext, SymbolicExpression, Value, eval_all};

fn print_trace(events: &[TraceEvent]) {
    let current_thread = std::thread::current();
    let test_name = current_thread
        .name()
        .and_then(|name| name.split("::").last())
        .unwrap_or("unknown test");
    println!();
    println!("=== {test_name} trace ===");
    for event in events {
        println!("{event:#?}");
    }
}

#[derive(Default)]
struct TraceHook {
    depth: usize,
    events: Vec<TraceEvent>,
    frames: Vec<TraceFrame>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TraceEvent {
    BeginArgumentEval {
        depth: usize,
        arg_index: usize,
        arg_name: String,
    },
    BeginCall {
        depth: usize,
        kind: TraceCallKind,
        target: TraceCallTarget,
        arg_count: usize,
    },
    ArgumentValue {
        depth: usize,
        kind: TraceCallKind,
        target: TraceCallTarget,
        arg_index: usize,
        arg_name: String,
        value: Value,
    },
    FinishCall {
        depth: usize,
        kind: TraceCallKind,
        target: TraceCallTarget,
        result: TraceResult,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TraceCallKind {
    Builtin,
    UserPublic,
    UserPrivate,
    UserReadOnly,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TraceCallTarget {
    Builtin(String),
    UserDefined {
        contract_name: String,
        function_name: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TraceResult {
    Ok(Value),
    Err(String),
}

struct TraceFrame {
    group_arg_evals: bool,
    arg_labels: Vec<String>,
    next_arg_index: usize,
    active_arg_index: Option<usize>,
}

impl TraceHook {
    fn call_kind(call: &CallHook) -> TraceCallKind {
        match call.kind() {
            "builtin" => TraceCallKind::Builtin,
            "user-public" => TraceCallKind::UserPublic,
            "user-private" => TraceCallKind::UserPrivate,
            "user-read-only" => TraceCallKind::UserReadOnly,
            other => panic!("unexpected call hook kind: {other}"),
        }
    }

    fn call_target(call: &CallHook) -> TraceCallTarget {
        match call {
            CallHook::Builtin { .. } => TraceCallTarget::Builtin(call.clarity_name().to_string()),
            CallHook::UserDefined {
                contract_identifier,
                ..
            } => TraceCallTarget::UserDefined {
                contract_name: contract_identifier.name.to_string(),
                function_name: call.clarity_name().to_string(),
            },
        }
    }

    fn arg_name(call: &CallHook, arg_index: usize) -> String {
        match call {
            CallHook::UserDefined { function, .. } => function
                .argument_names()
                .get(arg_index)
                .map(ToString::to_string)
                .unwrap_or_else(|| format!("arg{arg_index}")),
            _ => format!("arg{arg_index}"),
        }
    }

    fn open_parent_arg_eval_if_needed(&mut self) {
        let Some(parent) = self.frames.last_mut() else {
            return;
        };
        if !parent.group_arg_evals
            || parent.active_arg_index.is_some()
            || parent.next_arg_index >= parent.arg_labels.len()
        {
            return;
        }

        let arg_index = parent.next_arg_index;
        self.events.push(TraceEvent::BeginArgumentEval {
            depth: self.depth,
            arg_index,
            arg_name: parent.arg_labels[arg_index].clone(),
        });
        parent.active_arg_index = Some(arg_index);
        self.depth += 1;
    }

    fn close_current_arg_eval_if_needed(&mut self, arg_index: usize) {
        let Some(current) = self.frames.last_mut() else {
            return;
        };
        current.next_arg_index = current.next_arg_index.max(arg_index + 1);

        if current.active_arg_index == Some(arg_index) {
            current.active_arg_index = None;
            self.depth = self.depth.saturating_sub(1);
        }
    }
}

fn user_target(contract_name: &str, function_name: &str) -> TraceCallTarget {
    TraceCallTarget::UserDefined {
        contract_name: contract_name.into(),
        function_name: function_name.into(),
    }
}

fn assert_begin_call(
    hook: &TraceHook,
    kind: TraceCallKind,
    target: TraceCallTarget,
    arg_count: usize,
) {
    assert!(
        hook.events.iter().any(|event| matches!(
            event,
            TraceEvent::BeginCall {
                kind: event_kind,
                target: event_target,
                arg_count: event_arg_count,
                ..
            } if *event_kind == kind
                && event_target == &target
                && *event_arg_count == arg_count
        )),
        "missing begin-call event for {kind:#?} {target:#?} with {arg_count} args\n{:#?}",
        hook.events
    );
}

fn assert_user_begin(
    hook: &TraceHook,
    kind: TraceCallKind,
    contract_name: &str,
    function_name: &str,
    arg_count: usize,
) {
    assert_begin_call(
        hook,
        kind,
        user_target(contract_name, function_name),
        arg_count,
    );
}

fn assert_builtin_begin(hook: &TraceHook, function_name: &'static str, arg_count: usize) {
    assert_begin_call(
        hook,
        TraceCallKind::Builtin,
        TraceCallTarget::Builtin(function_name.into()),
        arg_count,
    );
}

fn assert_no_begin_call(hook: &TraceHook, kind: TraceCallKind, target: TraceCallTarget) {
    assert!(
        !hook.events.iter().any(|event| matches!(
            event,
            TraceEvent::BeginCall {
                kind: event_kind,
                target: event_target,
                ..
            } if *event_kind == kind && event_target == &target
        )),
        "unexpected begin-call event for {kind:#?} {target:#?}\n{:#?}",
        hook.events
    );
}

fn assert_no_builtin_begin(hook: &TraceHook, function_name: &'static str) {
    assert_no_begin_call(
        hook,
        TraceCallKind::Builtin,
        TraceCallTarget::Builtin(function_name.into()),
    );
}

fn assert_argument_value(
    hook: &TraceHook,
    kind: TraceCallKind,
    target: TraceCallTarget,
    arg_index: usize,
    arg_name: &str,
    value: Value,
) {
    assert!(
        hook.events.iter().any(|event| matches!(
            event,
            TraceEvent::ArgumentValue {
                kind: event_kind,
                target: event_target,
                arg_index: event_arg_index,
                arg_name: event_arg_name,
                value: event_value,
                ..
            } if *event_kind == kind
                && event_target == &target
                && *event_arg_index == arg_index
                && event_arg_name == arg_name
                && event_value == &value
        )),
        "missing argument-value event for {kind:#?} {target:#?} arg {arg_index} {arg_name}={value:#?}\n{:#?}",
        hook.events
    );
}

fn assert_user_argument_value(
    hook: &TraceHook,
    kind: TraceCallKind,
    contract_name: &str,
    function_name: &str,
    arg_index: usize,
    arg_name: &str,
    value: Value,
) {
    assert_argument_value(
        hook,
        kind,
        user_target(contract_name, function_name),
        arg_index,
        arg_name,
        value,
    );
}

fn assert_builtin_argument_value(
    hook: &TraceHook,
    function_name: &'static str,
    arg_index: usize,
    value: Value,
) {
    assert_argument_value(
        hook,
        TraceCallKind::Builtin,
        TraceCallTarget::Builtin(function_name.into()),
        arg_index,
        &format!("arg{arg_index}"),
        value,
    );
}

fn assert_user_finish_value(
    hook: &TraceHook,
    kind: TraceCallKind,
    contract_name: &str,
    function_name: &str,
    value: Value,
) {
    let target = user_target(contract_name, function_name);
    assert!(
        hook.events.iter().any(|event| matches!(
            event,
            TraceEvent::FinishCall {
                kind: event_kind,
                target: event_target,
                result: TraceResult::Ok(event_value),
                ..
            } if *event_kind == kind
                && event_target == &target
                && event_value == &value
        )),
        "missing finish-call event for {kind:#?} {target:#?} -> {value:#?}\n{:#?}",
        hook.events
    );
}

impl EvalHook for TraceHook {
    fn will_begin_call(
        &mut self,
        _env: &mut ExecutionState,
        _invoke_ctx: &InvocationContext,
        call: &CallHook,
        args: CallArguments,
    ) {
        self.open_parent_arg_eval_if_needed();

        let arg_len = args.len();
        self.events.push(TraceEvent::BeginCall {
            depth: self.depth,
            kind: Self::call_kind(call),
            target: Self::call_target(call),
            arg_count: arg_len,
        });
        self.frames.push(TraceFrame {
            group_arg_evals: matches!(call, CallHook::UserDefined { .. }),
            arg_labels: (0..arg_len)
                .map(|arg_index| Self::arg_name(call, arg_index))
                .collect(),
            next_arg_index: 0,
            active_arg_index: None,
        });
        self.depth += 1;
    }

    fn did_evaluate_call_argument(
        &mut self,
        _env: &mut ExecutionState,
        _invoke_ctx: &InvocationContext,
        call: &CallHook,
        arg_index: usize,
        value: &Value,
    ) {
        self.close_current_arg_eval_if_needed(arg_index);

        self.events.push(TraceEvent::ArgumentValue {
            depth: self.depth,
            kind: Self::call_kind(call),
            target: Self::call_target(call),
            arg_index,
            arg_name: Self::arg_name(call, arg_index),
            value: value.clone(),
        });
    }

    fn did_finish_call(
        &mut self,
        _env: &mut ExecutionState,
        _invoke_ctx: &InvocationContext,
        call: &CallHook,
        res: &Result<Value, VmExecutionError>,
    ) {
        if let Some(frame) = self.frames.pop()
            && frame.active_arg_index.is_some()
        {
            self.depth = self.depth.saturating_sub(1);
        }
        self.depth = self.depth.saturating_sub(1);
        self.events.push(TraceEvent::FinishCall {
            depth: self.depth,
            kind: Self::call_kind(call),
            target: Self::call_target(call),
            result: match res {
                Ok(value) => TraceResult::Ok(value.clone()),
                Err(err) => TraceResult::Err(format!("{err:?}")),
            },
        });
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ExecutionLifecycleEvent {
    Begin,
    Finish(ExecutionOutcome),
}

#[derive(Default)]
struct ExecutionLifecycleHook {
    events: Vec<ExecutionLifecycleEvent>,
}

impl EvalHook for ExecutionLifecycleHook {
    fn will_begin_execution(&mut self) {
        self.events.push(ExecutionLifecycleEvent::Begin);
    }

    fn did_finish_execution(&mut self, outcome: ExecutionOutcome) {
        self.events.push(ExecutionLifecycleEvent::Finish(outcome));
    }
}

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
    assert_user_begin(&hook, TraceCallKind::UserPublic, "trace-test", "entry", 1);
    assert_user_argument_value(
        &hook,
        TraceCallKind::UserPublic,
        "trace-test",
        "entry",
        0,
        "seed",
        Value::UInt(0),
    );
    assert_user_begin(&hook, TraceCallKind::UserPrivate, "trace-test", "foo", 2);
    assert_user_argument_value(
        &hook,
        TraceCallKind::UserPrivate,
        "trace-test",
        "foo",
        0,
        "a",
        Value::UInt(1),
    );
    assert_user_argument_value(
        &hook,
        TraceCallKind::UserPrivate,
        "trace-test",
        "foo",
        1,
        "b",
        Value::UInt(42),
    );
    assert_user_argument_value(
        &hook,
        TraceCallKind::UserPrivate,
        "trace-test",
        "scale",
        0,
        "a",
        Value::UInt(1),
    );
    assert_builtin_argument_value(&hook, "+", 0, Value::UInt(10));
    assert_builtin_argument_value(&hook, "+", 1, Value::UInt(30));
}

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
    assert_builtin_begin(&hook, "if", 3);
    assert_builtin_begin(&hook, "+", 2);
    assert_no_builtin_begin(&hook, "/");
}

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
    assert_user_begin(&hook, TraceCallKind::UserPublic, "trace-caller", "entry", 1);
    assert_user_argument_value(
        &hook,
        TraceCallKind::UserPublic,
        "trace-caller",
        "entry",
        0,
        "seed",
        Value::UInt(7),
    );
    assert_user_begin(
        &hook,
        TraceCallKind::UserPrivate,
        "trace-caller",
        "call-runner",
        3,
    );
    assert_user_argument_value(
        &hook,
        TraceCallKind::UserPrivate,
        "trace-caller",
        "call-runner",
        0,
        "runner",
        Value::Principal(PrincipalData::Contract(
            QualifiedContractIdentifier::local("trace-impl").unwrap(),
        )),
    );
    assert_user_argument_value(
        &hook,
        TraceCallKind::UserPrivate,
        "trace-caller",
        "call-runner",
        1,
        "x",
        Value::UInt(7),
    );
    assert_user_argument_value(
        &hook,
        TraceCallKind::UserPrivate,
        "trace-caller",
        "call-runner",
        2,
        "y",
        Value::UInt(17),
    );
    assert_user_begin(&hook, TraceCallKind::UserPublic, "trace-impl", "do-it", 2);
    assert_user_argument_value(
        &hook,
        TraceCallKind::UserPublic,
        "trace-impl",
        "do-it",
        0,
        "x",
        Value::UInt(7),
    );
    assert_user_argument_value(
        &hook,
        TraceCallKind::UserPublic,
        "trace-impl",
        "do-it",
        1,
        "y",
        Value::UInt(17),
    );
    assert_user_finish_value(
        &hook,
        TraceCallKind::UserPublic,
        "trace-impl",
        "do-it",
        Value::okay(Value::UInt(24)).unwrap(),
    );
}
