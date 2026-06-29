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
use crate::vm::types::QualifiedContractIdentifier;
use crate::vm::{ClarityVersion, ContractContext, SymbolicExpression, Value, eval_all};

fn print_trace(test_name: &str, events: &[String]) {
    println!();
    println!("=== {test_name} trace ===");
    for event in events {
        println!("{event}");
    }
}

#[derive(Default)]
struct TraceHook {
    depth: usize,
    events: Vec<String>,
    frames: Vec<TraceFrame>,
}

struct TraceFrame {
    group_arg_evals: bool,
    arg_labels: Vec<String>,
    next_arg_index: usize,
    active_arg_index: Option<usize>,
}

impl TraceHook {
    fn call_target(call: &CallHook) -> String {
        match call {
            CallHook::Builtin { clarity_name, .. } => clarity_name.to_string(),
            CallHook::UserDefined {
                contract_identifier,
                function,
            } => format!("{}.{}", contract_identifier.name, function.name()),
        }
    }

    fn format_arg(call: &CallHook, arg_index: usize, value: &Value) -> String {
        let arg_name = Self::arg_name(call, arg_index);
        format!("{arg_name}={value}")
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

    fn contains(&self, needle: &str) -> bool {
        self.events.iter().any(|event| event.contains(needle))
    }

    fn arg_count_label(arg_count: usize) -> String {
        if arg_count == 1 {
            "1 arg".to_string()
        } else {
            format!("{arg_count} args")
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
        let arg_number = arg_index + 1;
        let arg_label = parent.arg_labels[arg_index].clone();
        self.events.push(format!(
            "{:indent$}arg {arg_number} eval: {arg_label}",
            "",
            indent = self.depth * 2
        ));
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

fn assert_trace_contains(hook: &TraceHook, needle: &str) {
    assert!(
        hook.contains(needle),
        "missing trace event containing {needle:?}\n{:#?}",
        hook.events
    );
}

fn assert_trace_excludes(hook: &TraceHook, needle: &str) {
    assert!(
        !hook.contains(needle),
        "unexpected trace event containing {needle:?}\n{:#?}",
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
        let arg_count = Self::arg_count_label(args.len());
        self.events.push(format!(
            "{:indent$}begin {} {} [{arg_count}]",
            "",
            call.kind(),
            Self::call_target(call),
            indent = self.depth * 2
        ));
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

        let arg_number = arg_index + 1;
        self.events.push(format!(
            "{:indent$}arg {arg_number} value: {} {} {}",
            "",
            call.kind(),
            Self::call_target(call),
            Self::format_arg(call, arg_index, value),
            indent = self.depth * 2
        ));
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
        let result = match res {
            Ok(value) => value.to_string(),
            Err(err) => format!("ERR {err:?}"),
        };
        self.events.push(format!(
            "{:indent$}end {} {} -> {}",
            "",
            call.kind(),
            Self::call_target(call),
            result,
            indent = self.depth * 2
        ));
    }
}

#[derive(Default)]
struct ExecutionLifecycleHook {
    events: Vec<String>,
}

impl EvalHook for ExecutionLifecycleHook {
    fn will_begin_execution(&mut self) {
        self.events.push("begin execution".to_string());
    }

    fn did_finish_execution(&mut self, outcome: ExecutionOutcome) {
        self.events.push(format!("finish execution {outcome:?}"));
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
        vec!["begin execution", "finish execution Success"]
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
        vec!["begin execution", "finish execution Failure"]
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

    print_trace("eval_hook_captures_effective_call_arguments", &hook.events);

    assert_eq!(value, Value::okay(Value::UInt(84)).unwrap());
    assert_trace_contains(&hook, "begin user-public trace-test.entry [1 arg]");
    assert_trace_contains(&hook, "arg 1 value: user-public trace-test.entry seed=u0");
    assert_trace_contains(&hook, "begin user-private trace-test.foo [2 args]");
    assert_trace_contains(&hook, "arg 1 value: user-private trace-test.foo a=u1");
    assert_trace_contains(&hook, "arg 2 value: user-private trace-test.foo b=u42");
    assert_trace_contains(&hook, "arg 1 value: user-private trace-test.scale a=u1");
    assert_trace_contains(&hook, "arg 1 value: builtin + arg0=u10");
    assert_trace_contains(&hook, "arg 2 value: builtin + arg1=u30");
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

    print_trace(
        "eval_hook_captures_lazy_special_form_call_tree",
        &hook.events,
    );

    assert_eq!(value, Value::okay(Value::UInt(3)).unwrap());
    assert_trace_contains(&hook, "begin builtin if [3 args]");
    assert_trace_contains(&hook, "begin builtin + [2 args]");
    assert_trace_excludes(&hook, "begin builtin /");
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

    print_trace(
        "eval_hook_captures_trait_dispatched_contract_call_arguments",
        &hook.events,
    );

    assert_eq!(value, Value::okay(Value::UInt(24)).unwrap());
    assert_trace_contains(&hook, "begin user-public trace-caller.entry [1 arg]");
    assert_trace_contains(&hook, "arg 1 value: user-public trace-caller.entry seed=u7");
    assert_trace_contains(
        &hook,
        "begin user-private trace-caller.call-runner [3 args]",
    );
    assert!(
        hook.events.iter().any(|event| event
            .contains("arg 1 value: user-private trace-caller.call-runner runner=")
            && event.contains(".trace-impl")),
        "{:#?}",
        hook.events
    );
    assert_trace_contains(
        &hook,
        "arg 2 value: user-private trace-caller.call-runner x=u7",
    );
    assert_trace_contains(
        &hook,
        "arg 3 value: user-private trace-caller.call-runner y=u17",
    );
    assert_trace_contains(&hook, "begin user-public trace-impl.do-it [2 args]");
    assert_trace_contains(&hook, "arg 1 value: user-public trace-impl.do-it x=u7");
    assert_trace_contains(&hook, "arg 2 value: user-public trace-impl.do-it y=u17");
}
