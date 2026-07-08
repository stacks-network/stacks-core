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
use crate::vm::hooks::trace::{CallTraceHook, TracedCall, TracedCallee, TracedResult};
use crate::vm::hooks::{CallArguments, CallHook, EvalHook, ExecutionOutcome};
use crate::vm::types::{PrincipalData, QualifiedContractIdentifier};
use crate::vm::{
    ClarityVersion, ContractContext, SymbolicExpression, SymbolicExpressionType, Value, eval_all,
};

fn print_trace(events: &[TraceEvent]) {
    let current_thread = std::thread::current();
    let test_name = current_thread
        .name()
        .and_then(|name| name.split("::").last())
        .unwrap_or("unknown test");
    println!();
    println!("=== {test_name} trace ===");
    for event in events {
        println!("{}", render_trace_event(event));
    }
    println!();
    println!("=== {test_name} call tree ===");
    print!("{}", render_clarity_call_tree(events));
}

/// Renders a single [`TraceEvent`] as one indented, human-readable line. Indentation
/// follows the call/argument nesting depth recorded on each event, producing a tree:
///
/// ```text
/// ▶ "trace-test.entry" [public] (1 arg)
///   𝑎₁ (seed) = u0
///   ▶ "trace-test.foo" [private] (2 args)
///     ↳ eval 𝑎₁ (a)
///       ▶ "+" [builtin] (2 args)
///       ◀ "+" ⇒ u42
///     𝑎₁ (a) = u42
///   ◀ "trace-test.foo" ⇒ u84
/// ◀ "trace-test.entry" ⇒ (ok u84)
/// ```
fn render_trace_event(event: &TraceEvent) -> String {
    match event {
        TraceEvent::BeginCall {
            depth,
            kind,
            target,
            arg_count,
            ..
        } => format!(
            "{}𝑓(𝑥) {} [{}] ({})",
            indent(*depth),
            render_target(target),
            render_kind(*kind),
            arg_count_label(*arg_count),
        ),
        TraceEvent::BeginArgumentEval {
            depth,
            arg_index,
            arg_name,
        } => format!(
            "{}𝑓(𝑎{}) \"{arg_name}\"",
            indent(*depth),
            subscript(arg_index + 1),
        ),
        TraceEvent::ArgumentValue {
            depth,
            arg_index,
            arg_name,
            value,
            ..
        } => format!(
            "{}𝑎{} \"{arg_name}\" = {value}",
            indent(*depth),
            subscript(arg_index + 1),
        ),
        TraceEvent::FinishCall {
            depth,
            target,
            result,
            ..
        } => format!(
            "{}⏎ {} ⇒ {}",
            indent(*depth),
            render_target(target),
            render_result(result),
        ),
    }
}

fn indent(depth: usize) -> String {
    "  ".repeat(depth)
}

fn render_kind(kind: TraceCallKind) -> &'static str {
    match kind {
        TraceCallKind::Builtin => "builtin",
        TraceCallKind::UserPublic => "public",
        TraceCallKind::UserPrivate => "private",
        TraceCallKind::UserReadOnly => "read-only",
    }
}

fn render_target(target: &TraceCallTarget) -> String {
    match target {
        TraceCallTarget::Builtin(name) => format!("\"{name}\""),
        TraceCallTarget::UserDefined {
            contract_name,
            function_name,
        } => format!("\"{contract_name}.{function_name}\""),
    }
}

fn render_result(result: &TraceResult) -> String {
    match result {
        TraceResult::Ok(value) => value.to_string(),
        TraceResult::Err(err) => format!("ERR {err}"),
    }
}

fn arg_count_label(arg_count: usize) -> String {
    if arg_count == 1 {
        "1 arg".to_string()
    } else {
        format!("{arg_count} args")
    }
}

/// Renders `n` using Unicode subscript digits (e.g. `12` -> `₁₂`).
fn subscript(n: usize) -> String {
    n.to_string()
        .chars()
        .map(|digit| match digit {
            '0' => '₀',
            '1' => '₁',
            '2' => '₂',
            '3' => '₃',
            '4' => '₄',
            '5' => '₅',
            '6' => '₆',
            '7' => '₇',
            '8' => '₈',
            '9' => '₉',
            other => other,
        })
        .collect()
}

/// How an argument's value was produced, captured from its source expression at call time.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ArgKind {
    /// A variable/keyword reference, e.g. `acc` — the value is a resolved lookup.
    Variable(String),
    /// An inline literal, e.g. `u2`.
    Literal,
    /// A nested call expression, e.g. `(* item u2)` — produced by a child call.
    Call,
    /// The argument arrived already evaluated (no source expression, e.g. `fold` step
    /// functions and transaction entry points).
    ValueOnly,
}

/// An argument's begin-time source classification plus its rendered source text (used
/// for special forms, which report source but no evaluated values).
#[derive(Debug, Clone, PartialEq, Eq)]
struct ArgSource {
    kind: ArgKind,
    text: String,
}

/// Classifies an argument's source expression as a variable reference, a literal, or a
/// nested call, and records its rendered source text.
fn classify_arg_source(expr: &SymbolicExpression) -> ArgSource {
    let kind = match &expr.expr {
        SymbolicExpressionType::Atom(_) => ArgKind::Variable(expr.to_string()),
        SymbolicExpressionType::List(_) => ArgKind::Call,
        _ => ArgKind::Literal,
    };
    ArgSource {
        kind,
        text: expr.to_string(),
    }
}

/// A call reconstructed from the flat [`TraceEvent`] stream: its resolved argument
/// values, its result, and the nested calls that produced those arguments.
struct CallNode {
    kind: TraceCallKind,
    target: TraceCallTarget,
    /// `(arg_name, evaluated_value)` pairs, in evaluation order. Empty for special
    /// forms (`if`, `and`, ...) that evaluate their own arguments and report none.
    args: Vec<(String, Value)>,
    /// Per-argument source classification, captured when the call opened.
    arg_sources: Vec<ArgSource>,
    result: Option<TraceResult>,
    children: Vec<CallNode>,
    /// The argument index of the *parent* that this call produces, if it was invoked
    /// while evaluating one of the parent's arguments (vs. inside the parent's body).
    producing_arg: Option<usize>,
    /// Cross-reference label (`𝑓ₙ`) assigned when this call produces a parent call-argument.
    label: Option<usize>,
}

/// Reconstructs the call forest from the linear event stream using begin/finish as
/// push/pop. Argument values attach to the call on top of the stack — which is always
/// the consuming call, since a callable's `did_evaluate_call_argument` fires only after
/// the nested calls that produced that argument have finished and been popped.
///
/// Each child records `producing_arg`: the count of the parent's arguments reported so
/// far when the child opened. If that index is within the parent's argument list, the
/// child produced that argument (left-to-right arg evaluation); otherwise it ran in the
/// parent's body.
fn build_call_forest(events: &[TraceEvent]) -> Vec<CallNode> {
    let mut roots = Vec::new();
    let mut stack: Vec<CallNode> = Vec::new();
    for event in events {
        match event {
            TraceEvent::BeginCall {
                kind,
                target,
                arg_sources,
                ..
            } => {
                let producing_arg = stack.last().map(|parent| parent.args.len());
                stack.push(CallNode {
                    kind: *kind,
                    target: target.clone(),
                    args: Vec::new(),
                    arg_sources: arg_sources.clone(),
                    result: None,
                    children: Vec::new(),
                    producing_arg,
                    label: None,
                });
            }
            TraceEvent::ArgumentValue {
                arg_name, value, ..
            } => {
                if let Some(node) = stack.last_mut() {
                    node.args.push((arg_name.clone(), value.clone()));
                }
            }
            TraceEvent::FinishCall { result, .. } => {
                if let Some(mut node) = stack.pop() {
                    node.result = Some(result.clone());
                    match stack.last_mut() {
                        Some(parent) => parent.children.push(node),
                        None => roots.push(node),
                    }
                }
            }
            TraceEvent::BeginArgumentEval { .. } => {}
        }
    }
    roots
}

/// Assigns a fresh, globally-unique `𝑓ₙ` label (in reading order) to every call that
/// produces one of its parent's call-typed arguments.
fn assign_labels(node: &mut CallNode, next_label: &mut usize) {
    for child in &mut node.children {
        if child.producing_arg.is_some_and(|index| {
            node.arg_sources
                .get(index)
                .is_some_and(|source| source.kind == ArgKind::Call)
        }) {
            child.label = Some(*next_label);
            *next_label += 1;
        }
        assign_labels(child, next_label);
    }
}

/// Renders the call tree as executed Clarity-ish call notation. Arguments are annotated
/// with their origin: `𝑥(name)=value` for variable references, `𝑓ₙ=value` for values
/// produced by a nested call (cross-referenced to that child's trailing `(𝑓ₙ)` tag),
/// and bare `value` for literals.
///
/// ```text
/// (trace-fold.accumulate item=u1 acc=u0) ⇒ u2
///     (+ 𝑥(acc)=u0 𝑓₁=u2) ⇒ u2
///         (* 𝑥(item)=u1 u2) ⇒ u2  (𝑓₁)
/// ```
fn render_clarity_call_tree(events: &[TraceEvent]) -> String {
    let mut roots = build_call_forest(events);
    let mut next_label = 1;
    for root in &mut roots {
        assign_labels(root, &mut next_label);
    }
    let mut out = String::new();
    for root in &roots {
        render_call_node(root, 0, &mut out);
    }
    out
}

fn render_call_node(node: &CallNode, depth: usize, out: &mut String) {
    let result = node
        .result
        .as_ref()
        .map(render_result)
        .unwrap_or_else(|| "<unfinished>".to_string());
    let head = clarity_call_name(&node.target);
    let args = render_call_args(node);
    // s-expression head notation, per node: `(head args)`. Nested calls stay on their
    // own indented lines (we do NOT inline children into the parent expression, which
    // is what would collapse the whole trace onto one line).
    let call = if args.is_empty() {
        format!("({head})")
    } else {
        format!("({head} {args})")
    };
    // Trailing cross-reference tag: this call produces its parent's `𝑓ₙ` argument.
    let rendered_result = match node.label {
        Some(label) => format!("𝑓{}={result}", subscript(label)),
        None => result,
    };
    out.push_str(&format!(
        "{}{call} ⇒ {rendered_result}\n",
        "    ".repeat(depth)
    ));
    for child in &node.children {
        render_call_node(child, depth + 1, out);
    }
}

fn clarity_call_name(target: &TraceCallTarget) -> String {
    match target {
        TraceCallTarget::Builtin(name) => name.clone(),
        TraceCallTarget::UserDefined {
            contract_name,
            function_name,
        } => format!("{contract_name}.{function_name}"),
    }
}

/// Looks up the `𝑓ₙ` label of the child call that produced argument `index`.
fn child_label_for_arg(node: &CallNode, index: usize) -> Option<usize> {
    node.children
        .iter()
        .find(|child| child.producing_arg == Some(index))
        .and_then(|child| child.label)
}

fn render_call_args(node: &CallNode) -> String {
    // Special forms report no evaluated arguments; fall back to raw source expressions.
    if node.args.is_empty() {
        return node
            .arg_sources
            .iter()
            .map(|source| source.text.clone())
            .collect::<Vec<_>>()
            .join(" ");
    }
    node.args
        .iter()
        .enumerate()
        .map(|(index, (arg_name, value))| {
            match node.arg_sources.get(index).map(|source| &source.kind) {
                Some(ArgKind::Variable(name)) => format!("𝑥({name})={value}"),
                Some(ArgKind::Call) => match child_label_for_arg(node, index) {
                    Some(label) => format!("𝑓{}={value}", subscript(label)),
                    None => value.to_string(),
                },
                Some(ArgKind::Literal) => value.to_string(),
                // Pre-evaluated args: keep the user-function parameter name where we have
                // one; builtins have only synthetic names, so render positionally.
                _ => match node.kind {
                    TraceCallKind::Builtin => value.to_string(),
                    _ => format!("{arg_name}={value}"),
                },
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
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
        /// Per-argument source classification captured when the call opened: unevaluated
        /// expressions for source-level calls (special forms included), or `ValueOnly` for
        /// pre-evaluated call paths.
        arg_sources: Vec<ArgSource>,
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
        // Classify each begin-time argument. Source-level calls (special forms like
        // `if`/`fold`/`contract-call?` included) carry unevaluated expressions we can
        // classify as variable/literal/call; pre-evaluated call paths carry only values.
        let arg_sources = match args {
            CallArguments::Expressions(exprs) => exprs.iter().map(classify_arg_source).collect(),
            CallArguments::Values(values) => values
                .iter()
                .map(|value| ArgSource {
                    kind: ArgKind::ValueOnly,
                    text: value.to_string(),
                })
                .collect(),
        };
        self.events.push(TraceEvent::BeginCall {
            depth: self.depth,
            kind: Self::call_kind(call),
            target: Self::call_target(call),
            arg_count: arg_len,
            arg_sources,
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
    assert_builtin_begin(&hook, "fold", 3);
    // First iteration: item is the first list element, acc is the seed.
    assert_user_argument_value(
        &hook,
        TraceCallKind::UserPrivate,
        "trace-fold",
        "accumulate",
        0,
        "item",
        Value::UInt(1),
    );
    assert_user_argument_value(
        &hook,
        TraceCallKind::UserPrivate,
        "trace-fold",
        "accumulate",
        1,
        "acc",
        Value::UInt(0),
    );
    // Final iteration threads the running accumulator: item=u3, acc=u6.
    assert_user_argument_value(
        &hook,
        TraceCallKind::UserPrivate,
        "trace-fold",
        "accumulate",
        0,
        "item",
        Value::UInt(3),
    );
    assert_user_argument_value(
        &hook,
        TraceCallKind::UserPrivate,
        "trace-fold",
        "accumulate",
        1,
        "acc",
        Value::UInt(6),
    );
    assert_user_finish_value(
        &hook,
        TraceCallKind::UserPrivate,
        "trace-fold",
        "accumulate",
        Value::UInt(12),
    );
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
    assert_user_begin(&hook, TraceCallKind::UserPublic, "trace-top", "entry", 1);
    assert_user_begin(
        &hook,
        TraceCallKind::UserPublic,
        "trace-agg",
        "sum-doubled",
        1,
    );
    assert_builtin_begin(&hook, "fold", 3);
    assert_user_begin(
        &hook,
        TraceCallKind::UserPrivate,
        "trace-agg",
        "add-doubled",
        2,
    );
    // Branching forms are captured as builtin calls.
    assert_builtin_begin(&hook, "if", 3);
    assert_builtin_begin(&hook, "match", 5);

    // First fold step: item=u2, acc=u0, contract-calling double(n=u2) ⇒ (ok u4).
    assert_user_argument_value(
        &hook,
        TraceCallKind::UserPrivate,
        "trace-agg",
        "add-doubled",
        0,
        "item",
        Value::UInt(2),
    );
    assert_user_argument_value(
        &hook,
        TraceCallKind::UserPrivate,
        "trace-agg",
        "add-doubled",
        1,
        "acc",
        Value::UInt(0),
    );
    assert_user_begin(&hook, TraceCallKind::UserPublic, "trace-math", "double", 1);
    assert_user_argument_value(
        &hook,
        TraceCallKind::UserPublic,
        "trace-math",
        "double",
        0,
        "n",
        Value::UInt(2),
    );
    assert_user_finish_value(
        &hook,
        TraceCallKind::UserPublic,
        "trace-math",
        "double",
        Value::okay(Value::UInt(4)).unwrap(),
    );

    // Final fold step takes the `if` skip branch: item=u0, acc=u10, and simply returns
    // the accumulator (no contract-call is made for this element).
    assert_user_argument_value(
        &hook,
        TraceCallKind::UserPrivate,
        "trace-agg",
        "add-doubled",
        0,
        "item",
        Value::UInt(0),
    );
    assert_user_argument_value(
        &hook,
        TraceCallKind::UserPrivate,
        "trace-agg",
        "add-doubled",
        1,
        "acc",
        Value::UInt(10),
    );
    assert_user_finish_value(
        &hook,
        TraceCallKind::UserPublic,
        "trace-agg",
        "sum-doubled",
        Value::okay(Value::UInt(10)).unwrap(),
    );
}

/// Flattens a call forest into a pre-order list of references.
fn flatten_calls(calls: &[TracedCall]) -> Vec<&TracedCall> {
    fn walk<'a>(calls: &'a [TracedCall], out: &mut Vec<&'a TracedCall>) {
        for call in calls {
            out.push(call);
            walk(&call.children, out);
        }
    }
    let mut out = Vec::new();
    walk(calls, &mut out);
    out
}

#[test]
fn call_trace_hook_resolves_state_reads_and_captures_cost() {
    let mut marf = MemoryBackingStore::new();
    // A memory-backed store has no boot cost contracts, so it runs with the free cost
    // tracker and per-call cost deltas are zero here. This test validates the resolved
    // tree, value resolution, and the eval-merge for special-form arguments; non-zero
    // cost magnitude is exercised against a real cost tracker in the replay path.
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
    // The root carries the transaction's return value, confirming it finished and its
    // children attached to it (rather than to a stray root).
    assert_eq!(
        run.result,
        Some(TracedResult::Ok(
            Value::okay(Value::some(Value::UInt(1000)).unwrap()).unwrap()
        )),
        "run returned (ok (some u1000)): {:?}",
        run.result
    );

    let calls = flatten_calls(roots);

    // (a) Cost is sampled per call, and the exclusive-of-children subtraction never yields
    //     more than the inclusive cost in any dimension. (Trivially satisfied under the free
    //     tracker where all costs are zero, but it exercises the sampling + subtraction path.)
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
