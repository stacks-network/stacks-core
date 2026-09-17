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

//! Reusable [`EvalHook`] test fixtures, trace rendering, and assertions.
//!
//! This module is available to this crate's unit tests and to downstream test code that enables the
//! `testing` feature.

pub mod render;

use crate::vm::contexts::{ExecutionState, InvocationContext};
use crate::vm::errors::VmExecutionError;
use crate::vm::hooks::trace::TracedCall;
use crate::vm::hooks::{CallArguments, CallHook, EvalHook, ExecutionOutcome};
use crate::vm::{SymbolicExpression, SymbolicExpressionType, Value};

/// Flattens a call forest into a pre-order list of references.
pub fn flatten_calls(calls: &[TracedCall]) -> Vec<&TracedCall> {
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

/// How an argument's value was produced, captured from its source expression at call time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgKind {
    /// A variable/keyword reference, e.g. `acc` — the value is a resolved lookup.
    Variable(String),
    /// An inline literal, e.g. `u2`.
    Literal,
    /// A nested call expression, e.g. `(* item u2)` — produced by a child call.
    Call,
    /// The argument arrived already evaluated (no source expression, e.g. `fold` step functions and
    /// transaction entry points).
    ValueOnly,
}

/// An argument's begin-time source classification plus its rendered source text (used for special
/// forms, which report source but no evaluated values).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgSource {
    /// Classification of how the argument value was produced.
    kind: ArgKind,
    /// Source expression rendered when the call began.
    text: String,
}

/// Classifies an argument's source expression as a variable reference, a literal, or a nested call,
/// and records its rendered source text.
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

/// An [`EvalHook`] that records calls, evaluated arguments, results, and nesting depth.
#[derive(Default)]
pub struct TraceHook {
    /// Current rendered nesting depth.
    depth: usize,
    /// Linear stream of call and argument events observed by this hook.
    pub events: Vec<TraceEvent>,
    /// In-progress call frames used to group nested argument evaluation.
    frames: Vec<TraceFrame>,
}

/// One event in the linear call trace recorded by [`TraceHook`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraceEvent {
    /// Evaluation of one user-function argument has begun.
    BeginArgumentEval {
        /// Rendered nesting depth of the argument evaluation.
        depth: usize,
        /// Zero-based argument position.
        arg_index: usize,
        /// User-facing argument name.
        arg_name: String,
    },
    /// A builtin or user-defined call has begun.
    BeginCall {
        /// Rendered nesting depth of the call.
        depth: usize,
        /// Category of callable being invoked.
        kind: TraceCallKind,
        /// Identity of the callable being invoked.
        target: TraceCallTarget,
        /// Number of arguments received by the call.
        arg_count: usize,
        /// Per-argument source classification captured when the call opened: unevaluated
        /// expressions for source-level calls (special forms included), or `ValueOnly` for
        /// pre-evaluated call paths.
        arg_sources: Vec<ArgSource>,
    },
    /// One call argument has evaluated to its effective value.
    ArgumentValue {
        /// Rendered nesting depth of the resolved argument.
        depth: usize,
        /// Category of the call receiving the argument.
        kind: TraceCallKind,
        /// Identity of the call receiving the argument.
        target: TraceCallTarget,
        /// Zero-based argument position.
        arg_index: usize,
        /// User-facing argument name.
        arg_name: String,
        /// Effective value received by the call.
        value: Value,
    },
    /// A builtin or user-defined call has finished.
    FinishCall {
        /// Rendered nesting depth of the completed call.
        depth: usize,
        /// Category of callable that completed.
        kind: TraceCallKind,
        /// Identity of the callable that completed.
        target: TraceCallTarget,
        /// Success value or execution error reported by the call.
        result: TraceResult,
    },
}

/// Stable category assigned to a traced callable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceCallKind {
    /// Builtin function or special form.
    Builtin,
    /// User-defined public function.
    UserPublic,
    /// User-defined private function.
    UserPrivate,
    /// User-defined read-only function.
    UserReadOnly,
}

/// Identity of a builtin or user-defined traced call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraceCallTarget {
    /// Builtin identified by its Clarity source-level name.
    Builtin(String),
    /// User-defined function identified by contract and function name.
    UserDefined {
        /// Contract name containing the function.
        contract_name: String,
        /// Name of the user-defined function.
        function_name: String,
    },
}

/// Success value or execution error recorded when a traced call finishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraceResult {
    /// Call completed successfully with this value.
    Ok(Value),
    /// Call failed with this debug-formatted error.
    Err(String),
}

/// In-progress argument-evaluation state for a [`TraceHook`] call frame.
struct TraceFrame {
    /// Whether nested calls should be grouped under argument-evaluation markers.
    group_arg_evals: bool,
    /// User-facing labels for the call's arguments.
    arg_labels: Vec<String>,
    /// Next argument position expected to be evaluated.
    next_arg_index: usize,
    /// Argument currently being evaluated, when one is open.
    active_arg_index: Option<usize>,
}

impl TraceHook {
    /// Converts a VM call descriptor into the test trace's stable call category.
    fn call_kind(call: &CallHook) -> TraceCallKind {
        match call.kind() {
            "builtin" => TraceCallKind::Builtin,
            "user-public" => TraceCallKind::UserPublic,
            "user-private" => TraceCallKind::UserPrivate,
            "user-read-only" => TraceCallKind::UserReadOnly,
            other => panic!("unexpected call hook kind: {other}"),
        }
    }

    /// Converts a VM call descriptor into its recorded target identity.
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

    /// Returns the declared user-function argument name or a positional fallback.
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

    /// Opens the pending argument-evaluation marker for the current parent call.
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

    /// Advances argument bookkeeping and closes the matching evaluation marker.
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

impl TraceCallTarget {
    /// Creates a target for a user-defined contract function.
    pub fn user(contract_name: &str, function_name: &str) -> Self {
        Self::UserDefined {
            contract_name: contract_name.into(),
            function_name: function_name.into(),
        }
    }
}

impl TraceHook {
    /// Asserts that a call began with the expected kind, target, and argument count.
    #[track_caller]
    fn assert_begin_call(&self, kind: TraceCallKind, target: TraceCallTarget, arg_count: usize) {
        assert!(
            self.events.iter().any(|event| matches!(
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
            self.events
        );
    }

    /// Asserts that a user-defined call began with the expected identity and argument count.
    #[track_caller]
    pub fn assert_user_begin(
        &self,
        kind: TraceCallKind,
        contract_name: &str,
        function_name: &str,
        arg_count: usize,
    ) {
        self.assert_begin_call(
            kind,
            TraceCallTarget::user(contract_name, function_name),
            arg_count,
        );
    }

    /// Asserts that a builtin call began with the expected name and argument count.
    #[track_caller]
    pub fn assert_builtin_begin(&self, function_name: &'static str, arg_count: usize) {
        self.assert_begin_call(
            TraceCallKind::Builtin,
            TraceCallTarget::Builtin(function_name.into()),
            arg_count,
        );
    }

    /// Asserts that no call began with the expected kind and target.
    #[track_caller]
    fn assert_no_begin_call(&self, kind: TraceCallKind, target: TraceCallTarget) {
        assert!(
            !self.events.iter().any(|event| matches!(
                event,
                TraceEvent::BeginCall {
                    kind: event_kind,
                    target: event_target,
                    ..
                } if *event_kind == kind && event_target == &target
            )),
            "unexpected begin-call event for {kind:#?} {target:#?}\n{:#?}",
            self.events
        );
    }

    /// Asserts that no builtin call began with the given name.
    #[track_caller]
    pub fn assert_no_builtin_begin(&self, function_name: &'static str) {
        self.assert_no_begin_call(
            TraceCallKind::Builtin,
            TraceCallTarget::Builtin(function_name.into()),
        );
    }

    /// Asserts the resolved value and identity of one call argument.
    #[track_caller]
    fn assert_argument_value(
        &self,
        kind: TraceCallKind,
        target: TraceCallTarget,
        arg_index: usize,
        arg_name: &str,
        value: Value,
    ) {
        assert!(
            self.events.iter().any(|event| matches!(
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
            self.events
        );
    }

    /// Asserts the resolved value of one user-defined call argument.
    #[track_caller]
    pub fn assert_user_argument_value(
        &self,
        kind: TraceCallKind,
        contract_name: &str,
        function_name: &str,
        arg_index: usize,
        arg_name: &str,
        value: Value,
    ) {
        self.assert_argument_value(
            kind,
            TraceCallTarget::user(contract_name, function_name),
            arg_index,
            arg_name,
            value,
        );
    }

    /// Asserts the resolved value of one builtin call argument.
    #[track_caller]
    pub fn assert_builtin_argument_value(
        &self,
        function_name: &'static str,
        arg_index: usize,
        value: Value,
    ) {
        self.assert_argument_value(
            TraceCallKind::Builtin,
            TraceCallTarget::Builtin(function_name.into()),
            arg_index,
            &format!("arg{arg_index}"),
            value,
        );
    }

    /// Asserts that a user-defined call finished successfully with the expected value.
    #[track_caller]
    pub fn assert_user_finish_value(
        &self,
        kind: TraceCallKind,
        contract_name: &str,
        function_name: &str,
        value: Value,
    ) {
        let target = TraceCallTarget::user(contract_name, function_name);
        assert!(
            self.events.iter().any(|event| matches!(
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
            self.events
        );
    }
}

impl EvalHook for TraceHook {
    /// Records a new call and opens its trace frame.
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
        // `if`/`fold`/`contract-call?` included) carry unevaluated expressions we can classify as
        // variable/literal/call; pre-evaluated call paths carry only values.
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

    /// Records an effective argument value and advances argument-frame bookkeeping.
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

    /// Closes the active call frame and records its success or error result.
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

/// Top-level execution lifecycle notification recorded by [`ExecutionLifecycleHook`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionLifecycleEvent {
    /// Top-level execution began.
    Begin,
    /// Top-level execution finished with the contained outcome.
    Finish(ExecutionOutcome),
}

/// An [`EvalHook`] that records top-level execution lifecycle notifications.
#[derive(Default)]
pub struct ExecutionLifecycleHook {
    /// Lifecycle notifications in the order they were observed.
    pub events: Vec<ExecutionLifecycleEvent>,
}

impl EvalHook for ExecutionLifecycleHook {
    /// Records the beginning of top-level execution.
    fn will_begin_execution(&mut self) {
        self.events.push(ExecutionLifecycleEvent::Begin);
    }

    /// Records the outcome of completed top-level execution.
    fn did_finish_execution(&mut self, outcome: ExecutionOutcome) {
        self.events.push(ExecutionLifecycleEvent::Finish(outcome));
    }
}

/// A completed call observed by [`CallStackCheckingHook`].
#[derive(Debug, PartialEq, Eq)]
pub struct CompletedCall {
    /// Stable `kind:name` label identifying the completed call.
    pub label: String,
    /// Whether the call completed with a VM execution error.
    pub failed: bool,
}

/// Calls and outcome recorded for one completed top-level execution.
#[derive(Debug, PartialEq, Eq)]
pub struct CompletedExecution {
    /// Overall top-level execution outcome.
    pub outcome: ExecutionOutcome,
    /// Calls completed during the execution, in completion order.
    pub calls: Vec<CompletedCall>,
}

/// An [`EvalHook`] that asserts call frames open and close in strict LIFO order.
#[derive(Default)]
pub struct CallStackCheckingHook {
    /// Labels of calls that have begun but not yet finished.
    stack: Vec<String>,
    /// Calls completed during the active top-level execution.
    current_calls: Vec<CompletedCall>,
    /// Completed top-level executions in observation order.
    pub executions: Vec<CompletedExecution>,
    /// Greatest number of simultaneously open calls observed by the hook.
    pub max_depth: usize,
}

impl CallStackCheckingHook {
    /// Builds the stable `kind:name` label used for stack matching.
    fn call_label(call: &CallHook) -> String {
        format!("{}:{}", call.kind(), call.clarity_name())
    }
}

impl EvalHook for CallStackCheckingHook {
    /// Verifies that no call state leaked from the preceding execution.
    fn will_begin_execution(&mut self) {
        assert!(
            self.stack.is_empty(),
            "a new execution started with stale call frames: {:?}",
            self.stack
        );
        assert!(
            self.current_calls.is_empty(),
            "a new execution started with uncommitted call results: {:?}",
            self.current_calls
        );
    }

    /// Verifies an empty call stack and commits the completed execution record.
    fn did_finish_execution(&mut self, outcome: ExecutionOutcome) {
        assert!(
            self.stack.is_empty(),
            "execution finished with unclosed call frames: {:?}",
            self.stack
        );
        self.executions.push(CompletedExecution {
            outcome,
            calls: std::mem::take(&mut self.current_calls),
        });
    }

    /// Pushes a call label and updates the greatest observed stack depth.
    fn will_begin_call(
        &mut self,
        _env: &mut ExecutionState,
        _invoke_ctx: &InvocationContext,
        call: &CallHook,
        _args: CallArguments,
    ) {
        self.stack.push(Self::call_label(call));
        self.max_depth = self.max_depth.max(self.stack.len());
    }

    /// Pops and verifies the matching call, then records its completion status.
    fn did_finish_call(
        &mut self,
        _env: &mut ExecutionState,
        _invoke_ctx: &InvocationContext,
        call: &CallHook,
        res: &Result<Value, VmExecutionError>,
    ) {
        let actual = Self::call_label(call);
        let expected = self
            .stack
            .pop()
            .expect("received a finish notification without a matching begin");
        assert_eq!(
            actual, expected,
            "call finish notifications must unwind in LIFO order"
        );
        self.current_calls.push(CompletedCall {
            label: actual,
            failed: res.is_err(),
        });
    }
}
