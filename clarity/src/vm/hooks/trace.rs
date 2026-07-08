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

use std::time::{Duration, Instant};

use super::{CallArguments, CallHook, EvalHook};
use crate::vm::ValueRef;
use crate::vm::callables::DefineType;
use crate::vm::contexts::{ExecutionState, InvocationContext, LocalContext};
use crate::vm::costs::ExecutionCost;
use crate::vm::errors::VmExecutionError;
use crate::vm::representations::{SymbolicExpression, SymbolicExpressionType};
use crate::vm::types::{QualifiedContractIdentifier, Value};

/// Identity of a traced callable.
#[derive(Debug, Clone, PartialEq)]
pub enum TracedCallee {
    /// A built-in or special-form callable.
    Builtin {
        /// Clarity source-level name, e.g. `"+"`, `"map-get?"`.
        clarity_name: String,
        /// Rust implementation name, e.g. `"native_add"`.
        rust_name: String,
    },
    /// A user-defined contract function.
    UserDefined {
        /// The contract that owns the function.
        contract: QualifiedContractIdentifier,
        /// The function's Clarity name.
        function: String,
        /// The function's visibility.
        define_type: DefineType,
    },
}

/// How a traced argument's value was produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgOrigin {
    /// A source atom: usually a variable/keyword reference, but also a name used by a
    /// special form (a map name, a `fold` step-function name, a trait identifier, ...).
    /// The string is the atom's source text.
    Atom(String),
    /// An inline literal.
    Literal,
    /// A nested call expression, produced by a child call.
    Call,
    /// The argument arrived already evaluated (no source expression available).
    Value,
}

/// A single argument of a traced call: where it came from and its resolved value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TracedArg {
    /// The callee's parameter name, when known (user-defined functions).
    pub name: Option<String>,
    /// How the argument's value was produced.
    pub origin: ArgOrigin,
    /// The argument's rendered source expression.
    pub source: String,
    /// The resolved argument value. Present for evaluated arguments; may be `None` for
    /// arguments a special form never evaluates (e.g. a map name).
    pub value: Option<Value>,
}

/// The result of a traced call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TracedResult {
    /// The call returned this value.
    Ok(Value),
    /// The call errored; the string is the debug representation of the error.
    Err(String),
}

/// A fully reconstructed call: its identity, resolved arguments, result, cost, timing,
/// and the nested calls that produced its arguments and body.
///
/// This is the unit of a resolved call trace — a self-contained record of what ran,
/// with what values, at what cost. It captures the Clarity-level values observed by
/// the traced execution, which can help reconstruct an equivalent scenario.
#[derive(Debug, Clone)]
pub struct TracedCall {
    /// The callable that was invoked.
    pub callee: TracedCallee,
    /// The resolved arguments, in source order.
    pub args: Vec<TracedArg>,
    /// The call's result (`None` only if collection was interrupted mid-call).
    pub result: Option<TracedResult>,
    /// Execution cost charged during this call, including its children.
    pub cost_inclusive: ExecutionCost,
    /// Execution cost attributable to this call alone (inclusive minus children).
    pub cost_exclusive: ExecutionCost,
    /// Wall-clock time spent in this call, including its children.
    pub wall_time: Duration,
    /// Nested calls, in execution order.
    pub children: Vec<TracedCall>,
}

/// An in-progress call on the collector's stack.
struct PendingCall {
    callee: TracedCallee,
    args: Vec<TracedArg>,
    /// Source-expression ids of the arguments, used to resolve values for special-form
    /// arguments via [`EvalHook::did_finish_eval`]. Empty for pre-evaluated call paths.
    arg_ids: Vec<u64>,
    cost_at_begin: ExecutionCost,
    time_at_begin: Instant,
    children: Vec<TracedCall>,
}

/// An [`EvalHook`] that reconstructs a resolved call tree from the VM's call and eval
/// notifications, annotating each call with its resolved arguments, result, execution
/// cost (inclusive and exclusive of children), and wall-clock time.
///
/// Register it with `OwnedEnvironment::add_eval_hook`, run a transaction, then read the
/// collected roots with [`CallTraceHook::calls`] / [`CallTraceHook::into_calls`].
#[derive(Default)]
pub struct CallTraceHook {
    stack: Vec<PendingCall>,
    roots: Vec<TracedCall>,
}

impl CallTraceHook {
    /// Creates an empty collector.
    pub fn new() -> Self {
        Self::default()
    }

    /// The top-level calls collected so far, in execution order.
    pub fn calls(&self) -> &[TracedCall] {
        &self.roots
    }

    /// Consumes the collector, returning the collected top-level calls.
    pub fn into_calls(self) -> Vec<TracedCall> {
        self.roots
    }

    /// Removes and returns the collected top-level calls, leaving the collector empty so it
    /// can be reused for a subsequent execution (e.g. the next transaction in a block).
    pub fn take_calls(&mut self) -> Vec<TracedCall> {
        std::mem::take(&mut self.roots)
    }

    fn callee_of(call: &CallHook) -> TracedCallee {
        match call {
            CallHook::Builtin {
                clarity_name,
                rust_name,
            } => TracedCallee::Builtin {
                clarity_name: (*clarity_name).to_string(),
                rust_name: (*rust_name).to_string(),
            },
            CallHook::UserDefined {
                contract_identifier,
                function,
            } => TracedCallee::UserDefined {
                contract: (*contract_identifier).clone(),
                function: function.name().to_string(),
                define_type: function.define_type.clone(),
            },
        }
    }

    /// Builds the argument records (and their source-expression ids) for a call.
    fn build_args(call: &CallHook, args: CallArguments) -> (Vec<TracedArg>, Vec<u64>) {
        let param_name = |index: usize| match call {
            CallHook::UserDefined { function, .. } => function
                .argument_names()
                .get(index)
                .map(ToString::to_string),
            CallHook::Builtin { .. } => None,
        };
        match args {
            CallArguments::Expressions(exprs) => {
                let mut traced = Vec::with_capacity(exprs.len());
                let mut ids = Vec::with_capacity(exprs.len());
                for (index, expr) in exprs.iter().enumerate() {
                    let origin = match &expr.expr {
                        SymbolicExpressionType::Atom(name) => ArgOrigin::Atom(name.to_string()),
                        SymbolicExpressionType::List(_) => ArgOrigin::Call,
                        _ => ArgOrigin::Literal,
                    };
                    ids.push(expr.id);
                    traced.push(TracedArg {
                        name: param_name(index),
                        origin,
                        source: expr.to_string(),
                        value: None,
                    });
                }
                (traced, ids)
            }
            CallArguments::Values(values) => {
                let traced = values
                    .iter()
                    .enumerate()
                    .map(|(index, value)| TracedArg {
                        name: param_name(index),
                        origin: ArgOrigin::Value,
                        source: value.to_string(),
                        value: Some(value.clone()),
                    })
                    .collect();
                (traced, Vec::new())
            }
        }
    }

    fn current_cost(env: &ExecutionState) -> ExecutionCost {
        env.global_context.cost_track.get_total()
    }
}

/// Field-wise `end - begin`, saturating to avoid underflow if a counter is reset.
fn cost_delta(begin: &ExecutionCost, end: &ExecutionCost) -> ExecutionCost {
    ExecutionCost {
        runtime: end.runtime.saturating_sub(begin.runtime),
        read_count: end.read_count.saturating_sub(begin.read_count),
        read_length: end.read_length.saturating_sub(begin.read_length),
        write_count: end.write_count.saturating_sub(begin.write_count),
        write_length: end.write_length.saturating_sub(begin.write_length),
    }
}

/// `inclusive` minus the inclusive cost of every child, field-wise and saturating.
fn cost_exclusive(inclusive: &ExecutionCost, children: &[TracedCall]) -> ExecutionCost {
    let mut exclusive = inclusive.clone();
    for child in children {
        let child_cost = &child.cost_inclusive;
        exclusive.runtime = exclusive.runtime.saturating_sub(child_cost.runtime);
        exclusive.read_count = exclusive.read_count.saturating_sub(child_cost.read_count);
        exclusive.read_length = exclusive.read_length.saturating_sub(child_cost.read_length);
        exclusive.write_count = exclusive.write_count.saturating_sub(child_cost.write_count);
        exclusive.write_length = exclusive
            .write_length
            .saturating_sub(child_cost.write_length);
    }
    exclusive
}

impl EvalHook for CallTraceHook {
    fn will_begin_call(
        &mut self,
        env: &mut ExecutionState,
        _invoke_ctx: &InvocationContext,
        call: &CallHook,
        args: CallArguments,
    ) {
        let (args, arg_ids) = Self::build_args(call, args);
        self.stack.push(PendingCall {
            callee: Self::callee_of(call),
            args,
            arg_ids,
            cost_at_begin: Self::current_cost(env),
            time_at_begin: Instant::now(),
            children: Vec::new(),
        });
    }

    fn did_evaluate_call_argument(
        &mut self,
        _env: &mut ExecutionState,
        _invoke_ctx: &InvocationContext,
        _call: &CallHook,
        arg_index: usize,
        value: &Value,
    ) {
        if let Some(frame) = self.stack.last_mut()
            && let Some(arg) = frame.args.get_mut(arg_index)
        {
            arg.value = Some(value.clone());
        }
    }

    fn did_finish_eval<'a>(
        &mut self,
        _env: &mut ExecutionState,
        _invoke_ctx: &'a InvocationContext,
        _context: &'a LocalContext,
        expr: &SymbolicExpression,
        res: &Result<ValueRef<'a>, VmExecutionError>,
    ) {
        // Resolve any as-yet-unresolved source argument of the current call by matching the
        // finished expression against its argument ids. This is the only source of values
        // for special-form arguments (e.g. a `map-get?` key), which never fire
        // `did_evaluate_call_argument`; for normal calls it may fill the slot just before
        // that hook reports the same value, so we only write when the slot is empty.
        let Ok(value_ref) = res else {
            return;
        };
        if let Some(frame) = self.stack.last_mut()
            && let Some(index) = frame.arg_ids.iter().position(|id| *id == expr.id)
            && let Some(arg) = frame.args.get_mut(index)
            && arg.value.is_none()
        {
            arg.value = Some(value_ref.as_ref().clone());
        }
    }

    fn did_finish_call(
        &mut self,
        env: &mut ExecutionState,
        _invoke_ctx: &InvocationContext,
        _call: &CallHook,
        res: &Result<Value, VmExecutionError>,
    ) {
        let Some(frame) = self.stack.pop() else {
            return;
        };
        let cost_inclusive = cost_delta(&frame.cost_at_begin, &Self::current_cost(env));
        let cost_exclusive = cost_exclusive(&cost_inclusive, &frame.children);
        let call = TracedCall {
            callee: frame.callee,
            args: frame.args,
            result: Some(match res {
                Ok(value) => TracedResult::Ok(value.clone()),
                Err(err) => TracedResult::Err(format!("{err:?}")),
            }),
            cost_inclusive,
            cost_exclusive,
            wall_time: frame.time_at_begin.elapsed(),
            children: frame.children,
        };
        match self.stack.last_mut() {
            Some(parent) => parent.children.push(call),
            None => self.roots.push(call),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cost(runtime: u64, read_count: u64, write_count: u64) -> ExecutionCost {
        ExecutionCost {
            runtime,
            read_count,
            read_length: 0,
            write_count,
            write_length: 0,
        }
    }

    fn call_with_inclusive_cost(cost_inclusive: ExecutionCost) -> TracedCall {
        TracedCall {
            callee: TracedCallee::Builtin {
                clarity_name: "x".to_string(),
                rust_name: "x".to_string(),
            },
            args: Vec::new(),
            result: None,
            cost_inclusive,
            cost_exclusive: ExecutionCost::ZERO,
            wall_time: Duration::ZERO,
            children: Vec::new(),
        }
    }

    #[test]
    fn cost_delta_is_saturating() {
        let begin = cost(100, 5, 2);
        let end = cost(140, 8, 2);
        let delta = cost_delta(&begin, &end);
        assert_eq!(
            (delta.runtime, delta.read_count, delta.write_count),
            (40, 3, 0)
        );
        // A decrease (e.g. a tracker reset) saturates to zero rather than underflowing.
        assert_eq!(cost_delta(&end, &begin).runtime, 0);
    }

    #[test]
    fn cost_exclusive_subtracts_children() {
        let inclusive = cost(100, 10, 4);
        let children = [
            call_with_inclusive_cost(cost(30, 3, 1)),
            call_with_inclusive_cost(cost(20, 2, 1)),
        ];
        let exclusive = cost_exclusive(&inclusive, &children);
        assert_eq!(exclusive.runtime, 50);
        assert_eq!(exclusive.read_count, 5);
        assert_eq!(exclusive.write_count, 2);
    }

    #[test]
    fn cost_exclusive_saturates_when_children_exceed_parent() {
        let inclusive = cost(10, 1, 0);
        let children = [call_with_inclusive_cost(cost(30, 3, 0))];
        let exclusive = cost_exclusive(&inclusive, &children);
        assert_eq!((exclusive.runtime, exclusive.read_count), (0, 0));
    }
}
