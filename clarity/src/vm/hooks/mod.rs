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

mod internals;
pub mod trace;

pub(crate) use internals::{CallTraceFrame, EvalHookNotifier};

use crate::vm::callables::{DefineType, DefinedFunction};
use crate::vm::contexts::{ExecutionState, InvocationContext, LocalContext};
use crate::vm::errors::VmExecutionError;
use crate::vm::representations::SymbolicExpression;
use crate::vm::types::{QualifiedContractIdentifier, Value};
use crate::vm::{ExecutionResult, ValueRef};

/// Defines the contract for receiving notifications about Clarity evaluation and callable
/// invocation.
// NOTE: Used in the Clarinet repo.
pub trait EvalHook {
    /// Called before a top-level execution begins.
    fn will_begin_execution(&mut self) {}

    /// Called after a top-level execution finishes, with its [`ExecutionOutcome`].
    fn did_finish_execution(&mut self, _outcome: ExecutionOutcome) {}

    /// Called before a Clarity expression is evaluated.
    fn will_begin_eval(
        &mut self,
        _env: &mut ExecutionState,
        _invoke_ctx: &InvocationContext,
        _context: &LocalContext,
        _expr: &SymbolicExpression,
    ) {
    }

    /// Called after a Clarity expression has been evaluated.
    fn did_finish_eval<'a>(
        &mut self,
        _env: &mut ExecutionState,
        _invoke_ctx: &'a InvocationContext,
        _context: &'a LocalContext,
        _expr: &SymbolicExpression,
        _res: &Result<ValueRef<'a>, VmExecutionError>,
    ) {
    }

    /// Completion callback available to external consumers.
    ///
    /// **Note:** The Clarity VM itself never calls this method; `clarinet` invokes it
    /// internally as part of its REPL interpreter.
    fn did_complete(&mut self, _result: Result<&mut ExecutionResult, String>) {}

    /// Called before a callable starts evaluating or consuming its arguments.
    fn will_begin_call(
        &mut self,
        _env: &mut ExecutionState,
        _invoke_ctx: &InvocationContext,
        _call: &CallHook,
        _args: CallArguments,
    ) {
    }

    /// Called when an argument has been evaluated to the value the callable will receive.
    fn did_evaluate_call_argument(
        &mut self,
        _env: &mut ExecutionState,
        _invoke_ctx: &InvocationContext,
        _call: &CallHook,
        _arg_index: usize,
        _value: &Value,
    ) {
    }

    /// Called after a callable invocation that triggered [`EvalHook::will_begin_call`] finishes.
    fn did_finish_call(
        &mut self,
        _env: &mut ExecutionState,
        _invoke_ctx: &InvocationContext,
        _call: &CallHook,
        _res: &Result<Value, VmExecutionError>,
    ) {
    }
}

/// Callable invocation observed during Clarity execution.
///
/// Call hooks are emitted before a callable evaluates its arguments, so nested
/// calls that produce argument values can be reconstructed under the call that
/// consumes them. Some VM paths, such as transaction entry points and
/// `apply_evaluated`, already have concrete values when the call starts.
#[derive(Debug, Clone, Copy)]
pub enum CallHook<'a> {
    /// Built-in or special-form callable.
    Builtin {
        /// Clarity source-level function name.
        clarity_name: &'static str,
        /// Rust implementation name.
        rust_name: &'static str,
    },
    /// User-defined contract function.
    UserDefined {
        /// Contract that owns the function.
        contract_identifier: &'a QualifiedContractIdentifier,
        /// Function definition being invoked.
        function: &'a DefinedFunction,
    },
}

impl<'a> CallHook<'a> {
    pub fn builtin(clarity_name: &'static str, rust_name: &'static str) -> Self {
        CallHook::Builtin {
            clarity_name,
            rust_name,
        }
    }

    pub fn user_defined(
        contract_identifier: &'a QualifiedContractIdentifier,
        function: &'a DefinedFunction,
    ) -> CallHook<'a> {
        CallHook::UserDefined {
            contract_identifier,
            function,
        }
    }

    /// Clarity source-level function name.
    pub fn clarity_name(&self) -> &str {
        match self {
            CallHook::Builtin { clarity_name, .. } => clarity_name,
            CallHook::UserDefined { function, .. } => function.name(),
        }
    }

    /// Stable category label for trace consumers.
    pub fn kind(&self) -> &'static str {
        match self {
            CallHook::Builtin { .. } => "builtin",
            CallHook::UserDefined { function, .. } => match function.define_type {
                DefineType::Public => "user-public",
                DefineType::Private => "user-private",
                DefineType::ReadOnly => "user-read-only",
            },
        }
    }
}

/// Arguments available when a call hook opens.
///
/// Some call paths still have source expressions, while transaction entry points
/// and `apply_evaluated` already have concrete values.
#[derive(Debug, Clone, Copy)]
pub enum CallArguments<'a> {
    /// Unevaluated argument expressions.
    Expressions(&'a [SymbolicExpression]),
    /// Already evaluated argument values.
    Values(&'a [Value]),
}

impl CallArguments<'_> {
    /// Number of arguments in this call.
    pub fn len(&self) -> usize {
        match self {
            CallArguments::Expressions(args) => args.len(),
            CallArguments::Values(args) => args.len(),
        }
    }

    /// Returns true when the call has no arguments.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Indicates whether a top-level execution returned successfully or with an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionOutcome {
    /// Execution returned successfully.
    Success,
    /// Execution returned an error.
    Failure,
}
