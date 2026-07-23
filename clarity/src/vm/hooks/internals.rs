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

use clarity_types::Value;
use clarity_types::representations::SymbolicExpression;

use super::{CallArguments, CallHook};
use crate::vm::contexts::InvocationContext;
use crate::vm::errors::VmExecutionError;
use crate::vm::{LocalContext, ValueRef};

/// Optional call-hook frame with no-op helpers when call tracing is inactive.
#[derive(Debug, Clone, Copy)]
pub struct CallTraceFrame<'a>(Option<CallHook<'a>>);

impl<'a> CallTraceFrame<'a> {
    /// Builds an active call hook only when call tracing should be emitted.
    pub fn when(enabled: bool, call: impl FnOnce() -> CallHook<'a>) -> Self {
        if enabled {
            Self(Some(call()))
        } else {
            Self(None)
        }
    }

    /// Notifies hooks that this call is beginning.
    pub fn begin(
        &self,
        exec_state: &mut impl EvalHookNotifier,
        invoke_ctx: &InvocationContext,
        args: CallArguments,
    ) {
        if let Some(call) = &self.0 {
            exec_state.notify_will_begin_call(invoke_ctx, call, args);
        }
    }

    /// Notifies hooks that one call argument has been evaluated.
    pub fn did_evaluate_argument(
        &self,
        exec_state: &mut impl EvalHookNotifier,
        invoke_ctx: &InvocationContext,
        arg_index: usize,
        value: &Value,
    ) {
        if let Some(call) = &self.0 {
            exec_state.notify_did_evaluate_call_argument(invoke_ctx, call, arg_index, value);
        }
    }

    /// Notifies hooks that all pre-evaluated call arguments are available.
    pub fn did_evaluate_arguments(
        &self,
        exec_state: &mut impl EvalHookNotifier,
        invoke_ctx: &InvocationContext,
        args: &[Value],
    ) {
        for (arg_index, arg) in args.iter().enumerate() {
            self.did_evaluate_argument(exec_state, invoke_ctx, arg_index, arg);
        }
    }

    /// Notifies hooks that this call has finished.
    pub fn finish(
        &self,
        exec_state: &mut impl EvalHookNotifier,
        invoke_ctx: &InvocationContext,
        res: &Result<Value, VmExecutionError>,
    ) {
        if let Some(call) = &self.0 {
            exec_state.notify_did_finish_call(invoke_ctx, call, res);
        }
    }
}

/// Internal trait defining expression and call hook dispatch behavior.
pub trait EvalHookNotifier {
    /// Returns true when at least one eval hook is registered.
    fn has_eval_hooks(&self) -> bool;

    /// Notifies hooks before expression evaluation.
    fn notify_will_begin_eval(
        &mut self,
        invoke_ctx: &InvocationContext,
        context: &LocalContext,
        expr: &SymbolicExpression,
    );

    /// Notifies hooks after expression evaluation.
    fn notify_did_finish_eval<'a>(
        &mut self,
        invoke_ctx: &'a InvocationContext,
        context: &'a LocalContext,
        expr: &SymbolicExpression,
        res: &Result<ValueRef<'a>, VmExecutionError>,
    );

    /// Notifies hooks before callable execution.
    fn notify_will_begin_call(
        &mut self,
        invoke_ctx: &InvocationContext,
        call: &CallHook,
        args: CallArguments,
    );

    /// Notifies hooks after a call argument has evaluated.
    fn notify_did_evaluate_call_argument(
        &mut self,
        invoke_ctx: &InvocationContext,
        call: &CallHook,
        arg_index: usize,
        value: &Value,
    );

    /// Notifies hooks after callable execution completes.
    fn notify_did_finish_call(
        &mut self,
        invoke_ctx: &InvocationContext,
        call: &CallHook,
        res: &Result<Value, VmExecutionError>,
    );
}
