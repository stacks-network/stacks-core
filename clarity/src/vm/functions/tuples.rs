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

use stacks_common::bounded_format;

use crate::vm::contexts::{ExecutionState, InvocationContext};
use crate::vm::costs::cost_functions::ClarityCostFunction;
use crate::vm::costs::runtime_cost;
use crate::vm::errors::{
    RuntimeCheckErrorKind, SyntaxBindingErrorType, VmExecutionError, VmInternalError,
    check_argument_count, check_arguments_at_least,
};
use crate::vm::representations::SymbolicExpression;
use crate::vm::types::{TupleData, TypeSignature, Value};
use crate::vm::{LocalContext, eval};

pub fn tuple_cons(
    args: &[SymbolicExpression],
    exec_state: &mut ExecutionState,
    invoke_ctx: &InvocationContext,
    context: &LocalContext,
) -> Result<Value, VmExecutionError> {
    //    (tuple (arg-name value)
    //           (arg-name value))
    use super::parse_eval_bindings;

    check_arguments_at_least(1, args)?;

    let bindings = parse_eval_bindings(
        args,
        SyntaxBindingErrorType::TupleCons,
        exec_state,
        invoke_ctx,
        context,
    )?;
    runtime_cost(ClarityCostFunction::TupleCons, exec_state, bindings.len())?;

    Ok(TupleData::from_data(bindings).map(Value::from)?)
}

pub fn tuple_get(
    args: &[SymbolicExpression],
    exec_state: &mut ExecutionState,
    invoke_ctx: &InvocationContext,
    context: &LocalContext,
) -> Result<Value, VmExecutionError> {
    // (get arg-name (tuple ...))
    //    if the tuple argument is an option type, then return option(field-name).
    check_argument_count(2, args)?;

    let arg_name = args[0]
        .match_atom()
        .ok_or(RuntimeCheckErrorKind::Unreachable("Expected name".into()))?;

    let value = eval(&args[1], exec_state, invoke_ctx, context)?;

    match value.clone_with_cost(exec_state)? {
        Value::Optional(opt_data) => {
            match opt_data.data {
                Some(data) => {
                    if let Value::Tuple(tuple_data) = *data {
                        runtime_cost(ClarityCostFunction::TupleGet, exec_state, tuple_data.len())?;
                        Ok(Value::some(tuple_data.get_owned(arg_name)?).map_err(|_| {
                            VmInternalError::Expect(
                                "Tuple contents should *always* fit in a some wrapper".into(),
                            )
                        })?)
                    } else {
                        Err(RuntimeCheckErrorKind::Unreachable(bounded_format!(
                            "Expected tuple: {}",
                            TypeSignature::type_of(&data)?
                        ))
                        .into())
                    }
                }
                None => Ok(Value::none()), // just pass through none-types.
            }
        }
        Value::Tuple(tuple_data) => {
            runtime_cost(ClarityCostFunction::TupleGet, exec_state, tuple_data.len())?;
            Ok(tuple_data.get_owned(arg_name)?)
        }
        other_value => Err(RuntimeCheckErrorKind::Unreachable(bounded_format!(
            "Expected tuple: {}",
            TypeSignature::type_of(&other_value)?
        ))
        .into()),
    }
}

pub fn tuple_merge(
    mut args: Vec<Value>,
    exec_state: &mut ExecutionState,
    _invoke_ctx: &InvocationContext,
) -> Result<Value, VmExecutionError> {
    check_argument_count(2, &args)?;
    // `merge` is dispatched with two evaluated arguments; extract them in order.
    let update = args
        .pop()
        .ok_or_else(|| VmInternalError::Expect("Unexpected list length".into()))?;
    let base = args
        .pop()
        .ok_or_else(|| VmInternalError::Expect("Unexpected list length".into()))?;

    let initial_values = match base {
        Value::Tuple(initial_values) => Ok(initial_values),
        _ => Err(RuntimeCheckErrorKind::Unreachable(bounded_format!(
            "Expected tuple: {}",
            TypeSignature::type_of(&base)?
        ))),
    }?;

    let new_values = match update {
        Value::Tuple(new_values) => Ok(new_values),
        _ => Err(RuntimeCheckErrorKind::Unreachable(bounded_format!(
            "Expected tuple: {}",
            TypeSignature::type_of(&update)?
        ))),
    }?;

    let combined = TupleData::shallow_merge(initial_values, new_values);
    if exec_state.epoch().fixes_tuple_merge_size_check() {
        // 4.0+: reject an oversized merged tuple cleanly with `ValueTooLarge` instead of
        // block-invalidating later (the pre-4.0 behavior: the oversized value propagates and
        // fails during cost calculation with an `InvariantViolation`). This mirrors the
        // static-analysis gate in `check_special_merge` so no oversized tuple can exist at 4.0+.
        combined.type_signature.checked_value_size()?;
    }
    Ok(Value::Tuple(combined))
}
