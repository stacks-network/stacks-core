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

use crate::vm::Value::CallableContract;
use crate::vm::contexts::{ExecutionState, InvocationContext, LocalContext};
use crate::vm::costs::cost_functions::ClarityCostFunction;
use crate::vm::costs::{CostTracker, MemoryConsumer, runtime_cost};
use crate::vm::errors::{
    EarlyReturnError, RuntimeCheckErrorKind, RuntimeError, VmExecutionError, VmInternalError,
    check_arguments_at_least,
};
use crate::vm::types::{CallableData, OptionalData, ResponseData, TypeSignature, Value};
use crate::vm::{self, ClarityName, ClarityVersion, SymbolicExpression};

fn inner_unwrap(to_unwrap: Value) -> Result<Option<Value>, VmExecutionError> {
    let result = match to_unwrap {
        Value::Optional(data) => data.data.map(|data| *data),
        Value::Response(data) => {
            if data.committed {
                Some(*data.data)
            } else {
                None
            }
        }
        _ => {
            return Err(RuntimeCheckErrorKind::Unreachable(format!(
                "Expected optional or response value: {to_unwrap}"
            ))
            .into());
        }
    };

    Ok(result)
}

fn inner_unwrap_err(to_unwrap: Value) -> Result<Option<Value>, VmExecutionError> {
    let result = match to_unwrap {
        Value::Response(data) => {
            if !data.committed {
                Some(*data.data)
            } else {
                None
            }
        }
        _ => {
            return Err(RuntimeCheckErrorKind::Unreachable(format!(
                "Expected response value: {to_unwrap}"
            ))
            .into());
        }
    };

    Ok(result)
}

pub fn native_unwrap(input: Value) -> Result<Value, VmExecutionError> {
    inner_unwrap(input).and_then(|opt_value| match opt_value {
        Some(v) => Ok(v),
        None => Err(RuntimeError::UnwrapFailure.into()),
    })
}

pub fn native_unwrap_or_ret(input: Value, thrown: Value) -> Result<Value, VmExecutionError> {
    inner_unwrap(input).and_then(|opt_value| match opt_value {
        Some(v) => Ok(v),
        None => Err(EarlyReturnError::UnwrapFailed(Box::new(thrown)).into()),
    })
}

pub fn native_unwrap_err(input: Value) -> Result<Value, VmExecutionError> {
    inner_unwrap_err(input).and_then(|opt_value| match opt_value {
        Some(v) => Ok(v),
        None => Err(RuntimeError::UnwrapFailure.into()),
    })
}

pub fn native_unwrap_err_or_ret(input: Value, thrown: Value) -> Result<Value, VmExecutionError> {
    inner_unwrap_err(input).and_then(|opt_value| match opt_value {
        Some(v) => Ok(v),
        None => Err(EarlyReturnError::UnwrapFailed(Box::new(thrown)).into()),
    })
}

pub fn native_try_ret(input: Value) -> Result<Value, VmExecutionError> {
    match input {
        Value::Optional(data) => match data.data {
            Some(data) => Ok(*data),
            None => Err(EarlyReturnError::UnwrapFailed(Box::new(Value::none())).into()),
        },
        Value::Response(data) => {
            if data.committed {
                Ok(*data.data)
            } else {
                let short_return_val = Value::error(*data.data).map_err(|_| {
                    VmInternalError::Expect(
                        "BUG: Failed to construct new response type from old response type".into(),
                    )
                })?;
                Err(EarlyReturnError::UnwrapFailed(Box::new(short_return_val)).into())
            }
        }
        _ => Err(RuntimeCheckErrorKind::Unreachable(format!(
            "Expected optional or response value: {input}"
        ))
        .into()),
    }
}

fn eval_with_new_binding(
    body: &SymbolicExpression,
    bind_name: ClarityName,
    bind_value: Value,
    exec_state: &mut ExecutionState,
    invoke_ctx: &InvocationContext,
    context: &LocalContext,
) -> Result<Value, VmExecutionError> {
    let mut inner_context = context.extend()?;
    if vm::is_reserved(
        &bind_name,
        invoke_ctx.contract_context.get_clarity_version(),
    ) || invoke_ctx
        .contract_context
        .lookup_function(&bind_name)
        .is_some()
        || inner_context.lookup_variable(&bind_name).is_some()
    {
        return Err(RuntimeCheckErrorKind::NameAlreadyUsed(bind_name.into()).into());
    }

    let memory_use = bind_value.get_memory_use()?;
    exec_state.add_memory(memory_use)?;

    if *invoke_ctx.contract_context.get_clarity_version() >= ClarityVersion::Clarity2
        && let CallableContract(trait_data) = &bind_value
    {
        inner_context.callable_contracts.insert(
            bind_name.clone(),
            CallableData {
                contract_identifier: trait_data.contract_identifier.clone(),
                trait_identifier: trait_data.trait_identifier.clone(),
            },
        );
    }
    inner_context.variables.insert(bind_name, bind_value);
    let result = vm::eval(body, exec_state, invoke_ctx, &inner_context)
        .and_then(|v| v.clone_with_cost(exec_state));

    exec_state.drop_memory(memory_use)?;

    result
}

fn special_match_opt(
    input: OptionalData,
    args: &[SymbolicExpression],
    exec_state: &mut ExecutionState,
    invoke_ctx: &InvocationContext,
    context: &LocalContext,
) -> Result<Value, VmExecutionError> {
    if args.len() != 3 {
        Err(RuntimeCheckErrorKind::Unreachable(format!(
            "Bad match option syntax: args {} != 3",
            args.len()
        )))?;
    }

    let bind_name = args[0]
        .match_atom()
        .ok_or_else(|| {
            RuntimeCheckErrorKind::Unreachable("Bad match option syntax: expected name".to_string())
        })?
        .clone();
    let some_branch = &args[1];
    let none_branch = &args[2];

    match input.data {
        Some(data) => eval_with_new_binding(
            some_branch,
            bind_name,
            *data,
            exec_state,
            invoke_ctx,
            context,
        ),
        None => vm::eval(none_branch, exec_state, invoke_ctx, context)
            .and_then(|v| v.clone_with_cost(exec_state)),
    }
}

fn special_match_resp(
    input: ResponseData,
    args: &[SymbolicExpression],
    exec_state: &mut ExecutionState,
    invoke_ctx: &InvocationContext,
    context: &LocalContext,
) -> Result<Value, VmExecutionError> {
    if args.len() != 4 {
        Err(RuntimeCheckErrorKind::Unreachable(format!(
            "Bad match response syntax: args {} != 4",
            args.len()
        )))?;
    }

    let ok_bind_name = args[0]
        .match_atom()
        .ok_or_else(|| {
            RuntimeCheckErrorKind::Unreachable(
                "Bad match response syntax: expected name".to_string(),
            )
        })?
        .clone();
    let ok_branch = &args[1];
    let err_bind_name = args[2]
        .match_atom()
        .ok_or_else(|| {
            RuntimeCheckErrorKind::Unreachable(
                "Bad match response syntax: expected name".to_string(),
            )
        })?
        .clone();
    let err_branch = &args[3];

    if input.committed {
        eval_with_new_binding(
            ok_branch,
            ok_bind_name,
            *input.data,
            exec_state,
            invoke_ctx,
            context,
        )
    } else {
        eval_with_new_binding(
            err_branch,
            err_bind_name,
            *input.data,
            exec_state,
            invoke_ctx,
            context,
        )
    }
}

pub fn special_match(
    args: &[SymbolicExpression],
    exec_state: &mut ExecutionState,
    invoke_ctx: &InvocationContext,
    context: &LocalContext,
) -> Result<Value, VmExecutionError> {
    check_arguments_at_least(1, args)?;

    // TODO: Should this be clone_with_cost? We do need the internal ResponseData which also has clones the internal value
    let input =
        { vm::eval(&args[0], exec_state, invoke_ctx, context)?.clone_with_cost(exec_state)? };

    runtime_cost(ClarityCostFunction::Match, exec_state, 0)?;

    match input {
        Value::Response(data) => {
            special_match_resp(data, &args[1..], exec_state, invoke_ctx, context)
        }
        Value::Optional(data) => {
            special_match_opt(data, &args[1..], exec_state, invoke_ctx, context)
        }
        _ => Err(RuntimeCheckErrorKind::Unreachable(format!(
            "Bad match input: {}",
            TypeSignature::type_of(&input)?
        ))
        .into()),
    }
}

pub fn native_some(input: Value) -> Result<Value, VmExecutionError> {
    Ok(Value::some(input)?)
}

fn is_some(input: Value) -> Result<bool, RuntimeCheckErrorKind> {
    match input {
        Value::Optional(ref data) => Ok(data.data.is_some()),
        _ => Err(RuntimeCheckErrorKind::Unreachable(format!(
            "Expected option value: {input}"
        ))),
    }
}

fn is_okay(input: Value) -> Result<bool, RuntimeCheckErrorKind> {
    match input {
        Value::Response(data) => Ok(data.committed),
        _ => Err(RuntimeCheckErrorKind::Unreachable(format!(
            "Expected response value: {input}"
        ))),
    }
}

pub fn native_is_some(input: Value) -> Result<Value, VmExecutionError> {
    Ok(is_some(input).map(Value::Bool)?)
}

pub fn native_is_none(input: Value) -> Result<Value, VmExecutionError> {
    Ok(is_some(input).map(|is_some| Value::Bool(!is_some))?)
}

pub fn native_is_okay(input: Value) -> Result<Value, VmExecutionError> {
    Ok(is_okay(input).map(Value::Bool)?)
}

pub fn native_is_err(input: Value) -> Result<Value, VmExecutionError> {
    Ok(is_okay(input).map(|is_ok| Value::Bool(!is_ok))?)
}

pub fn native_okay(input: Value) -> Result<Value, VmExecutionError> {
    Ok(Value::okay(input)?)
}

pub fn native_error(input: Value) -> Result<Value, VmExecutionError> {
    Ok(Value::error(input)?)
}

pub fn native_default_to(default: Value, input: Value) -> Result<Value, VmExecutionError> {
    match input {
        Value::Optional(data) => match data.data {
            Some(data) => Ok(*data),
            None => Ok(default),
        },
        _ => Err(
            RuntimeCheckErrorKind::Unreachable(format!("Expected option value: {input}")).into(),
        ),
    }
}
