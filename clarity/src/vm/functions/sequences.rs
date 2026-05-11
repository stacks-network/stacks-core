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

use std::cmp;

use clarity_types::types::RetainValuesError;
use stacks_common::types::StacksEpochId;

use crate::vm::contexts::{ExecutionState, InvocationContext};
use crate::vm::costs::cost_functions::ClarityCostFunction;
use crate::vm::costs::{CostOverflowingMath, runtime_cost};
use crate::vm::errors::{
    RuntimeCheckErrorKind, VmExecutionError, VmInternalError, check_argument_count,
    check_arguments_at_least,
};
use crate::vm::representations::SymbolicExpression;
use crate::vm::types::TypeSignature::BoolType;
use crate::vm::types::signatures::ListTypeData;
use crate::vm::types::{ListData, SequenceData, TypeSignature, Value};
use crate::vm::{LocalContext, apply_evaluated, eval, lookup_function};

pub fn list_cons(
    args: &[SymbolicExpression],
    exec_state: &mut ExecutionState,
    invoke_ctx: &InvocationContext,
    context: &LocalContext,
) -> Result<Value, VmExecutionError> {
    let eval_tried: Result<Vec<Value>, VmExecutionError> = args
        .iter()
        .map(|x| {
            eval(x, exec_state, invoke_ctx, context).and_then(|v| v.clone_with_cost(exec_state))
        })
        .collect();
    let args = eval_tried?;

    let mut arg_size = 0;
    for a in args.iter() {
        arg_size = arg_size.cost_overflow_add(a.size()?.into())?;
    }

    runtime_cost(ClarityCostFunction::ListCons, exec_state, arg_size)?;

    let value = Value::cons_list(args, exec_state.epoch())?;
    Ok(value)
}

/// Implements the Clarity `filter` function: `(filter func sequence)`.
///
/// Applies a boolean predicate `func` to each element of `sequence`, returning a new
/// sequence containing only the elements for which `func` returned `true`.
/// The predicate must return a `bool`; a type error is raised otherwise.
///
/// `args[0]` is the function name (atom) and `args[1]` is the sequence expression.
pub fn special_filter(
    args: &[SymbolicExpression],
    exec_state: &mut ExecutionState,
    invoke_ctx: &InvocationContext,
    context: &LocalContext,
) -> Result<Value, VmExecutionError> {
    check_argument_count(2, args)?;

    runtime_cost(ClarityCostFunction::Filter, exec_state, 0)?;

    let function_name = args[0]
        .match_atom()
        .ok_or(RuntimeCheckErrorKind::Unreachable(
            "Expected name".to_string(),
        ))?;

    let mut sequence =
        eval(&args[1], exec_state, invoke_ctx, context)?.clone_with_cost(exec_state)?;
    let function = lookup_function(function_name, exec_state, invoke_ctx)?;

    match sequence {
        Value::Sequence(sequence_data) => {
            sequence = Value::Sequence(
                sequence_data
                    .try_retain(&mut |value: Value| -> Result<bool, VmExecutionError> {
                        let filter_eval = apply_evaluated(
                            &function,
                            vec![value],
                            exec_state,
                            invoke_ctx,
                            context,
                        )?;
                        if let Value::Bool(include) = filter_eval {
                            Ok(include)
                        } else {
                            Err(RuntimeCheckErrorKind::TypeValueError(
                                Box::new(BoolType),
                                filter_eval.to_error_string(),
                            )
                            .into())
                        }
                    })
                    .map_err(|e| match e {
                        RetainValuesError::Internal(err) => {
                            VmExecutionError::Internal(VmInternalError::Expect(format!(
                                "Internal error occurred while filtering sequence value: {err}"
                            )))
                        }
                        RetainValuesError::Predicate(vm_err) => vm_err,
                    })?,
            );
        }
        _ => {
            return Err(RuntimeCheckErrorKind::Unreachable(format!(
                "Expected sequence: {}",
                TypeSignature::type_of(&sequence)?
            ))
            .into());
        }
    };
    Ok(sequence)
}

/// Implements the Clarity `fold` function: `(fold func sequence initial)`.
///
/// Iterates over `sequence`, threading an accumulator through successive calls to `func`.
/// Each step calls `func` with `(element, accumulator)` and uses the result as the new
/// accumulator. Returns the final accumulator value.
///
/// `args[0]` is the function name (atom), `args[1]` is the sequence expression,
/// and `args[2]` is the initial accumulator value.
pub fn special_fold(
    args: &[SymbolicExpression],
    exec_state: &mut ExecutionState,
    invoke_ctx: &InvocationContext,
    context: &LocalContext,
) -> Result<Value, VmExecutionError> {
    check_argument_count(3, args)?;

    runtime_cost(ClarityCostFunction::Fold, exec_state, 0)?;

    let function_name = args[0]
        .match_atom()
        .ok_or(RuntimeCheckErrorKind::Unreachable(
            "Expected name".to_string(),
        ))?;

    let function = lookup_function(function_name, exec_state, invoke_ctx)?;
    let sequence = eval(&args[1], exec_state, invoke_ctx, context)?.clone_with_cost(exec_state)?;
    let initial = eval(&args[2], exec_state, invoke_ctx, context)?.clone_with_cost(exec_state)?;

    let Value::Sequence(seq) = sequence else {
        return Err(RuntimeCheckErrorKind::Unreachable(format!(
            "Expected sequence: {}",
            TypeSignature::type_of(&sequence)?
        ))
        .into());
    };

    let mut acc = initial;
    for element_result in seq {
        let element = element_result.map_err(|_| {
            VmInternalError::Expect("ERROR: Invalid sequence data successfully constructed".into())
        })?;
        acc = apply_evaluated(
            &function,
            vec![element, acc],
            exec_state,
            invoke_ctx,
            context,
        )?;
    }
    Ok(acc)
}

/// Implements the Clarity `map` function: `(map func sequence-0 ... sequence-n)`.
///
/// Applies `func` element-wise across one or more input sequences, collecting the results
/// into a new list. When multiple sequences are provided, iteration stops at the length of
/// the shortest sequence. Each call to `func` receives one element from each sequence,
/// positionally (e.g., the i-th call gets the i-th element of every sequence).
///
/// `args[0]` is the function name (atom) and `args[1..]` are the sequence expressions.
pub fn special_map(
    args: &[SymbolicExpression],
    exec_state: &mut ExecutionState,
    invoke_ctx: &InvocationContext,
    context: &LocalContext,
) -> Result<Value, VmExecutionError> {
    check_arguments_at_least(2, args)?;

    runtime_cost(ClarityCostFunction::Map, exec_state, args.len())?;

    let function_name = args[0]
        .match_atom()
        .ok_or(RuntimeCheckErrorKind::Unreachable(
            "Expected name".to_string(),
        ))?;
    let function = lookup_function(function_name, exec_state, invoke_ctx)?;

    // Let's consider a function f (f a b c ...)
    // We will first re-arrange our sequences [a0, a1, ...] [b0, b1, ...] [c0, c1, ...] ...
    // To get something like: [a0, b0, c0, ...] [a1, b1, c1, ...]
    let mut mapped_func_args: Vec<Vec<Value>> = vec![];
    let mut min_args_len = usize::MAX;
    for map_arg in args[1..].iter() {
        let sequence =
            eval(map_arg, exec_state, invoke_ctx, context)?.clone_with_cost(exec_state)?;
        let Value::Sequence(seq) = sequence else {
            return Err(RuntimeCheckErrorKind::Unreachable(format!(
                "Expected sequence: {}",
                TypeSignature::type_of(&sequence)?
            ))
            .into());
        };
        let seq_len = seq.len();
        min_args_len = min_args_len.min(seq_len);
        for (apply_index, element_result) in seq.into_iter().enumerate() {
            let value = element_result.map_err(|_| {
                VmInternalError::Expect(
                    "ERROR: Invalid sequence data successfully constructed".into(),
                )
            })?;
            if apply_index > min_args_len {
                break;
            }
            if apply_index >= mapped_func_args.len() {
                mapped_func_args.push(vec![value]);
            } else {
                mapped_func_args[apply_index].push(value);
            }
        }
    }

    // We can now apply the map
    let mut mapped_results = vec![];
    let mut previous_len = None;
    for arguments in mapped_func_args.into_iter() {
        // Stop iterating when we are done with the shortest sequence
        if let Some(previous_len) = previous_len {
            if previous_len != arguments.len() {
                break;
            }
        } else {
            previous_len = Some(arguments.len());
        }
        let res = apply_evaluated(&function, arguments, exec_state, invoke_ctx, context)?;
        mapped_results.push(res);
    }

    let value = Value::cons_list(mapped_results, exec_state.epoch())?;
    Ok(value)
}

pub fn special_append(
    args: &[SymbolicExpression],
    exec_state: &mut ExecutionState,
    invoke_ctx: &InvocationContext,
    context: &LocalContext,
) -> Result<Value, VmExecutionError> {
    check_argument_count(2, args)?;

    let sequence = eval(&args[0], exec_state, invoke_ctx, context)?.clone_with_cost(exec_state)?;
    match sequence {
        Value::Sequence(SequenceData::List(list)) => {
            let element = eval(&args[1], exec_state, invoke_ctx, context)?;
            let ListData {
                mut data,
                type_signature,
            } = list;
            let (entry_type, size) = type_signature.destruct();
            let element_type = TypeSignature::type_of(element.as_ref())?;
            runtime_cost(
                ClarityCostFunction::Append,
                exec_state,
                u64::from(cmp::max(entry_type.size()?, element_type.size()?)),
            )?;
            let element = element.clone_with_cost(exec_state)?;
            if entry_type.is_no_type() {
                assert_eq!(size, 0);
                return Ok(Value::cons_list(vec![element], exec_state.epoch())?);
            }

            let next_entry_type =
                TypeSignature::least_supertype(exec_state.epoch(), &entry_type, &element_type)?;
            let (element, _) = Value::sanitize_value(exec_state.epoch(), &next_entry_type, element)
                .ok_or_else(|| RuntimeCheckErrorKind::ListTypesMustMatch)?;

            let next_type_signature = ListTypeData::new_list(next_entry_type, size + 1)?;
            data.push(element);
            Ok(Value::Sequence(SequenceData::List(ListData {
                type_signature: next_type_signature,
                data,
            })))
        }
        _ => {
            Err(RuntimeCheckErrorKind::Unreachable("Expected list application".to_string()).into())
        }
    }
}

switch_on_global_epoch!(special_concat(special_concat_v200, special_concat_v205));

pub fn special_concat_v200(
    args: &[SymbolicExpression],
    exec_state: &mut ExecutionState,
    invoke_ctx: &InvocationContext,
    context: &LocalContext,
) -> Result<Value, VmExecutionError> {
    check_argument_count(2, args)?;

    let mut wrapped_seq =
        eval(&args[0], exec_state, invoke_ctx, context)?.clone_with_cost(exec_state)?;
    let other_wrapped_seq =
        eval(&args[1], exec_state, invoke_ctx, context)?.clone_with_cost(exec_state)?;

    runtime_cost(
        ClarityCostFunction::Concat,
        exec_state,
        u64::from(wrapped_seq.size()?).cost_overflow_add(u64::from(other_wrapped_seq.size()?))?,
    )?;

    match (&mut wrapped_seq, other_wrapped_seq) {
        (Value::Sequence(seq), Value::Sequence(other_seq)) => {
            seq.concat(exec_state.epoch(), other_seq)?
        }
        (Value::Sequence(_), other_value) => {
            // The first value is a sequence, but the second is not
            return Err(RuntimeCheckErrorKind::Unreachable(format!(
                "Expected sequence: {}",
                TypeSignature::type_of(&other_value)?
            ))
            .into());
        }
        (value, _) => {
            // The first value is not a sequence (the other may not be as well, but just error on the first)
            return Err(RuntimeCheckErrorKind::Unreachable(format!(
                "Expected sequence: {}",
                TypeSignature::type_of(value)?
            ))
            .into());
        }
    };

    Ok(wrapped_seq)
}

pub fn special_concat_v205(
    args: &[SymbolicExpression],
    exec_state: &mut ExecutionState,
    invoke_ctx: &InvocationContext,
    context: &LocalContext,
) -> Result<Value, VmExecutionError> {
    check_argument_count(2, args)?;

    let mut wrapped_seq =
        eval(&args[0], exec_state, invoke_ctx, context)?.clone_with_cost(exec_state)?;
    let other_wrapped_seq =
        eval(&args[1], exec_state, invoke_ctx, context)?.clone_with_cost(exec_state)?;

    match (&mut wrapped_seq, other_wrapped_seq) {
        (Value::Sequence(seq), Value::Sequence(other_seq)) => {
            runtime_cost(
                ClarityCostFunction::Concat,
                exec_state,
                (seq.len() as u64).cost_overflow_add(other_seq.len() as u64)?,
            )?;

            seq.concat(exec_state.epoch(), other_seq)?
        }
        (Value::Sequence(seq_data), other_value) => {
            runtime_cost(ClarityCostFunction::Concat, exec_state, 1)?;
            return Err(RuntimeCheckErrorKind::TypeValueError(
                Box::new(seq_data.type_signature()?),
                other_value.to_error_string(),
            )
            .into());
        }
        _ => {
            runtime_cost(ClarityCostFunction::Concat, exec_state, 1)?;
            return Err(RuntimeCheckErrorKind::Unreachable(format!(
                "Expected sequence: {}",
                TypeSignature::type_of(&wrapped_seq)?,
            ))
            .into());
        }
    };

    Ok(wrapped_seq)
}

pub fn special_as_max_len(
    args: &[SymbolicExpression],
    exec_state: &mut ExecutionState,
    invoke_ctx: &InvocationContext,
    context: &LocalContext,
) -> Result<Value, VmExecutionError> {
    check_argument_count(2, args)?;

    let mut sequence =
        eval(&args[0], exec_state, invoke_ctx, context)?.clone_with_cost(exec_state)?;

    runtime_cost(ClarityCostFunction::AsMaxLen, exec_state, 0)?;

    if let Some(Value::UInt(expected_len)) = args[1].match_literal_value() {
        let sequence_len = match sequence {
            Value::Sequence(ref sequence_data) => sequence_data.len() as u128,
            _ => {
                return Err(RuntimeCheckErrorKind::Unreachable(format!(
                    "Expected sequence: {}",
                    TypeSignature::type_of(&sequence)?
                ))
                .into());
            }
        };
        if sequence_len > *expected_len {
            Ok(Value::none())
        } else {
            if let Value::Sequence(SequenceData::List(ref mut list)) = sequence {
                list.type_signature.reduce_max_len(*expected_len as u32);
            }
            Ok(Value::some(sequence)?)
        }
    } else {
        let actual_len = eval(&args[1], exec_state, invoke_ctx, context)?;
        Err(RuntimeCheckErrorKind::TypeError(
            Box::new(TypeSignature::UIntType),
            Box::new(TypeSignature::type_of(actual_len.as_ref())?),
        )
        .into())
    }
}

pub fn native_len(sequence: Value) -> Result<Value, VmExecutionError> {
    match sequence {
        Value::Sequence(sequence_data) => Ok(Value::UInt(sequence_data.len() as u128)),
        _ => Err(RuntimeCheckErrorKind::Unreachable(format!(
            "Expected sequence: {}",
            TypeSignature::type_of(&sequence)?
        ))
        .into()),
    }
}

pub fn native_index_of(sequence: Value, to_find: Value) -> Result<Value, VmExecutionError> {
    if let Value::Sequence(sequence_data) = sequence {
        match sequence_data.contains(to_find)? {
            Some(index) => Ok(Value::some(Value::UInt(index as u128))?),
            None => Ok(Value::none()),
        }
    } else {
        Err(RuntimeCheckErrorKind::Unreachable(format!(
            "Expected sequence: {}",
            TypeSignature::type_of(&sequence)?
        ))
        .into())
    }
}

pub fn native_element_at(sequence: Value, index: Value) -> Result<Value, VmExecutionError> {
    let sequence_data = if let Value::Sequence(sequence_data) = sequence {
        sequence_data
    } else {
        return Err(RuntimeCheckErrorKind::Unreachable(format!(
            "Expected sequence: {}",
            TypeSignature::type_of(&sequence)?
        ))
        .into());
    };

    let index = if let Value::UInt(index_u128) = index {
        if let Ok(index_usize) = usize::try_from(index_u128) {
            index_usize
        } else {
            return Ok(Value::none());
        }
    } else {
        return Err(RuntimeCheckErrorKind::TypeValueError(
            Box::new(TypeSignature::UIntType),
            index.to_error_string(),
        )
        .into());
    };

    if let Some(result) = sequence_data.element_at(index).map_err(|_| {
        VmInternalError::Expect("Sequence data constructed with invalid data.".into())
    })? {
        Ok(Value::some(result)?)
    } else {
        Ok(Value::none())
    }
}

/// Executes the Clarity2 function `slice?`.
pub fn special_slice(
    args: &[SymbolicExpression],
    exec_state: &mut ExecutionState,
    invoke_ctx: &InvocationContext,
    context: &LocalContext,
) -> Result<Value, VmExecutionError> {
    check_argument_count(3, args)?;

    let seq = eval(&args[0], exec_state, invoke_ctx, context)?.clone_with_cost(exec_state)?;
    let left_position = eval(&args[1], exec_state, invoke_ctx, context)?;
    let right_position = eval(&args[2], exec_state, invoke_ctx, context)?;

    let sliced_seq_res: Result<Value, VmExecutionError> = (|| {
        match (seq, left_position.as_ref(), right_position.as_ref()) {
            (Value::Sequence(seq), Value::UInt(left_position), Value::UInt(right_position)) => {
                let (left_position, right_position) = match (
                    u32::try_from(*left_position),
                    u32::try_from(*right_position),
                ) {
                    (Ok(left_position), Ok(right_position)) => (left_position, right_position),
                    _ => return Ok(Value::none()),
                };

                // Perform bound checks. Not necessary to check if positions are less than 0 since the vars are unsigned.
                if left_position as usize >= seq.len() || right_position as usize > seq.len() {
                    return Ok(Value::none());
                }
                if right_position < left_position {
                    return Ok(Value::none());
                }

                runtime_cost(
                    ClarityCostFunction::Slice,
                    exec_state,
                    (right_position - left_position) * seq.element_size()?,
                )?;
                let seq_value = seq.slice(
                    exec_state.epoch(),
                    left_position as usize,
                    right_position as usize,
                )?;
                Ok(Value::some(seq_value)?)
            }
            _ => Err(RuntimeCheckErrorKind::Unreachable("Bad type construction".into()).into()),
        }
    })();

    match sliced_seq_res {
        Ok(sliced_seq) => Ok(sliced_seq),
        Err(e) => {
            runtime_cost(ClarityCostFunction::Slice, exec_state, 0)?;
            Err(e)
        }
    }
}

pub fn special_replace_at(
    args: &[SymbolicExpression],
    exec_state: &mut ExecutionState,
    invoke_ctx: &InvocationContext,
    context: &LocalContext,
) -> Result<Value, VmExecutionError> {
    check_argument_count(3, args)?;

    let seq = eval(&args[0], exec_state, invoke_ctx, context)?;
    let seq_type = TypeSignature::type_of(seq.as_ref())?;

    // runtime is the cost to copy over one element into its place
    runtime_cost(ClarityCostFunction::ReplaceAt, exec_state, seq_type.size()?)?;

    let expected_elem_type = if let TypeSignature::SequenceType(seq_subtype) = &seq_type {
        seq_subtype.unit_type()
    } else {
        return Err(
            RuntimeCheckErrorKind::Unreachable(format!("Expected sequence: {seq_type}")).into(),
        );
    };
    let index_val = eval(&args[1], exec_state, invoke_ctx, context)?;
    let new_element = eval(&args[2], exec_state, invoke_ctx, context)?;

    if expected_elem_type != TypeSignature::NoType
        && !expected_elem_type.admits(exec_state.epoch(), new_element.as_ref())?
    {
        return Err(RuntimeCheckErrorKind::TypeValueError(
            Box::new(expected_elem_type),
            new_element.as_ref().to_error_string(),
        )
        .into());
    }

    let index = if let Value::UInt(index_u128) = index_val.as_ref() {
        if let Ok(index_usize) = usize::try_from(*index_u128) {
            index_usize
        } else {
            return Ok(Value::none());
        }
    } else {
        return Err(RuntimeCheckErrorKind::TypeValueError(
            Box::new(TypeSignature::UIntType),
            index_val.as_ref().to_error_string(),
        )
        .into());
    };

    let Value::Sequence(data) = seq.clone_with_cost(exec_state)? else {
        return Err(
            RuntimeCheckErrorKind::Unreachable(format!("Expected sequence: {seq_type}")).into(),
        );
    };
    let seq_len = data.len();
    if index >= seq_len {
        return Ok(Value::none());
    }
    let new_element = new_element.clone_with_cost(exec_state)?;
    Ok(data.replace_at(exec_state.epoch(), index, new_element)?)
}
