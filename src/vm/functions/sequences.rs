// Copyright (C) 2013-2020 Blocstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
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
use std::convert::TryInto;
use vm::costs::{cost_functions, CostOverflowingMath};
use vm::errors::{
    check_argument_count, CheckErrors, InterpreterResult as Result, RuntimeErrorType,
};
use vm::representations::{SymbolicExpression, SymbolicExpressionType};
use vm::types::{
    signatures::ListTypeData, CharType, ListData, SequenceData, TypeSignature,
    TypeSignature::BoolType, Value,
};
use vm::{apply, eval, lookup_function, CallableType, Environment, LocalContext};

pub fn list_cons(
    args: &[SymbolicExpression],
    env: &mut Environment,
    context: &LocalContext,
) -> Result<Value> {
    let eval_tried: Result<Vec<Value>> = args.iter().map(|x| eval(x, env, context)).collect();
    let args = eval_tried?;

    let mut arg_size = 0;
    for a in args.iter() {
        arg_size = arg_size.cost_overflow_add(a.size().into())?;
    }

    runtime_cost!(cost_functions::LIST_CONS, env, arg_size)?;

    Value::list_from(args)
}

pub fn special_filter(
    args: &[SymbolicExpression],
    env: &mut Environment,
    context: &LocalContext,
) -> Result<Value> {
    check_argument_count(2, args)?;

    runtime_cost!(cost_functions::FILTER, env, 0)?;

    let function_name = args[0].match_atom().ok_or(CheckErrors::ExpectedName)?;

    let mut sequence = eval(&args[1], env, context)?;
    let function = lookup_function(&function_name, env)?;

    match sequence {
        Value::Sequence(ref mut sequence_data) => {
            sequence_data.filter(&mut |atom_value: SymbolicExpression| {
                let argument = [atom_value];
                let filter_eval = apply(&function, &argument, env, context)?;
                if let Value::Bool(include) = filter_eval {
                    return Ok(include);
                } else {
                    return Err(CheckErrors::TypeValueError(BoolType, filter_eval).into());
                }
            })?;
        }
        _ => return Err(CheckErrors::ExpectedSequence(TypeSignature::type_of(&sequence)).into()),
    };
    Ok(sequence)
}

pub fn special_fold(
    args: &[SymbolicExpression],
    env: &mut Environment,
    context: &LocalContext,
) -> Result<Value> {
    check_argument_count(3, args)?;

    runtime_cost!(cost_functions::FOLD, env, 0)?;

    let function_name = args[0].match_atom().ok_or(CheckErrors::ExpectedName)?;

    let function = lookup_function(&function_name, env)?;
    let mut sequence = eval(&args[1], env, context)?;
    let initial = eval(&args[2], env, context)?;

    match sequence {
        Value::Sequence(ref mut sequence_data) => {
            sequence_data
                .atom_values()
                .into_iter()
                .try_fold(initial, |acc, x| {
                    apply(
                        &function,
                        &[x, SymbolicExpression::atom_value(acc)],
                        env,
                        context,
                    )
                })
        }
        _ => Err(CheckErrors::ExpectedSequence(TypeSignature::type_of(&sequence)).into()),
    }
}

pub fn special_map(
    args: &[SymbolicExpression],
    env: &mut Environment,
    context: &LocalContext,
) -> Result<Value> {
    check_argument_count(2, args)?;

    runtime_cost!(cost_functions::MAP, env, 0)?;

    let function_name = args[0].match_atom().ok_or(CheckErrors::ExpectedName)?;
    let mut sequence = eval(&args[1], env, context)?;
    let function = lookup_function(&function_name, env)?;

    let mapped_sequence: Vec<_> = match sequence {
        Value::Sequence(ref mut sequence_data) => sequence_data
            .atom_values()
            .into_iter()
            .map(|argument| apply(&function, &[argument], env, context))
            .collect(),
        _ => Err(CheckErrors::ExpectedSequence(TypeSignature::type_of(&sequence)).into()),
    }?;
    Value::list_from(mapped_sequence)
}

pub fn special_append(
    args: &[SymbolicExpression],
    env: &mut Environment,
    context: &LocalContext,
) -> Result<Value> {
    check_argument_count(2, args)?;

    let sequence = eval(&args[0], env, context)?;
    match sequence {
        Value::Sequence(SequenceData::List(list)) => {
            let element = eval(&args[1], env, context)?;
            let ListData {
                mut data,
                type_signature,
            } = list;
            let (entry_type, size) = type_signature.destruct();
            let element_type = TypeSignature::type_of(&element);
            runtime_cost!(
                cost_functions::APPEND,
                env,
                u64::from(cmp::max(entry_type.size(), element_type.size()))
            )?;
            if entry_type.is_no_type() {
                assert_eq!(size, 0);
                return Value::list_from(vec![element]);
            }
            if let Ok(next_entry_type) = TypeSignature::least_supertype(&entry_type, &element_type)
            {
                let next_type_signature = ListTypeData::new_list(next_entry_type, size + 1)?;
                data.push(element);
                Ok(Value::Sequence(SequenceData::List(ListData {
                    type_signature: next_type_signature,
                    data,
                })))
            } else {
                Err(CheckErrors::TypeValueError(entry_type, element).into())
            }
        }
        _ => Err(CheckErrors::ExpectedListApplication.into()),
    }
}

pub fn special_concat(
    args: &[SymbolicExpression],
    env: &mut Environment,
    context: &LocalContext,
) -> Result<Value> {
    check_argument_count(2, args)?;

    let mut wrapped_seq = eval(&args[0], env, context)?;
    let mut other_wrapped_seq = eval(&args[1], env, context)?;

    runtime_cost!(
        cost_functions::CONCAT,
        env,
        u64::from(wrapped_seq.size()).cost_overflow_add(u64::from(other_wrapped_seq.size()))?
    )?;

    match (&mut wrapped_seq, &mut other_wrapped_seq) {
        (Value::Sequence(ref mut seq), Value::Sequence(ref mut other_seq)) => seq.append(other_seq),
        _ => Err(RuntimeErrorType::BadTypeConstruction.into()),
    }?;

    Ok(wrapped_seq)
}

pub fn special_as_max_len(
    args: &[SymbolicExpression],
    env: &mut Environment,
    context: &LocalContext,
) -> Result<Value> {
    check_argument_count(2, args)?;

    let mut sequence = eval(&args[0], env, context)?;

    runtime_cost!(cost_functions::AS_MAX_LEN, env, 0)?;

    if let Some(Value::UInt(expected_len)) = args[1].match_literal_value() {
        let sequence_len = match sequence {
            Value::Sequence(ref sequence_data) => sequence_data.len() as u128,
            _ => {
                return Err(CheckErrors::ExpectedSequence(TypeSignature::type_of(&sequence)).into())
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
        let actual_len = eval(&args[1], env, context)?;
        Err(
            CheckErrors::TypeError(TypeSignature::UIntType, TypeSignature::type_of(&actual_len))
                .into(),
        )
    }
}

pub fn native_len(sequence: Value) -> Result<Value> {
    match sequence {
        Value::Sequence(sequence_data) => Ok(Value::UInt(sequence_data.len() as u128)),
        _ => Err(CheckErrors::ExpectedSequence(TypeSignature::type_of(&sequence)).into()),
    }
}
