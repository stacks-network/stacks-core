use vm::errors::{CheckErrors, InterpreterResult as Result, check_argument_count};
use vm::types::{Value, TypeSignature::BoolType, TypeSignature};
use vm::representations::{SymbolicExpression, SymbolicExpressionType};
use vm::{LocalContext, Environment, eval, apply, lookup_function};
use std::convert::TryInto;

pub fn list_cons(args: &[Value]) -> Result<Value> {
    Value::list_from(Vec::from(args))
}

pub fn native_filter(args: &[SymbolicExpression], env: &mut Environment, context: &LocalContext) -> Result<Value> {
    check_argument_count(2, args)?;

    let function_name = args[0].match_atom()
        .ok_or(CheckErrors::ExpectedName)?;

    let function = lookup_function(&function_name, env)?;
    let iterable = eval(&args[1], env, context)?;

    match iterable {
        Value::List(mut list) => {
            let mut filtered_vec = Vec::new();
            for x in list.data.drain(..) {
                let argument = [ SymbolicExpression::atom_value(x.clone()) ];
                let filter_eval = apply(&function, &argument, env, context)?;
                if let Value::Bool(include) = filter_eval {
                    if include {
                        filtered_vec.push(x);
                    } // else, filter out.
                } else {
                    return Err(CheckErrors::TypeValueError(BoolType, filter_eval).into())
                }
            }
            Value::list_with_type(filtered_vec, list.type_signature)
        },
        Value::Buffer(mut buff) => {
            let mut filtered_vec = Vec::new();
            for x in buff.data.drain(..) {
                let v = Value::buff_from(vec![x.clone()]).unwrap();
                let argument = [ SymbolicExpression::atom_value(v) ];
                let filter_eval = apply(&function, &argument, env, context)?;
                if let Value::Bool(include) = filter_eval {
                    if include {
                        filtered_vec.push(x);
                    } // else, filter out.
                } else {
                    return Err(CheckErrors::TypeValueError(BoolType, filter_eval).into())
                }
            }
            Value::buff_from(filtered_vec)
        },
        _ => Err(CheckErrors::ExpectedListOrBuffer(TypeSignature::type_of(&iterable)).into())
    }
}

pub fn native_fold(args: &[SymbolicExpression], env: &mut Environment, context: &LocalContext) -> Result<Value> {
    check_argument_count(3, args)?;

    let function_name = args[0].match_atom()
        .ok_or(CheckErrors::ExpectedName)?;

    let function = lookup_function(&function_name, env)?;
    let iterable = eval(&args[1], env, context)?;
    let initial = eval(&args[2], env, context)?;

    let mapped_args: Vec<_> = match iterable {
        Value::List(mut list) => {
            list.data.drain(..).map(|x| {
                SymbolicExpression::atom_value(x)
            }).collect()
        },
        Value::Buffer(mut buff) => {
            buff.data.drain(..).map(|x| {
                let element = Value::buff_from(vec![x]).unwrap();
                SymbolicExpression::atom_value(element)
            }).collect()
        },
        _ => return Err(CheckErrors::ExpectedListOrBuffer(TypeSignature::type_of(&iterable)).into())
    };
    mapped_args.iter().try_fold(initial, |acc, x| {
        apply(&function, &[x.clone(), SymbolicExpression::atom_value(acc)], env, context)
    })
}

pub fn native_map(args: &[SymbolicExpression], env: &mut Environment, context: &LocalContext) -> Result<Value> {
    check_argument_count(2, args)?;

    let function_name = args[0].match_atom()
        .ok_or(CheckErrors::ExpectedName)?;
    let iterable = eval(&args[1], env, context)?;
    let function = lookup_function(&function_name, env)?;

    let mapped_args: Vec<_> = match iterable {
        Value::List(mut list) => {
            list.data.drain(..).map(|x| {
                vec![SymbolicExpression::atom_value(x)]
            }).collect()
        },
        Value::Buffer(mut buff) => {
            buff.data.drain(..).map(|x| {
                let element = Value::buff_from(vec![x]).unwrap();
                vec![SymbolicExpression::atom_value(element)]
            }).collect()
        },
        _ => return Err(CheckErrors::ExpectedListOrBuffer(TypeSignature::type_of(&iterable)).into())
    };
    let mapped_vec: Result<Vec<_>> =
        mapped_args.iter().map(|argument| apply(&function, &argument, env, context)).collect();
    Value::list_from(mapped_vec?)
}

pub fn native_append(args: &[SymbolicExpression], env: &mut Environment, context: &LocalContext) -> Result<Value> {
    check_argument_count(2, args)?;

    let iterable = eval(&args[0], env, context)?;
    match iterable {
        Value::List(list) => {
            let element = eval(&args[1], env, context)?;
            let mut data_appended = list.data.clone();
            data_appended.push(element);
            Value::list_from(data_appended)
        },
        _ => Err(CheckErrors::ExpectedListApplication.into())
    }
}

pub fn native_concat(args: &[SymbolicExpression], env: &mut Environment, context: &LocalContext) -> Result<Value> {
    check_argument_count(2, args)?;

    let lhs = eval(&args[0], env, context)?;
    let rhs = eval(&args[1], env, context)?;

    match (lhs, rhs) {
        (Value::List(lhs_data), Value::List(mut rhs_data)) => {
            let mut data = lhs_data.data;
            data.append(&mut rhs_data.data);
            Value::list_from(data)
        },
        (Value::Buffer(lhs_data), Value::Buffer(mut rhs_data)) => {
            let mut data = lhs_data.data;
            data.append(&mut rhs_data.data);
            Value::buff_from(data)
        },
        (_, _) => {
            Err(RuntimeErrorType::BadTypeConstruction.into())
        }
    }
}

pub fn native_asserts_max_len(args: &[SymbolicExpression], env: &mut Environment, context: &LocalContext) -> Result<Value> {
    check_argument_count(2, args)?;

    let iterable = eval(&args[0], env, context)?;

    if let Some(Value::UInt(expected_len)) = args[1].match_literal_value() {
        let iterable_len = match iterable {
            Value::List(ref list) => list.data.len(),
            Value::Buffer(ref buff) => buff.data.len(),
            _ => return Err(CheckErrors::ExpectedListOrBuffer(TypeSignature::type_of(&iterable)).into())
        };
        if iterable_len as u128 > *expected_len {
            Ok(Value::none())
        } else {
            Ok(Value::some(iterable))
        }
    } else {
        let actual_len = eval(&args[1], env, context)?;
        Err(CheckErrors::TypeError(TypeSignature::UIntType, TypeSignature::type_of(&actual_len)).into())
    }
}

pub fn native_len(args: &[SymbolicExpression], env: &mut Environment, context: &LocalContext) -> Result<Value> {
    check_argument_count(1, args)?;
    
    let iterable = eval(&args[0], env, context)?;
    match iterable {
        Value::List(list) => Ok(Value::UInt(list.data.len() as u128)),
        Value::Buffer(buff) => Ok(Value::UInt(buff.data.len() as u128)),
        _ => Err(CheckErrors::ExpectedListOrBuffer(TypeSignature::type_of(&iterable)).into())
    }
}
