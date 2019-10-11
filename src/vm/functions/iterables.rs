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

    match iterable {
        Value::List(mut list) => {
            list.data.drain(..).try_fold(initial, |acc, x| {
                let arguments = vec![
                    SymbolicExpression::atom_value(x), 
                    SymbolicExpression::atom_value(acc)];
                apply(&function, &arguments, env, context)
            })
        },
        Value::Buffer(mut buff) => {
            buff.data.drain(..).try_fold(initial, |acc, x| {
                let arguments = vec![
                    SymbolicExpression::atom_value(Value::buff_from(vec![x]).unwrap()), 
                    SymbolicExpression::atom_value(acc)];
                apply(&function, &arguments, env, context)
            })
        },
        _ => Err(CheckErrors::ExpectedListOrBuffer(TypeSignature::type_of(&iterable)).into())
    }
}

pub fn native_map(args: &[SymbolicExpression], env: &mut Environment, context: &LocalContext) -> Result<Value> {
    check_argument_count(2, args)?;

    let function_name = args[0].match_atom()
        .ok_or(CheckErrors::ExpectedName)?;
    let function = lookup_function(&function_name, env)?;

    let iterable = eval(&args[1], env, context)?;
    match iterable {
        Value::List(mut list) => {
            let mapped_vec = list.data.drain(..).map(|x| {
                let argument = vec![SymbolicExpression::atom_value(x)];
                apply(&function, &argument, env, context).unwrap()
            }).collect();
            Value::list_from(mapped_vec)
        },
        Value::Buffer(mut buff) => {
            let mapped_vec = buff.data.drain(..).map(|x| {
                let element = Value::buff_from(vec![x]).unwrap();
                let argument = vec![SymbolicExpression::atom_value(element)];
                apply(&function, &argument, env, context).unwrap()
            }).collect();
            Value::list_from(mapped_vec)
        },
        _ => Err(CheckErrors::ExpectedListOrBuffer(TypeSignature::type_of(&iterable)).into())
    }
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

    let iterable = eval(&args[0], env, context)?;
    match iterable {
        Value::List(mut lhs) => {
            let mut res = Vec::new();
            res.append(&mut lhs.data);
            let mut rhs = eval(&args[1], env, context)?;
            if let Value::List(ref mut rhs_data) = rhs {
                res.append(&mut rhs_data.data);
                Value::list_from(res)
            } else {
                Err(CheckErrors::TypeError(
                    TypeSignature::type_of(&Value::List(lhs)), 
                    TypeSignature::type_of(&rhs)).into())
            }
        },
        Value::Buffer(mut lhs) => {
            let mut res = Vec::new();
            res.append(&mut lhs.data);
            let mut rhs = eval(&args[1], env, context)?;
            if let Value::Buffer(ref mut rhs_data) = rhs {
                res.append(&mut rhs_data.data);
                Value::buff_from(res)
            } else {
                println!("-> {:?}", lhs);
                println!("-> {:?}", rhs);

                Err(CheckErrors::TypeError(
                    TypeSignature::BufferType(res.len().try_into().unwrap()),
                    TypeSignature::type_of(&rhs)).into())
            }
        },
        _ => Err(CheckErrors::ExpectedListOrBuffer(TypeSignature::type_of(&iterable)).into())
    }
}

pub fn native_asserts_max_len(args: &[SymbolicExpression], env: &mut Environment, context: &LocalContext) -> Result<Value> {
    check_argument_count(2, args)?;

    let iterable = eval(&args[0], env, context)?;

    let expected_len = eval(&args[1], env, context)?;
    if let Value::UInt(expected_len) = expected_len {
        match iterable {
            Value::List(list) => {
                let iterable_len = list.data.len() as u128;
                if iterable_len > expected_len {
                    Ok(Value::none())
                } else {
                    Ok(Value::some(Value::List(list)))
                }
            },
            Value::Buffer(buff) => {
                let iterable_len = buff.data.len() as u128;
                if iterable_len > expected_len { 
                    Ok(Value::none())
                } else {
                    Ok(Value::some(Value::Buffer(buff)))
                }
            },
            _ => return Err(CheckErrors::ExpectedListOrBuffer(TypeSignature::type_of(&iterable)).into())
        }
    } else {
        Err(CheckErrors::TypeError(TypeSignature::UIntType, TypeSignature::type_of(&expected_len)).into())
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
