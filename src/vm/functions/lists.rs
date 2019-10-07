use vm::errors::{CheckErrors, InterpreterResult as Result, check_argument_count};
use vm::types::{Value, TypeSignature::BoolType, TypeSignature};
use vm::representations::{SymbolicExpression, SymbolicExpressionType};
use vm::{LocalContext, Environment, eval, apply, lookup_function};

pub fn list_cons(args: &[Value]) -> Result<Value> {
    Value::list_from(Vec::from(args))
}

pub fn list_filter(args: &[SymbolicExpression], env: &mut Environment, context: &LocalContext) -> Result<Value> {
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

pub fn list_fold(args: &[SymbolicExpression], env: &mut Environment, context: &LocalContext) -> Result<Value> {
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

pub fn list_map(args: &[SymbolicExpression], env: &mut Environment, context: &LocalContext) -> Result<Value> {
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

pub fn list_len(args: &[SymbolicExpression], env: &mut Environment, context: &LocalContext) -> Result<Value> {
    check_argument_count(1, args)?;
    
    let iterable = eval(&args[0], env, context)?;
    match iterable {
        Value::List(list) => Ok(Value::UInt(list.data.len() as u128)),
        Value::Buffer(buff) => Ok(Value::UInt(buff.data.len() as u128)),
        _ => Err(CheckErrors::ExpectedListOrBuffer(TypeSignature::type_of(&iterable)).into())
    }
}
