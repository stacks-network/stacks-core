use vm::errors::{CheckErrors, InterpreterResult as Result, check_argument_count};
use vm::types::{Value, TypeSignature::BoolType};
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
    let list = eval(&args[1], env, context)?;
    if let Value::List(mut list_data) = list { 
        let mut output = Vec::new();
        for x in list_data.data.drain(..) {
            let argument = [ SymbolicExpression::atom_value(x.clone()) ];
            let filter_eval = apply(&function, &argument, env, context)?;
            if let Value::Bool(include) = filter_eval {
                if include {
                    output.push(x);
                } // else, filter out.
            } else {
                return Err(CheckErrors::TypeValueError(BoolType, filter_eval).into())
            }
        }
        Value::list_with_type(output, list_data.type_signature)
    } else {
        Err(CheckErrors::ExpectedListApplication.into())
    }
}

pub fn list_fold(args: &[SymbolicExpression], env: &mut Environment, context: &LocalContext) -> Result<Value> {
    check_argument_count(3, args)?;

    let function_name = args[0].match_atom()
        .ok_or(CheckErrors::ExpectedName)?;

    let function = lookup_function(&function_name, env)?;
    let list = eval(&args[1], env, context)?;
    let initial = eval(&args[2], env, context)?;
    if let Value::List(mut list_data) = list {
        list_data.data.drain(..).try_fold(
            initial,
            |acc, x| {
                let argument = [ SymbolicExpression::atom_value(x),
                                 SymbolicExpression::atom_value(acc) ];
                apply(&function, &argument, env, context)
            })
    } else {
        Err(CheckErrors::ExpectedListApplication.into())
    }
}

pub fn list_map(args: &[SymbolicExpression], env: &mut Environment, context: &LocalContext) -> Result<Value> {
    check_argument_count(2, args)?;

    let function_name = args[0].match_atom()
        .ok_or(CheckErrors::ExpectedName)?;
    let function = lookup_function(&function_name, env)?;

    let list = eval(&args[1], env, context)?;
    if let Value::List(mut list_data) = list {
        let mapped_vec: Result<Vec<_>> = list_data.data.drain(..).map(|x| {
            let argument = [ SymbolicExpression::atom_value(x) ];
            apply(&function, &argument, env, context)
        }).collect();
        Value::list_from(mapped_vec?)
    } else {
        Err(CheckErrors::ExpectedListApplication.into())
    }
}

pub fn list_len(args: &[SymbolicExpression], env: &mut Environment, context: &LocalContext) -> Result<Value> {
    check_argument_count(1, args)?;

    let len_target = eval(&args[0], env, context)?;
    match len_target {
        Value::List(list) => Ok(Value::UInt(list.data.len() as u128)),
        Value::Buffer(buff) => Ok(Value::UInt(buff.data.len() as u128)),
        _ => Err(CheckErrors::ExpectedListApplication.into())
    }
}

