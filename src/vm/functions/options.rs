use vm::errors::{CheckErrors, RuntimeErrorType, ShortReturnType, InterpreterResult as Result,
                 check_argument_count, check_arguments_at_least};
use vm::types::{Value, ResponseData, OptionalData};
use vm::contexts::{LocalContext, Environment};
use vm::{SymbolicExpression, ClarityName};
use vm;

fn inner_unwrap(to_unwrap: &Value) -> Result<Option<Value>> {
    let result = match to_unwrap {
        Value::Optional(data) => {
            match data.data {
                Some(ref data) => Some((**data).clone()),
                None => None
            }
        },
        Value::Response(data) => {
            if data.committed {
                Some((*data.data).clone())
            } else {
                None
            }
        },
        _ => return Err(CheckErrors::ExpectedResponseValue(to_unwrap.clone()).into())
    };

    Ok(result)
}

fn inner_unwrap_err(to_unwrap: &Value) -> Result<Option<Value>> {
    let result = match to_unwrap {
        Value::Response(data) => {
            if !data.committed {
                Some((*data.data).clone())
            } else {
                None
            }
        },
        _ => return Err(CheckErrors::ExpectedResponseValue(to_unwrap.clone()).into())
    };

    Ok(result)
}

pub fn native_unwrap(args: &[Value]) -> Result<Value> {
    check_argument_count(1, args)?;

    inner_unwrap(&args[0])
        .and_then(|opt_value| {
            match opt_value {
                Some(v) => Ok(v),
                None => Err(RuntimeErrorType::UnwrapFailure.into())
            }
        })
}

pub fn native_unwrap_or_ret(args: &[Value]) -> Result<Value> {
    check_argument_count(2, args)?;

    let input = &args[0];
    let thrown = &args[1];

    inner_unwrap(input)
        .and_then(|opt_value| {
            match opt_value {
                Some(v) => Ok(v),
                None => Err(ShortReturnType::ExpectedValue(thrown.clone()).into())
            }
        })
}

pub fn native_unwrap_err(args: &[Value]) -> Result<Value> {
    check_argument_count(1, args)?;

    inner_unwrap_err(&args[0])
        .and_then(|opt_value| {
            match opt_value {
                Some(v) => Ok(v),
                None => Err(RuntimeErrorType::UnwrapFailure.into())
            }
        })
}

pub fn native_unwrap_err_or_ret(args: &[Value]) -> Result<Value> {
    check_argument_count(2, args)?;

    let input = &args[0];
    let thrown = &args[1];

    inner_unwrap_err(input)
        .and_then(|opt_value| {
            match opt_value {
                Some(v) => Ok(v),
                None => Err(ShortReturnType::ExpectedValue(thrown.clone()).into())
            }
        })
}

pub fn native_try_ret(args: &[Value]) -> Result<Value> {
    check_argument_count(1, args)?;

    let input = &args[0];

    match input {
        Value::Optional(data) => {
            match data.data {
                Some(ref data) => Ok((**data).clone()),
                None => Err(ShortReturnType::ExpectedValue(Value::none()).into())
            }
        },
        Value::Response(data) => {
            if data.committed {
                Ok((*data.data).clone())
            } else {
                Err(ShortReturnType::ExpectedValue((*data.data).clone()).into())
            }
        },
        _ => Err(CheckErrors::ExpectedResponseValue(input.clone()).into())
    }
}

fn eval_with_new_binding(body: &SymbolicExpression, bind_name: ClarityName, bind_value: Value, 
                         env: &mut Environment, context: &LocalContext) -> Result<Value> {
    let mut inner_context = context.extend()?;
    if vm::is_reserved(&bind_name) ||
       env.contract_context.lookup_function(&bind_name).is_some() ||
       inner_context.lookup_variable(&bind_name).is_some() {
        return Err(CheckErrors::NameAlreadyUsed(bind_name.into()).into())
    }

    inner_context.variables.insert(bind_name, bind_value);

    vm::eval(body, env, &inner_context)
}

fn special_match_opt(input: OptionalData, args: &[SymbolicExpression], env: &mut Environment, context: &LocalContext) -> Result<Value> {
    check_argument_count(3, args)?;

    let bind_name = args[0].match_atom()
        .ok_or_else(|| CheckErrors::ExpectedName)?
        .clone();
    let some_branch = &args[1];
    let none_branch = &args[2];

    match input.data {
        Some(data) => eval_with_new_binding(some_branch, bind_name, *data, env, context),
        None => vm::eval(none_branch, env, context)
    }
}


fn special_match_resp(input: ResponseData, args: &[SymbolicExpression], env: &mut Environment, context: &LocalContext) -> Result<Value> {
    check_argument_count(5, args)?;

    let ok_bind_name = args[0].match_atom()
        .ok_or_else(|| CheckErrors::ExpectedName)?
        .clone();
    let ok_branch = &args[1];
    let err_bind_name = args[2].match_atom()
        .ok_or_else(|| CheckErrors::ExpectedName)?
        .clone();
    let err_branch = &args[3];

    if input.committed {
        eval_with_new_binding(ok_branch, ok_bind_name, *input.data, env, context)
    } else {
        eval_with_new_binding(err_branch, err_bind_name, *input.data, env, context)
    }
}

pub fn special_match(args: &[SymbolicExpression], env: &mut Environment, context: &LocalContext) -> Result<Value> {
    check_arguments_at_least(1, args)?;

    let input = vm::eval(&args[0], env, context)?;

    match input {
        Value::Response(data) => {
            special_match_resp(data, &args[1..], env, context) 
        },
        Value::Optional(data) => {
            special_match_opt(data, &args[1..], env, context) 
        },
        _ => return Err(CheckErrors::ExpectedOptionalOrResponseValue(input.clone()).into())
    }
}

pub fn native_some(args: &[Value]) -> Result<Value> {
    check_argument_count(1, args)?;

    Ok(Value::some(args[0].clone()))
}

fn is_some(args: &[Value]) -> Result<bool> {
    check_argument_count(1, args)?;

    let input = &args[0];

    match input {
        Value::Optional(ref data) => Ok(data.data.is_some()),
        _ => Err(CheckErrors::ExpectedOptionalValue(input.clone()).into())
    }
}

fn is_okay(args: &[Value]) -> Result<bool> {
    check_argument_count(1, args)?;

    let input = &args[0];

    match input {
        Value::Response(data) => Ok(data.committed),
        _ => Err(CheckErrors::ExpectedResponseValue(input.clone()).into())
    }
}

pub fn native_is_some(args: &[Value]) -> Result<Value> {
    is_some(args)
        .map(|is_some| { Value::Bool(is_some) })
}

pub fn native_is_none(args: &[Value]) -> Result<Value> {
    is_some(args)
        .map(|is_some| { Value::Bool(!is_some) })
}

pub fn native_is_okay(args: &[Value]) -> Result<Value> {
    is_okay(args)
        .map(|is_ok| { Value::Bool(is_ok) })
}

pub fn native_is_err(args: &[Value]) -> Result<Value> {
    is_okay(args)
        .map(|is_ok| { Value::Bool(!is_ok) })
}

pub fn native_okay(args: &[Value]) -> Result<Value> {
    check_argument_count(1, args)?;

    let input = &args[0];
    Ok(Value::okay(input.clone()))
}

pub fn native_error(args: &[Value]) -> Result<Value> {
    check_argument_count(1, args)?;

    let input = &args[0];
    Ok(Value::error(input.clone()))
}

pub fn native_default_to(args: &[Value]) -> Result<Value> {
    check_argument_count(2, args)?;

    let default = &args[0];
    let input = &args[1];

    match input {
        Value::Optional(data) => {
            match data.data {
                Some(ref data) => Ok((**data).clone()),
                None => Ok(default.clone())
            }
        },
        _ => Err(CheckErrors::ExpectedOptionalValue(input.clone()).into())
    }
}
