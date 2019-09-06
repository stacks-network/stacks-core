use vm::errors::{CheckErrors, ShortReturnType, InterpreterResult as Result, check_argument_count};
use vm::types::{Value, ResponseData};

pub fn native_expects(args: &[Value]) -> Result<Value> {
    check_argument_count(2, args)?;

    let input = &args[0];
    let thrown = &args[1];

    match input {
        Value::Optional(data) => {
            match data.data {
                Some(ref data) => Ok((**data).clone()),
                None => Err(ShortReturnType::ExpectedValue(thrown.clone()).into())
            }
        },
        Value::Response(data) => {
            if data.committed {
                Ok((*data.data).clone())
            } else {
                Err(ShortReturnType::ExpectedValue(thrown.clone()).into())
            }
        },
        _ => Err(CheckErrors::ExpectedResponseValue(input.clone()).into())
    }
}

pub fn native_expects_err(args: &[Value]) -> Result<Value> {
    check_argument_count(2, args)?;

    let input = &args[0];
    let thrown = &args[1];

    match input {
        Value::Response(data) => {
            if !data.committed {
                Ok((*data.data).clone())
            } else {
                Err(ShortReturnType::ExpectedValue(thrown.clone()).into())
            }
        },
        _ => Err(CheckErrors::ExpectedResponseValue(input.clone()).into())
    }
}

pub fn native_some(args: &[Value]) -> Result<Value> {
    check_argument_count(1, args)?;

    Ok(Value::some(args[0].clone()))
}

pub fn native_is_none(args: &[Value]) -> Result<Value> {
    check_argument_count(1, args)?;

    let input = &args[0];

    match input {
        Value::Optional(ref data) => Ok(Value::Bool(data.data.is_none())),
        _ => Err(CheckErrors::ExpectedOptionalValue(input.clone()).into())
    }
}

pub fn native_is_okay(args: &[Value]) -> Result<Value> {
    check_argument_count(1, args)?;

    let input = &args[0];

    match input {
        Value::Response(data) => Ok(Value::Bool(data.committed)),
        _ => Err(CheckErrors::ExpectedResponseValue(input.clone()).into())
    }
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
