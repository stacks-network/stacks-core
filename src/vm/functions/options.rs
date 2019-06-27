use vm::errors::{UncheckedError, ShortReturnType, InterpreterResult as Result};
use vm::types::{Value, ResponseData};

pub fn native_expects(args: &[Value]) -> Result<Value> {
    if args.len() != 2 {
        return Err(UncheckedError::InvalidArguments("Wrong number of arguments to expects (expects! input-value thrown-value)".to_string()).into())
    }

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
        _ => Err(UncheckedError::TypeError("OptionalType|ResponseType".to_string(), input.clone()).into())
    }
}

pub fn native_expects_err(args: &[Value]) -> Result<Value> {
    if args.len() != 2 {
        return Err(UncheckedError::InvalidArguments("Wrong number of arguments to expects (expects-err! input-value thrown-value)".to_string()).into())
    }

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
        _ => Err(UncheckedError::TypeError("ResponseType".to_string(), input.clone()).into())
    }
}

pub fn native_some(args: &[Value]) -> Result<Value> {
    if args.len() != 1 {
        return Err(UncheckedError::InvalidArguments("Wrong number of arguments to some (expects 1)".to_string()).into())
    }

    Ok(Value::some(args[0].clone()))
}

pub fn native_is_none(args: &[Value]) -> Result<Value> {
    if args.len() != 1 {
        return Err(UncheckedError::InvalidArguments("Wrong number of arguments to is-none? (expects 1)".to_string()).into())
    }

    let input = &args[0];

    match input {
        Value::Optional(ref data) => Ok(Value::Bool(data.data.is_none())),
        _ => Err(UncheckedError::TypeError("OptionalType".to_string(), input.clone()).into())
    }
}

pub fn native_is_okay(args: &[Value]) -> Result<Value> {
    if args.len() != 1 {
        return Err(UncheckedError::InvalidArguments("Wrong number of arguments to is-ok? (expects 1)".to_string()).into())
    }

    let input = &args[0];

    match input {
        Value::Response(data) => Ok(Value::Bool(data.committed)),
        _ => Err(UncheckedError::TypeError("ResponseType".to_string(), input.clone()).into())
    }
}

pub fn native_okay(args: &[Value]) -> Result<Value> {
    if args.len() != 1 {
        return Err(UncheckedError::InvalidArguments("Wrong number of arguments to ok (expects 1)".to_string()).into())
    }

    let input = &args[0];
    Ok(Value::Response(ResponseData { committed: true, data: Box::new(input.clone()) }))
}

pub fn native_error(args: &[Value]) -> Result<Value> {
    if args.len() != 1 {
        return Err(UncheckedError::InvalidArguments("Wrong number of arguments to err (expects 1)".to_string()).into())
    }

    let input = &args[0];
    Ok(Value::Response(ResponseData { committed: false, data: Box::new(input.clone()) }))
}

pub fn native_default_to(args: &[Value]) -> Result<Value> {
    if args.len() != 2 {
        return Err(UncheckedError::InvalidArguments("Wrong number of arguments to default-to (expects 2)".to_string()).into())
    }

    let default = &args[0];
    let input = &args[1];

    match input {
        Value::Optional(data) => {
            match data.data {
                Some(ref data) => Ok((**data).clone()),
                None => Ok(default.clone())
            }
        },
        _ => Err(UncheckedError::TypeError("OptionalType".to_string(), input.clone()).into())
    }
}
