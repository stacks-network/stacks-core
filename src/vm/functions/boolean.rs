use vm::types::Value;
use vm::errors::{Error, InterpreterResult as Result};
use vm::representations::SymbolicExpression;
use vm::{Context,Environment,eval};

fn type_force_bool(value: &Value) -> Result<bool> {
    match *value {
        Value::Bool(boolean) => Ok(boolean),
        _ => Err(Error::TypeError("BoolType".to_string(), value.clone()))
    }
}

pub fn special_or(args: &[SymbolicExpression], env: &mut Environment, context: &Context) -> Result<Value> {
    if args.len() < 1 {
        return Err(Error::InvalidArguments("(or ...) requires at least 1 argument".to_string()))
    }

    for arg in args.iter() {
        let evaluated = eval(&arg, env, context)?;
        let result = type_force_bool(&evaluated)?;
        if result {
            return Ok(Value::Bool(true))
        }
    }

    Ok(Value::Bool(false))
}

pub fn special_and(args: &[SymbolicExpression], env: &mut Environment, context: &Context) -> Result<Value> {
    if args.len() < 1 {
        return Err(Error::InvalidArguments("(and ...) requires at least 1 argument".to_string()))
    }

    for arg in args.iter() {
        let evaluated = eval(&arg, env, context)?;
        let result = type_force_bool(&evaluated)?;
        if !result {
            return Ok(Value::Bool(false))
        }
    }

    Ok(Value::Bool(true))
}

pub fn native_not(args: &[Value]) -> Result<Value> {
    if args.len() != 1 {
        return Err(Error::InvalidArguments("(not ...) requires exactly 1 argument".to_string()))
    }
    let value = type_force_bool(&args[0])?;
    Ok(Value::Bool(!value))
}
