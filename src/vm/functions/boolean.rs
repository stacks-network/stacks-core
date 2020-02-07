use vm::types::{Value, TypeSignature};
use vm::errors::{CheckErrors, check_arguments_at_least, check_argument_count, InterpreterResult as Result};
use vm::representations::SymbolicExpression;
use vm::{LocalContext, Environment, eval};

fn type_force_bool(value: &Value) -> Result<bool> {
    match *value {
        Value::Bool(boolean) => Ok(boolean),
        _ => Err(CheckErrors::TypeValueError(TypeSignature::BoolType, value.clone()).into())
    }
}

pub fn special_or(args: &[SymbolicExpression], env: &mut Environment, context: &LocalContext) -> Result<Value> {
    check_arguments_at_least(1, args)?;

    for arg in args.iter() {
        let evaluated = eval(&arg, env, context)?;
        let result = type_force_bool(&evaluated)?;
        if result {
            return Ok(Value::Bool(true))
        }
    }

    Ok(Value::Bool(false))
}

pub fn special_and(args: &[SymbolicExpression], env: &mut Environment, context: &LocalContext) -> Result<Value> {
    check_arguments_at_least(1, args)?;

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
    check_argument_count(1, args)?;
    let value = type_force_bool(&args[0])?;
    Ok(Value::Bool(!value))
}
