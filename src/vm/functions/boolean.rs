use vm::costs::cost_functions;
use vm::errors::{
    check_argument_count, check_arguments_at_least, CheckErrors, InterpreterResult as Result,
};
use vm::representations::SymbolicExpression;
use vm::types::{TypeSignature, Value};
use vm::{eval, Environment, LocalContext};

fn type_force_bool(value: &Value) -> Result<bool> {
    match *value {
        Value::Bool(boolean) => Ok(boolean),
        _ => Err(CheckErrors::TypeValueError(TypeSignature::BoolType, value.clone()).into()),
    }
}

pub fn special_or(
    args: &[SymbolicExpression],
    env: &mut Environment,
    context: &LocalContext,
) -> Result<Value> {
    check_arguments_at_least(1, args)?;

    runtime_cost!(cost_functions::OR, env, args.len())?;

    for arg in args.iter() {
        let evaluated = eval(&arg, env, context)?;
        let result = type_force_bool(&evaluated)?;
        if result {
            return Ok(Value::Bool(true));
        }
    }

    Ok(Value::Bool(false))
}

pub fn special_and(
    args: &[SymbolicExpression],
    env: &mut Environment,
    context: &LocalContext,
) -> Result<Value> {
    check_arguments_at_least(1, args)?;

    runtime_cost!(cost_functions::AND, env, args.len())?;

    for arg in args.iter() {
        let evaluated = eval(&arg, env, context)?;
        let result = type_force_bool(&evaluated)?;
        if !result {
            return Ok(Value::Bool(false));
        }
    }

    Ok(Value::Bool(true))
}

pub fn native_not(input: Value) -> Result<Value> {
    let value = type_force_bool(&input)?;
    Ok(Value::Bool(!value))
}
