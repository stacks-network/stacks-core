use vm::errors::{Error, InterpreterResult as Result};
use vm::types::{Value};
use vm::representations::SymbolicExpression;
use vm::representations::SymbolicExpression::{NamedParameter};
use vm::{LocalContext, Environment, eval};

pub fn tuple_cons(args: &[SymbolicExpression], env: &mut Environment, context: &LocalContext) -> Result<Value> {
    // (tuple #arg-name value
    //        #arg-name value ...)

    // or actually:
    //    (tuple (arg-name value)
    //           (arg-name value))
    use super::parse_eval_bindings;

    if args.len() < 1 {
        return Err(Error::InvalidArguments(format!("Tuples must be constructed with named-arguments and corresponding values")))
    }

    let bindings = parse_eval_bindings(args, env, context)?;

    Value::tuple_from_data(bindings)
}

pub fn tuple_get(args: &[SymbolicExpression], env: &mut Environment, context: &LocalContext) -> Result<Value> {
    // (get arg-name (tuple ...))
    //    if the tuple argument is 'null, then return 'null.
    //  NOTE:  a tuple field value itself may _never_ be 'null

    if args.len() != 2 {
        return Err(Error::InvalidArguments(format!("(get ..) requires exactly 2 arguments")))
    }
    let arg_name = match args[0] {
        SymbolicExpression::Atom(ref name) => Ok(name),
        _ => Err(Error::InvalidArguments(format!("Second argument to (get ..) must be a name, found: {:?}", args[0])))
    }?;

    let value = eval(&args[1], env, context)?;

    match value {
        Value::Void => Ok(Value::Void),
        Value::Tuple(tuple_data) => tuple_data.get(arg_name),
        _ => Err(Error::TypeError("TupleType".to_string(), value.clone()))
    }
}
