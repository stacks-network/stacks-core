use super::super::types::{ValueType};
use super::super::representations::SymbolicExpression;
use super::super::{InterpreterResult,eval,Context,Environment};
use super::super::errors::Error;
use super::super::database::DataMap;

fn obtain_map <'a> (map_arg: &SymbolicExpression, env: &'a mut Environment) -> Result<&'a mut DataMap, Error> {
    let map_name = match map_arg {
        SymbolicExpression::Atom(value) => Ok(value),
        _ => Err(Error::InvalidArguments("First argument in data functions must be the map name".to_string()))
    }?;
    match env.database.get_data_map(map_name) {
        Some(map) => Ok(map),
        None => Err(Error::Undefined(format!("No such map named: {}", map_name)))
    }
}

pub fn special_fetch_entry(args: &[SymbolicExpression],
                           env: &mut Environment,
                           context: &Context) -> InterpreterResult {
    // arg0 -> map name
    // arg1 -> key
    if args.len() != 2 {
        return Err(Error::InvalidArguments("(fetch-entry ...) requires exactly 2 arguments".to_string()))
    }

    let key = eval(&args[1], env, context)?;

    let map = obtain_map(&args[0], env)?;

    map.fetch_entry(&key)
}

pub fn special_set_entry(args: &[SymbolicExpression],
                         env: &mut Environment,
                         context: &Context) -> InterpreterResult {
    // arg0 -> map name
    // arg1 -> key
    // arg2 -> value
    if args.len() != 3 {
        return Err(Error::InvalidArguments("(set-entry! ...) requires exactly 3 arguments".to_string()))
    }

    let key = eval(&args[1], env, context)?;
    let value = eval(&args[2], env, context)?;

    let map = obtain_map(&args[0], env)?;

    match map.set_entry(key, value) {
        Ok(_) => Ok(ValueType::VoidType),
        Err(e) => Err(e)
    }
}

pub fn special_insert_entry(args: &[SymbolicExpression],
                            env: &mut Environment,
                            context: &Context) -> InterpreterResult {
    // arg0 -> map name
    // arg1 -> key
    // arg2 -> value
    if args.len() != 3 {
        return Err(Error::InvalidArguments("(insert-entry! ...) requires exactly 3 arguments".to_string()))
    }

    let key = eval(&args[1], env, context)?;
    let value = eval(&args[2], env, context)?;

    let map = obtain_map(&args[0], env)?;

    map.insert_entry(key, value)
}

pub fn special_delete_entry(args: &[SymbolicExpression],
                            env: &mut Environment,
                            context: &Context) -> InterpreterResult {
    // arg0 -> map name
    // arg1 -> key
    if args.len() != 2 {
        return Err(Error::InvalidArguments("(delete-entry! ...) requires exactly 2 arguments".to_string()))
    }

    let key = eval(&args[1], env, context)?;

    let map = obtain_map(&args[0], env)?;

    map.delete_entry(&key)
}

