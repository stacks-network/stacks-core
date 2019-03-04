use vm::types::{Value};
use vm::representations::SymbolicExpression;
use vm::errors::{Error, ErrType, InterpreterResult as Result};
use vm::database::DataMap;
use vm::variables;
use vm::{eval, LocalContext, Environment};

fn obtain_map <'a> (map_arg: &SymbolicExpression, env: &'a mut Environment) -> Result<&'a mut DataMap> {
    let map_name = match map_arg {
        SymbolicExpression::Atom(value) => Ok(value),
        _ => Err(Error::new(ErrType::InvalidArguments("First argument in data functions must be the map name".to_string())))
    }?;
    match env.database.get_mut_data_map(map_name) {
        Some(map) => Ok(map),
        None => Err(Error::new(ErrType::UndefinedVariable(map_name.clone())))
    }
}

pub fn special_contract_call(args: &[SymbolicExpression],
                         env: &mut Environment,
                         context: &LocalContext) -> Result<Value> {
    if args.len() < 2 {
        return Err(Error::new(ErrType::InvalidArguments(
            "(contract-call ...) requires at least 2 arguments: the contract name and the public function name".to_string())))
    }

    let contract_name = match &args[0] {
        SymbolicExpression::Atom(value) => Ok(value),
        _ => Err(Error::new(ErrType::InvalidArguments("First argument to (contract-call ...) must be contract name".to_string())))
    }?;

    let function_name = match &args[1] {
        SymbolicExpression::Atom(value) => Ok(value),
        _ => Err(Error::new(ErrType::InvalidArguments("Second argument to (contract-call ...) must be function name".to_string())))
    }?;

    let rest_args = &args[2..];

    let rest_args: Result<Vec<_>> = rest_args.iter().map(|x| { eval(x, env, context) }).collect();
    let mut rest_args = rest_args?;
    let rest_args: Vec<_> = rest_args.drain(..).map(|x| { SymbolicExpression::AtomValue(x) }).collect();

    let sender = env.sender.as_ref()
        .ok_or(Error::new(ErrType::InvalidArguments(
            "No sender in current context. Did you attempt to (contract-call ...) from a non-contract aware environment?"
                .to_string())))?;

    env.global_context.execute_contract(
        contract_name, sender, function_name, &rest_args)
        .map_err(|x| {
            if x.has_stack_trace() {
                x.extend_with(env.call_stack.make_stack_trace())
            } else {
                x.clone()
            }
        })
}

pub fn special_fetch_entry(args: &[SymbolicExpression],
                           env: &mut Environment,
                           context: &LocalContext) -> Result<Value> {
    // arg0 -> map name
    // arg1 -> key
    if args.len() != 2 {
        return Err(Error::new(ErrType::InvalidArguments("(fetch-entry ...) requires exactly 2 arguments".to_string())))
    }

    let key = eval(&args[1], env, context)?;

    let map_name = match &args[0] {
        SymbolicExpression::Atom(value) => Ok(value),
        _ => Err(Error::new(ErrType::InvalidArguments("First argument in data functions must be the map name".to_string())))
    }?;

    let map = match env.database.get_data_map(&map_name) {
        Some(map) => Ok(map),
        None => Err(Error::new(ErrType::UndefinedVariable(map_name.clone())))
    }?;

    map.fetch_entry(&key)
}

pub fn special_set_entry(args: &[SymbolicExpression],
                         env: &mut Environment,
                         context: &LocalContext) -> Result<Value> {
    // arg0 -> map name
    // arg1 -> key
    // arg2 -> value
    if args.len() != 3 {
        return Err(Error::new(ErrType::InvalidArguments("(set-entry! ...) requires exactly 3 arguments".to_string())))
    }

    let key = eval(&args[1], env, context)?;
    let value = eval(&args[2], env, context)?;

    let map = obtain_map(&args[0], env)?;

    match map.set_entry(key, value) {
        Ok(_) => Ok(Value::Void),
        Err(e) => Err(e)
    }
}

pub fn special_insert_entry(args: &[SymbolicExpression],
                            env: &mut Environment,
                            context: &LocalContext) -> Result<Value> {
    // arg0 -> map name
    // arg1 -> key
    // arg2 -> value
    if args.len() != 3 {
        return Err(Error::new(ErrType::InvalidArguments("(insert-entry! ...) requires exactly 3 arguments".to_string())))
    }

    let key = eval(&args[1], env, context)?;
    let value = eval(&args[2], env, context)?;

    let map = obtain_map(&args[0], env)?;

    map.insert_entry(key, value)
}

pub fn special_delete_entry(args: &[SymbolicExpression],
                            env: &mut Environment,
                            context: &LocalContext) -> Result<Value> {
    // arg0 -> map name
    // arg1 -> key
    if args.len() != 2 {
        return Err(Error::new(ErrType::InvalidArguments("(delete-entry! ...) requires exactly 2 arguments".to_string())))
    }

    let key = eval(&args[1], env, context)?;

    let map = obtain_map(&args[0], env)?;

    map.delete_entry(&key)
}

