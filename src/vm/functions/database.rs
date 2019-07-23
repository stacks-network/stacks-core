use std::convert::TryFrom;

use vm::functions::tuples;
use vm::functions::tuples::TupleDefinitionType::{Implicit, Explicit};

use vm::types::{Value, OptionalData, BuffData, PrincipalData, BlockInfoProperty};
use vm::representations::{SymbolicExpression};
use vm::errors::{UncheckedError, InterpreterError, RuntimeErrorType, InterpreterResult as Result, check_argument_count};
use vm::{eval, LocalContext, Environment};

pub fn special_contract_call(args: &[SymbolicExpression],
                             env: &mut Environment,
                             context: &LocalContext) -> Result<Value> {
    if args.len() < 2 {
        return Err(UncheckedError::IncorrectArgumentCount(2, args.len()).into())
    }

    let contract_name = args[0].match_atom()
        .ok_or(UncheckedError::ExpectedContractName)?;

    let function_name = args[1].match_atom()
        .ok_or(UncheckedError::ExpectedFunctionName)?;

    let rest_args = &args[2..];

    let rest_args: Result<Vec<_>> = rest_args.iter().map(|x| { eval(x, env, context) }).collect();
    let mut rest_args = rest_args?;
    let rest_args: Vec<_> = rest_args.drain(..).map(|x| { SymbolicExpression::atom_value(x) }).collect();

    let contract_principal = Value::Principal(PrincipalData::ContractPrincipal(
        env.contract_context.name.clone()));
    let mut nested_env = env.nest_with_caller(contract_principal);

    nested_env.execute_contract(
        contract_name, function_name, &rest_args)
}

pub fn special_fetch_variable(args: &[SymbolicExpression],
                              env: &mut Environment,
                              context: &LocalContext) -> Result<Value> {
    check_argument_count(1, args)?;

    let var_name = args[0].match_atom()
        .ok_or(UncheckedError::ExpectedVariableName)?;

    let data = env.global_context.database.lookup_variable(&env.contract_context.name, var_name)?;
    match data {
        Some(data) => Ok(data),
        None => Err(InterpreterError::UninitializedPersistedVariable.into())
    }
}

pub fn special_set_variable(args: &[SymbolicExpression],
                            env: &mut Environment,
                            context: &LocalContext) -> Result<Value> {
    if env.global_context.is_read_only() {
        return Err(UncheckedError::WriteFromReadOnlyContext.into())
    }

    check_argument_count(2, args)?;

    let value = eval(&args[1], env, &context)?;

    let var_name = args[0].match_atom()
        .ok_or(UncheckedError::ExpectedMapName)?;

    env.global_context.database.set_variable(&env.contract_context.name, var_name, value)
}

pub fn special_fetch_entry(args: &[SymbolicExpression],
                           env: &mut Environment,
                           context: &LocalContext) -> Result<Value> {
    check_argument_count(2, args)?;

    let map_name = args[0].match_atom()
        .ok_or(UncheckedError::ExpectedVariableName)?;

    let key = match tuples::get_definition_type_of_tuple_argument(&args[1]) {
        Implicit(ref expr) => tuples::tuple_cons(expr, env, context)?,
        Explicit => eval(&args[1], env, &context)?
    };

    let value = env.global_context.database.fetch_entry(&env.contract_context.name, map_name, &key)?;
    match value {
        Some(data) => Ok(Value::some(data)),
        None => Ok(Value::none())
    }
}


pub fn special_fetch_contract_entry(args: &[SymbolicExpression],
                                    env: &mut Environment,
                                    context: &LocalContext) -> Result<Value> {
    check_argument_count(3, args)?;

    let contract_name = args[0].match_atom()
        .ok_or(UncheckedError::ExpectedContractName)?;
    let map_name = args[1].match_atom()
        .ok_or(UncheckedError::ExpectedMapName)?;

    let key = match tuples::get_definition_type_of_tuple_argument(&args[2]) {
        Implicit(ref expr) => tuples::tuple_cons(expr, env, context)?,
        Explicit => eval(&args[2], env, &context)?
    };

    let value = env.global_context.database.fetch_entry(contract_name, map_name, &key)?;
    match value {
        Some(data) => Ok(Value::some(data)),
        None => Ok(Value::none())
    }
}

pub fn special_set_entry(args: &[SymbolicExpression],
                         env: &mut Environment,
                         context: &LocalContext) -> Result<Value> {
    if env.global_context.is_read_only() {
        return Err(UncheckedError::WriteFromReadOnlyContext.into())
    }

    check_argument_count(3, args)?;

    let key = match tuples::get_definition_type_of_tuple_argument(&args[1]) {
        Implicit(ref expr) => tuples::tuple_cons(expr, env, context)?,
        Explicit => eval(&args[1], env, &context)?
    };

    let value = match tuples::get_definition_type_of_tuple_argument(&args[2]) {
        Implicit(ref expr) => tuples::tuple_cons(expr, env, context)?,
        Explicit => eval(&args[2], env, &context)?
    };

    let map_name = args[0].match_atom()
        .ok_or(UncheckedError::ExpectedMapName)?;

    env.global_context.database.set_entry(&env.contract_context.name, map_name, key, value)
}

pub fn special_insert_entry(args: &[SymbolicExpression],
                            env: &mut Environment,
                            context: &LocalContext) -> Result<Value> {
    if env.global_context.is_read_only() {
        return Err(UncheckedError::WriteFromReadOnlyContext.into())
    }

    check_argument_count(3, args)?;
    
    let key = match tuples::get_definition_type_of_tuple_argument(&args[1]) {
        Implicit(ref expr) => tuples::tuple_cons(expr, env, context)?,
        Explicit => eval(&args[1], env, &context)?
    };

    let value = match tuples::get_definition_type_of_tuple_argument(&args[2]) {
        Implicit(ref expr) => tuples::tuple_cons(expr, env, context)?,
        Explicit => eval(&args[2], env, &context)?
    };

    let map_name = args[0].match_atom()
        .ok_or(UncheckedError::ExpectedMapName)?;

    env.global_context.database.insert_entry(&env.contract_context.name, map_name, key, value)
}

pub fn special_delete_entry(args: &[SymbolicExpression],
                            env: &mut Environment,
                            context: &LocalContext) -> Result<Value> {
    if env.global_context.is_read_only() {
        return Err(UncheckedError::WriteFromReadOnlyContext.into())
    }
 
    check_argument_count(2, args)?;

    let key = match tuples::get_definition_type_of_tuple_argument(&args[1]) {
        Implicit(ref expr) => tuples::tuple_cons(expr, env, context)?,
        Explicit => eval(&args[1], env, &context)?
    };

    let map_name = args[0].match_atom()
        .ok_or(UncheckedError::ExpectedMapName)?;

    env.global_context.database.delete_entry(&env.contract_context.name, map_name, &key)
}

pub fn special_get_block_info(args: &[SymbolicExpression], 
                              env: &mut Environment, 
                              context: &LocalContext) -> Result<Value> {

    // (get-block-info property-name block-height-int)

    check_argument_count(2, args)?;

    // Handle the block property name input arg.
    let property_name = args[0].match_atom()
        .ok_or(UncheckedError::ExpectedBlockPropertyName)?;

    let block_info_prop = BlockInfoProperty::from_str(property_name)
        .ok_or(UncheckedError::ExpectedBlockPropertyName)?;

    // Handle the block-height input arg clause.
    let height_eval = eval(&args[1], env, context)?;
    let height_value = match height_eval {
        Value::Int(result) => Ok(result),
        _ => Err(UncheckedError::TypeError("IntType".to_string(), height_eval))
    }?;

    let height_value = match u64::try_from(height_value) {
        Ok(result) => result,
        _ => return Err(RuntimeErrorType::BadBlockHeight(height_value.to_string()).into())
    };

    let current_block_height = env.global_context.get_block_height();
    if height_value > current_block_height {
        return Err(RuntimeErrorType::BadBlockHeight(height_value.to_string()).into());
    }

    use self::BlockInfoProperty::*;
    match block_info_prop {
        Time => {
            let block_time = env.global_context.get_block_time(height_value);
            Ok(Value::Int(block_time as i128))
        },
        VrfSeed => {
            let vrf_seed = env.global_context.get_block_vrf_seed(height_value);
            Ok(Value::Buffer(BuffData { data: vrf_seed.to_bytes().to_vec() }))
        },
        HeaderHash => {
            let header_hash = env.global_context.get_block_header_hash(height_value);
            Ok(Value::Buffer(BuffData { data: header_hash.to_bytes().to_vec() }))
        },
        BurnchainHeaderHash => {
            let burnchain_header_hash = env.global_context.get_burnchain_block_header_hash(height_value);
            Ok(Value::Buffer(BuffData { data: burnchain_header_hash.to_bytes().to_vec() }))
        },
    }
}
