use vm::types::{Value, TypeSignature, TupleTypeSignature, parse_name_type_pairs};
use vm::callables::{DefinedFunction, DefineType};
use vm::representations::SymbolicExpression;
use vm::representations::SymbolicExpressionType::{Atom, AtomValue, List};
use vm::errors::{RuntimeErrorType, UncheckedError, InterpreterResult as Result, check_argument_count};
use vm::contexts::{ContractContext, LocalContext, Environment};
use vm::eval;

pub enum DefineResult {
    Variable(String, Value),
    Function(String, DefinedFunction),
    Map(String, TupleTypeSignature, TupleTypeSignature),
    PersistedVariable(String, TypeSignature, Value),
    FungibleToken(String, Option<i128>),
    NonFungibleAsset(String, TypeSignature),
    NoDefine
}

fn check_legal_define(name: &str, contract_context: &ContractContext) -> Result<()> {
    use vm::is_reserved;

    if is_reserved(name) {
        Err(UncheckedError::ReservedName(name.to_string()).into())
    } else if contract_context.variables.contains_key(name) || contract_context.functions.contains_key(name) {
        Err(UncheckedError::VariableDefinedMultipleTimes(name.to_string()).into())
    } else {
        Ok(())
    }
}

fn handle_define_variable(variable: &String, expression: &SymbolicExpression, env: &mut Environment) -> Result<DefineResult> {
    // is the variable name legal?
    check_legal_define(variable, &env.contract_context)?;
    let context = LocalContext::new();
    let value = eval(expression, env, &context)?;
    Ok(DefineResult::Variable(variable.clone(), value))
}

fn handle_define_function(signature: &[SymbolicExpression],
                          expression: &SymbolicExpression,
                          env: &Environment,
                          define_type: DefineType) -> Result<DefineResult> {
    let (function_symbol, arg_symbols) = signature.split_first()
        .ok_or(UncheckedError::InvalidArguments("Must supply atleast a name argument to define a function".to_string()))?;

    let function_name = function_symbol.match_atom()
        .ok_or(UncheckedError::ExpectedFunctionName)?;

    check_legal_define(&function_name, &env.contract_context)?;

    let arguments = parse_name_type_pairs(arg_symbols)?;

    for (argument, _) in arguments.iter() {
        check_legal_define(argument, &env.contract_context)?;
    }

    let function = DefinedFunction::new(
        arguments,
        expression.clone(),
        define_type,
        function_name,
        &env.contract_context.name);

    Ok(DefineResult::Function(function_name.clone(), function))
}

fn handle_define_persisted_variable(variable_name: &SymbolicExpression, value_type: &SymbolicExpression, value: &SymbolicExpression, env: &mut Environment) -> Result<DefineResult> {
    let variable_str = variable_name.match_atom()
        .ok_or(UncheckedError::ExpectedVariableName)?;

    check_legal_define(&variable_str, &env.contract_context)?;

    let value_type_signature = TypeSignature::parse_type_repr(value_type, true)?;

    let context = LocalContext::new();
    let value = eval(value, env, &context)?;

    Ok(DefineResult::PersistedVariable(variable_str.clone(), value_type_signature, value))
}

fn handle_define_nonfungible_asset(asset_name: &SymbolicExpression, key_type: &SymbolicExpression, env: &mut Environment) -> Result<DefineResult> {
    let asset_name = asset_name.match_atom()
        .ok_or(UncheckedError::ExpectedVariableName)?;

    check_legal_define(&asset_name, &env.contract_context)?;

    let key_type_signature = TypeSignature::parse_type_repr(key_type, true)?;

    Ok(DefineResult::NonFungibleAsset(asset_name.clone(), key_type_signature))
}

fn handle_define_fungible_token(asset_name: &SymbolicExpression, total_supply: Option<&SymbolicExpression>, env: &mut Environment) -> Result<DefineResult> {
    let asset_name = asset_name.match_atom()
        .ok_or(UncheckedError::ExpectedVariableName)?;

    check_legal_define(&asset_name, &env.contract_context)?;

    if let Some(total_supply_expr) = total_supply {
        let context = LocalContext::new();
        let total_supply_value = eval(total_supply_expr, env, &context)?;
        if let Value::Int(total_supply_int) = total_supply_value {
            if total_supply_int <= 0 {
                Err(RuntimeErrorType::NonPositiveTokenSupply.into())
            } else {
                Ok(DefineResult::FungibleToken(asset_name.clone(), Some(total_supply_int)))
            }
        } else {
            Err(UncheckedError::TypeError("int".to_string(), total_supply_value).into())
        }
    } else {
        Ok(DefineResult::FungibleToken(asset_name.clone(), None))
    }
}

fn handle_define_map(map_name: &SymbolicExpression,
                     key_type: &SymbolicExpression,
                     value_type: &SymbolicExpression,
                     env: &Environment) -> Result<DefineResult> {
    let map_str = map_name.match_atom()
        .ok_or(UncheckedError::ExpectedMapName)?;

    check_legal_define(&map_str, &env.contract_context)?;

    let key_type_signature = TupleTypeSignature::parse_name_type_pair_list(key_type)?;
    let value_type_signature = TupleTypeSignature::parse_name_type_pair_list(value_type)?;

    Ok(DefineResult::Map(map_str.clone(), key_type_signature, value_type_signature))
}

pub fn evaluate_define(expression: &SymbolicExpression, env: &mut Environment) -> Result<DefineResult> {
    
    if let List(ref elements) = expression.expr {

        if elements.len() < 1 {
            return Ok(DefineResult::NoDefine)
        }

        let (func_name, args) = elements.split_first()
            .unwrap(); // should never fail, because of len check above.

        if let Some(func_name) = func_name.match_atom() {
            return match func_name.as_str() {
                "define" => {
                    check_argument_count(2, args)?;
                    match args[0].expr {
                        Atom(ref variable) => handle_define_variable(variable, &args[1], env),
                        AtomValue(ref _value) => Err(UncheckedError::InvalidArguments(
                            "Illegal operation: attempted to re-define a value type.".to_string()).into()),
                        List(ref function_signature) =>
                            handle_define_function(&function_signature, &args[1], env, DefineType::Private)
                    }
                },
                "define-read-only" => {
                    check_argument_count(2, args)?;
                    let function_signature = args[0].match_list()
                        .ok_or(UncheckedError::InvalidArguments(
                            "Illegal operation: attempted to define-read-only a non-function.".to_string()))?;
                    handle_define_function(&function_signature, &args[1], env, DefineType::ReadOnly)
                },
                "define-non-fungible-token" => {
                    check_argument_count(2, args)?;
                    handle_define_nonfungible_asset(&args[0], &args[1], env)
                },
                "define-fungible-token" => {
                    if args.len() == 1 {
                        handle_define_fungible_token(&args[0], None, env)
                    } else if args.len() == 2 {
                        handle_define_fungible_token(&args[0], Some(&args[1]), env)
                    } else {
                        Err(UncheckedError::IncorrectArgumentCount(1, args.len()).into())
                    }
                },
                "define-public" => {
                    check_argument_count(2, args)?;
                    let function_signature = args[0].match_list()
                        .ok_or(UncheckedError::InvalidArguments(
                            "Illegal operation: attempted to define-public a non-function.".to_string()))?;
                    handle_define_function(&function_signature, &args[1], env, DefineType::Public)
                },
                "define-map" => {
                    check_argument_count(3, args)?;
                    handle_define_map(&args[0], &args[1], &args[2], env)
                }
                "define-data-var" => {
                    check_argument_count(3, args)?;
                    handle_define_persisted_variable(&args[0], &args[1], &args[2], env)
                }
                _ => Ok(DefineResult::NoDefine)
            }
        }
    }

    Ok(DefineResult::NoDefine)
}
