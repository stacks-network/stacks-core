use vm::types::{Value, TypeSignature, TupleTypeSignature, parse_name_type_pairs};
use vm::callables::{DefinedFunction, DefineType};
use vm::representations::{SymbolicExpression, ClarityName};
use vm::representations::SymbolicExpressionType::{Atom, AtomValue, List};
use vm::errors::{RuntimeErrorType, CheckErrors, InterpreterResult as Result, check_argument_count};
use vm::contexts::{ContractContext, LocalContext, Environment};
use vm::eval;

define_named_enum!(DefineFunctions {
    Constant("define-constant"),
    PrivateFunction("define-private"),
    PublicFunction("define-public"),
    ReadOnlyFunction("define-read-only"),
    Map("define-map"),
    PersistedVariable("define-data-var"),
    FungibleToken("define-fungible-token"),
    NonFungibleToken("define-non-fungible-token"),
});

pub enum DefineFunctionsParsed <'a> {
    Constant { name: &'a ClarityName, value: &'a SymbolicExpression },
    PrivateFunction { signature: &'a [SymbolicExpression], body: &'a SymbolicExpression },
    ReadOnlyFunction { signature: &'a [SymbolicExpression], body: &'a SymbolicExpression },
    PublicFunction { signature: &'a [SymbolicExpression], body: &'a SymbolicExpression },
    NonFungibleToken { name: &'a ClarityName, nft_type: &'a SymbolicExpression },
    BoundedFungibleToken { name: &'a ClarityName, max_supply: &'a SymbolicExpression },
    UnboundedFungibleToken { name: &'a ClarityName },
    Map { name: &'a ClarityName, key_type: &'a SymbolicExpression, value_type: &'a SymbolicExpression },
    PersistedVariable  { name: &'a ClarityName, data_type: &'a SymbolicExpression, initial: &'a SymbolicExpression },
}

pub enum DefineResult {
    Variable(ClarityName, Value),
    Function(ClarityName, DefinedFunction),
    Map(String, TupleTypeSignature, TupleTypeSignature),
    PersistedVariable(String, TypeSignature, Value),
    FungibleToken(String, Option<i128>),
    NonFungibleAsset(String, TypeSignature),
    NoDefine
}

fn check_legal_define(name: &str, contract_context: &ContractContext) -> Result<()> {
    use vm::is_reserved;

    if is_reserved(name) || contract_context.variables.contains_key(name) || contract_context.functions.contains_key(name) {
        Err(CheckErrors::NameAlreadyUsed(name.to_string()).into())
    } else {
        Ok(())
    }
}

fn handle_define_variable(variable: &ClarityName, expression: &SymbolicExpression, env: &mut Environment) -> Result<DefineResult> {
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
        .ok_or(CheckErrors::DefineFunctionBadSignature)?;

    let function_name = function_symbol.match_atom()
        .ok_or(CheckErrors::ExpectedName)?;

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

fn handle_define_persisted_variable(variable_str: &ClarityName, value_type: &SymbolicExpression, value: &SymbolicExpression, env: &mut Environment) -> Result<DefineResult> {
    check_legal_define(&variable_str, &env.contract_context)?;

    let value_type_signature = TypeSignature::parse_type_repr(value_type)?;

    let context = LocalContext::new();
    let value = eval(value, env, &context)?;

    Ok(DefineResult::PersistedVariable(variable_str.to_string(), value_type_signature, value))
}

fn handle_define_nonfungible_asset(asset_name: &ClarityName, key_type: &SymbolicExpression, env: &mut Environment) -> Result<DefineResult> {
    check_legal_define(&asset_name, &env.contract_context)?;

    let key_type_signature = TypeSignature::parse_type_repr(key_type)?;

    Ok(DefineResult::NonFungibleAsset(asset_name.to_string(), key_type_signature))
}

fn handle_define_fungible_token(asset_name: &ClarityName, total_supply: Option<&SymbolicExpression>, env: &mut Environment) -> Result<DefineResult> {
    check_legal_define(&asset_name, &env.contract_context)?;

    if let Some(total_supply_expr) = total_supply {
        let context = LocalContext::new();
        let total_supply_value = eval(total_supply_expr, env, &context)?;
        if let Value::Int(total_supply_int) = total_supply_value {
            if total_supply_int <= 0 {
                Err(RuntimeErrorType::NonPositiveTokenSupply.into())
            } else {
                Ok(DefineResult::FungibleToken(asset_name.to_string(), Some(total_supply_int)))
            }
        } else {
            Err(CheckErrors::TypeValueError(TypeSignature::IntType, total_supply_value).into())
        }
    } else {
        Ok(DefineResult::FungibleToken(asset_name.to_string(), None))
    }
}

fn handle_define_map(map_str: &ClarityName,
                     key_type: &SymbolicExpression,
                     value_type: &SymbolicExpression,
                     env: &Environment) -> Result<DefineResult> {
    check_legal_define(&map_str, &env.contract_context)?;

    let key_type_signature = TupleTypeSignature::parse_name_type_pair_list(key_type)?;
    let value_type_signature = TupleTypeSignature::parse_name_type_pair_list(value_type)?;

    Ok(DefineResult::Map(map_str.to_string(), key_type_signature, value_type_signature))
}

impl DefineFunctions {
    pub fn try_parse(expression: &SymbolicExpression) -> Option<(DefineFunctions, &[SymbolicExpression])> {
        let expression = expression.match_list()?;
        let (function_name, args) = expression.split_first()?;
        let function_name = function_name.match_atom()?;
        let define_type = DefineFunctions::lookup_by_name(function_name)?;
        Some((define_type, args))
    }
}

impl <'a> DefineFunctionsParsed <'a> {
    /// Try to parse a Top-Level Expression (e.g., (define-private (foo) 1)) as
    /// a define-statement, returns None if the supplied expression is not a define.
    pub fn try_parse (expression: &'a SymbolicExpression) -> std::result::Result<Option<DefineFunctionsParsed<'a>>, CheckErrors> {
        let (define_type, args) = match DefineFunctions::try_parse(expression) {
            Some(x) => x,
            None => return Ok(None)
        };
        let result = match define_type {
            DefineFunctions::Constant => {
                check_argument_count(2, args)?;
                let name = args[0].match_atom().ok_or(CheckErrors::ExpectedName)?;
                DefineFunctionsParsed::Constant { name, value: &args[1] }
            },
            DefineFunctions::PrivateFunction => {
                check_argument_count(2, args)?;
                let signature = args[0].match_list().ok_or(CheckErrors::DefineFunctionBadSignature)?;
                DefineFunctionsParsed::PrivateFunction { signature, body: &args[1] }
            },
            DefineFunctions::ReadOnlyFunction => {
                check_argument_count(2, args)?;
                let signature = args[0].match_list().ok_or(CheckErrors::DefineFunctionBadSignature)?;
                DefineFunctionsParsed::ReadOnlyFunction { signature, body: &args[1] }
            },
            DefineFunctions::PublicFunction => {
                check_argument_count(2, args)?;
                let signature = args[0].match_list().ok_or(CheckErrors::DefineFunctionBadSignature)?;
                DefineFunctionsParsed::PublicFunction { signature, body: &args[1] }
            },
            DefineFunctions::NonFungibleToken => {
                check_argument_count(2, args)?;
                let name = args[0].match_atom().ok_or(CheckErrors::ExpectedName)?;
                DefineFunctionsParsed::NonFungibleToken { name, nft_type: &args[1] }
            },
            DefineFunctions::FungibleToken => {
                let name = args[0].match_atom().ok_or(CheckErrors::ExpectedName)?;
                if args.len() == 1 {
                    DefineFunctionsParsed::UnboundedFungibleToken { name }
                } else if args.len() == 2 {
                    DefineFunctionsParsed::BoundedFungibleToken { name, max_supply: &args[1] }
                } else {
                    return Err(CheckErrors::IncorrectArgumentCount(1, args.len()).into())
                }
            },
            DefineFunctions::Map => {
                check_argument_count(3, args)?;
                let name = args[0].match_atom().ok_or(CheckErrors::ExpectedName)?;
                DefineFunctionsParsed::Map { name, key_type: &args[1], value_type: &args[2] }
            },
            DefineFunctions::PersistedVariable => {
                check_argument_count(3, args)?;
                let name = args[0].match_atom().ok_or(CheckErrors::ExpectedName)?;
                DefineFunctionsParsed::PersistedVariable { name, data_type: &args[1], initial: &args[2] }
            }
        };
        Ok(Some(result))
    }
}

pub fn evaluate_define(expression: &SymbolicExpression, env: &mut Environment) -> Result<DefineResult> {
    if let Some(define_type) = DefineFunctionsParsed::try_parse(expression)? {
        match define_type {
            DefineFunctionsParsed::Constant { name, value } => {
                handle_define_variable(name, value, env)
            },
            DefineFunctionsParsed::PrivateFunction { signature, body } => {
                handle_define_function(signature, body, env, DefineType::Private)
            },
            DefineFunctionsParsed::ReadOnlyFunction { signature, body } => {
                handle_define_function(signature, body, env, DefineType::ReadOnly)
            },
            DefineFunctionsParsed::PublicFunction { signature, body } => {
                handle_define_function(signature, body, env, DefineType::Public)
            },
            DefineFunctionsParsed::NonFungibleToken { name, nft_type } => {
                handle_define_nonfungible_asset(name, nft_type, env)
            },
            DefineFunctionsParsed::BoundedFungibleToken { name, max_supply } => {
                handle_define_fungible_token(name, Some(max_supply), env)
            },
            DefineFunctionsParsed::UnboundedFungibleToken { name } => {
                handle_define_fungible_token(name, None, env)
            },
            DefineFunctionsParsed::Map { name, key_type, value_type } => {
                handle_define_map(name, key_type, value_type, env)
            },
            DefineFunctionsParsed::PersistedVariable { name, data_type, initial } => {
                handle_define_persisted_variable(name, data_type, initial, env)
            }
        }
    } else {
        Ok(DefineResult::NoDefine)
    }
}
