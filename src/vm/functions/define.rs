use vm::types::{Value, TypeSignature, TupleTypeSignature, parse_name_type_pairs};
use vm::callables::{DefinedFunction, DefineType};
use vm::representations::SymbolicExpression;
use vm::representations::SymbolicExpressionType::{Atom, AtomValue, List};
use vm::errors::{UncheckedError, InterpreterResult as Result};
use vm::contexts::{ContractContext, LocalContext, Environment};
use vm::eval;

pub enum DefineResult {
    Variable(String, Value),
    Function(String, DefinedFunction),
    Map(String, TupleTypeSignature, TupleTypeSignature),
    PersistedVariable(String, TypeSignature, Value),
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
        .ok_or(UncheckedError::InvalidArguments(format!("Invalid function name {:?}", function_symbol)))?;

    check_legal_define(&function_name, &env.contract_context)?;

    let arguments = parse_name_type_pairs(arg_symbols)?;

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
        .ok_or(UncheckedError::InvalidArguments("Non-name argument to define-data-var".to_string()))?;

    check_legal_define(&variable_str, &env.contract_context)?;

    let value_type_signature = TypeSignature::parse_type_repr(value_type, true)?;

    let context = LocalContext::new();
    let value = eval(value, env, &context)?;

    Ok(DefineResult::PersistedVariable(variable_str.clone(), value_type_signature, value))
}

fn handle_define_map(map_name: &SymbolicExpression,
                     key_type: &SymbolicExpression,
                     value_type: &SymbolicExpression,
                     env: &Environment) -> Result<DefineResult> {
    let map_str = map_name.match_atom()
        .ok_or(UncheckedError::InvalidArguments("Non-name argument to define-map".to_string()))?;

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

        if let Some(func_name) = elements[0].match_atom() {
            return match func_name.as_str() {
                "define" => {
                    if elements.len() != 3 {
                        Err(UncheckedError::InvalidArguments("(define ...) requires 2 arguments".to_string()).into())
                    } else {
                        match elements[1].expr {
                            Atom(ref variable) => handle_define_variable(variable, &elements[2], env),
                            AtomValue(ref _value) => Err(UncheckedError::InvalidArguments(
                                "Illegal operation: attempted to re-define a value type.".to_string()).into()),
                            List(ref function_signature) =>
                                handle_define_function(&function_signature, &elements[2], env, DefineType::Private)
                        }
                    }
                },
                "define-read-only" => {
                    if elements.len() != 3 {
                        Err(UncheckedError::InvalidArguments("(define-read-only ...) must be supplied an argument list and a function body".to_string()).into())
                    } else {
                        let function_signature = elements[1].match_list()
                            .ok_or(UncheckedError::InvalidArguments(
                                "Illegal operation: attempted to define-read-only a non-function.".to_string()))?;
                        handle_define_function(&function_signature, &elements[2], env, DefineType::ReadOnly)
                    }
                },
                "define-public" => {
                    if elements.len() != 3 {
                        Err(UncheckedError::InvalidArguments("(define-public ...) must be supplied an argument list and a function body".to_string()).into())
                    } else {
                        let function_signature = elements[1].match_list()
                            .ok_or(UncheckedError::InvalidArguments(
                                "Illegal operation: attempted to define-public a non-function.".to_string()))?;
                        handle_define_function(&function_signature, &elements[2], env, DefineType::Public)
                    }
                },
                "define-map" => {
                    if elements.len() != 4 {
                        Err(UncheckedError::InvalidArguments("(define-map ...) must be supplied a name, a list of key fields, and a list of value fields".to_string()).into())
                    } else {
                        handle_define_map(&elements[1], &elements[2], &elements[3], env)
                    }
                }
                "define-data-var" => {
                    if elements.len() != 4 {
                        Err(UncheckedError::InvalidArguments("(define-data-var ...) must be supplied a name, a type and a value".to_string()).into())
                    } else {
                        handle_define_persisted_variable(&elements[1], &elements[2], &elements[3], env)
                    }
                }
                _ => Ok(DefineResult::NoDefine)
            }
        }
    }

    Ok(DefineResult::NoDefine)
}
