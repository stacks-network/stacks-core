pub mod define;
mod lists;
mod arithmetic;
mod boolean;
mod database;
mod tuples;

use vm::errors::{Error, InterpreterResult as Result};
use vm::types::Value;
use vm::callables::CallableType;
use vm::representations::SymbolicExpression;
use vm::{LocalContext, Environment, eval};


fn native_eq(args: &[Value]) -> Result<Value> {
    // TODO: this currently uses the derived equality checks of Value,
    //   however, that's probably not how we want to implement equality
    //   checks on the ::ListTypes
    if args.len() < 2 {
        Ok(Value::Bool(true))
    } else {
        let first = &args[0];
        let result = args.iter().fold(true, |acc, x| acc && (*x == *first));
        Ok(Value::Bool(result))
    }
}

fn native_begin(args: &[Value]) -> Result<Value> {
    match args.last() {
        Some(v) => Ok(v.clone()),
        None => Ok(Value::Void)
    }
}

fn special_if(args: &[SymbolicExpression], env: &mut Environment, context: &LocalContext) -> Result<Value> {
    if !(args.len() == 2 || args.len() == 3) {
        return Err(Error::InvalidArguments("Wrong number of arguments to if (expect 2 or 3)".to_string()))
    }
    // handle the conditional clause.
    let conditional = eval(&args[0], env, context)?;
    match conditional {
        Value::Bool(result) => {
            if result {
                eval(&args[1], env, context)
            } else {
                if args.len() == 3 {
                    eval(&args[2], env, context)
                } else {
                    Ok(Value::Void)
                }
            }
        },
        _ => Err(Error::TypeError("BoolType".to_string(), conditional))
    }
}

fn special_let(args: &[SymbolicExpression], env: &mut Environment, context: &LocalContext) -> Result<Value> {
    use vm::is_reserved;

    // (let ((x 1) (y 2)) (+ x y)) -> 3
    // arg0 => binding list
    // arg1 => body
    if args.len() != 2 {
        return Err(Error::InvalidArguments("Wrong number of arguments to let (expect 2)".to_string()))
    }
    // create a new context.
    let mut inner_context = context.extend()?;

    if let SymbolicExpression::List(ref bindings) = args[0] {
        for binding in bindings.iter() {
            if let SymbolicExpression::List(ref binding_exps) = *binding {
                if binding_exps.len() != 2 {
                    return Err(Error::Generic("Passed non 2-length list as binding in let expression".to_string()))
                } else {
                    if let SymbolicExpression::Atom(ref var_name) = binding_exps[0] {
                        if is_reserved(var_name) {
                            return Err(Error::ReservedName(var_name.to_string()))
                        }
                        let value = eval(&binding_exps[1], env, context)?;
                        match inner_context.variables.insert((*var_name).clone(), value) {
                            Some(_val) => return Err(Error::VariableDefinedMultipleTimes(var_name.to_string())),
                            _ => continue
                        }
                    } else {
                        return Err(Error::InvalidArguments("Passed non-atomic variable name to let expression binding".to_string()))
                    }
                }
            } else {
                return Err(Error::InvalidArguments("Passed non-list as binding in let expression.".to_string()))
            }
        }
        // evaluate the let-body
        eval(&args[1], env, &inner_context)
    } else {
        Err(Error::InvalidArguments("Passed non-list as second argument to let expression.".to_string()))
    }
}

pub fn lookup_reserved_functions<'a> (name: &str) -> Option<CallableType<'a>> {
    match name {
        "+" => Some(CallableType::NativeFunction(&arithmetic::native_add)),
        "-" => Some(CallableType::NativeFunction(&arithmetic::native_sub)),
        "*" => Some(CallableType::NativeFunction(&arithmetic::native_mul)),
        "/" => Some(CallableType::NativeFunction(&arithmetic::native_div)),
        ">=" => Some(CallableType::NativeFunction(&arithmetic::native_geq)),
        "<=" => Some(CallableType::NativeFunction(&arithmetic::native_leq)),
        "<" => Some(CallableType::NativeFunction(&arithmetic::native_le)),
        ">" => Some(CallableType::NativeFunction(&arithmetic::native_ge)),
        "mod" => Some(CallableType::NativeFunction(&arithmetic::native_mod)),
        "pow" => Some(CallableType::NativeFunction(&arithmetic::native_pow)),
        "and" => Some(CallableType::SpecialFunction(&boolean::special_and)),
        "or" => Some(CallableType::SpecialFunction(&boolean::special_or)),
        "not" => Some(CallableType::NativeFunction(&boolean::native_not)),
        "eq?" => Some(CallableType::NativeFunction(&native_eq)),
        "if" => Some(CallableType::SpecialFunction(&special_if)),
        "let" => Some(CallableType::SpecialFunction(&special_let)),
        "map" => Some(CallableType::SpecialFunction(&lists::list_map)),
        "fold" => Some(CallableType::SpecialFunction(&lists::list_fold)),
        "list" => Some(CallableType::NativeFunction(&lists::list_cons)),
        "fetch-entry" => Some(CallableType::SpecialFunction(&database::special_fetch_entry)),
        "set-entry!" => Some(CallableType::SpecialFunction(&database::special_set_entry)),
        "insert-entry!" => Some(CallableType::SpecialFunction(&database::special_insert_entry)),
        "delete-entry!" => Some(CallableType::SpecialFunction(&database::special_delete_entry)),
        "tuple" => Some(CallableType::SpecialFunction(&tuples::tuple_cons)),
        "get" => Some(CallableType::SpecialFunction(&tuples::tuple_get)),
        "begin" => Some(CallableType::NativeFunction(&native_begin)),
        "contract-call!" => Some(CallableType::SpecialFunction(&database::special_contract_call)),
        _ => None
    }
}
