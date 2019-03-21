pub mod define;
mod lists;
mod arithmetic;
mod boolean;
mod database;
mod tuples;

use vm::errors::{Error, ErrType, InterpreterResult as Result};
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

fn native_hash160(args: &[Value]) -> Result<Value> {
    use util::hash::Hash160;

    if !(args.len() == 1) {
        return Err(Error::new(ErrType::InvalidArguments("Wrong number of arguments to hash160 (expects 1)".to_string())))
    }
    let input = &args[0];
    let bytes = match input {
        Value::Int(value) => Ok(value.to_le_bytes().to_vec()),
        Value::Buffer(value) => Ok(value.data.clone()),
        _ => Err(Error::new(ErrType::NotImplemented))
    }?;
    let hash160 = Hash160::from_data(&bytes);
    Value::buff_from(hash160.as_bytes().to_vec())
}

fn native_begin(args: &[Value]) -> Result<Value> {
    match args.last() {
        Some(v) => Ok(v.clone()),
        None => Ok(Value::Void)
    }
}

fn native_print(args: &[Value]) -> Result<Value> {
    if !(args.len() == 1) {
        return Err(Error::new(ErrType::InvalidArguments("Wrong number of arguments to print (expects 1)".to_string())))
    }
    eprintln!("{:?}", args[0]);
    Ok(args[0].clone())
}

fn special_if(args: &[SymbolicExpression], env: &mut Environment, context: &LocalContext) -> Result<Value> {
    if !(args.len() == 2 || args.len() == 3) {
        return Err(Error::new(ErrType::InvalidArguments("Wrong number of arguments to if (expect 2 or 3)".to_string())))
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
        _ => Err(Error::new(ErrType::TypeError("BoolType".to_string(), conditional)))
    }
}

fn parse_eval_bindings(bindings: &[SymbolicExpression],
                       env: &mut Environment, context: &LocalContext)-> Result<Vec<(String, Value)>> {
    let mut result = Vec::new();
    for binding in bindings.iter() {
        if let SymbolicExpression::List(ref binding_exps) = *binding {
            if binding_exps.len() != 2 {
                return Err(Error::new(ErrType::InvalidArguments("Passed non 2-length list as a binding. Bindings should be of the form (name value).".to_string())))
            }
            if let SymbolicExpression::Atom(ref var_name) = binding_exps[0] {
                let value = eval(&binding_exps[1], env, context)?;
                result.push((var_name.clone(), value));
            } else {
                return Err(Error::new(ErrType::InvalidArguments("Passed bad variable name as a binding. Bindings should be of the form (name value).".to_string())))
            }
        } else {
            return Err(Error::new(ErrType::InvalidArguments("Passed non 2-length list as a binding. Bindings should be of the form (name value).".to_string())))
        }
    }

    Ok(result)
}

fn special_let(args: &[SymbolicExpression], env: &mut Environment, context: &LocalContext) -> Result<Value> {
    use vm::is_reserved;

    // (let ((x 1) (y 2)) (+ x y)) -> 3
    // arg0 => binding list
    // arg1 => body
    if args.len() != 2 {
        return Err(Error::new(ErrType::InvalidArguments("Wrong number of arguments to let (expect 2)".to_string())))
    }
    // create a new context.
    let mut inner_context = context.extend()?;

    if let SymbolicExpression::List(ref bindings) = args[0] {
        // parse and eval the bindings.
        let mut binding_results = parse_eval_bindings(bindings, env, context)?;
        for (binding_name, binding_value) in binding_results.drain(..) {
            if is_reserved(&binding_name) {
                return Err(Error::new(ErrType::ReservedName(binding_name)))
            }
            if inner_context.variables.contains_key(&binding_name) {
                return Err(Error::new(ErrType::VariableDefinedMultipleTimes(binding_name)))
            }
            inner_context.variables.insert(binding_name, binding_value);
        }

        // evaluate the let-body
        eval(&args[1], env, &inner_context)
    } else {
        Err(Error::new(ErrType::InvalidArguments("Passed non-list as second argument to let expression.".to_string())))
    }
}

pub fn lookup_reserved_functions(name: &str) -> Option<CallableType> {
    match name {
        "+" => Some(CallableType::NativeFunction("native_add", &arithmetic::native_add)),
        "-" => Some(CallableType::NativeFunction("native_sub", &arithmetic::native_sub)),
        "*" => Some(CallableType::NativeFunction("native_mul", &arithmetic::native_mul)),
        "/" => Some(CallableType::NativeFunction("native_div", &arithmetic::native_div)),
        ">=" => Some(CallableType::NativeFunction("native_geq", &arithmetic::native_geq)),
        "<=" => Some(CallableType::NativeFunction("native_leq", &arithmetic::native_leq)),
        "<" => Some(CallableType::NativeFunction("native_le", &arithmetic::native_le)),
        ">" => Some(CallableType::NativeFunction("native_ge", &arithmetic::native_ge)),
        "mod" => Some(CallableType::NativeFunction("native_mod", &arithmetic::native_mod)),
        "pow" => Some(CallableType::NativeFunction("native_pow", &arithmetic::native_pow)),
        "xor" => Some(CallableType::NativeFunction("native_xor", &arithmetic::native_xor)),
        "and" => Some(CallableType::SpecialFunction("native_and", &boolean::special_and)),
        "or" => Some(CallableType::SpecialFunction("native_or", &boolean::special_or)),
        "not" => Some(CallableType::NativeFunction("native_not", &boolean::native_not)),
        "eq?" => Some(CallableType::NativeFunction("native_eq", &native_eq)),
        "if" => Some(CallableType::SpecialFunction("native_if", &special_if)),
        "let" => Some(CallableType::SpecialFunction("native_let", &special_let)),
        "map" => Some(CallableType::SpecialFunction("native_map", &lists::list_map)),
        "fold" => Some(CallableType::SpecialFunction("native_fold", &lists::list_fold)),
        "list" => Some(CallableType::NativeFunction("native_cons", &lists::list_cons)),
        "fetch-entry" => Some(CallableType::SpecialFunction("native_fetch-entry", &database::special_fetch_entry)),
        "set-entry!" => Some(CallableType::SpecialFunction("native_set-entry", &database::special_set_entry)),
        "insert-entry!" => Some(CallableType::SpecialFunction("native_insert-entry", &database::special_insert_entry)),
        "delete-entry!" => Some(CallableType::SpecialFunction("native_delete-entry", &database::special_delete_entry)),
        "tuple" => Some(CallableType::SpecialFunction("native_tuple", &tuples::tuple_cons)),
        "get" => Some(CallableType::SpecialFunction("native_get-tuple", &tuples::tuple_get)),
        "begin" => Some(CallableType::NativeFunction("native_begin", &native_begin)),
        "hash160" => Some(CallableType::NativeFunction("native_hash160", &native_hash160)),
        "print" => Some(CallableType::NativeFunction("native_print", &native_print)),
        "contract-call!" => Some(CallableType::SpecialFunction("native_contract-call", &database::special_contract_call)),
        _ => None
    }
}
