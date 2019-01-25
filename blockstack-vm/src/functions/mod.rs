pub mod define;
mod lists;

use super::types::{ValueType, CallableType};
use super::types::type_force_integer;
use super::representations::SymbolicExpression;
use super::{Context,CallStack};
use super::InterpreterResult;
use super::errors::Error;
use super::eval;

fn native_add(args: &[ValueType]) -> InterpreterResult {
    let typed_args: Result<Vec<_>, Error> = args.iter().map(|x| type_force_integer(x)).collect();
    let parsed_args = typed_args?;
    let checked_result = parsed_args.iter().fold(Some(0), |acc: Option<u64>, x| {
        match acc {
            Some(value) => value.checked_add(*x),
            None => None
        }});
    if let Some(result) = checked_result{
        Ok(ValueType::IntType(result))
    } else {
        panic!("Overflowed in addition!");
    }
}

fn native_sub(args: &[ValueType]) -> InterpreterResult {
    let typed_args: Result<Vec<_>, Error> = args.iter().map(|x| type_force_integer(x)).collect();
    let parsed_args = typed_args?;
    if let Some((first, rest)) = parsed_args.split_first() {
        let checked_result = rest.iter().fold(Some(*first), |acc, x| {
            match acc {
                Some(value) => value.checked_sub(*x),
                None => None
            }});
        if let Some(result) = checked_result{
            Ok(ValueType::IntType(result))
        } else {
            panic!("Underflowed in subtraction!");
        }
    } else {
        panic!("(- ...) must be called with at least 1 argument");
    }
}

fn native_mul(args: &[ValueType]) -> InterpreterResult {
    let typed_args: Result<Vec<_>, Error> = args.iter().map(|x| type_force_integer(x)).collect();
    let parsed_args = typed_args?;
    let checked_result = parsed_args.iter().fold(Some(1), |acc: Option<u64>, x| {
        match acc {
            Some(value) => value.checked_mul(*x),
            None => None
        }});
    if let Some(result) = checked_result{
        Ok(ValueType::IntType(result))
    } else {
        panic!("Overflowed in multiplication!");
    }
}

fn native_div(args: &[ValueType]) -> InterpreterResult {
    let typed_args: Result<Vec<_>, Error> = args.iter().map(|x| type_force_integer(x)).collect();
    let parsed_args = typed_args?;
    if let Some((first, rest)) = parsed_args.split_first() {
        let checked_result = rest.iter().fold(Some(*first), |acc, x| {
            match acc {
                Some(value) => value.checked_div(*x),
                None => None
            }});
        if let Some(result) = checked_result{
            Ok(ValueType::IntType(result))
        } else {
            panic!("Tried to divide by 0!");
        }
    } else {
        panic!("(/ ...) must be called with at least 1 argument");
    }
}

fn native_mod(args: &[ValueType]) -> InterpreterResult {
    if args.len() == 2 {
        let numerator = type_force_integer(&args[0])?;
        let denominator = type_force_integer(&args[1])?;
        let checked_result = numerator.checked_rem(denominator);
        if let Some(result) = checked_result{
            Ok(ValueType::IntType(result))
        } else {
            panic!("Tried to modulus by 0!");
        }
    } else {
        Err(Error::Generic("(mod ...) must be called with exactly 2 arguments".to_string()))
    }
}

fn native_eq(args: &[ValueType]) -> InterpreterResult {
    // TODO: this currently uses the derived equality checks of ValueType,
    //   however, that's probably not how we want to implement equality
    //   checks on the ::ListTypes
    if args.len() < 2 {
        Ok(ValueType::BoolType(true))
    } else {
        let first = &args[0];
        let result = args.iter().fold(true, |acc, x| acc && (*x == *first));
        Ok(ValueType::BoolType(result))
    }
}

fn special_if(args: &[SymbolicExpression], context: &Context, call_stack: &mut CallStack, global: &Context) -> InterpreterResult {
    if !(args.len() == 2 || args.len() == 3) {
        panic!("Wrong number of arguments to if");
    }
    // handle the conditional clause.
    let conditional = eval(&args[0], context, call_stack, global)?;
    match conditional {
        ValueType::BoolType(result) => {
            if result {
                eval(&args[1], context, call_stack, global)
            } else {
                if args.len() == 3 {
                    eval(&args[2], context, call_stack, global)
                } else {
                    Ok(ValueType::VoidType)
                }
            }
        },
        _ => panic!("Conditional argument must evaluate to BoolType")
    }
}

fn special_let(args: &[SymbolicExpression], context: &Context, call_stack: &mut CallStack, global: &Context) -> InterpreterResult {
    // (let ((x 1) (y 2)) (+ x y)) -> 3
    // arg0 => binding list
    // arg1 => body
    if args.len() != 2 {
        panic!("Wrong number of arguments to let");
    }
    // create a new context.
    let mut inner_context = Context::new();
    inner_context.parent = Option::Some(context);

    if let SymbolicExpression::List(ref bindings) = args[0] {
        let bind_result = bindings.iter().try_for_each(|binding| {
            if let SymbolicExpression::List(ref binding_exps) = *binding {
                if binding_exps.len() != 2 {
                    Err(Error::Generic("Passed non 2-length list as binding in let expression".to_string()))
                } else {
                    if let SymbolicExpression::Atom(ref var_name) = binding_exps[0] {
                        let value = eval(&binding_exps[1], context, call_stack, global)?;
                        match inner_context.variables.insert((*var_name).clone(), value) {
                            Some(_val) => Err(Error::Generic("Multiply defined binding in let expression".to_string())),
                            _ => Ok(())
                        }
                    } else {
                        Err(Error::Generic("Passed non-atomic variable name to let expression binding".to_string()))
                    }
                }
            } else {
                Err(Error::Generic("Passed non-list as binding in let expression.".to_string()))
            }
        });
        // if there was an error during binding, return error.
        if let Err(e) = bind_result {
            Err(e)
        } else {
            // otherwise, evaluate the let-body
            eval(&args[1], &inner_context, call_stack, global)
        }
    } else {
        Err(Error::Generic("Passed non-list as second argument to let expression.".to_string()))
    }
}

pub fn lookup_reserved_functions<'a> (name: &str) -> Option<CallableType<'a>> {
    match name {
        "+" => Some(CallableType::NativeFunction(&native_add)),
        "-" => Some(CallableType::NativeFunction(&native_sub)),
        "*" => Some(CallableType::NativeFunction(&native_mul)),
        "/" => Some(CallableType::NativeFunction(&native_div)),
        "mod" => Some(CallableType::NativeFunction(&native_mod)),
        "eq?" => Some(CallableType::NativeFunction(&native_eq)),
        "if" => Some(CallableType::SpecialFunction(&special_if)),
        "let" => Some(CallableType::SpecialFunction(&special_let)),
        "map" => Some(CallableType::SpecialFunction(&lists::list_map)),
        "fold" => Some(CallableType::SpecialFunction(&lists::list_fold)),
        "list" => Some(CallableType::NativeFunction(&lists::list_cons)),
        _ => None
    }
}
