use super::types::ValueType;
use super::types::CallableType;
use super::types::type_force_integer;
use super::representations::SymbolicExpression;
use super::Context;
use super::eval;

fn native_add(args: &[ValueType]) -> ValueType {
    let parsed_args = args.iter().map(|x| type_force_integer(x));
    let checked_result = parsed_args.fold(Some(0), |acc: Option<u64>, x| {
            match acc {
                Some(value) => value.checked_add(x),
                None => None
            }});
    if let Some(result) = checked_result{
        ValueType::IntType(result)
    } else {
        panic!("Overflowed in addition!");
    }
}

fn native_sub(args: &[ValueType]) -> ValueType {
    let parsed_args: Vec<u64> = args.iter().map(|x| type_force_integer(x)).collect();
    if let Some((first, rest)) = parsed_args.split_first() {
        let checked_result = rest.iter().fold(Some(*first), |acc, x| {
            match acc {
                Some(value) => value.checked_sub(*x),
                None => None
            }});
        if let Some(result) = checked_result{
            ValueType::IntType(result)
        } else {
            panic!("Underflowed in subtraction!");
        }
    } else {
        panic!("(- ...) must be called with at least 1 argument");
    }
}

fn native_mul(args: &[ValueType]) -> ValueType {
    let parsed_args = args.iter().map(|x| type_force_integer(x));
    let checked_result = parsed_args.fold(Some(1), |acc: Option<u64>, x| {
            match acc {
                Some(value) => value.checked_mul(x),
                None => None
            }});
    if let Some(result) = checked_result{
        ValueType::IntType(result)
    } else {
        panic!("Overflowed in multiplication!");
    }
}

fn native_div(args: &[ValueType]) -> ValueType {
    let parsed_args: Vec<u64> = args.iter().map(|x| type_force_integer(x)).collect();
    if let Some((first, rest)) = parsed_args.split_first() {
        let checked_result = rest.iter().fold(Some(*first), |acc, x| {
            match acc {
                Some(value) => value.checked_div(*x),
                None => None
            }});
        if let Some(result) = checked_result{
            ValueType::IntType(result)
        } else {
            panic!("Tried to divide by 0!");
        }
    } else {
        panic!("(/ ...) must be called with at least 1 argument");
    }
}

fn native_mod(args: &[ValueType]) -> ValueType {
    if args.len() == 2 {
        let numerator = type_force_integer(&args[0]);
        let denominator = type_force_integer(&args[1]);
        let checked_result = numerator.checked_rem(denominator);
        if let Some(result) = checked_result{
            ValueType::IntType(result)
        } else {
            panic!("Tried to modulus by 0!");
        }
    } else {
        panic!("(mod ...) must be called with exactly 2 arguments");
    }
}

fn native_eq(args: &[ValueType]) -> ValueType {
    // TODO: this currently uses the derived equality checks of ValueType,
    //   however, that's probably not how we want to implement equality
    //   checks on the ::ListTypes
    if args.len() < 2 {
        ValueType::BoolType(true)
    } else {
        let first = &args[0];
        let result = args.iter().fold(true, |acc, x| acc && (*x == *first));
        ValueType::BoolType(result)
    }
}

fn special_if(args: &[SymbolicExpression], context: &Context) -> ValueType {
    if !(args.len() == 2 || args.len() == 3) {
        panic!("Wrong number of arguments to if");
    }
    // handle the conditional clause.
    let conditional = eval(&args[0], context);
    match conditional {
        ValueType::BoolType(result) => {
            if result {
                eval(&args[1], context)
            } else {
                if args.len() == 3 {
                    eval(&args[2], context)
                } else {
                    ValueType::VoidType
                }
            }
        },
        _ => panic!("Conditional argument must evaluate to BoolType")
    }
}

fn special_let(args: &[SymbolicExpression], context: &Context) -> ValueType {
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
        bindings.iter().for_each(|binding| {
            if let SymbolicExpression::List(ref binding_exps) = *binding {
                if binding_exps.len() != 2 {
                    panic!("Passed non 2-length list as binding in let expression");
                } else {
                    if let SymbolicExpression::Atom(ref var_name) = binding_exps[0] {
                        let value = eval(&binding_exps[1], context);
                        match inner_context.variables.insert((*var_name).clone(), value) {
                            Some(_val) => panic!("Multiply defined binding in let expression"),
                            _ => ()
                        }
                    } else {
                        panic!("Passed non-atomic variable name to let expression binding");
                    }
                }
            } else {
                panic!("Passed non-list as binding in let expression.");
            }
        });
    } else {
        panic!("Passed non-list as second argument to let expression.");
    }

    eval(&args[1], &inner_context)
}

pub fn lookup_reserved_functions<'a> (name: &str) -> Option<CallableType<'a>> {
    match name {
        "+" => Option::Some(CallableType::NativeFunction(&native_add)),
        "-" => Option::Some(CallableType::NativeFunction(&native_sub)),
        "*" => Option::Some(CallableType::NativeFunction(&native_mul)),
        "/" => Option::Some(CallableType::NativeFunction(&native_div)),
        "mod" => Option::Some(CallableType::NativeFunction(&native_mod)),
        "eq?" => Option::Some(CallableType::NativeFunction(&native_eq)),
        "if" => Option::Some(CallableType::SpecialFunction(&special_if)),
        "let" => Option::Some(CallableType::SpecialFunction(&special_let)),
        _ => Option::None
    }
}
