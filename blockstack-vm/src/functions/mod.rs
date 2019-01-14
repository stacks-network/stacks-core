use super::types::ValueType;
use super::types::CallableType;
use super::types::type_force_integer;
use super::representations::SymbolicExpression;
use super::Context;
use super::eval;

fn native_add(args: &[ValueType]) -> ValueType {
    let parsed_args = args.iter().map(|x| type_force_integer(x));
    let result = parsed_args.fold(0, |acc, x| acc + x);
    ValueType::IntType(result)
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


pub fn lookup_reserved_functions<'a> (name: &str) -> Option<CallableType<'a>> {
    match name {
        "+" => Option::Some(CallableType::NativeFunction(&native_add)),
        "eq?" => Option::Some(CallableType::NativeFunction(&native_eq)),
        "if" => Option::Some(CallableType::SpecialFunction(&special_if)),
        _ => Option::None
    }
}
