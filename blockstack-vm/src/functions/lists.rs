use super::super::types::ValueType;
use super::super::types::ValueType::{ListType};
use super::super::representations::SymbolicExpression;
use super::super::representations::SymbolicExpression::{AtomValue};
use super::super::{Context,CallStack,eval,apply,lookup_function};

pub fn list_cons(args: &[ValueType]) -> ValueType {
    ListType(args.iter().map(|x| x.clone()).collect())
}

pub fn list_fold(args: &[SymbolicExpression], context: &Context,
                 call_stack: &mut CallStack, global: &Context) -> ValueType {
    if args.len() != 3 {
        panic!("Wrong number of arguments to fold")
    }
    if let SymbolicExpression::Atom(ref function_name) = args[0] {
        let function = lookup_function(&function_name, context);
        let list = eval(&args[1], context, call_stack, global);
        let initial = eval(&args[2], context, call_stack, global);
        match list {
            ListType(vector) => vector.iter().fold(
                initial,
                |acc, x| {
                    let argument = [ AtomValue(x.clone()), AtomValue(acc) ];
                    apply(&function, &argument, context, call_stack, global)
                }),
            _ => panic!("Fold called on non-list! Totally unacceptable.")
        }
    } else {
        panic!("Fold must be called with a function name. We do not support eval'ing to functions.")
    }
}

pub fn list_map(args: &[SymbolicExpression], context: &Context,
            call_stack: &mut CallStack, global: &Context) -> ValueType {
    if args.len() != 2 {
        panic!("Wrong number of arguments to map");
    }
    if let SymbolicExpression::Atom(ref function_name) = args[0] {
        let function = lookup_function(&function_name, context);
        let list = eval(&args[1], context, call_stack, global);
        match list {
            ListType(vector) => ListType(
                vector.iter().map(|x| {
                    let argument = [ SymbolicExpression::AtomValue(x.clone()) ];
                    apply(&function, &argument, context, call_stack, global)
                }).collect()),
            _ => panic!("Map called on non-list! Totally unacceptable.")
        }
    } else {
        panic!("Map must be called with a function name. We do not support eval'ing to functions.")
    }
}
