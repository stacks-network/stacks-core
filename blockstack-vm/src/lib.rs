pub mod types;
pub mod representations;

mod functions;
pub mod parser;

use std::collections::HashMap;
use std::collections::HashSet;
use types::ValueType;
use types::CallableType;
use types::{DefinedFunction, FunctionIdentifier};
use representations::SymbolicExpression;

pub struct Context <'a> {
    pub parent: Option< &'a Context<'a>>,
    pub variables: HashMap<String, ValueType>,
    pub functions: HashMap<String, Box<DefinedFunction<'a>>>,
}

impl <'a> Context <'a> {
    pub fn new() -> Context<'a> {
        Context { parent: Option::None,
                  variables: HashMap::new(),
                  functions: HashMap::new() }
    }

    fn lookup_variable(&self, name: &str) -> Option<ValueType> {
        match self.variables.get(name) {
            Some(value) => Option::Some((*value).clone()),
            None => {
                match self.parent {
                    Some(parent) => parent.lookup_variable(name),
                    None => Option::None
                }
            }
        }
    }

    fn lookup_function(&self, name: &str) -> Option<Box<DefinedFunction<'a>>> {
        match self.functions.get(name) {
            Some(value) => {
                Option::Some(Box::new(*value.clone()))
            },
            None => {
                match self.parent {
                    Some(parent) => parent.lookup_function(name),
                    None => Option::None
                }
            }
        }
    }
}

pub struct CallStack {
    pub stack: HashSet<FunctionIdentifier>
}


impl CallStack {
    pub fn new() -> CallStack {
        CallStack {
            stack: HashSet::new()
        }
    }
    fn contains(&self, user_function: &FunctionIdentifier) -> bool {
        self.stack.contains(user_function)
    }

    fn insert(&mut self, user_function: &FunctionIdentifier) {
        self.stack.insert(user_function.clone());
    }

    fn remove(&mut self, user_function: &FunctionIdentifier) {
        if !self.stack.remove(&user_function) {
            panic!("Tried to remove function from call stack, but could not find in current context.")
        }
    }
}

fn lookup_variable(name: &str, context: &Context) -> ValueType {
    // first off, are we talking about a constant?
    if name.starts_with(char::is_numeric) {
        match u64::from_str_radix(name, 10) {
            Ok(parsed) => ValueType::IntType(parsed),
            Err(_e) => panic!("Failed to parse!")
        }
    } else {
        match context.lookup_variable(name) {
            Some(value) => value,
            None => panic!("No such variable found in context: {}", name)
        }
    }
}

fn lookup_function<'a> (name: &str, context: &'a Context)-> CallableType<'a> {
    match functions::lookup_reserved_functions(name) {
        Some(result) => result,
        _ => {
            match context.lookup_function(name) {
                Some(func) => { 
                    CallableType::UserFunction(func)
                }
                None => panic!("Crash and burn")
            }
        }
    }
}

pub fn apply(function: &CallableType, args: &[SymbolicExpression], context: &Context, call_stack: &mut CallStack) -> ValueType {
    match function {
        CallableType::SpecialFunction(function) => function(&args, &context, call_stack),
        _ => {
            let evaluated_args: Vec<ValueType> = args.iter().map(|x| eval(x, context, call_stack)).collect();
            match function {
                CallableType::NativeFunction(function) => function(&evaluated_args),
                CallableType::UserFunction(function) => {
                    // check for recursion.
                    // TODO: we must check for recursion during our static checks!
                    let identifier = function.get_identifier();
                    if call_stack.contains(&identifier) {
                        panic!("Recursion detected");
                    } else {
                        call_stack.insert(&identifier);
                        let resp = function.apply(&evaluated_args, call_stack);
                        call_stack.remove(&identifier);
                        resp
                    }
                },
                _ => panic!("Should be unreachable.")
            }
        }
    }
}

pub fn eval <'a> (exp: &SymbolicExpression, context: &'a Context<'a>, call_stack: &mut CallStack) -> ValueType {
    match exp {
        &SymbolicExpression::Atom(ref value) => lookup_variable(&value, context),
        &SymbolicExpression::List(ref children) => {
            if let Some((function_variable, rest)) = children.split_first() {
                match function_variable {
                    &SymbolicExpression::List(ref _children) => panic!("Attempt to evaluate to function. Illegal!"),
                    &SymbolicExpression::Atom(ref value) => {
                        let f = lookup_function(&value, &context);
                        apply(&f, &rest, context, call_stack)
                    }
                }
            } else {
                ValueType::VoidType
            }
        }
    }
}

/* This function evaluates a list of expressions, sharing a global context.
 *  
 * 
 */
pub fn eval_all(expressions: &[&SymbolicExpression]) -> ValueType {
    panic!("Unimplemented");
}
