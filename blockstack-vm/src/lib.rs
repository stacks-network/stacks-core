pub mod types;
pub mod representations;

use std::collections::HashMap;
use types::ValueType;
use types::CallableType;
use types::DefinedFunction;
use representations::SymbolicExpression;

fn type_force_integer(value: &ValueType) -> u64 {
    match *value {
        ValueType::IntType(int) => int,
        _ => panic!("Not an integer")
    }
}

pub struct Context <'a> {
    pub parent: Option< &'a Context<'a>>,
    pub variables: HashMap<String, ValueType>,
    pub functions: HashMap<String, Box<DefinedFunction>>
}

impl <'a> Context <'a> {
    fn new() -> Context<'a> {
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

    fn lookup_function(&self, name: &str) -> Option<Box<DefinedFunction>> {
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
            None => panic!("No such variable found in context")
        }
    }
}

fn lookup_function<'a> (name: &str, context: &'a Context)-> CallableType<'a> {
    match name {
        "+" => CallableType::NativeFunction(&native_add),
        "eq?" => CallableType::NativeFunction(&native_eq),
        "if" => CallableType::SpecialFunction(&special_if),
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

pub fn apply(function: CallableType, args: &[SymbolicExpression], context: &Context) -> ValueType {
    match function {
        CallableType::SpecialFunction(function) => function(&args, &context),
        _ => {
            let evaluated_args: Vec<ValueType> = args.iter().map(|x| eval(x, context)).collect();
            match function {
                CallableType::NativeFunction(function) => function(&evaluated_args),
                CallableType::UserFunction(function) => function.apply(&evaluated_args),
                _ => panic!("Should be unreachable.")
            }
        }
    }
}

pub fn eval(exp: &SymbolicExpression, context: &Context) -> ValueType {
    match exp.children {
        None => lookup_variable(&exp.value, context),
        Some(ref children) => {
            let f = lookup_function(&exp.value, &context);
            apply(f, &children, context)
        }
    }
}
