use std::collections::HashMap;

pub struct SymbolicExpression {
    value: String,
    children: Option<Box<[SymbolicExpression]>>
}

pub struct Contract {
    content: Box<[SymbolicExpression]>
}

#[derive(Debug)]
#[derive(Clone)]
pub enum ValueType {
    IntType(u64),
    BoolType(bool),
    BufferType(Box<[char]>),
    IntListType(Vec<u64>),
    BoolListType(Vec<bool>),
    BufferListType(Vec<Box<[char]>>)
}

pub struct Context <'a> {
    parent: Option< &'a Context<'a>>,
    variables: HashMap<String, ValueType>,
    functions: HashMap<String, Box<Fn(&[ValueType]) -> ValueType>>
}

impl <'a> Context <'a> {
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
}

fn type_force_integer(value: &ValueType) -> u64 {
    match *value {
        ValueType::IntType(int) => int,
        _ => panic!("Not an integer")
    }
}

fn native_add(args: &[ValueType]) -> ValueType {
    let parsed_args = args.iter().map(|x| type_force_integer(x));
    let result = parsed_args.fold(0, |acc, x| acc + x);
    ValueType::IntType(result)
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

fn lookup_function(name: &str)-> fn(&[ValueType]) -> ValueType {
    match name {
        "+" => native_add,
        _ => panic!("Crash and burn")
    }
}

fn apply<F>(function: &F, args: &[SymbolicExpression], context: &Context) -> ValueType
    where F: Fn(&[ValueType]) -> ValueType {
    let evaluated_args: Vec<ValueType> = args.iter().map(|x| eval(x, context)).collect();
    function(&evaluated_args)
}

fn eval(exp: &SymbolicExpression, context: &Context) -> ValueType {
    match exp.children {
        None => lookup_variable(&exp.value, context),
        Some(ref children) => {
            let f = lookup_function(&exp.value);
            apply(&f, &children, context)
        }
    }
}

fn main() {
    let content = [ SymbolicExpression { value: "+".to_string(),
                                         children:
                                         Some(Box::new([ SymbolicExpression { value: "1".to_string(),
                                                                              children: None },
                                                         SymbolicExpression { value: "a".to_string(),
                                                                              children: None } ])) } ];
//    let contract = Contract { content: Box::new(content) } ;
    let mut context = Context {
        parent: Option::None,
        variables: HashMap::new(),
        functions: HashMap::new() };

    context.variables.insert("a".to_string(), ValueType::IntType(63));

    println!("{:?}", eval(&content[0], &context));
}
