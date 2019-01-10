use std::collections::HashMap;


#[derive(Clone)]
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

pub enum CallableType <'a> {
    UserFunction(Box<DefinedFunction>),
    NativeFunction(&'a Fn(&[ValueType]) -> ValueType)
}

pub struct Context <'a> {
    parent: Option< &'a Context<'a>>,
    variables: HashMap<String, ValueType>,
    functions: HashMap<String, Box<DefinedFunction>>
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

#[derive(Clone)]
pub struct DefinedFunction {
    arguments: Vec<String>,
    body: SymbolicExpression
}


impl DefinedFunction {
    fn apply(&self, args: &[ValueType]) -> ValueType {
        let mut context = Context::new();
        let arg_iterator = self.arguments.iter().zip(args.iter());
        arg_iterator.for_each(|(arg, value)| {
            match context.variables.insert((*arg).clone(), (*value).clone()) {
                Some(_val) => panic!("Multiply defined function argument."),
                _ => ()
            }
        });
        eval(&self.body, &context) 
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

fn lookup_function<'a> (name: &str, context: &'a Context)-> CallableType<'a> {
    match name {
        "+" => CallableType::NativeFunction(&native_add),
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
    let evaluated_args: Vec<ValueType> = args.iter().map(|x| eval(x, context)).collect();
    match function {
        CallableType::NativeFunction(function) => function(&evaluated_args),
        CallableType::UserFunction(function) => function.apply(&evaluated_args)
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

fn main() {
    let content = [ SymbolicExpression { value: "do_work".to_string(),
                                         children:
                                         Some(Box::new([ SymbolicExpression { value: "a".to_string(),
                                                                              children: None } ])) } ];
    let func_body = SymbolicExpression { value: "+".to_string(),
                                         children:
                                         Some(Box::new([ SymbolicExpression { value: "5".to_string(),
                                                                              children: None },
                                                         SymbolicExpression { value: "x".to_string(),
                                                                              children: None }])) };
    let func_args = vec!["x".to_string()];
    let user_function = Box::new(DefinedFunction { body: func_body,
                                                   arguments: func_args });

//    let contract = Contract { content: Box::new(content) } ;
    let mut context = Context {
        parent: Option::None,
        variables: HashMap::new(),
        functions: HashMap::new() };

    context.variables.insert("a".to_string(), ValueType::IntType(59));
    context.functions.insert("do_work".to_string(), user_function);

    println!("{:?}", eval(&content[0], &context));
}
