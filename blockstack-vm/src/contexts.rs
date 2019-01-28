use std::collections::HashMap;
use std::collections::HashSet;

use super::types::{DefinedFunction, FunctionIdentifier, ValueType};


pub struct Environment <'a> {
    pub global_context: Context <'a>,
    pub call_stack: CallStack
}

impl <'a> Environment <'a> {
    pub fn new() -> Environment<'a> {
        let global_context = Context::new();
        Environment {
            global_context: global_context,
            call_stack: CallStack::new()
        }
    }
}

pub struct Context <'a> {
    pub parent: Option< &'a Context<'a>>,
    pub variables: HashMap<String, ValueType>,
    pub functions: HashMap<String, Box<DefinedFunction>>,
}

impl <'a> Context <'a> {
    pub fn new() -> Context<'a> {
        Context { parent: Option::None,
                  variables: HashMap::new(),
                  functions: HashMap::new() }
    }
    
    pub fn extend(&'a self) -> Context<'a> {
        Context {
            parent: Some(self),
            variables: HashMap::new(),
            functions: HashMap::new()
        }
    }

    pub fn lookup_variable(&self, name: &str) -> Option<ValueType> {
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

    pub fn lookup_function(&self, name: &str) -> Option<Box<DefinedFunction>> {
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
    pub stack: HashSet<FunctionIdentifier>,
}


impl CallStack {
    pub fn new() -> CallStack {
        CallStack {
            stack: HashSet::new(),
        }
    }

    pub fn contains(&self, user_function: &FunctionIdentifier) -> bool {
        self.stack.contains(user_function)
    }

    pub fn insert(&mut self, user_function: &FunctionIdentifier) {
        self.stack.insert(user_function.clone());
    }

    pub fn remove(&mut self, user_function: &FunctionIdentifier) {
        if !self.stack.remove(&user_function) {
            panic!("Tried to remove function from call stack, but could not find in current context.")
        }
    }
}
