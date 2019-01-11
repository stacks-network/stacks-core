use super::representations::SymbolicExpression;
use super::Context;
use super::eval;

#[derive(Debug)]
#[derive(Clone)]
#[derive(PartialEq)]
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

#[derive(Clone)]
pub struct DefinedFunction {
    pub arguments: Vec<String>,
    pub body: SymbolicExpression
}


impl DefinedFunction {
    pub fn apply(&self, args: &[ValueType]) -> ValueType {
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
