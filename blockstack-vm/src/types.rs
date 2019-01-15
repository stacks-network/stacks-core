use super::representations::SymbolicExpression;
use super::{Context,CallStack};
use super::eval;

#[derive(Debug)]
#[derive(Clone)]
#[derive(PartialEq)]
pub enum ValueType {
    VoidType,
    IntType(u64),
    BoolType(bool),
    BufferType(Box<[char]>),
    IntListType(Vec<u64>),
    BoolListType(Vec<bool>),
    BufferListType(Vec<Box<[char]>>)
}

pub enum CallableType <'a> {
    UserFunction(Box<DefinedFunction <'a>>),
    NativeFunction(&'a Fn(&[ValueType]) -> ValueType),
    SpecialFunction(&'a Fn(&[SymbolicExpression], &Context, &mut CallStack) -> ValueType)
}

#[derive(Clone)]
pub struct DefinedFunction <'a> {
    pub context: Option<&'a Context<'a>>,
    pub arguments: Vec<String>,
    pub body: SymbolicExpression
}


pub fn type_force_integer(value: &ValueType) -> u64 {
    match *value {
        ValueType::IntType(int) => int,
        _ => panic!("Not an integer")
    }
}

#[derive(Clone,PartialEq,Eq,Hash)]
pub struct FunctionIdentifier {
    pub arguments: Vec<String>,
    pub body: SymbolicExpression
}

impl <'a> DefinedFunction <'a> {
    pub fn new(body: SymbolicExpression, arguments: Vec<String>) -> DefinedFunction <'a> {
        DefinedFunction {
            body: body,
            arguments: arguments,
            context: None,
        }
    }

    pub fn apply(&self, args: &[ValueType], call_stack: &mut CallStack) -> ValueType {
        let mut context = Context::new();
        if let Some(global) = self.context {
            context.parent = Some(global);
        }

        let arg_iterator = self.arguments.iter().zip(args.iter());
        arg_iterator.for_each(|(arg, value)| {
            match context.variables.insert((*arg).clone(), (*value).clone()) {
                Some(_val) => panic!("Multiply defined function argument."),
                _ => ()
            }
        });
        eval(&self.body, &context, call_stack)
    }

    pub fn get_identifier(&self) -> FunctionIdentifier {
        return FunctionIdentifier {
            body: self.body.clone(),
            arguments: self.arguments.clone() }
    }
}
