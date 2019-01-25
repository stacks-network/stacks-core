use super::InterpreterResult;
use super::errors::Error;
use super::representations::SymbolicExpression;
use super::{Context,CallStack};
use super::eval;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ValueType {
    VoidType,
    IntType(u64),
    BoolType(bool),
    BufferType(Box<[char]>),
    // Q: do we need to enforce that lists are composed
    //   only of elements of the same type? if so, this has
    //   to be done during runtime or via our type checker.
    //  Rust will NOT do it for us.
    ListType(Vec<ValueType>)
}

pub enum CallableType <'a> {
    UserFunction(Box<DefinedFunction>),
    NativeFunction(&'a Fn(&[ValueType]) -> InterpreterResult),
    SpecialFunction(&'a Fn(&[SymbolicExpression], &Context, &mut CallStack, &Context) -> InterpreterResult)
}

#[derive(Clone)]
pub struct DefinedFunction {
    pub arguments: Vec<String>,
    pub body: SymbolicExpression
}


pub fn type_force_integer(value: &ValueType) -> Result<u64, Error> {
    match *value {
        ValueType::IntType(int) => Ok(int),
        _ => Err(Error::TypeError("Integer".to_string(),
                                  format!("{:?}", value)))
    }
}

#[derive(Clone,PartialEq,Eq,Hash)]
pub struct FunctionIdentifier {
    pub arguments: Vec<String>,
    pub body: SymbolicExpression
}

impl DefinedFunction {
    pub fn new(body: SymbolicExpression, arguments: Vec<String>) -> DefinedFunction {
        DefinedFunction {
            body: body,
            arguments: arguments,
        }
    }

    pub fn apply(&self, args: &[ValueType], call_stack: &mut CallStack, global: &Context) -> InterpreterResult {
        let mut context = Context::new();
        context.parent = Some(global);        

        let arg_iterator = self.arguments.iter().zip(args.iter());
        arg_iterator.for_each(|(arg, value)| {
            match context.variables.insert((*arg).clone(), (*value).clone()) {
                Some(_val) => panic!("Multiply defined function argument."),
                _ => ()
            }
        });
        eval(&self.body, &context, call_stack, global)
    }

    pub fn get_identifier(&self) -> FunctionIdentifier {
        return FunctionIdentifier {
            body: self.body.clone(),
            arguments: self.arguments.clone() }
    }
}
