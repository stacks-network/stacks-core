use super::InterpreterResult;
use super::errors::Error;
use super::representations::SymbolicExpression;
use super::{Context,CallStack};
use super::eval;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ListTypeIdentifier {
    IntType,
    BoolType,
    BufferType
}

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
    ListType(Vec<ValueType>, (ListTypeIdentifier, u8))
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

        let mut arg_iterator = self.arguments.iter().zip(args.iter());
        let _result = arg_iterator.try_for_each(|(arg, value)| {
            match context.variables.insert((*arg).clone(), (*value).clone()) {
                Some(_val) => Err(Error::InvalidArguments("Multiply defined function argument".to_string())),
                _ => Ok(())
            }
        })?;
        eval(&self.body, &context, call_stack, global)
    }

    pub fn get_identifier(&self) -> FunctionIdentifier {
        return FunctionIdentifier {
            body: self.body.clone(),
            arguments: self.arguments.clone() }
    }
}
