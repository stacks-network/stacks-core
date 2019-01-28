use super::InterpreterResult;
use super::errors::Error;
use super::representations::SymbolicExpression;
use super::{Context,Environment};
use super::eval;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ListTypeIdentifier {
    IntType,
    BoolType,
    BufferType
}

pub type TypeSignature = (ListTypeIdentifier, u8);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ValueType {
    VoidType,
    IntType(i128),
    BoolType(bool),
    BufferType(Box<[char]>),
    // Q: do we need to enforce that lists are composed
    //   only of elements of the same type? if so, this has
    //   to be done during runtime or via our type checker.
    //  Rust will NOT do it for us.
    ListType(Vec<ValueType>, TypeSignature)
}

pub enum CallableType <'a> {
    UserFunction(Box<DefinedFunction>),
    NativeFunction(&'a Fn(&[ValueType]) -> InterpreterResult),
    SpecialFunction(&'a Fn(&[SymbolicExpression], &mut Environment, &Context) -> InterpreterResult)
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

    pub fn apply(&self, args: &[ValueType], env: &mut Environment) -> InterpreterResult {
        let mut context = Context::new();

        let mut arg_iterator = self.arguments.iter().zip(args.iter());
        let _result = arg_iterator.try_for_each(|(arg, value)| {
            match context.variables.insert((*arg).clone(), (*value).clone()) {
                Some(_val) => Err(Error::InvalidArguments("Multiply defined function argument".to_string())),
                _ => Ok(())
            }
        })?;
        eval(&self.body, env, &context)
    }

    pub fn get_identifier(&self) -> FunctionIdentifier {
        return FunctionIdentifier {
            body: self.body.clone(),
            arguments: self.arguments.clone() }
    }
}

pub fn get_list_type_for(x: &ValueType) -> Result<TypeSignature, Error> {
    match x {
        ValueType::VoidType => Err(Error::InvalidArguments("Cannot construct list of void types".to_string())),
        ValueType::IntType(_r) => Ok((ListTypeIdentifier::IntType, 0)),
        ValueType::BoolType(_r) => Ok((ListTypeIdentifier::BoolType, 0)),
        ValueType::BufferType(_r) => Ok((ListTypeIdentifier::BufferType, 0)),
        ValueType::ListType(_r, (identifier, list_order)) => Ok((identifier.clone(), list_order + 1))
    }
}

pub fn get_empty_list_type() -> TypeSignature {
    (ListTypeIdentifier::IntType, 0)
}
