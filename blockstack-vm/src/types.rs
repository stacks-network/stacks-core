use super::InterpreterResult;
use super::errors::Error;
use super::representations::SymbolicExpression;
use super::{Context,Environment};
use super::eval;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AtomTypeIdentifier {
    VoidType,
    IntType,
    BoolType,
    BufferType
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TypeSignature {
    atomic_type: AtomTypeIdentifier,
    dimension: u8
}

impl TypeSignature {
    pub fn new(atomic_type: AtomTypeIdentifier, dimension: u8) -> TypeSignature {
        TypeSignature { atomic_type: atomic_type,
                        dimension: dimension }
    }

    pub fn type_of(x: &ValueType) -> TypeSignature {
        match x {
            ValueType::VoidType => TypeSignature::new(AtomTypeIdentifier::VoidType, 0),
            ValueType::IntType(_v) => TypeSignature::new(AtomTypeIdentifier::IntType, 0),
            ValueType::BoolType(_v) => TypeSignature::new(AtomTypeIdentifier::BoolType, 0),
            ValueType::BufferType(_v) => TypeSignature::new(AtomTypeIdentifier::BufferType, 0),
            ValueType::ListType(_v, type_signature) => type_signature.clone()
        }
    }

    pub fn get_list_type_for(x: &ValueType) -> Result<TypeSignature, Error> {
        match x {
            ValueType::VoidType => Err(Error::InvalidArguments("Cannot construct list of void types".to_string())),
            _ => {
                let mut base_type = TypeSignature::type_of(x);
                base_type.dimension += 1;
                Ok(base_type)
            }
        }
    }

    pub fn get_empty_list_type() -> TypeSignature {
        TypeSignature::new(AtomTypeIdentifier::IntType, 0)
    }
}

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
