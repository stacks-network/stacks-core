use std::collections::BTreeMap;

use InterpreterResult;
use errors::Error;
use representations::SymbolicExpression;
use {Context,Environment};
use eval;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AtomTypeIdentifier {
    VoidType,
    IntType,
    BoolType,
    BufferType,
    TupleType(TupleTypeSignature)
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TypeSignature {
    atomic_type: AtomTypeIdentifier,
    dimension: u8
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TupleTypeSignature {
    type_map: BTreeMap<String, TypeSignature>
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TupleData {
    pub type_signature: TupleTypeSignature,
    data_map: BTreeMap<String, Value>
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Value {
    Void,
    Int(i128),
    Bool(bool),
    Buffer(Box<[char]>),
    List(Vec<Value>, TypeSignature),
    Tuple(TupleData)
}

pub enum CallableType <'a> {
    UserFunction(Box<DefinedFunction>),
    NativeFunction(&'a Fn(&[Value]) -> InterpreterResult),
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

impl TupleTypeSignature {
    pub fn new(type_data: Vec<(String, TypeSignature)>) -> Result<TupleTypeSignature, Error> {
        let mut type_map = BTreeMap::new();
        for (name, type_info) in type_data {
            if let Some(_v) = type_map.insert(name, type_info) {
                return Err(Error::InvalidArguments("Cannot use named argument twice in tuple construction.".to_string()))
            }
        }
        Ok(TupleTypeSignature { type_map: type_map })
    }

    pub fn check_valid(&self, name: &str, value: &Value) -> bool {
        if let Some(expected_type) = self.type_map.get(name) {
            *expected_type == TypeSignature::type_of(value)
        } else {
            false
        }
    }
}

impl TupleData {
    pub fn from_data(data: &[(&str, Value)]) -> Result<TupleData, Error> {
        let mut type_map = BTreeMap::new();
        let mut data_map = BTreeMap::new();
        for (name, value) in data {
            let type_info = TypeSignature::type_of(value);
            if type_info.atomic_type == AtomTypeIdentifier::VoidType {
                return Err(Error::InvalidArguments("Cannot use VoidTypes in tuples.".to_string()))
            }
            if let Some(_v) = type_map.insert(name.to_string(), type_info) {
                return Err(Error::InvalidArguments("Cannot use named argument twice in tuple construction.".to_string()))
            }
            data_map.insert(name.to_string(), (*value).clone());
        }
        Ok(TupleData { type_signature: TupleTypeSignature { type_map: type_map },
                       data_map: data_map })

    }

    pub fn get(&self, name: &str) -> InterpreterResult {
        if let Some(value) = self.data_map.get(name) {
            Ok(value.clone())
        } else {
            Err(Error::InvalidArguments(format!("No such field {:?} in tuple", name)))
        }
        
    }
}

impl TypeSignature {
    pub fn new(atomic_type: AtomTypeIdentifier, dimension: u8) -> TypeSignature {
        TypeSignature { atomic_type: atomic_type,
                        dimension: dimension }
    }

    pub fn type_of(x: &Value) -> TypeSignature {
        match x {
            Value::Void => TypeSignature::new(AtomTypeIdentifier::VoidType, 0),
            Value::Int(_v) => TypeSignature::new(AtomTypeIdentifier::IntType, 0),
            Value::Bool(_v) => TypeSignature::new(AtomTypeIdentifier::BoolType, 0),
            Value::Buffer(_v) => TypeSignature::new(AtomTypeIdentifier::BufferType, 0),
            Value::List(_v, type_signature) => type_signature.clone(),
            Value::Tuple(v) => TypeSignature::new(AtomTypeIdentifier::TupleType(
                v.type_signature.clone()), 0)
        }
    }

    pub fn get_list_type_for(x: &Value) -> Result<TypeSignature, Error> {
        match x {
            Value::Void => Err(Error::InvalidArguments("Cannot construct list of void types".to_string())),
            Value::Tuple(_a) => Err(Error::InvalidArguments("Cannot construct list of tuple types".to_string())),
            _ => {
                let mut base_type = TypeSignature::type_of(x);
                base_type.dimension += 1;
                Ok(base_type)
            }
        }
    }

    fn get_atom_type(typename: &str) -> Result<AtomTypeIdentifier, Error> {
        match typename {
            "int" => Ok(AtomTypeIdentifier::IntType),
            "void" => Ok(AtomTypeIdentifier::VoidType),
            "bool" => Ok(AtomTypeIdentifier::BoolType),
            "buff" => Ok(AtomTypeIdentifier::BufferType),
            _ => Err(Error::ParseError(format!("Unknown type name: '{:?}'", typename)))
        }
    }

    
    fn get_list_type(prefix: &str, typename: &str, dimension: &str) -> Result<TypeSignature, Error> {
        if prefix != "list" {
            let message = format!("Unknown type name: '{}-{}-{}'", prefix, typename, dimension);
            return Err(Error::ParseError(message))
        }
        let atom_type = TypeSignature::get_atom_type(typename)?;
        let dimension = match u8::from_str_radix(dimension, 10) {
            Ok(parsed) => Ok(parsed),
            Err(_e) => Err(Error::ParseError(
                format!("Failed to parse dimension of type: '{}-{}-{}'",
                        prefix, typename, dimension)))
        }?;
        Ok(TypeSignature::new(atom_type, dimension))
    }

    pub fn parse_type_str(x: &str) -> Result<TypeSignature, Error> {
        let components: Vec<_> = x.split('-').collect();
        match components.len() {
            1 => {
                let atom_type = TypeSignature::get_atom_type(components[0])?;
                Ok(TypeSignature::new(atom_type, 0))
            },
            3 => TypeSignature::get_list_type(components[0], components[1], components[2]),
            _ => Err(Error::ParseError(
                format!("Unknown type name: '{}'", x)))
        }
    }


    pub fn get_empty_list_type() -> TypeSignature {
        TypeSignature::new(AtomTypeIdentifier::IntType, 0)
    }
}

impl DefinedFunction {
    pub fn new(body: SymbolicExpression, arguments: Vec<String>) -> DefinedFunction {
        DefinedFunction {
            body: body,
            arguments: arguments,
        }
    }

    pub fn apply(&self, args: &[Value], env: &mut Environment) -> InterpreterResult {
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
