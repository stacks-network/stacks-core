use std::collections::BTreeMap;

use vm::errors::{Error, InterpreterResult as Result};
use vm::representations::SymbolicExpression;
use vm::{eval, Context, Environment};
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
    list_dimensions: Option<(u8, u8)>,
    // NOTE: for the purposes of type-checks and cost computations, list size = dimension * max_length!
    //       high dimensional lists are _expensive_ --- use lists of tuples!
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
    Buffer(Vec<u8>),
    List(Vec<Value>, TypeSignature),
    Tuple(TupleData)
}

pub enum CallableType <'a> {
    UserFunction(DefinedFunction),
    NativeFunction(&'a Fn(&[Value]) -> Result<Value>),
    SpecialFunction(&'a Fn(&[SymbolicExpression], &mut Environment, &Context) -> Result<Value>)
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

impl Value {
    pub fn new_list(list_data: Vec<Value>) -> Result<Value> {
        let type_sig = TypeSignature::construct_parent_list_type(&list_data)?;
        Ok(Value::List(list_data, type_sig))
    }
}

impl TupleTypeSignature {
    pub fn new(type_data: Vec<(String, TypeSignature)>) -> Result<TupleTypeSignature> {
        let mut type_map = BTreeMap::new();
        for (name, type_info) in type_data {
            if let Some(_v) = type_map.insert(name, type_info) {
                return Err(Error::InvalidArguments("Cannot use named argument twice in tuple construction.".to_string()))
            }
        }
        Ok(TupleTypeSignature { type_map: type_map })
    }

    pub fn admits(&self, other: &TupleTypeSignature) -> bool {
        if self.type_map.len() != other.type_map.len() {
            return false
        }

        for (name, my_type_sig) in self.type_map.iter() {
            if let Some(other_type_sig) = other.type_map.get(name) {
                if !my_type_sig.admits_type(other_type_sig) {
                    return false
                }
            } else {
                return false
            }
        }

        return true
    }
}

impl TupleData {
    pub fn from_data(data: &[(&str, Value)]) -> Result<TupleData> {
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

    pub fn get(&self, name: &str) -> Result<Value> {
        if let Some(value) = self.data_map.get(name) {
            Ok(value.clone())
        } else {
            Err(Error::InvalidArguments(format!("No such field {:?} in tuple", name)))
        }
        
    }
}

impl TypeSignature {
    pub fn new_atom(atomic_type: AtomTypeIdentifier) -> TypeSignature {
        TypeSignature { atomic_type: atomic_type,
                        list_dimensions: None }
    }

    pub fn new_list(atomic_type: AtomTypeIdentifier, max_len: u8, dimension: u8) -> Result<TypeSignature> {
        if dimension == 0 {
            return Err(Error::InvalidArguments("Cannot construct list of dimension 0".to_string()))
        } else {
            Ok(TypeSignature { atomic_type: atomic_type,
                               list_dimensions: Some((max_len, dimension)) })
        }
    }

    pub fn get_empty_list_type() -> TypeSignature {
        TypeSignature { atomic_type: AtomTypeIdentifier::IntType,
                        list_dimensions: Some((0, 1)) }
    }

    pub fn type_of(x: &Value) -> TypeSignature {
        match x {
            Value::Void => TypeSignature::new_atom(AtomTypeIdentifier::VoidType),
            Value::Int(_v) => TypeSignature::new_atom(AtomTypeIdentifier::IntType),
            Value::Bool(_v) => TypeSignature::new_atom(AtomTypeIdentifier::BoolType),
            Value::Buffer(_v) => TypeSignature::new_atom(AtomTypeIdentifier::BufferType),
            Value::List(_v, type_signature) => type_signature.clone(),
            Value::Tuple(v) => TypeSignature::new_atom(AtomTypeIdentifier::TupleType(
                v.type_signature.clone()))
        }
    }

    pub fn construct_parent_list_type(args: &[Value]) -> Result<TypeSignature> {
        if let Some((first, rest)) = args.split_first() {
            // children must be all of identical types, though we're a little more permissive about
            //   children which are _lists_: we don't care about their max_len, we just take the max()
            let first_type = TypeSignature::type_of(first);
            let (mut max_len, dimension) = match first_type.list_dimensions {
                Some((max_len, dimension)) => {
                    let parent_dimension = dimension.checked_add(1)
                        .ok_or(Error::ListDimensionTooHigh)?;
                    Ok((max_len, parent_dimension))
                },
                None => {
                    Ok((args.len() as u8, 1))
                }
            }?;

            for x in rest {
                let x_type = TypeSignature::type_of(x);
                if let Some((child_max_len, child_dimension)) = x_type.list_dimensions {
                    // we're making a higher order list, so check the type more loosely.
                    let expected_dimension = child_dimension.checked_add(1)
                        .ok_or(Error::ListDimensionTooHigh)?;

                    if !(x_type.atomic_type == first_type.atomic_type &&
                         dimension == expected_dimension) {
                        return Err(Error::InvalidArguments(
                            format!("List must be composed of a single type. Expected {:?}. Found {:?}.",
                                    first_type, x_type)))
                    } else {
                        // otherwise, it matches, so make sure we expand max_len to fit the child list.
                        if child_max_len > max_len {
                            max_len = child_max_len;
                        }
                    }
                } else if x_type != first_type {
                    return Err(Error::InvalidArguments(
                        format!("List must be composed of a single type. Expected {:?}. Found {:?}.",
                                first_type, x_type)))
                }
            }

            Ok(TypeSignature { atomic_type: first_type.atomic_type,
                               list_dimensions: Some((max_len, dimension)) })
        } else {
            Ok(TypeSignature::get_empty_list_type())
        }
    }

    pub fn admits(&self, x: &Value) -> bool {
        let x_type = TypeSignature::type_of(x);
        self.admits_type(&x_type)
    }

    pub fn admits_type(&self, x_type: &TypeSignature) -> bool {
        if let Some((x_max_len, x_dimension)) = x_type.list_dimensions {
            if x_type.atomic_type != self.atomic_type {
                false
            } else if let Some((max_len, dimension)) = self.list_dimensions {
                dimension == x_dimension && max_len >= x_max_len
            } else {
                false
            }
        } else if let AtomTypeIdentifier::TupleType(ref x_tuple_sig) = x_type.atomic_type {
            // tuple admission must recurse on .admits
            if let AtomTypeIdentifier::TupleType(ref my_tuple_sig) = self.atomic_type {
                my_tuple_sig.admits(x_tuple_sig)
            } else {
                false
            }
        } else {
            x_type == self
        }
    }

    fn get_atom_type(typename: &str) -> Result<AtomTypeIdentifier> {
        match typename {
            "int" => Ok(AtomTypeIdentifier::IntType),
            "void" => Ok(AtomTypeIdentifier::VoidType),
            "bool" => Ok(AtomTypeIdentifier::BoolType),
            "buff" => Ok(AtomTypeIdentifier::BufferType),
            _ => Err(Error::ParseError(format!("Unknown type name: '{:?}'", typename)))
        }
    }

    fn get_list_type(prefix: &str, typename: &str, dimension: &str, max_len: &str) -> Result<TypeSignature> {
        if prefix != "list" {
            let message = format!("Unknown type name: '{}-{}-{}-{}'", prefix, typename, dimension, max_len);
            return Err(Error::ParseError(message))
        }
        let atom_type = TypeSignature::get_atom_type(typename)?;
        let dimension = match u8::from_str_radix(dimension, 10) {
            Ok(parsed) => Ok(parsed),
            Err(_e) => Err(Error::ParseError(
                format!("Failed to parse dimension of type: '{}-{}-{}-{}'",
                        prefix, typename, dimension, max_len)))
        }?;
        let max_len = match u8::from_str_radix(max_len, 10) {
            Ok(parsed) => Ok(parsed),
            Err(_e) => Err(Error::ParseError(
                format!("Failed to parse max_len of type: '{}-{}-{}-{}'",
                        prefix, typename, dimension, max_len)))
        }?;
        TypeSignature::new_list(atom_type, max_len, dimension)
    }

    // TODO: these type strings are limited to conveying lists of non-tuple types.
    pub fn parse_type_str(x: &str) -> Result<TypeSignature> {
        let components: Vec<_> = x.splitn(4, '-').collect();
        match components.len() {
            1 => {
                let atom_type = TypeSignature::get_atom_type(components[0])?;
                Ok(TypeSignature::new_atom(atom_type))
            },
            4 => TypeSignature::get_list_type(components[0], components[1], components[2], components[3]),
            _ => Err(Error::ParseError(
                format!("Unknown type name: '{}'", x)))
        }
    }
}

impl DefinedFunction {
    pub fn new(body: SymbolicExpression, arguments: Vec<String>) -> DefinedFunction {
        DefinedFunction {
            body: body,
            arguments: arguments,
        }
    }

    pub fn apply(&self, args: &[Value], env: &mut Environment) -> Result<Value> {
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
