use std::fmt;
use std::collections::BTreeMap;

use vm::errors::{Error, InterpreterResult as Result};
use util::hash;

const MAX_VALUE_SIZE: i128 = 1024 * 1024; // 1MB

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TupleTypeSignature {
    type_map: BTreeMap<String, TypeSignature>
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AtomTypeIdentifier {
    VoidType,
    IntType,
    BoolType,
    BufferType(u32),
    TupleType(TupleTypeSignature)
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ListTypeData {
    max_len: u32,
    dimension: u8
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TypeSignature {
    atomic_type: AtomTypeIdentifier,
    list_dimensions: Option<ListTypeData>,
    // NOTE: for the purposes of type-checks and cost computations, list size = dimension * max_length!
    //       high dimensional lists are _expensive_ --- use lists of tuples!
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TupleData {
    type_signature: TupleTypeSignature,
    data_map: BTreeMap<String, Value>
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BuffData {
    data: Vec<u8>,
    length: u32
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Value {
    Void,
    Int(i128),
    Bool(bool),
    Buffer(BuffData),
    List(Vec<Value>, TypeSignature),
    Tuple(TupleData)
}

impl Value {
    pub fn new_list(list_data: &[Value]) -> Result<Value> {
        let vec_data = Vec::from(list_data);
        Value::list_from(vec_data)
    }

    pub fn list_from(list_data: Vec<Value>) -> Result<Value> {
        let type_sig = TypeSignature::construct_parent_list_type(&list_data)?;
        // Aaron: at this point, we've _already_ allocated memory for this type.
        //     (e.g., from a (map...) call, or a (list...) call.
        //     this is a problem _if_ the static analyzer cannot already prevent
        //     this case. This applies to all the constructor size checks.
        if type_sig.size() > MAX_VALUE_SIZE {
            return Err(Error::ValueTooLarge)
        }
        Ok(Value::List(list_data, type_sig))
    }

    pub fn buff_from(buff_data: Vec<u8>) -> Result<Value> {
        if buff_data.len() > u32::max_value() as usize {
            Err(Error::BufferTooLarge)
        } else if buff_data.len() as i128 > MAX_VALUE_SIZE {
            Err(Error::ValueTooLarge)
        } else {
            let length = buff_data.len() as u32;
            Ok(Value::Buffer(BuffData { data: buff_data,
                                        length: length }))
        }
    }

    pub fn tuple_from_data(paired_tuple_data: Vec<(String, Value)>) -> Result<Value> {
        let tuple_data = TupleData::from_data(paired_tuple_data)?;
        if tuple_data.size() > MAX_VALUE_SIZE {
            return Err(Error::ValueTooLarge)
        }
        Ok(Value::Tuple(tuple_data))
    }

    pub fn size(&self) -> i128 {
        match self {
            Value::Void => 1,
            Value::Int(_i) => 16,
            Value::Bool(_i) => 1,
            Value::Buffer(ref buff_data) => buff_data.length as i128,
            Value::Tuple(ref tuple_data) => tuple_data.size(),
            Value::List(ref _v, ref type_signature) => type_signature.size()
        }
    }

}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Value::Void => write!(f, "null"),
            Value::Int(int) => write!(f, "{}", int),
            Value::Bool(boolean) => write!(f, "{}", boolean),
            Value::Buffer(vec_bytes) => write!(f, "0x{}", hash::to_hex(&vec_bytes.data)),
            Value::Tuple(data) => write!(f, "{}", data),
            Value::List(values, _type) => {
                write!(f, "( ")?;
                for v in values.iter() {
                    write!(f, "{} ", v)?;
                }
                write!(f, ")")
            }
        }
    }
}

impl AtomTypeIdentifier {
    pub fn size(&self) -> i128 {
        match self {
            AtomTypeIdentifier::VoidType => 1,
            AtomTypeIdentifier::IntType => 16,
            AtomTypeIdentifier::BoolType => 1,
            AtomTypeIdentifier::BufferType(len) => *len as i128,
            AtomTypeIdentifier::TupleType(tuple_sig) => tuple_sig.size()
        }
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

    pub fn size(&self) -> i128 {
        let mut name_size: i128 = 0;
        let mut value_size: i128 = 0;
        for (name, type_signature) in self.type_map.iter() {
            // we only accept ascii names, so 1 char = 1 byte.
            name_size = name_size.checked_add(name.len() as i128).unwrap();
            value_size = value_size.checked_add(type_signature.size() as i128).unwrap();
        }
        let name_total_size = name_size.checked_mul(2).unwrap(); // counts the b-tree size...
        value_size.checked_add(name_total_size).unwrap()
    }
}

impl TupleData {
    fn from_data(mut data: Vec<(String, Value)>) -> Result<TupleData> {
        let mut type_map = BTreeMap::new();
        let mut data_map = BTreeMap::new();
        for (name, value) in data.drain(..) {
            let type_info = TypeSignature::type_of(&value);
            if type_info.atomic_type == AtomTypeIdentifier::VoidType {
                return Err(Error::InvalidArguments("Cannot use VoidTypes in tuples.".to_string()))
            }
            if let Some(_v) = type_map.insert(name.to_string(), type_info) {
                return Err(Error::InvalidArguments("Cannot use named argument twice in tuple construction.".to_string()))
            }
            data_map.insert(name.to_string(), value);
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

    pub fn size(&self) -> i128 {
        self.type_signature.size()
    }
}

impl fmt::Display for TupleData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut first = true;
        write!(f, "(")?;
        for (name, value) in self.data_map.iter() {
            if !first {
                write!(f, ", ")?;
            }
            first = false;
            write!(f, "{}: {}", name, value)?;
        }
        write!(f, ")")
    }
}

impl TypeSignature {
    pub fn new_atom(atomic_type: AtomTypeIdentifier) -> TypeSignature {
        TypeSignature { atomic_type: atomic_type,
                        list_dimensions: None }
    }

    pub fn new_list(atomic_type: AtomTypeIdentifier, max_len: u32, dimension: u8) -> Result<TypeSignature> {
        if dimension == 0 {
            return Err(Error::InvalidArguments("Cannot construct list of dimension 0".to_string()))
        } else {
            Ok(TypeSignature { atomic_type: atomic_type,
                               list_dimensions: Some(ListTypeData { max_len: max_len,
                                                                    dimension: dimension })})
        }
    }

    pub fn get_empty_list_type() -> TypeSignature {
        TypeSignature { atomic_type: AtomTypeIdentifier::IntType,
                        list_dimensions: Some(ListTypeData { max_len: 0,
                                                             dimension: 1 })}
    }

    pub fn size(&self) -> i128 {
        let list_multiplier = match self.list_dimensions {
                Some(ref list_data) => (list_data.max_len as i128).checked_mul(list_data.dimension as i128).unwrap(),
                None => 1
        };
        list_multiplier.checked_mul(self.atomic_type.size()).unwrap()
    }

    pub fn type_of(x: &Value) -> TypeSignature {
        match x {
            Value::Void => TypeSignature::new_atom(AtomTypeIdentifier::VoidType),
            Value::Int(_v) => TypeSignature::new_atom(AtomTypeIdentifier::IntType),
            Value::Bool(_v) => TypeSignature::new_atom(AtomTypeIdentifier::BoolType),
            Value::Buffer(buff_data) => TypeSignature::new_atom(
                AtomTypeIdentifier::BufferType(buff_data.length)),
            Value::List(_v, type_signature) => type_signature.clone(),
            Value::Tuple(v) => TypeSignature::new_atom(AtomTypeIdentifier::TupleType(
                v.type_signature.clone()))
        }
    }

    fn construct_parent_list_type(args: &[Value]) -> Result<TypeSignature> {
        if let Some((first, rest)) = args.split_first() {
            // children must be all of identical types, though we're a little more permissive about
            //   children which are _lists_: we don't care about their max_len, we just take the max()
            let first_type = TypeSignature::type_of(first);
            let (mut parent_max_len, parent_dimension) = match first_type.list_dimensions {
                Some(ref type_data) => {
                    let parent_dimension = type_data.dimension.checked_add(1)
                        .ok_or(Error::ListDimensionTooHigh)?;
                    Ok((type_data.max_len, parent_dimension))
                },
                None => {
                    let max_len = args.len();
                    if max_len > (u32::max_value() as usize) {
                        Err(Error::ListTooLarge)
                    } else {
                        Ok((args.len() as u32, 1))
                    }
                }
            }?;

            for x in rest {
                let x_type = TypeSignature::type_of(x);
                if let Some(ref child_type_data) = x_type.list_dimensions {
                    // we're making a higher order list, so check the type more loosely.
                    let child_dimension = child_type_data.dimension;
                    let child_max_len = child_type_data.max_len;

                    let expected_dimension = child_dimension.checked_add(1)
                        .ok_or(Error::ListDimensionTooHigh)?;

                    if !(x_type.atomic_type == first_type.atomic_type &&
                         parent_dimension == expected_dimension) {
                        return Err(Error::InvalidArguments(
                            format!("List must be composed of a single type. Expected {:?}. Found {:?}.",
                                    first_type, x_type)))
                    } else {
                        // otherwise, it matches, so make sure we expand max_len to fit the child list.
                        if child_max_len > parent_max_len {
                            parent_max_len = child_max_len;
                        }
                    }
                } else if x_type != first_type {
                    return Err(Error::InvalidArguments(
                        format!("List must be composed of a single type. Expected {:?}. Found {:?}.",
                                first_type, x_type)))
                }
            }

            Ok(TypeSignature { atomic_type: first_type.atomic_type,
                               list_dimensions: Some(ListTypeData { max_len: parent_max_len,
                                                                    dimension: parent_dimension })})
        } else {
            Ok(TypeSignature::get_empty_list_type())
        }
    }

    pub fn admits(&self, x: &Value) -> bool {
        let x_type = TypeSignature::type_of(x);
        self.admits_type(&x_type)
    }

    pub fn admits_type(&self, x_type: &TypeSignature) -> bool {
        if let Some(ref x_type_data) = x_type.list_dimensions {
            if x_type.atomic_type != self.atomic_type {
                false
            } else if let Some(ref my_type_data) = self.list_dimensions {
                my_type_data.dimension == x_type_data.dimension &&
                    my_type_data.max_len >= x_type_data.max_len
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
            "buff" => Err(Error::NotImplemented),
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
        let max_len = match u32::from_str_radix(max_len, 10) {
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
