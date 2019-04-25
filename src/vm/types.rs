use std::hash::{Hash, Hasher};
use std::fmt;
use std::collections::BTreeMap;

use address::c32;
use vm::representations::{SymbolicExpression, SymbolicExpressionType};
use vm::errors::{Error, ErrType, InterpreterResult as Result, IncomparableError};
use util::hash;

const MAX_VALUE_SIZE: i128 = 1024 * 1024; // 1MB

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TupleTypeSignature {
    type_map: BTreeMap<String, TypeSignature>
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AtomTypeIdentifier {
    AnyType,
    NoType,
    VoidType,
    IntType,
    BoolType,
    BufferType(u32),
    PrincipalType,
    TupleType(TupleTypeSignature)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ListTypeData {
    max_len: u32,
    dimension: u8
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeSignature {
    atomic_type: AtomTypeIdentifier,
    list_dimensions: Option<ListTypeData>,
    // NOTE: for the purposes of type-checks and cost computations, list size = dimension * max_length!
    //       high dimensional lists are _expensive_ --- use lists of tuples!
}

#[derive(Debug, Clone, Eq, Serialize, Deserialize)]
pub struct TupleData {
    type_signature: TupleTypeSignature,
    data_map: BTreeMap<String, Value>
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BuffData {
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Eq, Serialize, Deserialize)]
pub struct ListData {
    pub data: Vec<Value>,
    type_signature: TypeSignature
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum PrincipalData {
    StandardPrincipal(u8, [u8; 20]),  // a standard principal is a version byte + hash160 (20 bytes)
    ContractPrincipal(String)
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum Value {
    Void,
    Int(i128),
    Bool(bool),
    Buffer(BuffData),
    List(ListData),
    Principal(PrincipalData),
    Tuple(TupleData)
}

impl PartialEq for ListData {
    fn eq(&self, other: &ListData) -> bool {
        self.data == other.data
    }
}

impl Hash for ListData {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.data.hash(state);
    }
}

impl PartialEq for TupleData {
    fn eq(&self, other: &TupleData) -> bool {
        self.data_map == other.data_map
    }
}

impl Hash for TupleData {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.data_map.hash(state);
    }
}

impl Value {
    pub fn deserialize(json: &str) -> Result<Value> {
        serde_json::from_str(json)
            .map_err(|x| Error::new(ErrType::DeserializationFailure(
                IncomparableError { err: x } )))
    }

    pub fn serialize(&self) -> Result<String> {
        serde_json::to_string(self)
            .map_err(|x| Error::new(ErrType::SerializationFailure(
                IncomparableError { err: x } )))
    }

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
        if type_sig.size()? > MAX_VALUE_SIZE {
            return Err(Error::new(ErrType::ValueTooLarge))
        }
        Ok(Value::List(ListData { data: list_data, type_signature: type_sig }))
    }

    pub fn buff_from(buff_data: Vec<u8>) -> Result<Value> {
        if buff_data.len() > u32::max_value() as usize {
            Err(Error::new(ErrType::BufferTooLarge))
        } else if buff_data.len() as i128 > MAX_VALUE_SIZE {
            Err(Error::new(ErrType::ValueTooLarge))
        } else {
            Ok(Value::Buffer(BuffData { data: buff_data }))
        }
    }

    pub fn tuple_from_data(paired_tuple_data: Vec<(String, Value)>) -> Result<Value> {
        let tuple_data = TupleData::from_data(paired_tuple_data)?;
        if tuple_data.size()? > MAX_VALUE_SIZE {
            return Err(Error::new(ErrType::ValueTooLarge))
        }
        Ok(Value::Tuple(tuple_data))
    }

    pub fn size(&self) -> Result<i128> {
        match self {
            Value::Void => AtomTypeIdentifier::VoidType.size(),
            Value::Int(_i) => AtomTypeIdentifier::IntType.size(),
            Value::Bool(_i) => AtomTypeIdentifier::BoolType.size(),
            Value::Principal(_) => AtomTypeIdentifier::PrincipalType.size(),
            Value::Buffer(ref buff_data) => Ok(buff_data.data.len() as i128),
            Value::Tuple(ref tuple_data) => tuple_data.size(),
            Value::List(ref list_data) => list_data.type_signature.size()
        }
    }

}

impl fmt::Display for AtomTypeIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::AtomTypeIdentifier::*;
        match self {
            AnyType => write!(f, "AnyType"),
            NoType => write!(f, "NoType"),
            VoidType => write!(f, "void"),
            IntType => write!(f, "int"),
            BoolType => write!(f, "bool"),
            PrincipalType => write!(f, "principal"),
            BufferType(len) => write!(f, "(buff {})", len),
            TupleType(TupleTypeSignature{ type_map }) => {
                write!(f, "(tuple (")?;
                for (key_name, value_type) in type_map.iter() {
                    write!(f, "({} {})", key_name, value_type)?;
                }
                write!(f, "))")
            }
        }
    }
}

impl fmt::Display for TypeSignature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {        
        if let Some(ref list_type_data) = self.list_dimensions {
            write!(f, "(list {}", list_type_data.max_len)?;
            if list_type_data.dimension > 1 {
                write!(f, "{}", list_type_data.dimension)?;
            }
            write!(f, "{})", self.atomic_type)
        } else {
            write!(f, "{}", self.atomic_type)
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
            Value::Principal(principal_data) => {
                write!(f, "'{}", principal_data)
            },
            Value::List(list_data) => {
                write!(f, "( ")?;
                for v in list_data.data.iter() {
                    write!(f, "{} ", v)?;
                }
                write!(f, ")")
            }
        }
    }
}

impl fmt::Display for PrincipalData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PrincipalData::StandardPrincipal(version, vec_bytes) => {
                let c32_str = match c32::c32_address(*version, &vec_bytes[..]) {
                    Ok(val) => val,
                    Err(_) => "INVALID_C32_ADDR".to_string()
                };
                write!(f, "'{}", c32_str)                
            },
            PrincipalData::ContractPrincipal(contract_name) => {
                write!(f, "'C{}", contract_name)
            }
        }
    }
}

impl AtomTypeIdentifier {
    pub fn size(&self) -> Result<i128> {
        match self {
            // AnyType/NoType should _never_ be asked for size. It is only ever used
            //   in type checking native functions.
            AtomTypeIdentifier::AnyType => Err(Error::new(ErrType::BadTypeConstruction)),
            AtomTypeIdentifier::NoType => Err(Error::new(ErrType::BadTypeConstruction)),
            AtomTypeIdentifier::VoidType => Ok(1),
            AtomTypeIdentifier::IntType => Ok(16),
            AtomTypeIdentifier::BoolType => Ok(1),
            AtomTypeIdentifier::PrincipalType => Ok(21),
            AtomTypeIdentifier::BufferType(len) => Ok(*len as i128),
            AtomTypeIdentifier::TupleType(tuple_sig) => tuple_sig.size()
        }
    }

    fn expand_to_admit(&mut self, other: &AtomTypeIdentifier) -> Result<()> {
        match self {
            AtomTypeIdentifier::BufferType(ref mut my_len) => {
                if let AtomTypeIdentifier::BufferType(ref other_len) = other {
                    if other_len > my_len {
                        *my_len = *other_len
                    }
                    Ok(())
                } else {
                    Err(Error::new(ErrType::BadTypeConstruction))
                }
            },
            AtomTypeIdentifier::TupleType(ref mut tuple_sig) => {
                if let AtomTypeIdentifier::TupleType(ref other_tuple_sig) = other {
                    tuple_sig.expand_to_admit(other_tuple_sig)
                } else {
                    Err(Error::new(ErrType::BadTypeConstruction))
                }
            },
            _ => {
                if other == self {
                    Ok(())
                } else {
                    Err(Error::new(ErrType::BadTypeConstruction))
                }
            }
        }
    }

    fn admits(&self, other: &AtomTypeIdentifier) -> bool {
        match self {
            AtomTypeIdentifier::AnyType => {
                true
            },
            AtomTypeIdentifier::NoType => {
                false
            },
            AtomTypeIdentifier::BufferType(ref my_len) => {
                if let AtomTypeIdentifier::BufferType(ref other_len) = other {
                    my_len >= other_len
                } else {
                    false
                }
            },
            AtomTypeIdentifier::TupleType(ref tuple_sig) => {
                if let AtomTypeIdentifier::TupleType(ref other_tuple_sig) = other {
                    tuple_sig.admits(other_tuple_sig)
                } else {
                    false
                }
            },
            _ => other == self
        }
    }
}


impl TupleTypeSignature {
    pub fn new(type_data: Vec<(String, TypeSignature)>) -> Result<TupleTypeSignature> {
        let mut type_map = BTreeMap::new();
        for (name, type_info) in type_data {
            if let Some(_v) = type_map.insert(name, type_info) {
                return Err(Error::new(ErrType::InvalidArguments("Cannot use named argument twice in tuple construction.".to_string())))
            }
        }
        Ok(TupleTypeSignature { type_map: type_map })
    }

    pub fn field_type(&self, field: &str) -> Option<&TypeSignature> {
        self.type_map.get(field)
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

    pub fn size(&self) -> Result<i128> {
        let mut name_size: i128 = 0;
        let mut value_size: i128 = 0;
        for (name, type_signature) in self.type_map.iter() {
            // we only accept ascii names, so 1 char = 1 byte.
            name_size = name_size.checked_add(name.len() as i128)
                .ok_or(Error::new(ErrType::ValueTooLarge))?;
            value_size = value_size.checked_add(type_signature.size()? as i128)
                .ok_or(Error::new(ErrType::ValueTooLarge))?;
        }
        let name_total_size = name_size.checked_mul(2)
            .ok_or(Error::new(ErrType::ValueTooLarge))?;
        value_size.checked_add(name_total_size)
            .ok_or(Error::new(ErrType::ValueTooLarge))
    }

    // NOTE: this function mutates self _even if it returns an error_.
    fn expand_to_admit(&mut self, other: &TupleTypeSignature) -> Result<()> {
        if self.type_map.len() != other.type_map.len() {
            return Err(Error::new(ErrType::BadTypeConstruction))
        }

        for (name, my_type_sig) in self.type_map.iter_mut() {
            let other_type_sig = other.type_map.get(name).ok_or(Error::new(ErrType::BadTypeConstruction))?;
            my_type_sig.expand_to_admit(other_type_sig)?;
        }

        Ok(())
    }

    pub fn parse_name_type_pair_list(type_def: &SymbolicExpression) -> Result<TupleTypeSignature> {
        if let SymbolicExpressionType::List(ref name_type_pairs) = type_def.expr {
            let mapped_key_types = parse_name_type_pairs(name_type_pairs)?;
            TupleTypeSignature::new(mapped_key_types)
        } else {
            Err(Error::new(ErrType::ExpectedListPairs))
        }
    }
}

impl TupleData {
    fn from_data(mut data: Vec<(String, Value)>) -> Result<TupleData> {
        let mut type_map = BTreeMap::new();
        let mut data_map = BTreeMap::new();
        for (name, value) in data.drain(..) {
            let type_info = TypeSignature::type_of(&value);
            if type_info.atomic_type == AtomTypeIdentifier::VoidType {
                return Err(Error::new(ErrType::InvalidArguments("Cannot use VoidTypes in tuples.".to_string())))
            }
            if let Some(_v) = type_map.insert(name.to_string(), type_info) {
                return Err(Error::new(ErrType::InvalidArguments("Cannot use named argument twice in tuple construction.".to_string())))
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
            Err(Error::new(ErrType::InvalidArguments(format!("No such field {:?} in tuple", name))))
        }
        
    }

    pub fn size(&self) -> Result<i128> {
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

    pub fn new_list(atomic_type: AtomTypeIdentifier, max_len: i128, dimension: i128) -> Result<TypeSignature> {
        if dimension == 0 {
            Err(Error::new(ErrType::InvalidTypeDescription))
        } else if max_len > u32::max_value() as i128 || dimension > u8::max_value() as i128 {
            Err(Error::new(ErrType::ListTooLarge))
        } else {
            let list_dimensions = Some(ListTypeData { max_len: max_len as u32,
                                                      dimension: dimension as u8 });
            let type_sig = TypeSignature { atomic_type: atomic_type,
                                           list_dimensions: list_dimensions };
            if type_sig.size()? > MAX_VALUE_SIZE {
                Err(Error::new(ErrType::ValueTooLarge))
            } else {
                Ok(type_sig)
            }
        }
    }

    pub fn list_max_len(&self) -> Option<u32> {
        if let Some(ListTypeData{ max_len, dimension: _ }) = self.list_dimensions {
            Some(max_len.clone())
        } else {
            None
        }
    }

    pub fn list_of(item_type: TypeSignature, max_len: u32) -> Result<TypeSignature> {
        let next_dimensions = {
            if let Some(ListTypeData{ max_len: item_max_len, dimension: item_dim }) = item_type.list_dimensions {
                let dimension = item_dim.checked_add(1)
                    .ok_or(Error::new(ErrType::ListTooLarge))?;
                let max_len = {
                    if item_max_len > max_len {
                        item_max_len
                    } else {
                        max_len
                    }
                };
                ListTypeData { max_len: max_len, dimension: dimension }
            } else {
                ListTypeData { max_len: max_len, dimension: 1 }
            }
        };

        Ok(TypeSignature { atomic_type: item_type.atomic_type,
                           list_dimensions: Some(next_dimensions) })
    }

    pub fn deserialize(json: &str) -> Result<TypeSignature> {
        serde_json::from_str(json)
            .map_err(|x| Error::new(ErrType::DeserializationFailure(
                IncomparableError { err: x } )))
    }

    pub fn serialize(&self) -> Result<String> {
        serde_json::to_string(self)
            .map_err(|x| Error::new(ErrType::SerializationFailure(
                IncomparableError { err: x } )))
    }

    fn new_atom_checked(atom_type: AtomTypeIdentifier) -> Result<TypeSignature> {
        if atom_type.size()? > MAX_VALUE_SIZE {
            Err(Error::new(ErrType::ValueTooLarge))
        } else {
            Ok(TypeSignature::new_atom(atom_type))
        }
    }

    pub fn new_tuple(tuple_type_sig: TupleTypeSignature) -> Result<TypeSignature> {
        TypeSignature::new_atom_checked(AtomTypeIdentifier::TupleType(tuple_type_sig))
    }

    fn new_buffer(buff_len: i128) -> Result<TypeSignature> {
        if buff_len > u32::max_value() as i128 {
            Err(Error::new(ErrType::BufferTooLarge))
        } else {
            let atom_type = AtomTypeIdentifier::BufferType(buff_len as u32);
            TypeSignature::new_atom_checked(atom_type)
        }
    }

    pub fn get_empty_list_type() -> TypeSignature {
        // TODO: empty list type should be typed/handled differently.
        //         any list type should _admit_
        //         an empty list type
        TypeSignature { atomic_type: AtomTypeIdentifier::IntType,
                        list_dimensions: Some(ListTypeData { max_len: 0,
                                                             dimension: 1 })}
    }

    pub fn size(&self) -> Result<i128> {
        let list_multiplier = match self.list_dimensions {
                Some(ref list_data) => (list_data.max_len as i128).checked_mul(list_data.dimension as i128)
                .ok_or(Error::new(ErrType::ValueTooLarge)),
                None => Ok(1)
        }?;
        list_multiplier.checked_mul(self.atomic_type.size()?)
            .ok_or(Error::new(ErrType::ValueTooLarge))
    }

    pub fn type_of(x: &Value) -> TypeSignature {
        if let Value::List(list_data) = x {
            list_data.type_signature.clone()
        } else {
            let atom = match x {
                Value::Void => AtomTypeIdentifier::VoidType,
                Value::Principal(_) => AtomTypeIdentifier::PrincipalType,
                Value::Int(_v) => AtomTypeIdentifier::IntType,
                Value::Bool(_v) => AtomTypeIdentifier::BoolType,
                Value::Buffer(buff_data) => AtomTypeIdentifier::BufferType(buff_data.data.len() as u32),
                Value::Tuple(v) => AtomTypeIdentifier::TupleType(
                    v.type_signature.clone()),
                Value::List(_) => panic!("Unreachable code")
            };

            TypeSignature::new_atom(atom)
        }
    }

    fn expand_to_admit(&mut self, x_type: &TypeSignature) -> Result<()> {
        if let Some(ref mut my_list_dimensions) = self.list_dimensions {
            if let Some(ref x_list_dimensions) = x_type.list_dimensions {
                if my_list_dimensions.dimension != x_list_dimensions.dimension {
                    return Err(Error::new(ErrType::BadTypeConstruction))
                }
                if my_list_dimensions.max_len < x_list_dimensions.max_len {
                    my_list_dimensions.max_len = x_list_dimensions.max_len;
                }
            } else {
                return Err(Error::new(ErrType::BadTypeConstruction))
            }
        } else {
            if let Some(_) = x_type.list_dimensions {
                return Err(Error::new(ErrType::BadTypeConstruction))
            }
        }

        self.atomic_type.expand_to_admit(& x_type.atomic_type)
    }

    // Checks if resulting type signature is of valid size.
    // Aaron:
    //    currently, this does "loose admission" for higher-order lists --
    //     but should it do the same for buffers and tuples or is it better
    //     like it is now, where it requires an exact type match on those?
    //     e.g.: (list "abcd" "abc") will currently error because one etry is
    //           if type (buffer 4) and the other is of type (buffer 3)
    //       my feeling is that this should probably be allowed, and the resulting
    //       type should be (list 2 (buffer 4)) 
    fn construct_parent_list_type(args: &[Value]) -> Result<TypeSignature> {
        let children_types:Vec<_> = args.iter().map(|x| TypeSignature::type_of(x)).collect();
        TypeSignature::parent_list_type(&children_types)
    }

    pub fn parent_list_type(children: &[TypeSignature]) -> Result<TypeSignature> {
        if let Some((first, rest)) = children.split_first() {
            // children must be all of identical types, though we're a little more permissive about
            //   children which are _lists_: we don't care about their max_len, we just take the max()
            let mut child_type = first.clone();
            for cur_child_type in rest {
                child_type.expand_to_admit(&cur_child_type)?;
            }

            let mut parent_max_len = {
                let args_len = children.len();
                if args_len > (u32::max_value() as usize) {
                    Err(Error::new(ErrType::ListTooLarge))
                } else {
                    Ok(args_len as u32)
                }
            }?;

            let parent_dimension = match child_type.list_dimensions {
                Some(ref type_data) => {
                    if type_data.max_len > parent_max_len {
                        parent_max_len = type_data.max_len
                    }
                    type_data.dimension.checked_add(1)
                        .ok_or(Error::new(ErrType::ListDimensionTooHigh))
                },
                None => {
                    Ok(1)
                }
            }?;

            TypeSignature::new_list(child_type.atomic_type,
                                    parent_max_len as i128, parent_dimension as i128)
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
            if let Some(ref my_type_data) = self.list_dimensions {
                if my_type_data.dimension == x_type_data.dimension && my_type_data.max_len >= x_type_data.max_len {
                    self.atomic_type.admits(&x_type.atomic_type)
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            self.atomic_type.admits(&x_type.atomic_type)
        }
    }

    // Returns Some(AtomTypeIdentifier) in the case that this type
    //   is an atomic type.
    //  If this type is a _list_, however, return None
    pub fn match_atomic(&self) -> Option<&AtomTypeIdentifier> {
        if self.list_dimensions.is_some() {
            return None
        }
        Some(&self.atomic_type)
    }

    pub fn get_list_item_type(&self) -> Option<TypeSignature> {
        if let Some(ref my_dimensions) = self.list_dimensions {
            if my_dimensions.dimension == 0 {
                None // should never occur, but this case will handle it gracefully anyways...
            } else if my_dimensions.dimension == 1 {
                Some(TypeSignature::new_atom(self.atomic_type.clone()))
            } else {
                let list_dimensions = Some(ListTypeData { max_len: my_dimensions.max_len.clone(),
                                                          dimension: my_dimensions.dimension - 1 });
                Some(TypeSignature { atomic_type: self.atomic_type.clone(),
                                     list_dimensions: list_dimensions })
            }
        } else {
            None
        }
    }

    fn parse_atom_type(typename: &str) -> Result<AtomTypeIdentifier> {
        match typename {
            "int" => Ok(AtomTypeIdentifier::IntType),
            "void" => Ok(AtomTypeIdentifier::VoidType),
            "bool" => Ok(AtomTypeIdentifier::BoolType),
            "principal" => Ok(AtomTypeIdentifier::PrincipalType),
            _ => Err(Error::new(ErrType::ParseError(format!("Unknown type name: '{:?}'", typename))))
        }
    }

    // Parses list type signatures ->
    // (list maximum-length dimension atomic-type) or
    // (list maximum-length atomic-type) -> denotes list of dimension 1
    fn parse_list_type_repr(type_args: &[SymbolicExpression]) -> Result<TypeSignature> {
        if type_args.len() != 2 && type_args.len() != 3 {
            return Err(Error::new(ErrType::InvalidTypeDescription));
        }
        let dimension = {
            if type_args.len() == 2 {
                Ok(1)
            } else {
                if let SymbolicExpressionType::AtomValue(Value::Int(dimension)) = &type_args[1].expr {
                    Ok(*dimension)
                } else {
                    Err(Error::new(ErrType::InvalidTypeDescription))
                }
            }
        }?;

        if let SymbolicExpressionType::AtomValue(Value::Int(max_len)) = &type_args[0].expr {            
            let atomic_type_arg = &type_args[type_args.len()-1];
            let atomic_type = TypeSignature::parse_type_repr(atomic_type_arg, false)?;
            TypeSignature::new_list(atomic_type.atomic_type, *max_len, dimension)
        } else {
            Err(Error::new(ErrType::InvalidTypeDescription))
        }
    }

    // Parses type signatures of the following form:
    // (tuple ((key-name-0 value-type-0) (key-name-1 value-type-1)))
    fn parse_tuple_type_repr(type_args: &[SymbolicExpression]) -> Result<TypeSignature> {
        if type_args.len() != 1 {
            return Err(Error::new(ErrType::InvalidTypeDescription))
        }
        let tuple_type_signature = TupleTypeSignature::parse_name_type_pair_list(&type_args[0])?;
        TypeSignature::new_tuple(tuple_type_signature)
    }

    // Parses type signatures of the form:
    // (buff 10)
    fn parse_buff_type_repr(type_args: &[SymbolicExpression]) -> Result<TypeSignature> {
        if type_args.len() != 1 {
            return Err(Error::new(ErrType::InvalidTypeDescription))
        }
        if let SymbolicExpressionType::AtomValue(Value::Int(buff_len)) = &type_args[0].expr {
            TypeSignature::new_buffer(*buff_len)
        } else {
            Err(Error::new(ErrType::InvalidTypeDescription))
        }
    }

    fn parse_type_repr(x: &SymbolicExpression, allow_list: bool) -> Result<TypeSignature> {
        match x.expr {
            SymbolicExpressionType::Atom(ref atom_type_str) => {
                let atomic_type = TypeSignature::parse_atom_type(atom_type_str)?;
                Ok(TypeSignature::new_atom(atomic_type))
            },
            SymbolicExpressionType::List(ref list_contents) => {
                let (compound_type, rest) = list_contents.split_first()
                    .ok_or(Error::new(ErrType::InvalidTypeDescription))?;
                if let SymbolicExpressionType::Atom(ref compound_type) = compound_type.expr {
                    match compound_type.as_str() {
                        "list" =>
                            if !allow_list {
                                Err(Error::new(ErrType::InvalidTypeDescription))
                            } else {
                                TypeSignature::parse_list_type_repr(rest)
                            },
                        "buff" => TypeSignature::parse_buff_type_repr(rest),
                        "tuple" => TypeSignature::parse_tuple_type_repr(rest),
                        _ => Err(Error::new(ErrType::InvalidTypeDescription))
                    }
                } else {
                    Err(Error::new(ErrType::InvalidTypeDescription))
                }
            },
            _ => Err(Error::new(ErrType::InvalidTypeDescription))
        }
    }
}


pub fn parse_name_type_pairs(name_type_pairs: &[SymbolicExpression]) -> Result<Vec<(String, TypeSignature)>> {
    // this is a pretty deep nesting here, but what we're trying to do is pick out the values of
    // the form:
    // ((name1 type1) (name2 type2) (name3 type3) ...)
    // which is a list of 2-length lists of atoms.
    use vm::representations::SymbolicExpressionType::{List, Atom};

    // step 1: parse it into a vec of symbolicexpression pairs.
    let as_pairs: Result<Vec<_>> = 
        name_type_pairs.iter().map(
            |key_type_pair| {
                if let List(ref as_vec) = key_type_pair.expr {
                    if as_vec.len() != 2 {
                        Err(Error::new(ErrType::ExpectedListPairs))
                    } else {
                        Ok((&as_vec[0], &as_vec[1]))
                    }
                } else {
                    Err(Error::new(ErrType::ExpectedListPairs))
                }
            }).collect();

    // step 2: turn into a vec of (name, typesignature) pairs.
    let key_types: Result<Vec<_>> =
        (as_pairs?).iter().map(|(name_symbol, type_symbol)| {
            let name = match name_symbol.expr {
                Atom(ref var) => Ok(var.clone()),
                _ => Err(Error::new(ErrType::ExpectedListPairs))
            }?;
            let type_info = TypeSignature::parse_type_repr(type_symbol, true)?;
            Ok((name, type_info))
        }).collect();
    
    key_types
}
