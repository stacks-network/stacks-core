// TypeSignatures
use std::hash::{Hash, Hasher};
use std::{fmt, cmp};
use std::collections::BTreeMap;

use address::c32;
use vm::types::{Value, MAX_VALUE_SIZE};
use vm::representations::{SymbolicExpression, SymbolicExpressionType, ClarityName};
use vm::errors::{RuntimeErrorType, UncheckedError, InterpreterResult as Result, IncomparableError};
use util::hash;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct AssetIdentifier {
    pub contract_name: String,
    pub asset_name: String
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TupleTypeSignature {
    pub type_map: BTreeMap<ClarityName, TypeSignature>
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AtomTypeIdentifier {
    NoType,
    IntType,
    BoolType,
    BufferType(u32),
    PrincipalType,
    TupleType(TupleTypeSignature),
    OptionalType(Box<TypeSignature>),
    ResponseType(Box<(TypeSignature, TypeSignature)>)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListTypeData {
    // NOTE: for the purposes of type-checks and cost computations, list size = dimension * max_length!
    //       high dimensional lists are _expensive_ --- use lists of tuples!
    pub max_len: u32,
    pub dimension: u8,
    pub atomic_type: AtomTypeIdentifier
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FunctionType {
    Variadic(TypeSignature, TypeSignature),
    Fixed(Vec<FunctionArg>, TypeSignature),
    // Functions where the single input is a union type, e.g., Buffer or Int
    UnionArgs(Vec<TypeSignature>, TypeSignature),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TypeSignature {
    Atom(AtomTypeIdentifier),
    List(ListTypeData),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionArg {
    pub signature: TypeSignature,
    #[serde(skip)]
    pub name: String,
}

impl FunctionType {
    pub fn return_type(&self) -> TypeSignature {
        match self {
            FunctionType::Variadic(_, return_type) => return_type.clone(),
            FunctionType::Fixed(_, return_type) => return_type.clone(),
            FunctionType::UnionArgs(_, return_type) => return_type.clone()
        }
    }
}

impl From<AtomTypeIdentifier> for TypeSignature {
    fn from(atom: AtomTypeIdentifier) -> Self {
        TypeSignature::Atom(atom)
    }
}

impl From<ListTypeData> for TypeSignature {
    fn from(data: ListTypeData) -> Self {
        TypeSignature::List(data)
    }
}

impl ListTypeData {
    pub fn get_list_item_type(&self) -> TypeSignature {
        if self.dimension == 0 {
            panic!("Invalid dimension of 0")
        } else if self.dimension == 1 {
            TypeSignature::Atom(self.atomic_type.clone())
        } else {
            let list_type = ListTypeData { 
                atomic_type: self.atomic_type.clone(),
                max_len: self.max_len.clone(),
                dimension: self.dimension - 1 };
            TypeSignature::List(list_type)
        }
    }

    pub fn size(&self) -> Result<i128> {
        if self.max_len <= 0 {
            Ok(32 as i128)
        } else {
            let multiplier = (self.max_len as i128).checked_mul(self.dimension as i128)
                .ok_or(RuntimeErrorType::ValueTooLarge)?;
            multiplier.checked_mul(self.atomic_type.size()?)
                .ok_or(RuntimeErrorType::ValueTooLarge.into())
        }
    }
}

impl AtomTypeIdentifier {
    pub fn size(&self) -> Result<i128> {
        match self {
            // NoType should _never_ be asked for size. It is only ever used
            //   in type checking native functions.
            AtomTypeIdentifier::NoType => Err(RuntimeErrorType::BadTypeConstruction.into()),
            AtomTypeIdentifier::IntType => Ok(16),
            AtomTypeIdentifier::BoolType => Ok(1),
            AtomTypeIdentifier::PrincipalType => Ok(21),
            AtomTypeIdentifier::BufferType(len) => Ok(*len as i128),
            AtomTypeIdentifier::TupleType(tuple_sig) => tuple_sig.size(),
            AtomTypeIdentifier::OptionalType(t) => {
                t.size()?
                    .checked_add(1)
                    .ok_or(RuntimeErrorType::ValueTooLarge.into())
            },
            AtomTypeIdentifier::ResponseType(v) => {
                let (t, s) = (&v.0, &v.1);
                let t_size = t.size()?;
                let s_size = s.size()?;
                cmp::max(t_size, s_size)
                    .checked_add(1)
                    .ok_or(RuntimeErrorType::ValueTooLarge.into())
            },
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
                    Err(RuntimeErrorType::BadTypeConstruction.into())
                }
            },
            AtomTypeIdentifier::TupleType(ref mut tuple_sig) => {
                if let AtomTypeIdentifier::TupleType(ref other_tuple_sig) = other {
                    tuple_sig.expand_to_admit(other_tuple_sig)
                } else {
                    Err(RuntimeErrorType::BadTypeConstruction.into())
                }
            },
            _ => {
                if other == self {
                    Ok(())
                } else {
                    Err(RuntimeErrorType::BadTypeConstruction.into())
                }
            }
        }
    }

    fn admits(&self, other: &AtomTypeIdentifier) -> bool {
        match self {
            AtomTypeIdentifier::OptionalType(ref my_inner_type) => {
                if let AtomTypeIdentifier::OptionalType(other_inner_type) = other {
                    // Option types will always admit a "NoType" OptionalType -- which
                    //   can only be a None
                    if other_inner_type.is_no_type() {
                        true
                    } else {
                        my_inner_type.admits_type(other_inner_type)
                    }
                } else {
                    false
                }
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
    pub fn new(type_data: Vec<(ClarityName, TypeSignature)>) -> Result<TupleTypeSignature> {
        if type_data.len() == 0 {
            return Err(UncheckedError::ExpectedListPairs.into())
        }

        let mut type_map = BTreeMap::new();
        for (name, type_info) in type_data {
            if type_map.contains_key(&name) {
                return Err(UncheckedError::VariableDefinedMultipleTimes(name.into()).into());
            } else {
                type_map.insert(name, type_info);
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
                .ok_or(RuntimeErrorType::ValueTooLarge)?;
            value_size = value_size.checked_add(type_signature.size()? as i128)
                .ok_or(RuntimeErrorType::ValueTooLarge)?;
        }
        let name_total_size = name_size.checked_mul(2)
            .ok_or(RuntimeErrorType::ValueTooLarge)?;
        value_size.checked_add(name_total_size)
            .ok_or(RuntimeErrorType::ValueTooLarge.into())
    }

    // NOTE: this function mutates self _even if it returns an error_.
    fn expand_to_admit(&mut self, other: &TupleTypeSignature) -> Result<()> {
        if self.type_map.len() != other.type_map.len() {
            return Err(RuntimeErrorType::BadTypeConstruction.into())
        }

        for (name, my_type_sig) in self.type_map.iter_mut() {
            let other_type_sig = other.type_map.get(name)
                .ok_or(RuntimeErrorType::BadTypeConstruction)?;
            my_type_sig.expand_to_admit(other_type_sig)?;
        }

        Ok(())
    }

    pub fn parse_name_type_pair_list(type_def: &SymbolicExpression) -> Result<TupleTypeSignature> {
        if let SymbolicExpressionType::List(ref name_type_pairs) = type_def.expr {
            let mapped_key_types = parse_name_type_pairs(name_type_pairs)?;
            TupleTypeSignature::new(mapped_key_types)
        } else {
            Err(UncheckedError::ExpectedListPairs.into())
        }
    }
}

impl FunctionArg {
    pub fn new(sig: TypeSignature, name: &str) -> FunctionArg {
        FunctionArg { 
            signature: sig, 
            name: name.to_owned() }
    }
}

impl TypeSignature {
    pub fn new_atom(atomic_type: AtomTypeIdentifier) -> TypeSignature {
        TypeSignature::Atom(atomic_type)
    }

    pub fn new_option(inner_type: TypeSignature) -> TypeSignature {
        TypeSignature::new_atom(
            AtomTypeIdentifier::OptionalType(
                Box::new(inner_type)))
    }

    pub fn new_response(ok_type: TypeSignature, err_type: TypeSignature) -> TypeSignature {
        TypeSignature::new_atom(
            AtomTypeIdentifier::ResponseType(
                Box::new((ok_type, err_type))))
    }

    fn make_union_response_type(response_type_a: &(TypeSignature, TypeSignature),
                                response_type_b: &(TypeSignature, TypeSignature)) -> Option<TypeSignature> {

        // if a has any "no type" fields, then just use b's types for that field
        let (a_type_okay, a_type_err) = {
            let okay_type = match response_type_a.0.match_atomic() {
                Some(AtomTypeIdentifier::NoType) => response_type_b.0.clone(),
                _ => response_type_a.0.clone()
            };
            let err_type = match response_type_a.1.match_atomic() {
                Some(AtomTypeIdentifier::NoType) => response_type_b.1.clone(),
                _ => response_type_a.1.clone()
            };
            (okay_type, err_type)
        };

        // and vice-versa
        let (b_type_okay, b_type_err) = {
            let okay_type = match response_type_b.0.match_atomic() {
                Some(AtomTypeIdentifier::NoType) => response_type_a.0.clone(),
                _ => response_type_b.0.clone()
            };
            let err_type = match response_type_b.1.match_atomic() {
                Some(AtomTypeIdentifier::NoType) => response_type_a.1.clone(),
                _ => response_type_b.1.clone()
            };
            (okay_type, err_type)
        };


        let okay_type = TypeSignature::most_admissive(a_type_okay, b_type_okay);
        let error_type = TypeSignature::most_admissive(a_type_err, b_type_err);
        if let (Ok(okay_type), Ok(error_type)) = (okay_type, error_type) {
            Some(TypeSignature::new_atom(
                AtomTypeIdentifier::ResponseType(
                    Box::new((okay_type, error_type)))))
        } else {
            None
        }
    }

    pub fn is_no_type(&self) -> bool {
        if let Some(AtomTypeIdentifier::NoType) = self.match_atomic() {
            true
        } else {
            false
        }
    }

    pub fn most_admissive(a: TypeSignature, b: TypeSignature) -> std::result::Result<TypeSignature, 
                                                                                     (TypeSignature, TypeSignature)> {
        // if response type, we may need to return the union of a and b.
        if let (Some(AtomTypeIdentifier::ResponseType(ref response_type_a)),
                Some(AtomTypeIdentifier::ResponseType(ref response_type_b))) =
            (a.match_atomic(), b.match_atomic()) {
                return TypeSignature::make_union_response_type(response_type_a, response_type_b)
                    .ok_or_else(|| (a.clone(), b.clone()))
            }

        // same goes for the option type
        // this little monster is an attempt to avoid an unneccessary clone
        // Some(0) indicates that we should return type_a
        // Some(1) indicates that we should return type_b
        // None indicates that we should continue trying to find the most
        //   admissive of type_a, type_b or error if no such
        //   admission is possible.
        let short_return_optional = 
            if let (TypeSignature::Atom(AtomTypeIdentifier::OptionalType(ref opt_type_a)),
                    TypeSignature::Atom(AtomTypeIdentifier::OptionalType(ref opt_type_b))) = (&a, &b) {
                if opt_type_b.is_no_type() {
                    Some(0)
                } else if opt_type_a.is_no_type() {
                    Some(1)
                } else {
                    None
                }
            } else {
                None
            };

        match short_return_optional {
            Some(0) => Ok(a),
            Some(1) => Ok(b),
            _ => {
                if a.admits_type(&b) {
                    Ok(a)
                } else if b.admits_type(&a) {
                    Ok(b)
                } else {
                    Err((a,b))
                }
            }
        }
    }

    pub fn new_list(atomic_type: AtomTypeIdentifier, max_len: i128, dimension: i128) -> Result<TypeSignature> {
        if dimension == 0 {
            Err(RuntimeErrorType::InvalidTypeDescription.into())
        } else if max_len > u32::max_value() as i128 || dimension > u8::max_value() as i128 {
            Err(RuntimeErrorType::ListTooLarge.into())
        } else {
            let list_data = ListTypeData { 
                atomic_type,
                max_len: max_len as u32,
                dimension: dimension as u8 };
            let type_sig = TypeSignature::List(list_data);
            if type_sig.size()? > MAX_VALUE_SIZE {
                Err(RuntimeErrorType::ValueTooLarge.into())
            } else {
                Ok(type_sig)
            }
        }
    }

    pub fn list_max_len(&self) -> Option<u32> {
        if let TypeSignature::List(ListTypeData{ max_len, .. }) = self {
            Some(max_len.clone())
        } else {
            None
        }
    }

    pub fn list_of(item_type: TypeSignature, max_len: u32) -> Result<TypeSignature> {
        let list_type = match item_type {
            TypeSignature::List(ListTypeData { max_len: item_max_len,
                                               dimension: item_dim,
                                               atomic_type }) => {
                let dimension = item_dim.checked_add(1)
                    .ok_or(RuntimeErrorType::ListTooLarge)?;
                let max_len = {
                    if item_max_len > max_len {
                        item_max_len
                    } else {
                        max_len
                    }
                };
                ListTypeData { max_len, dimension, atomic_type }                
            }
            TypeSignature::Atom(atomic_type) => {
                ListTypeData { max_len, dimension: 1, atomic_type }
            }
        };

        Ok(TypeSignature::List(list_type))
    }

    pub fn deserialize(json: &str) -> TypeSignature {
        serde_json::from_str(json)
            .expect("Failed to deserialize vm.TypeSignature")
    }

    pub fn serialize(&self) -> String {
        serde_json::to_string(self)
            .expect("Failed to serialize vm.TypeSignature")
    }

    fn new_atom_checked(atom_type: AtomTypeIdentifier) -> Result<TypeSignature> {
        if atom_type.size()? > MAX_VALUE_SIZE {
            Err(RuntimeErrorType::ValueTooLarge.into())
        } else {
            Ok(TypeSignature::new_atom(atom_type))
        }
    }

    pub fn new_tuple(tuple_type_sig: TupleTypeSignature) -> Result<TypeSignature> {
        TypeSignature::new_atom_checked(AtomTypeIdentifier::TupleType(tuple_type_sig))
    }

    fn new_buffer(buff_len: i128) -> Result<TypeSignature> {
        if buff_len > u32::max_value() as i128 {
            Err(RuntimeErrorType::BufferTooLarge.into())
        } else {
            let atom_type = AtomTypeIdentifier::BufferType(buff_len as u32);
            TypeSignature::new_atom_checked(atom_type)
        }
    }

    pub fn get_empty_list_type() -> ListTypeData {
        // TODO: empty list type should be typed/handled differently.
        //         any list type should _admit_
        //         an empty list type
        ListTypeData {
            atomic_type: AtomTypeIdentifier::NoType,
            max_len: 0,
            dimension: 1 }
    }

    pub fn size(&self) -> Result<i128> {
        match self {
            TypeSignature::List(list_type) => list_type.size(),
            TypeSignature::Atom(atomic_type) => atomic_type.size()
        }
    }

    pub fn type_of(x: &Value) -> TypeSignature {
        let atom = match x {
            Value::Principal(_) => AtomTypeIdentifier::PrincipalType,
            Value::Int(_v) => AtomTypeIdentifier::IntType,
            Value::Bool(_v) => AtomTypeIdentifier::BoolType,
            Value::Buffer(buff_data) => AtomTypeIdentifier::BufferType(buff_data.data.len() as u32),
            Value::Tuple(v) => AtomTypeIdentifier::TupleType(
                v.type_signature.clone()),
            Value::List(list_data) => return TypeSignature::List(list_data.type_signature.clone()),
            Value::Optional(v) => v.type_signature(),
            Value::Response(v) => v.type_signature()
        };
        
        TypeSignature::new_atom(atom)
    }

    fn expand_to_admit(&mut self, x_type: &TypeSignature) -> Result<()> {
        match (self, x_type) {
            (TypeSignature::List(ref mut my_list_type),
             TypeSignature::List(ref x_list_type)) => {
                if my_list_type.dimension != x_list_type.dimension {
                    return Err(RuntimeErrorType::BadTypeConstruction.into())
                }
                if my_list_type.max_len < x_list_type.max_len {
                    my_list_type.max_len = x_list_type.max_len;
                }
                my_list_type.atomic_type.expand_to_admit(&x_list_type.atomic_type)
            },
            (TypeSignature::Atom(ref mut my_atomic),
             TypeSignature::Atom(ref x_atomic)) => {
                my_atomic.expand_to_admit(x_atomic)
            },
            _ => Err(RuntimeErrorType::BadTypeConstruction.into())
        }
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
    pub fn construct_parent_list_type(args: &[Value]) -> Result<ListTypeData> {
        let children_types:Vec<_> = args.iter().map(|x| TypeSignature::type_of(x)).collect();
        TypeSignature::parent_list_type(&children_types)
    }

    pub fn parent_list_type(children: &[TypeSignature]) -> Result<ListTypeData> {
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
                    Err(RuntimeErrorType::ListTooLarge)
                } else {
                    Ok(args_len as u32)
                }
            }?;

            let parent_dimension = match child_type {
                TypeSignature::List(ref type_data) => {
                    if type_data.max_len > parent_max_len {
                        parent_max_len = type_data.max_len
                    }
                    type_data.dimension.checked_add(1)
                        .ok_or(RuntimeErrorType::ListDimensionTooHigh)
                },
                TypeSignature::Atom(_) => {
                    Ok(1)
                }
            }?;

            let atomic_type = match child_type {
                TypeSignature::List(list_type) => {
                    list_type.atomic_type
                },
                TypeSignature::Atom(atomic_type) => {
                    atomic_type
                }
            };

            Ok(ListTypeData { atomic_type,
                              max_len: parent_max_len,
                              dimension: parent_dimension })
        } else {
            Ok(TypeSignature::get_empty_list_type())
        }
    }

    pub fn admits(&self, x: &Value) -> bool {
        let x_type = TypeSignature::type_of(x);
        self.admits_type(&x_type)
    }

    pub fn admits_type(&self, x_type: &TypeSignature) -> bool {
        match (x_type, self) {
            (TypeSignature::List(ref x_list_type), TypeSignature::List(ref my_list_type)) => {
                if x_list_type.max_len <= 0 {
                    // if x_type is an empty list, a list type should always admit.
                    return true
                }

                if my_list_type.dimension == x_list_type.dimension
                    && my_list_type.max_len >= x_list_type.max_len {
                    my_list_type.atomic_type.admits(&x_list_type.atomic_type)
                } else {
                    false
                }
            },
            (TypeSignature::Atom(ref x_atomic_type), TypeSignature::Atom(ref my_atomic_type)) => {
                my_atomic_type.admits(x_atomic_type)
            },
            _ => false
        }
    }

    // Returns Some(AtomTypeIdentifier) in the case that this type
    //   is an atomic type.
    //  If this type is a _list_, however, return None
    pub fn match_atomic(&self) -> Option<&AtomTypeIdentifier> {
        if let TypeSignature::Atom(ref atomic_type) = self {
            Some(atomic_type)
        } else {
            None
        }
    }

    pub fn match_list(&self) -> Option<&ListTypeData> {
        if let TypeSignature::List(ref list_type) = self {
            Some(list_type)
        } else {
            None
        }
    }

    pub fn get_list_item_type(&self) -> Option<TypeSignature> {
        if let TypeSignature::List(list_type) = self {
            Some(list_type.get_list_item_type())
        } else {
            None
        }
    }

    fn parse_atom_type(typename: &str) -> Result<AtomTypeIdentifier> {
        match typename {
            "int" => Ok(AtomTypeIdentifier::IntType),
            "bool" => Ok(AtomTypeIdentifier::BoolType),
            "principal" => Ok(AtomTypeIdentifier::PrincipalType),
            _ => Err(RuntimeErrorType::ParseError(format!("Unknown type name: '{}'", typename)).into())
        }
    }

    // Parses list type signatures ->
    // (list maximum-length dimension atomic-type) or
    // (list maximum-length atomic-type) -> denotes list of dimension 1
    fn parse_list_type_repr(type_args: &[SymbolicExpression]) -> Result<TypeSignature> {
        if type_args.len() != 2 && type_args.len() != 3 {
            return Err(RuntimeErrorType::InvalidTypeDescription.into());
        }
        let dimension = {
            if type_args.len() == 2 {
                Ok(1)
            } else {
                if let SymbolicExpressionType::AtomValue(Value::Int(dimension)) = &type_args[1].expr {
                    Ok(*dimension)
                } else {
                    Err(RuntimeErrorType::InvalidTypeDescription)
                }
            }
        }?;

        if let SymbolicExpressionType::AtomValue(Value::Int(max_len)) = &type_args[0].expr {            
            let atomic_type_arg = &type_args[type_args.len()-1];
            let atomic_type = TypeSignature::parse_type_repr(atomic_type_arg, false)?;
            if let TypeSignature::Atom(atomic_type) = atomic_type {
                TypeSignature::new_list(atomic_type, *max_len, dimension)
            } else {
                panic!("Parser should not have returned a non-atom")
            }
        } else {
            Err(RuntimeErrorType::InvalidTypeDescription.into())
        }
    }

    // Parses type signatures of the following form:
    // (tuple (key-name-0 value-type-0) (key-name-1 value-type-1))
    fn parse_tuple_type_repr(type_args: &[SymbolicExpression]) -> Result<TypeSignature> {
        let mapped_key_types = parse_name_type_pairs(type_args)?;
        let tuple_type_signature = TupleTypeSignature::new(mapped_key_types)?;
        TypeSignature::new_tuple(tuple_type_signature)
    }

    // Parses type signatures of the form:
    // (buff 10)
    fn parse_buff_type_repr(type_args: &[SymbolicExpression]) -> Result<TypeSignature> {
        if type_args.len() != 1 {
            return Err(RuntimeErrorType::InvalidTypeDescription.into())
        }
        if let SymbolicExpressionType::AtomValue(Value::Int(buff_len)) = &type_args[0].expr {
            TypeSignature::new_buffer(*buff_len)
        } else {
            Err(RuntimeErrorType::InvalidTypeDescription.into())
        }
    }

    fn parse_optional_type_repr(type_args: &[SymbolicExpression]) -> Result<TypeSignature> {
        if type_args.len() != 1 {
            return Err(RuntimeErrorType::InvalidTypeDescription.into())
        }
        let inner_type = TypeSignature::parse_type_repr(&type_args[0], true)?;
        Ok(TypeSignature::Atom(AtomTypeIdentifier::OptionalType(
            Box::new(inner_type))))
    }

    pub fn parse_type_repr(x: &SymbolicExpression, allow_list: bool) -> Result<TypeSignature> {
        match x.expr {
            SymbolicExpressionType::Atom(ref atom_type_str) => {
                let atomic_type = TypeSignature::parse_atom_type(atom_type_str)?;
                Ok(TypeSignature::Atom(atomic_type))
            },
            SymbolicExpressionType::List(ref list_contents) => {
                let (compound_type, rest) = list_contents.split_first()
                    .ok_or(RuntimeErrorType::InvalidTypeDescription)?;
                if let SymbolicExpressionType::Atom(ref compound_type) = compound_type.expr {
                    match compound_type.as_ref() {
                        "list" =>
                            if !allow_list {
                                Err(RuntimeErrorType::InvalidTypeDescription.into())
                            } else {
                                TypeSignature::parse_list_type_repr(rest)
                            },
                        "buff" => TypeSignature::parse_buff_type_repr(rest),
                        "tuple" => TypeSignature::parse_tuple_type_repr(rest),
                        "optional" => TypeSignature::parse_optional_type_repr(rest),
                        _ => Err(RuntimeErrorType::InvalidTypeDescription.into())
                    }
                } else {
                    Err(RuntimeErrorType::InvalidTypeDescription.into())
                }
            },
            _ => Err(RuntimeErrorType::InvalidTypeDescription.into())
        }
    }
}

pub fn parse_name_type_pairs(name_type_pairs: &[SymbolicExpression]) -> Result<Vec<(ClarityName, TypeSignature)>> {
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
                        Err(UncheckedError::ExpectedListPairs.into())
                    } else {
                        Ok((&as_vec[0], &as_vec[1]))
                    }
                } else {
                    Err(UncheckedError::ExpectedListPairs.into())
                }
            }).collect();

    // step 2: turn into a vec of (name, typesignature) pairs.
    let key_types: Result<Vec<_>> =
        (as_pairs?).iter().map(|(name_symbol, type_symbol)| {
            let name = name_symbol.match_atom()
                .ok_or(UncheckedError::ExpectedListPairs)?
                .clone();
            let type_info = TypeSignature::parse_type_repr(type_symbol, true)?;
            Ok((name, type_info))
        }).collect();
    
    key_types
}

impl fmt::Display for TupleTypeSignature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "(tuple")?;
        for (field_name, field_type) in self.type_map.iter() {
            write!(f, " ({} {})", &**field_name, field_type)?;
        }
        write!(f, ")")
    }
}

impl fmt::Display for AssetIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}::{}", &self.contract_name, &self.asset_name)
    }
}

impl fmt::Display for AtomTypeIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::AtomTypeIdentifier::*;
        match self {
            NoType => write!(f, "NoType"),
            IntType => write!(f, "int"),
            BoolType => write!(f, "bool"),
            PrincipalType => write!(f, "principal"),
            BufferType(len) => write!(f, "(buff {})", len),
            OptionalType(t) => write!(f, "(optional {})", t),
            ResponseType(v) => write!(f, "(response {} {})", v.0, v.1),
            TupleType(t) => write!(f, "{}", t)
        }
    }
}

impl fmt::Display for FunctionArg {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.signature)
    }
}

impl fmt::Display for TypeSignature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TypeSignature::Atom(ref atomic_type) => write!(f, "{}", atomic_type),
            TypeSignature::List(ref list_type_data) => {
                write!(f, "(list {}", list_type_data.max_len)?;
                if list_type_data.dimension > 1 {
                    write!(f, "{}", list_type_data.dimension)?;
                }
                write!(f, "{})", list_type_data.atomic_type)
            }
        }
    }
}
