// TypeSignatures
use std::hash::{Hash, Hasher};
use std::{fmt, cmp};
use std::convert::TryFrom;
use std::collections::BTreeMap;

use address::c32;
use vm::types::{Value, MAX_VALUE_SIZE};
use vm::representations::{SymbolicExpression, SymbolicExpressionType, ClarityName, ContractName};
use vm::errors::{RuntimeErrorType, UncheckedError, InterpreterResult as Result, IncomparableError, Error as VMError};
use util::hash;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct AssetIdentifier {
    pub contract_name: ContractName,
    pub asset_name: ClarityName
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TupleTypeSignature {
    type_map: BTreeMap<ClarityName, TypeSignature>
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BufferLength (u32);

// INVARIANTS enforced by the Type Signatures.
//   1. A TypeSignature constructor will always fail rather than construct a
//        type signature for a too large or invalid type. This is why any variable length
//        type signature has a guarded constructor.
//   2. The only methods which may be called on TypeSignatures that are too large
//        (i.e., the only function that can be called by the constructor before
//         it fails) is the `.size()` method, which may be used to check the size.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TypeSignature {
    NoType,
    IntType,
    UIntType,
    BoolType,
    BufferType(BufferLength),
    PrincipalType,
    ListType(ListTypeData),
    TupleType(TupleTypeSignature),
    OptionalType(Box<TypeSignature>),
    ResponseType(Box<(TypeSignature, TypeSignature)>)
}

use self::TypeSignature::{NoType, IntType, UIntType, BoolType, BufferType,
                          PrincipalType, ListType, TupleType, OptionalType, ResponseType};

pub const BUFF_32: TypeSignature = BufferType(BufferLength(32));
pub const BUFF_20: TypeSignature = BufferType(BufferLength(20));

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListTypeData {
    max_len: u32,
    entry_type: Box<TypeSignature>
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixedFunction {
    pub args: Vec<FunctionArg>,
    pub returns: TypeSignature
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FunctionType {
    Variadic(TypeSignature, TypeSignature),
    Fixed(FixedFunction),
    // Functions where the single input is a union type, e.g., Buffer or Int
    UnionArgs(Vec<TypeSignature>, TypeSignature),
    ArithmeticVariadic, ArithmeticBinary, ArithmeticComparison
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionArg {
    pub signature: TypeSignature,
    pub name: ClarityName,
}

#[cfg(test)]
impl From<&str> for TypeSignature {
    fn from(val: &str) -> Self {
        use vm::parser;
        let expr = &parser::parse(val).unwrap()[0];
        TypeSignature::parse_type_repr(expr).unwrap()
    }
}

impl From<ListTypeData> for TypeSignature {
    fn from(data: ListTypeData) -> Self {
        ListType(data)
    }
}

impl From<TupleTypeSignature> for TypeSignature {
    fn from(data: TupleTypeSignature) -> Self {
        TupleType(data)
    }
}

impl From<&BufferLength> for u32 {
    fn from(v: &BufferLength) -> u32 {
        v.0
    }
}

impl From<BufferLength> for u32 {
    fn from(v: BufferLength) -> u32 {
        v.0
    }
}

impl TryFrom<u32> for BufferLength {
    type Error = VMError;
    fn try_from(data: u32) -> Result<BufferLength> {
        if (data as i128) > MAX_VALUE_SIZE {
            Err(RuntimeErrorType::ValueTooLarge.into())
        } else {
            Ok(BufferLength(data))
        }
    }
}

impl TryFrom<usize> for BufferLength {
    type Error = VMError;
    fn try_from(data: usize) -> Result<BufferLength> {
        if (data as i128) > MAX_VALUE_SIZE || data > (u32::max_value() as usize) {
            Err(RuntimeErrorType::ValueTooLarge.into())
        } else {
            Ok(BufferLength(data as u32))
        }
    }
}

impl ListTypeData {
    pub fn new_list(entry_type: TypeSignature, max_len: u32) -> Result<ListTypeData> {
        let list_data = ListTypeData { 
            entry_type: Box::new(entry_type),
            max_len: max_len as u32 
        };
        if list_data.size()? > MAX_VALUE_SIZE {
            Err(RuntimeErrorType::ValueTooLarge.into())
        } else {
            Ok(list_data)
        }
    }

    pub fn destruct(self) -> (TypeSignature, u32) {
        (*self.entry_type, self.max_len)
    }

    pub fn get_max_len(&self) -> u32 {
        self.max_len
    }

    pub fn get_list_item_type(&self) -> &TypeSignature {
        &self.entry_type
    }

    pub fn size(&self) -> Result<i128> {
        let base_cost = self.type_size()?; 
        if self.max_len <= 0 {
            Ok(base_cost)
        } else {
            self.entry_type.size()?
                .checked_mul(self.max_len as i128)
                .and_then(|x| x.checked_mul(base_cost))
                .ok_or(RuntimeErrorType::ValueTooLarge.into())
        }
    }

    pub fn type_size(&self) -> Result<i128> {
        let fixed_cost = 4 + 1; // 1 byte for Type enum, 4 for max_len.
        self.entry_type.type_size()?
            .checked_add(fixed_cost)
            .ok_or(RuntimeErrorType::ValueTooLarge.into())
    }

}

impl TypeSignature {
    pub fn new_option(inner_type: TypeSignature) -> TypeSignature {
        OptionalType(Box::new(inner_type))
    }

    pub fn new_response(ok_type: TypeSignature, err_type: TypeSignature) -> TypeSignature {
        ResponseType(Box::new((ok_type, err_type)))
    }

    pub fn is_no_type(&self) -> bool {
        if let TypeSignature::NoType = self {
            true
        } else {
            false
        }
    }

    pub fn admits(&self, x: &Value) -> bool {
        let x_type = TypeSignature::type_of(x);
        self.admits_type(&x_type)
    }

    pub fn size(&self) -> Result<i128> {
        match self {
            // NoType's may be asked for their size at runtime --
            //  legal constructions like `(ok 1)` have NoType parts (if they have unknown error variant types).
            NoType => Ok(1),
            IntType => Ok(16),
            UIntType => Ok(16),
            BoolType => Ok(1),
            // TODO: Principal Size isn't quite right.
            //    it can be much larger due to contract principals.
            PrincipalType => Ok(21),
            BufferType(len) => Ok(u32::from(len) as i128),
            TupleType(tuple_sig) => tuple_sig.size(),
            OptionalType(t) => {
                t.size()?
                    .checked_add(1)
                    .ok_or(RuntimeErrorType::ValueTooLarge.into())
            },
            ListType(list_type) => list_type.size(),
            ResponseType(v) => {
                let (t, s) = (&v.0, &v.1);
                let t_size = t.size()?;
                let s_size = s.size()?;
                cmp::max(t_size, s_size)
                    .checked_add(1)
                    .ok_or(RuntimeErrorType::ValueTooLarge.into())
            },
        }
    }

    /// Returns the size of the _type signature_
    fn type_size(&self) -> Result<i128> {
        match self {
            // NoType's may be asked for their size at runtime --
            //  legal constructions like `(ok 1)` have NoType parts (if they have unknown error variant types).
            NoType => Ok(1),
            IntType => Ok(1),
            UIntType => Ok(1),
            BoolType => Ok(1),
            PrincipalType => Ok(1),
            BufferType(len) => Ok(1 + 4),
            TupleType(tuple_sig) => tuple_sig.type_size(),
            OptionalType(t) => {
                t.type_size()?
                    .checked_add(1)
                    .ok_or(RuntimeErrorType::ValueTooLarge.into())
            },
            ResponseType(v) => {
                let (t, s) = (&v.0, &v.1);
                t.type_size()?
                    .checked_add(s.type_size()?)
                    .ok_or(RuntimeErrorType::ValueTooLarge)?
                    .checked_add(1)
                    .ok_or(RuntimeErrorType::ValueTooLarge.into())
            },
            ListType(list_type) => list_type.type_size()
        }
    }

    pub fn admits_type(&self, other: &TypeSignature) -> bool {
        match self {
            ListType(ref my_list_type) => {
                if let ListType(other_list_type) = other {
                    if other_list_type.max_len <= 0 {
                        // if other is an empty list, a list type should always admit.
                        true
                    } else if my_list_type.max_len >= other_list_type.max_len {
                        my_list_type.entry_type.admits_type(&*other_list_type.entry_type)
                    } else {
                        false
                    }
                } else {
                    false
                }
            },
            OptionalType(ref my_inner_type) => {
                if let OptionalType(other_inner_type) = other {
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
            ResponseType(ref my_inner_type) => {
                if let ResponseType(other_inner_type) = other {
                    // ResponseTypes admit according to the following rule:
                    //   if other.ErrType is NoType, and other.OkType admits => admit
                    //   if other.OkType is NoType, and other.ErrType admits => admit
                    //   if both OkType and ErrType admit => admit
                    //   otherwise fail.
                    if other_inner_type.0.is_no_type() {
                        my_inner_type.1.admits_type(&other_inner_type.1)
                    } else if other_inner_type.1.is_no_type() {
                        my_inner_type.0.admits_type(&other_inner_type.0)
                    } else {
                        my_inner_type.1.admits_type(&other_inner_type.1)
                            && my_inner_type.0.admits_type(&other_inner_type.0)
                    }
                } else {
                    false
                }
            },
            BufferType(ref my_len) => {
                if let BufferType(ref other_len) = other {
                    my_len.0 >= other_len.0
                } else {
                    false
                }
            },
            TupleType(ref tuple_sig) => {
                if let TupleType(ref other_tuple_sig) = other {
                    tuple_sig.admits(other_tuple_sig)
                } else {
                    false
                }
            },
            NoType => panic!("NoType should never be asked to admit."),
            _ => other == self
        }
    }
}

impl TryFrom<Vec<(ClarityName, TypeSignature)>> for TupleTypeSignature {
    type Error = VMError;
    fn try_from(mut type_data: Vec<(ClarityName, TypeSignature)>) -> Result<TupleTypeSignature> {
        if type_data.len() == 0 {
            return Err(UncheckedError::ExpectedListPairs.into())
        }

        let mut type_map = BTreeMap::new();
        for (name, type_info) in type_data.drain(..) {
            if type_map.contains_key(&name) {
                return Err(UncheckedError::VariableDefinedMultipleTimes(name.into()).into());
            } else {
                type_map.insert(name, type_info);
            }
        }
        let result = TupleTypeSignature { type_map };        
        if result.size()? > MAX_VALUE_SIZE {
            Err(RuntimeErrorType::ValueTooLarge.into())
        } else {
            Ok(result)
        }
    }
}

impl TryFrom<BTreeMap<ClarityName, TypeSignature>> for TupleTypeSignature {
    type Error = VMError;
    fn try_from(type_map: BTreeMap<ClarityName, TypeSignature>) -> Result<TupleTypeSignature> {
        if type_map.len() == 0 {
            return Err(UncheckedError::ExpectedListPairs.into())
        }
        let result = TupleTypeSignature { type_map };
        if result.size()? > MAX_VALUE_SIZE {
            Err(RuntimeErrorType::ValueTooLarge.into())
        } else {
            Ok(result)
        }
    }
}

impl TupleTypeSignature {
    pub fn field_type(&self, field: &str) -> Option<&TypeSignature> {
        self.type_map.get(field)
    }

    pub fn get_type_map(&self) -> &BTreeMap<ClarityName, TypeSignature> {
        &self.type_map
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

    fn type_size(&self) -> Result<i128> {
        let mut name_size: i128 = 0;
        let mut value_size: i128 = 0;
        for (name, type_signature) in self.type_map.iter() {
            // we only accept ascii names, so 1 char = 1 byte.
            name_size = name_size.checked_add(name.len() as i128)
                .ok_or(RuntimeErrorType::ValueTooLarge)?;
            value_size = value_size.checked_add(type_signature.type_size()? as i128)
                .ok_or(RuntimeErrorType::ValueTooLarge)?;
        }
        let name_total_size = name_size.checked_mul(2)
            .ok_or(RuntimeErrorType::ValueTooLarge)?;
        value_size.checked_add(name_total_size)
            .ok_or(RuntimeErrorType::ValueTooLarge.into())        
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
            .ok_or(RuntimeErrorType::ValueTooLarge)?
            .checked_add(self.type_size()?)
            .ok_or(RuntimeErrorType::ValueTooLarge.into())
    }

    pub fn parse_name_type_pair_list(type_def: &SymbolicExpression) -> Result<TupleTypeSignature> {
        if let SymbolicExpressionType::List(ref name_type_pairs) = type_def.expr {
            let mapped_key_types = parse_name_type_pairs(name_type_pairs)?;
            TupleTypeSignature::try_from(mapped_key_types)
        } else {
            Err(UncheckedError::ExpectedListPairs.into())
        }
    }
}

impl FunctionArg {
    pub fn new(signature: TypeSignature, name: ClarityName) -> FunctionArg {
        FunctionArg { signature, name }
    }
}

impl TypeSignature {
    /// If one of the types is a NoType, return Ok(the other type), otherwise return least_supertype(a, b)
    fn factor_out_no_type(a: &TypeSignature, b: &TypeSignature) -> Result<TypeSignature> {
        if a.is_no_type() {
            Ok(b.clone())
        } else if b.is_no_type() {
            Ok(a.clone())
        } else {
            Self::least_supertype(a, b)
        }
    }

    ///
    /// This function returns the most-restrictive type that admits _both_ A and B (something like a least common supertype),
    /// or Errors if no such type exists. On error, it throws NoSuperType(A,B), unless a constructor error'ed -- in which case,
    /// it throws the constructor's error.
    ///
    ///  For two Tuples:
    ///      least_supertype(A, B) := (tuple \for_each(key k) least_supertype(type_a_k, type_b_k))
    ///  For two Lists:
    ///      least_supertype(A, B) := (list max_len: max(max_len A, max_len B), entry: least_supertype(entry_a, entry_b))
    ///        if max_len A | max_len B is 0: entry := Non-empty list entry
    ///  For two responses:
    ///      least_supertype(A, B) := (response least_supertype(ok_a, ok_b), least_supertype(err_a, err_b))
    ///        if any entries are NoType, use the other type's entry
    ///  For two options:
    ///      least_supertype(A, B) := (option least_supertype(some_a, some_b))
    ///        if some_a | some_b is NoType, use the other type's entry.
    ///  For buffers:
    ///      least_supertype(A, B) := (buff len: max(len A, len B))
    ///  For ints, uints, principals, bools:
    ///      least_supertype(A, B) := if A != B, error, else A
    ///
    pub fn least_supertype(a: &TypeSignature, b: &TypeSignature) -> Result<TypeSignature> {
        match (a, b) {
            (TupleType(TupleTypeSignature{ type_map: types_a }), TupleType(TupleTypeSignature{ type_map: types_b })) => {
                if types_a.len() != types_b.len() {
                    return Err(UncheckedError::NoSuperType(a.clone(), b.clone()).into())
                }
                let mut type_map_out = BTreeMap::new();
                for (name, entry_a) in types_a.iter() {
                    let entry_b = types_b.get(name)
                        .ok_or(UncheckedError::NoSuperType(a.clone(), b.clone()))?;
                    let entry_out = Self::least_supertype(entry_a, entry_b)?;
                    type_map_out.insert(name.clone(), entry_out);
                }
                TupleTypeSignature::try_from(type_map_out).map(|x| x.into())
            },
            (ListType(ListTypeData{ max_len: len_a, entry_type: entry_a }), ListType(ListTypeData{ max_len: len_b, entry_type: entry_b })) => {
                let entry_type =
                    if *len_a == 0 {
                        *(entry_b.clone())
                    } else if *len_b == 0 {
                        *(entry_a.clone())
                    } else {
                        Self::least_supertype(entry_a, entry_b)?
                    };
                let max_len = cmp::max(len_a, len_b);
                Self::list_of(entry_type, *max_len)
            },
            (ResponseType(resp_a), ResponseType(resp_b)) => {
                let ok_type = Self::factor_out_no_type(&resp_a.0, &resp_b.0)?;
                let err_type = Self::factor_out_no_type(&resp_a.1, &resp_b.1)?;
                Ok(Self::new_response(ok_type, err_type))
            },
            (OptionalType(some_a), OptionalType(some_b)) => {
                let some_type = Self::factor_out_no_type(some_a, some_b)?;
                Ok(Self::new_option(some_type))
            },
            (BufferType(buff_a), BufferType(buff_b)) => {
                let buff_len = if u32::from(buff_a) > u32::from(buff_b) {
                    buff_a
                } else {
                    buff_b
                }.clone();
                Ok(BufferType(buff_len))
            },
            (x, y) => {
                if x == y {
                    Ok(x.clone())
                } else {
                    Err(UncheckedError::NoSuperType(a.clone(), b.clone()).into())
                }
            }
        }
    }

    pub fn list_of(item_type: TypeSignature, max_len: u32) -> Result<TypeSignature> {
        ListTypeData::new_list(item_type, max_len).map(|x| x.into())
    }

    pub fn new_buffer(buff_len: i128) -> Result<TypeSignature> {
        if buff_len > u32::max_value() as i128 {
            Err(RuntimeErrorType::ValueTooLarge.into())
        } else {
            BufferLength::try_from(buff_len as u32)
                .map(|buffer_len| TypeSignature::BufferType(buffer_len))
        }
    }

    pub fn get_empty_list_type() -> ListTypeData {
        ListTypeData {
            entry_type: Box::new(TypeSignature::NoType),
            max_len: 0 
        }
    }

    pub fn type_of(x: &Value) -> TypeSignature {
        match x {
            Value::Principal(_) => PrincipalType,
            Value::Int(_v) => IntType,
            Value::UInt(_v) => UIntType,
            Value::Bool(_v) => BoolType,
            Value::Buffer(buff_data) => {
                let buff_length = BufferLength::try_from(buff_data.data.len())
                    .expect("ERROR: Too large of a buffer successfully constructed.");
                BufferType(buff_length)
            },
            Value::Tuple(v) => TupleType(
                v.type_signature.clone()),
            Value::List(list_data) => ListType(list_data.type_signature.clone()),
            Value::Optional(v) => v.type_signature(),
            Value::Response(v) => v.type_signature()
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
            let mut current_entry_type = first.clone();
            for next_entry in rest.iter() {
                current_entry_type = Self::least_supertype(&current_entry_type, next_entry)?;
            }
            let len = u32::try_from(children.len())
                .map_err(|_| RuntimeErrorType::ValueTooLarge)?;
            ListTypeData::new_list(current_entry_type, len)
        } else {
            Ok(TypeSignature::get_empty_list_type())
        }
    }
}


/// Parsing functions.
impl TypeSignature {
    fn parse_atom_type(typename: &str) -> Result<TypeSignature> {
        match typename {
            "int" => Ok(TypeSignature::IntType),
            "uint" => Ok(TypeSignature::UIntType),
            "bool" => Ok(TypeSignature::BoolType),
            "principal" => Ok(TypeSignature::PrincipalType),
            _ => Err(RuntimeErrorType::ParseError(format!("Unknown type name: '{}'", typename)).into())
        }
    }

    // Parses list type signatures ->
    // (list maximum-length atomic-type)
    fn parse_list_type_repr(type_args: &[SymbolicExpression]) -> Result<TypeSignature> {
        if type_args.len() != 2 {
            return Err(RuntimeErrorType::InvalidTypeDescription.into());
        }

        if let SymbolicExpressionType::AtomValue(Value::Int(max_len)) = &type_args[0].expr {            
            let atomic_type_arg = &type_args[type_args.len()-1];
            let entry_type = TypeSignature::parse_type_repr(atomic_type_arg)?;
            let max_len = u32::try_from(*max_len)
                .map_err(|_| RuntimeErrorType::InvalidTypeDescription)?;
            ListTypeData::new_list(entry_type, max_len).map(|x| x.into())
        } else {
            Err(RuntimeErrorType::InvalidTypeDescription.into())
        }
    }

    // Parses type signatures of the following form:
    // (tuple (key-name-0 value-type-0) (key-name-1 value-type-1))
    fn parse_tuple_type_repr(type_args: &[SymbolicExpression]) -> Result<TypeSignature> {
        let mapped_key_types = parse_name_type_pairs(type_args)?;
        let tuple_type_signature = TupleTypeSignature::try_from(mapped_key_types)?;
        Ok(TypeSignature::from(tuple_type_signature))
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
        let inner_type = TypeSignature::parse_type_repr(&type_args[0])?;
        
        Ok(TypeSignature::new_option(inner_type))
    }

    fn parse_response_type_repr(type_args: &[SymbolicExpression]) -> Result<TypeSignature> {
        if type_args.len() != 2 {
            return Err(RuntimeErrorType::InvalidTypeDescription.into())
        }
        let ok_type = TypeSignature::parse_type_repr(&type_args[0])?;
        let err_type = TypeSignature::parse_type_repr(&type_args[1])?;
        Ok(TypeSignature::new_response(ok_type, err_type))
    }

    pub fn parse_type_repr(x: &SymbolicExpression) -> Result<TypeSignature> {
        match x.expr {
            SymbolicExpressionType::Atom(ref atom_type_str) => {
                let atomic_type = TypeSignature::parse_atom_type(atom_type_str)?;
                Ok(atomic_type)
            },
            SymbolicExpressionType::List(ref list_contents) => {
                let (compound_type, rest) = list_contents.split_first()
                    .ok_or(RuntimeErrorType::InvalidTypeDescription)?;
                if let SymbolicExpressionType::Atom(ref compound_type) = compound_type.expr {
                    match compound_type.as_ref() {
                        "list" => TypeSignature::parse_list_type_repr(rest),
                        "buff" => TypeSignature::parse_buff_type_repr(rest),
                        "tuple" => TypeSignature::parse_tuple_type_repr(rest),
                        "optional" => TypeSignature::parse_optional_type_repr(rest),
                        "response" => TypeSignature::parse_response_type_repr(rest),
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
            let type_info = TypeSignature::parse_type_repr(type_symbol)?;
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
        write!(f, "{}::{}", &*self.contract_name, &*self.asset_name)
    }
}

impl fmt::Display for TypeSignature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            NoType => write!(f, "UnknownType"),
            IntType => write!(f, "int"),
            UIntType => write!(f, "uint"),
            BoolType => write!(f, "bool"),
            PrincipalType => write!(f, "principal"),
            BufferType(len) => write!(f, "(buff {})", len),
            OptionalType(t) => write!(f, "(optional {})", t),
            ResponseType(v) => write!(f, "(response {} {})", v.0, v.1),
            TupleType(t) => write!(f, "{}", t),
            ListType(list_type_data) => write!(f, "(list {} {})", list_type_data.max_len, list_type_data.entry_type)
        }
    }
}

impl fmt::Display for BufferLength {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Display for FunctionArg {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.signature)
    }
}
