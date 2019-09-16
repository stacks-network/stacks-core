// TypeSignatures
use std::hash::{Hash, Hasher};
use std::{fmt, cmp};
use std::convert::TryFrom;
use std::collections::BTreeMap;

use address::c32;
use vm::types::{Value, MAX_VALUE_SIZE, QualifiedContractIdentifier};
use vm::representations::{SymbolicExpression, SymbolicExpressionType, ClarityName, ContractName};
use vm::errors::{RuntimeErrorType, CheckErrors, IncomparableError, Error as VMError};
use util::hash;

type Result <R> = std::result::Result<R, CheckErrors>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct AssetIdentifier {
    pub contract_identifier: QualifiedContractIdentifier,
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

pub const BUFF_64: TypeSignature = BufferType(BufferLength(64));
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
        use vm::ast::parse;
        let expr = &parse(&QualifiedContractIdentifier::transient(), val).unwrap()[0];
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
    type Error = CheckErrors;
    fn try_from(data: u32) -> Result<BufferLength> {
        if data > MAX_VALUE_SIZE {
            Err(CheckErrors::ValueTooLarge)
        } else {
            Ok(BufferLength(data))
        }
    }
}

impl TryFrom<usize> for BufferLength {
    type Error = CheckErrors;
    fn try_from(data: usize) -> Result<BufferLength> {
        if data > (MAX_VALUE_SIZE as usize) {
            Err(CheckErrors::ValueTooLarge)
        } else {
            Ok(BufferLength(data as u32))
        }
    }
}

impl TryFrom<i128> for BufferLength {
    type Error = CheckErrors;
    fn try_from(data: i128) -> Result<BufferLength> {
        if data > (MAX_VALUE_SIZE as i128) {
            Err(CheckErrors::ValueTooLarge)
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
        let would_be_size = list_data.inner_size()
            .ok_or_else(|| CheckErrors::ValueTooLarge)?;
        if would_be_size > MAX_VALUE_SIZE {
            Err(CheckErrors::ValueTooLarge)
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
}

impl TypeSignature {
    pub fn new_option(inner_type: TypeSignature) -> TypeSignature {
        OptionalType(Box::new(inner_type))
    }

    pub fn new_response(ok_type: TypeSignature, err_type: TypeSignature) -> TypeSignature {
        ResponseType(Box::new((ok_type, err_type)))
    }

    pub fn is_no_type(&self) -> bool {
        &TypeSignature::NoType == self
    }

    pub fn admits(&self, x: &Value) -> bool {
        let x_type = TypeSignature::type_of(x);
        self.admits_type(&x_type)
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
    type Error = CheckErrors;
    fn try_from(mut type_data: Vec<(ClarityName, TypeSignature)>) -> Result<TupleTypeSignature> {
        if type_data.len() == 0 {
            return Err(CheckErrors::EmptyTuplesNotAllowed)
        }

        let mut type_map = BTreeMap::new();
        for (name, type_info) in type_data.drain(..) {
            if type_map.contains_key(&name) {
                return Err(CheckErrors::NameAlreadyUsed(name.into()));
            } else {
                type_map.insert(name, type_info);
            }
        }
        let result = TupleTypeSignature { type_map };
        let would_be_size = result.inner_size()
            .ok_or_else(|| CheckErrors::ValueTooLarge)?;
        if would_be_size > MAX_VALUE_SIZE {
            Err(CheckErrors::ValueTooLarge)
        } else {
            Ok(result)
        }
    }
}

impl TryFrom<BTreeMap<ClarityName, TypeSignature>> for TupleTypeSignature {
    type Error = CheckErrors;
    fn try_from(type_map: BTreeMap<ClarityName, TypeSignature>) -> Result<TupleTypeSignature> {
        if type_map.len() == 0 {
            return Err(CheckErrors::EmptyTuplesNotAllowed)
        }
        let result = TupleTypeSignature { type_map };
        let would_be_size = result.inner_size()
            .ok_or_else(|| CheckErrors::ValueTooLarge)?;
        if would_be_size > MAX_VALUE_SIZE {
            Err(CheckErrors::ValueTooLarge)
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

    pub fn parse_name_type_pair_list(type_def: &SymbolicExpression) -> Result<TupleTypeSignature> {
        if let SymbolicExpressionType::List(ref name_type_pairs) = type_def.expr {
            let mapped_key_types = parse_name_type_pairs(name_type_pairs)?;
            TupleTypeSignature::try_from(mapped_key_types)
        } else {
            Err(CheckErrors::BadSyntaxExpectedListOfPairs)
        }
    }
}

impl FunctionArg {
    pub fn new(signature: TypeSignature, name: ClarityName) -> FunctionArg {
        FunctionArg { signature, name }
    }
}

impl TypeSignature {
    pub fn max_buffer() -> TypeSignature {
        BufferType(BufferLength(u32::try_from(MAX_VALUE_SIZE)
                                .expect("FAIL: Max Clarity Value Size is no longer realizable in Buffer Type")))
    }

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
                    return Err(CheckErrors::TypeError(a.clone(), b.clone()))
                }
                let mut type_map_out = BTreeMap::new();
                for (name, entry_a) in types_a.iter() {
                    let entry_b = types_b.get(name)
                        .ok_or(CheckErrors::TypeError(a.clone(), b.clone()))?;
                    let entry_out = Self::least_supertype(entry_a, entry_b)?;
                    type_map_out.insert(name.clone(), entry_out);
                }
                Ok(TupleTypeSignature::try_from(type_map_out).map(|x| x.into())
                   .expect("ERR: least_supertype attempted to construct a too-large supertype of two types"))
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
                Ok(Self::list_of(entry_type, *max_len)
                   .expect("ERR: least_supertype attempted to construct a too-large supertype of two types"))
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
                    Err(CheckErrors::TypeError(a.clone(), b.clone()))
                }
            }
        }
    }

    pub fn list_of(item_type: TypeSignature, max_len: u32) -> Result<TypeSignature> {
        ListTypeData::new_list(item_type, max_len).map(|x| x.into())
    }

    pub fn empty_list() -> ListTypeData {
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

    pub fn parent_list_type(children: &[TypeSignature]) -> std::result::Result<ListTypeData, CheckErrors> {
        if let Some((first, rest)) = children.split_first() {
            let mut current_entry_type = first.clone();
            for next_entry in rest.iter() {
                current_entry_type = Self::least_supertype(&current_entry_type, next_entry)?;
            }
            let len = u32::try_from(children.len())
                .map_err(|_| CheckErrors::ValueTooLarge)?;
            ListTypeData::new_list(current_entry_type, len)
        } else {
            Ok(TypeSignature::empty_list())
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
            _ => Err(CheckErrors::UnknownTypeName(typename.into()))
        }
    }

    // Parses list type signatures ->
    // (list maximum-length atomic-type)
    fn parse_list_type_repr(type_args: &[SymbolicExpression]) -> Result<TypeSignature> {
        if type_args.len() != 2 {
            return Err(CheckErrors::InvalidTypeDescription);
        }

        if let SymbolicExpressionType::AtomValue(Value::Int(max_len)) = &type_args[0].expr {            
            let atomic_type_arg = &type_args[type_args.len()-1];
            let entry_type = TypeSignature::parse_type_repr(atomic_type_arg)?;
            let max_len = u32::try_from(*max_len)
                .map_err(|_| CheckErrors::ValueTooLarge)?;
            ListTypeData::new_list(entry_type, max_len).map(|x| x.into())
        } else {
            Err(CheckErrors::InvalidTypeDescription)
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
            return Err(CheckErrors::InvalidTypeDescription)
        }
        if let SymbolicExpressionType::AtomValue(Value::Int(buff_len)) = &type_args[0].expr {
            BufferLength::try_from(*buff_len)
                .map(|buff_len| TypeSignature::BufferType(buff_len))
        } else {
            Err(CheckErrors::InvalidTypeDescription)
        }
    }

    fn parse_optional_type_repr(type_args: &[SymbolicExpression]) -> Result<TypeSignature> {
        if type_args.len() != 1 {
            return Err(CheckErrors::InvalidTypeDescription)
        }
        let inner_type = TypeSignature::parse_type_repr(&type_args[0])?;
        
        Ok(TypeSignature::new_option(inner_type))
    }

    fn parse_response_type_repr(type_args: &[SymbolicExpression]) -> Result<TypeSignature> {
        if type_args.len() != 2 {
            return Err(CheckErrors::InvalidTypeDescription)
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
                    .ok_or(CheckErrors::InvalidTypeDescription)?;
                if let SymbolicExpressionType::Atom(ref compound_type) = compound_type.expr {
                    match compound_type.as_ref() {
                        "list" => TypeSignature::parse_list_type_repr(rest),
                        "buff" => TypeSignature::parse_buff_type_repr(rest),
                        "tuple" => TypeSignature::parse_tuple_type_repr(rest),
                        "optional" => TypeSignature::parse_optional_type_repr(rest),
                        "response" => TypeSignature::parse_response_type_repr(rest),
                        _ => Err(CheckErrors::InvalidTypeDescription)
                    }
                } else {
                    Err(CheckErrors::InvalidTypeDescription)
                }
            },
            _ => Err(CheckErrors::InvalidTypeDescription)
        }
    }
}

/// These implement the size calculations in TypeSignatures
///    in constructors of TypeSignatures, only `.inner_size()` may be called.
///    .inner_size is a failable method to compute the size of the type signature,
///    Failures indicate that a type signature represents _too large_ of a value.
/// TypeSignature constructors will fail instead of constructing such a type.
///   because of this, the public interface to size is infallible.
impl TypeSignature {
    pub fn size(&self) -> u32 {
        self.inner_size()
            .expect("FAIL: .size() overflowed on too large of a type. construction should have failed!")
    }

    fn inner_size(&self) -> Option<u32> {
        match self {
            // NoType's may be asked for their size at runtime --
            //  legal constructions like `(ok 1)` have NoType parts (if they have unknown error variant types).
            NoType => Some(1),
            IntType => Some(16),
            UIntType => Some(16),
            BoolType => Some(1),
            // TODO: This principal size isn't quite right.
            //    it can be much larger due to contract principals.
            PrincipalType => Some(21),
            BufferType(len) => Some(u32::from(len)),
            TupleType(tuple_sig) => tuple_sig.inner_size(),
            ListType(list_type) => list_type.inner_size(),
            OptionalType(t) => t.size().checked_add(1),
            ResponseType(v) => {
                // ResponseTypes are 1 byte for the committed bool,
                //   plus max(err_type, ok_type)
                let (t, s) = (&v.0, &v.1);
                let t_size = t.size();
                let s_size = s.size();
                cmp::max(t_size, s_size)
                    .checked_add(1)
            },
        }
    }

    /// Returns the size of the _type signature_
    fn type_size(&self) -> Option<u32> {
        match self {
            // NoType's may be asked for their size at runtime --
            //  legal constructions like `(ok 1)` have NoType parts (if they have unknown error variant types).
            // These types all only use ~1 byte for their type enum
            NoType | IntType | UIntType | BoolType | PrincipalType => Some(1),
            // u32 length + type enum
            BufferType(len) => Some(1 + 4),
            TupleType(tuple_sig) => tuple_sig.type_size(),
            ListType(list_type) => list_type.type_size(),
            OptionalType(t) => {
                t.type_size()?
                    .checked_add(1)
            },
            ResponseType(v) => {
                let (t, s) = (&v.0, &v.1);
                t.type_size()?
                    .checked_add(s.type_size()?)?
                    .checked_add(1)
            },
        }
    }
}

impl ListTypeData {
    /// List Size: type_signature_size + max_len * entry_type.size() 
    fn inner_size(&self) -> Option<u32> {
        let total_size = self.entry_type.size()
            .checked_mul(self.max_len)?
            .checked_add(self.type_size()?)?;
        if total_size > MAX_VALUE_SIZE {
            None
        } else {
            Some(total_size)
        }
    }

    fn type_size(&self) -> Option<u32> {
        let total_size = self.entry_type.type_size()?
            .checked_add(4 + 1)?; // 1 byte for Type enum, 4 for max_len.
        if total_size > MAX_VALUE_SIZE {
            None
        } else {
            Some(total_size)
        }
    }
}

impl TupleTypeSignature {
    /// Tuple Size:
    ///    size( btreemap<name, type> ) = 2*map.len() + sum(names) + sum(values)
    fn type_size(&self) -> Option<u32> {
        let mut type_map_size = u32::try_from(self.type_map.len())
            .ok()?
            .checked_mul(2)?;

        for (name, type_signature) in self.type_map.iter() {
            // we only accept ascii names, so 1 char = 1 byte.
            type_map_size = type_map_size
                .checked_add(type_signature.type_size()?)?
                // name.len() is bound to MAX_STRING_LEN (128), so `as u32` won't ever truncate
                .checked_add(name.len() as u32)?;
        }

        if type_map_size > MAX_VALUE_SIZE {
            None
        } else {
            Some(type_map_size)
        }
    }

    /// Tuple Size:
    ///    size( btreemap<name, value> ) + type_size
    ///    size( btreemap<name, value> ) = 2*map.len() + sum(names) + sum(values)
    fn inner_size(&self) -> Option<u32> {
        let mut total_size = u32::try_from(self.type_map.len())
            .ok()?
            .checked_mul(2)?
            .checked_add(self.type_size()?)?;

        for (name, type_signature) in self.type_map.iter() {
            // we only accept ascii names, so 1 char = 1 byte.
            total_size = total_size
                .checked_add(type_signature.size())?
                // name.len() is bound to MAX_STRING_LEN (128), so `as u32` won't ever truncate
                .checked_add(name.len() as u32)?;
        }

        if total_size > MAX_VALUE_SIZE {
            None
        } else {
            Some(total_size)
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
                        Err(CheckErrors::BadSyntaxExpectedListOfPairs)
                    } else {
                        Ok((&as_vec[0], &as_vec[1]))
                    }
                } else {
                    Err(CheckErrors::BadSyntaxExpectedListOfPairs)
                }
            }).collect();

    // step 2: turn into a vec of (name, typesignature) pairs.
    let key_types: Result<Vec<_>> =
        (as_pairs?).iter().map(|(name_symbol, type_symbol)| {
            let name = name_symbol.match_atom()
                .ok_or(CheckErrors::BadSyntaxExpectedListOfPairs)?
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
        write!(f, "{}::{}", &*self.contract_identifier.to_string(), &*self.asset_name)
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


#[cfg(test)]
mod test {
    use super::*;
    use super::CheckErrors::*;

    fn fail_parse(val: &str) -> CheckErrors {
        use vm::ast::parse;
        let expr = &parse(&QualifiedContractIdentifier::transient(), val).unwrap()[0];
        TypeSignature::parse_type_repr(expr).unwrap_err()
    }

    #[test]
    fn type_signature_way_too_big() {
        // first_tuple.type_size ~= 131
        // second_tuple.type_size = k * (130+130)
        // to get a type-size greater than max_value all by itself,
        //   set k = 4033
        let first_tuple = TypeSignature::from("(tuple (a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 bool))");

        let mut keys = vec![];
        for i in 0..4033 {
            let key_name = ClarityName::try_from(format!("a{:0127}", i)).unwrap();
            let key_val = first_tuple.clone();
            keys.push((key_name, key_val));
        }

        assert_eq!(TupleTypeSignature::try_from(keys).unwrap_err(), ValueTooLarge);
    }

    #[test]
    fn test_construction() {
        let bad_type_descriptions = [
            ("(tuple)", EmptyTuplesNotAllowed),
            ("(list int int)", InvalidTypeDescription),
            ("(list 4294967296 int)", ValueTooLarge),
            ("(list 50 bazel)", UnknownTypeName("bazel".into())),
            ("(buff)", InvalidTypeDescription),
            ("(buff 4294967296)", ValueTooLarge),
            ("(buff int)", InvalidTypeDescription),
            ("(response int)", InvalidTypeDescription),
            ("(optional bazel)", UnknownTypeName("bazel".into())),
            ("(response bazel int)", UnknownTypeName("bazel".into())),
            ("(response int bazel)", UnknownTypeName("bazel".into())),
            ("bazel", UnknownTypeName("bazel".into())),
            ("()", InvalidTypeDescription),
            ("(1234)", InvalidTypeDescription),
            ("(int 3 int)", InvalidTypeDescription),
            ("1234", InvalidTypeDescription),
            ("(list 1 (buff 1048576))", ValueTooLarge),
            ("(list 4294967295 (buff 2))", ValueTooLarge),
            ("(list 2147483647 (buff 2))", ValueTooLarge),
            ("(tuple (l (buff 1048576)))", ValueTooLarge),
        ];

        for (desc, expected) in bad_type_descriptions.iter() {
            assert_eq!(&fail_parse(desc), expected);
        }

        let okay_types = [
            "(list 16 uint)",
            "(list 15 (response int bool))",
            "(list 15 (response bool int))",
            "(buff 1048576)",
            "(list 4400 bool)",
            "(tuple (l (buff 1048550)))",
        ];

        for desc in okay_types.iter() {
            TypeSignature::from(*desc); // panics on failed types.
        }
    }
}