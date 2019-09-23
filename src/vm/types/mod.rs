pub mod serialization;
mod signatures;

use std::{fmt, cmp};
use std::convert::{TryInto, TryFrom};
use std::collections::BTreeMap;

use address::c32;
use vm::representations::{ClarityName, ContractName, SymbolicExpression, SymbolicExpressionType};
use vm::errors::{RuntimeErrorType, CheckErrors, InterpreterResult as Result, IncomparableError, InterpreterError};
use util::hash;

pub use vm::types::signatures::{
    TupleTypeSignature, AssetIdentifier, FixedFunction,
    TypeSignature, FunctionType, ListTypeData, FunctionArg, parse_name_type_pairs,
    BUFF_64, BUFF_32, BUFF_20, BufferLength
};

pub const MAX_VALUE_SIZE: u32 = 1024 * 1024; // 1MB

#[derive(Debug, Clone, Eq, Serialize, Deserialize)]
pub struct TupleData {
    pub type_signature: TupleTypeSignature,
    pub data_map: BTreeMap<ClarityName, Value>
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuffData {
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Eq, Serialize, Deserialize)]
pub struct ListData {
    pub data: Vec<Value>,
    pub type_signature: ListTypeData
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct StandardPrincipalData(pub u8, pub [u8; 20]);

impl StandardPrincipalData {

    pub fn transient() -> StandardPrincipalData {
        Self(1, [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1])
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct QualifiedContractIdentifier {
    pub issuer: StandardPrincipalData,
    pub name: ContractName
}

impl QualifiedContractIdentifier {

    pub fn new(issuer: StandardPrincipalData, name: ContractName) -> QualifiedContractIdentifier {
        Self { issuer, name }
    }

    pub fn local(name: &str) -> Result<QualifiedContractIdentifier> {
        let name = name.to_string().try_into()?;
        Ok(Self::new(StandardPrincipalData::transient(), name))
    }

    pub fn transient() -> QualifiedContractIdentifier {
        let name = String::from("__transient").try_into().unwrap();
        Self { 
            issuer: StandardPrincipalData::transient(), 
            name
        }
    }

    pub fn parse(literal: &str) -> Result<QualifiedContractIdentifier> {
        let split: Vec<_> = literal.splitn(2, ".").collect();
        if split.len() != 2 {
            return Err(RuntimeErrorType::ParseError(
                "Invalid principal literal: expected a `.` in a qualified contract name".to_string()).into());
        }
        let sender = PrincipalData::parse_standard_principal(split[0])?;
        let name = split[1].to_string().try_into()?;
        Ok(QualifiedContractIdentifier::new(sender, name))
    }

    pub fn to_string(&self) -> String {
        format!("'{}.{}", self.issuer, self.name.to_string())
    }
}

impl fmt::Display for QualifiedContractIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum PrincipalData {
    Standard(StandardPrincipalData),
    Contract(QualifiedContractIdentifier),
}

pub enum ContractIdentifier {
    Relative(ContractName),
    Qualified(QualifiedContractIdentifier)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptionalData {
    pub data: Option<Box<Value>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseData {
    pub committed: bool,
    pub data: Box<Value>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum Value {
    Int(i128),
    UInt(u128),
    Bool(bool),
    Buffer(BuffData),
    List(ListData),
    Principal(PrincipalData),
    Tuple(TupleData),
    Optional(OptionalData),
    Response(ResponseData)
}

define_named_enum!(BlockInfoProperty {
    Time("time"),
    VrfSeed("vrf-seed"),
    HeaderHash("header-hash"),
    BurnchainHeaderHash("burnchain-header-hash"),
});

impl OptionalData {
    pub fn type_signature(&self) -> TypeSignature {
        match self.data {
            Some(ref v) => TypeSignature::new_option(TypeSignature::type_of(&v)),
            None => TypeSignature::new_option(TypeSignature::NoType)
        }
    }
}

impl ResponseData {
    pub fn type_signature(&self) -> TypeSignature {
        match self.committed {
            true => TypeSignature::new_response(
                TypeSignature::type_of(&self.data), TypeSignature::NoType),
            false => TypeSignature::new_response(
                TypeSignature::NoType, TypeSignature::type_of(&self.data))
        }
    }
}

impl BlockInfoProperty {
    pub fn type_result(&self) -> TypeSignature {
        use self::BlockInfoProperty::*;
        match self {
            Time => TypeSignature::IntType,
            VrfSeed | HeaderHash | BurnchainHeaderHash => BUFF_32.clone(),
        }
    }
}

impl PartialEq for ListData {
    fn eq(&self, other: &ListData) -> bool {
        self.data == other.data
    }
}

impl PartialEq for TupleData {
    fn eq(&self, other: &TupleData) -> bool {
        self.data_map == other.data_map
    }
}

pub const NONE: Value = Value::Optional(OptionalData { data: None });

impl Value {
    pub fn some(data: Value) -> Value {
        Value::Optional(OptionalData {
            data: Some(Box::new(data)) })
    }

    pub fn none() -> Value {
        NONE.clone()
    }

    pub fn okay(data: Value) -> Value {
        Value::Response(ResponseData { 
            committed: true,
            data: Box::new(data) })
    }

    pub fn error(data: Value) -> Value {
        Value::Response(ResponseData { 
            committed: false,
            data: Box::new(data) })
    }

    /// Invariant: the supplied Values have already been "checked", i.e., it's a valid Value object
    ///  this invariant is enforced through the Value constructors, each of which checks to ensure
    ///  that any typing data is correct.
    pub fn list_with_type(list_data: Vec<Value>, expected_type: ListTypeData) -> Result<Value> {
        // Constructors for TypeSignature ensure that the size of the Value cannot
        //   be greater than MAX_VALUE_SIZE (they error on such constructions)
        //   so we do not need to perform that check here.
        if (expected_type.get_max_len() as usize) < list_data.len() {
            return Err(InterpreterError::FailureConstructingListWithType.into())
        }

        {
            let expected_item_type = expected_type.get_list_item_type();

            for item in &list_data {
                if !expected_item_type.admits(&item) {
                    return Err(InterpreterError::FailureConstructingListWithType.into())
                }
            }
        }

        Ok(Value::List(ListData { data: list_data, type_signature: expected_type }))
    }

    pub fn list_from(list_data: Vec<Value>) -> Result<Value> {
        // Constructors for TypeSignature ensure that the size of the Value cannot
        //   be greater than MAX_VALUE_SIZE (they error on such constructions)
        // Aaron: at this point, we've _already_ allocated memory for this type.
        //     (e.g., from a (map...) call, or a (list...) call.
        //     this is a problem _if_ the static analyzer cannot already prevent
        //     this case. This applies to all the constructor size checks.
        let type_sig = TypeSignature::construct_parent_list_type(&list_data)?;
        Ok(Value::List(ListData { data: list_data, type_signature: type_sig }))
    }

    pub fn buff_from(buff_data: Vec<u8>) -> Result<Value> {
        // check the buffer size
        BufferLength::try_from(buff_data.len())?;
        // construct the buffer
        Ok(Value::Buffer(BuffData { data: buff_data }))
    }
}

impl fmt::Display for OptionalData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.data {
            Some(ref x) => write!(f, "(some {})", x),
            None => write!(f, "none")
        }
    }
}

impl fmt::Display for ResponseData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.committed {
            true => write!(f, "(ok {})", self.data),
            false => write!(f, "(err {})", self.data)
        }
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Value::Int(int) => write!(f, "{}", int),
            Value::UInt(int) => write!(f, "u{}", int),
            Value::Bool(boolean) => write!(f, "{}", boolean),
            Value::Buffer(vec_bytes) => write!(f, "0x{}", hash::to_hex(&vec_bytes.data)),
            Value::Tuple(data) => write!(f, "{}", data),
            Value::Principal(principal_data) => write!(f, "{}", principal_data),
            Value::Optional(opt_data) => write!(f, "{}", opt_data),
            Value::Response(res_data) => write!(f, "{}", res_data),
            Value::List(list_data) => {
                write!(f, "(")?;
                for (ix, v) in list_data.data.iter().enumerate() {
                    if ix > 0 {
                        write!(f, " ")?;
                    }
                    write!(f, "{}", v)?;
                }
                write!(f, ")")
            }
        }
    }
}

impl PrincipalData {
    pub fn parse_qualified_contract_principal(literal: &str) -> Result<PrincipalData> {
        let contract_id = QualifiedContractIdentifier::parse(literal)?;
        Ok(PrincipalData::Contract(contract_id))
    }

    pub fn parse_standard_principal(literal: &str) -> Result<StandardPrincipalData> {
        let (version, data) = c32::c32_address_decode(&literal)
            .map_err(|x| { RuntimeErrorType::ParseError(format!("Invalid principal literal: {}", x)) })?;
        if data.len() != 20 {
            return Err(RuntimeErrorType::ParseError(
                "Invalid principal literal: Expected 20 data bytes.".to_string()).into());
        }
        let mut fixed_data = [0; 20];
        fixed_data.copy_from_slice(&data[..20]);
        Ok(StandardPrincipalData(version, fixed_data))
    }
}

impl StandardPrincipalData {
    pub fn to_address(&self) -> String {
        c32::c32_address(self.0, &self.1[..])
            .unwrap_or_else(|_| "INVALID_C32_ADD".to_string())
    }
}

impl fmt::Display for StandardPrincipalData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let c32_str = self.to_address();
        write!(f, "{}", c32_str)
    }
}

impl fmt::Display for PrincipalData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PrincipalData::Standard(sender) => {
                write!(f, "'{}", sender)                
            },
            PrincipalData::Contract(contract_identifier) => {
                write!(f, "'{}.{}", contract_identifier.issuer, contract_identifier.name.to_string())
            }
        }
    }
}

impl From<StandardPrincipalData> for Value {
    fn from(principal: StandardPrincipalData) -> Self {
        Value::Principal(PrincipalData::from(principal))
    }
}

impl From<PrincipalData> for Value {
    fn from(p: PrincipalData) -> Self {
        Value::Principal(p)
    }
}

impl From<StandardPrincipalData> for PrincipalData {
    fn from(p: StandardPrincipalData) -> Self {
        PrincipalData::Standard(p)
    }
}

impl From<TupleData> for Value {
    fn from(t: TupleData) -> Self {
        Value::Tuple(t)
    }
}

impl TupleData {
    fn new(type_signature: TupleTypeSignature, data_map: BTreeMap<ClarityName, Value>) -> Result<TupleData> {
        let t = TupleData { type_signature, data_map };
        Ok(t)
    }

    pub fn from_data(mut data: Vec<(ClarityName, Value)>) -> Result<TupleData> {
        let mut type_map = BTreeMap::new();
        let mut data_map = BTreeMap::new();
        for (name, value) in data.drain(..) {
            let type_info = TypeSignature::type_of(&value);
            if type_map.contains_key(&name) {
                return Err(CheckErrors::NameAlreadyUsed(name.into()).into());
            } else {
                type_map.insert(name.clone(), type_info);
            }
            data_map.insert(name, value);
        }

        Self::new(TupleTypeSignature::try_from(type_map)?, data_map)
    }

    pub fn from_data_typed(mut data: Vec<(ClarityName, Value)>, expected: &TupleTypeSignature) -> Result<TupleData> {
        let mut data_map = BTreeMap::new();
        for (name, value) in data.drain(..) {
            let expected_type = expected.field_type(&name)
                .ok_or(InterpreterError::FailureConstructingTupleWithType)?;
            if !expected_type.admits(&value) {
                return Err(InterpreterError::FailureConstructingTupleWithType.into());
            }
            data_map.insert(name, value);
        }
        Self::new(expected.clone(), data_map)
    }

    pub fn get(&self, name: &str) -> Result<Value> {
        self.data_map.get(name)
            .cloned()
            .ok_or_else(|| CheckErrors::NoSuchTupleField(name.to_string(), self.type_signature.clone()).into())
    }
}

impl fmt::Display for TupleData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "(tuple")?;
        for (name, value) in self.data_map.iter() {
            write!(f, " ")?;
            write!(f, "({} {})", &**name, value)?;
        }
        write!(f, ")")
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_constructors() {
        assert_eq!(
            Value::list_with_type(
                vec![Value::Int(5), Value::Int(2)],
                ListTypeData::new_list(TypeSignature::BoolType, 3).unwrap()),
            Err(InterpreterError::FailureConstructingListWithType.into()));
        assert_eq!(
            ListTypeData::new_list(TypeSignature::IntType, MAX_VALUE_SIZE as u32),
            Err(CheckErrors::ValueTooLarge));

        assert_eq!(
            Value::buff_from(
                vec![0; (MAX_VALUE_SIZE+1) as usize]),
            Err(CheckErrors::ValueTooLarge.into()));

        // on 32-bit archs, this error cannot even happen, so don't test (and cause an overflow panic)
        if (u32::max_value() as usize) < usize::max_value() {
            assert_eq!(
                Value::buff_from(
                    vec![0; (u32::max_value() as usize) + 10]),
                Err(CheckErrors::ValueTooLarge.into()));
        }
    }
    #[test]
    fn test_some_displays() {
        assert_eq!(&format!("{}", Value::list_from(vec![Value::Int(10), Value::Int(5)]).unwrap()),
                   "(10 5)");
        assert_eq!(&format!("{}", Value::some(Value::Int(10))),
                   "(some 10)");
        assert_eq!(&format!("{}", Value::okay(Value::Int(10))),
                   "(ok 10)");
        assert_eq!(&format!("{}", Value::error(Value::Int(10))),
                   "(err 10)");
        assert_eq!(&format!("{}", Value::none()),
                   "none");
        assert_eq!(&format!("{}", Value::from(
            PrincipalData::parse_standard_principal("SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G").unwrap())),
                   "'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G");

        assert_eq!(&format!("{}", Value::from(TupleData::from_data(
            vec![("a".into(), Value::Int(2))]).unwrap())),
                   "(tuple (a 2))");
    }
}
