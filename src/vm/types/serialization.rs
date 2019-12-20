use vm::errors::{RuntimeErrorType, InterpreterResult, InterpreterError, Error as ClarityError, CheckErrors};
use vm::types::{Value, StandardPrincipalData, OptionalData, PrincipalData, BufferLength,
                TypeSignature, TupleData, QualifiedContractIdentifier, ResponseData};
use vm::database::{ClaritySerializable, ClarityDeserializable};
use vm::representations::{ClarityName, ContractName};

use std::borrow::Borrow;
use std::convert::{TryFrom, TryInto};
use std::collections::HashMap;
use serde_json::{Value as JSONValue};
use util::hash;

use std::io::{Write, Read};

const TYPE_I128: &str = "i128";
const TYPE_U128: &str = "u128";
const TYPE_BOOL: &str = "bool";
const TYPE_BUFF: &str = "buff";
const TYPE_STANDARD_PRINCIPAL: &str = "principal";
const TYPE_CONTRACT_PRINCIPAL: &str = "contract_principal";
const TYPE_RESP_OK: &str = "ok";
const TYPE_RESP_ERR: &str = "err";
const TYPE_OPT_SOME: &str = "some";
const TYPE_OPT_NONE: &str = "none";
const TYPE_TUPLE: &str = "tuple";
const TYPE_LIST: &str = "list";

enum ContainerTypes { OPT_SOME, RESP_OK, RESP_ERR }

#[derive(Deserialize)]
#[serde(untagged, deny_unknown_fields)]
enum JSONParser {
    None {
        #[serde(rename="type")]
        type_n: String },
    Bool { 
        #[serde(rename="type")]
        type_n: String,
        value: bool },
    Simple { 
        #[serde(rename="type")]
        type_n: String,
        value: String },
    Container {
        #[serde(rename="type")]
        type_n: String,
        value: Box<JSONParser> },
    List {
        #[serde(rename="type")]
        type_n: String,
        entries: Vec<JSONParser> },
    Tuple {
        #[serde(rename="type")]
        type_n: String,
        entries: HashMap<String, JSONParser> },
    ContractPrincipal {
        #[serde(rename="type")]
        type_n: String,
        issuer: String,
        name: String
    }
}

macro_rules! make_to_hex {
    ($f_name:ident, $type:ty, $negation:expr) => {
        #[allow(unused_comparisons)]
        pub fn $f_name(mut val: $type) -> String {
            let mut result = vec![];
            let mut negated = "";
            
            if val < 0 {
                let (new_negated, new_val) = $negation(val);
                negated = new_negated;
                val = new_val;
            }

            loop {
                let digit = match (val % 16) as u8 {
                    x @  0 ..=  9 => b'0' + x,
                    x @ 10 ..= 15 => b'a' + (x - 10),
                    _ => panic!("number not in the range 0..15")
                };
                result.push(digit.into());
                val = val / 16;
                if val == 0 {
            break
                }
            }
            result.reverse();
            format!("{}{}", negated, std::str::from_utf8(&result)
                    .expect("ERROR: Hex serializer created non-utf8 string."))
        }
    }
}

make_to_hex!(i128_to_hex, i128, |x: i128| ("-", -x));
make_to_hex!(u128_to_hex, u128, |_x: u128| panic!("Negative UINT"));

fn json_simple_object(type_name: &str, val: &str) -> String {
    format!(
        r#"{{ "type": "{}", "value": "{}" }}"#,
        type_name, val)
}

fn json_recursive_object(type_name: &str, val: &str) -> String {
    format!(
        r#"{{ "type": "{}", "value": {} }}"#,
        type_name, val)
}

fn type_prefix(v: &Value) -> u8 {
    use super::Value::*;
    use super::PrincipalData::*;

    match v {
        Int(_) => 1,
        UInt(_) => 2,
        Buffer(_) => 3,
        Bool(value) => {
            if *value {
                4
            } else {
                5
            }
        },
        Principal(Standard(_)) => 6,
        Principal(Contract(_)) => 7,
        Response(response) => {
            if response.committed {
                8
            } else {
                9
            }
        },
        Optional(OptionalData{ data: None }) => 10,
        Optional(OptionalData{ data: Some(value) }) => 11,
        List(_) => 12,
        Tuple(_) => 13,
    }
}

trait ClarityValueSerializable<T: std::marker::Sized> {
    fn serialize_write<W: Write>(&self, w: &mut W) -> std::io::Result<()>;
    fn deserialize_read<R: Read>(r: &mut R) -> Result<T, SerializationError>;
}

impl ClarityValueSerializable<StandardPrincipalData> for StandardPrincipalData {
    fn serialize_write<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
        w.write_all(&[self.0])?;
        w.write_all(&self.1)
    }

    fn deserialize_read<R: Read>(r: &mut R) -> Result<Self, SerializationError> {
        let mut version = [0; 1];
        let mut data = [0; 20];
        r.read_exact(&mut version)?;
        r.read_exact(&mut data)?;
        Ok(StandardPrincipalData(version[0], data))
    }
}

macro_rules! serialize_guarded_string {
    ($Name:ident) => {

impl ClarityValueSerializable<$Name> for $Name {
    fn serialize_write<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
        w.write_all(&u32::try_from(self.as_str().len())
                    .unwrap()
                    .to_be_bytes())?;
        // self.as_bytes() is always len bytes, because this is only used for GuardedStrings
        //   which are a subset of ASCII
        w.write_all(self.as_str().as_bytes())
    }

    fn deserialize_read<R: Read>(r: &mut R) -> Result<Self, SerializationError> {
        let mut len = [0; 4];
        r.read_exact(&mut len)?;
        let len = u32::from_be_bytes(len);
        let mut data = vec![0; len as usize];
        r.read_exact(&mut data)?;

        String::from_utf8(data)
            .map_err(|_| "Non-UTF8 string data".into())
            .and_then(|x| $Name::try_from(x)
                      .map_err(|_| "Illegal Clarity string".into()))
    }
}

}}

serialize_guarded_string!(ClarityName);
serialize_guarded_string!(ContractName);

enum SerializationError {
    IoError(std::io::Error),
    BadTypeError(CheckErrors),
    DeserializationError(String),
}

impl From<std::io::Error> for SerializationError {
    fn from(e: std::io::Error) -> Self {
        // todo:: UnexpectedEOF should become a ParseError.
        SerializationError::IoError(e)
    }
}

impl From<&str> for SerializationError {
    fn from(e: &str) -> Self {
        SerializationError::DeserializationError(e.into())
    }
}

impl From<CheckErrors> for SerializationError {
    fn from(e: CheckErrors) -> Self {
        SerializationError::BadTypeError(e)
    }
}


impl Value {
    fn deserialize_read<R: Read>(r: &mut R) -> Result<Value, SerializationError> {
         use super::Value::*;
        use super::PrincipalData::*;

        let mut header = [0];
        r.read_exact(&mut header)?;
        match header[0] {
            1 => {
                let mut buffer = [0; 16];
                r.read_exact(&mut buffer)?;
                Ok(Int(i128::from_be_bytes(buffer)))
            },
            2 => {
                let mut buffer = [0; 16];
                r.read_exact(&mut buffer)?;
                Ok(UInt(u128::from_be_bytes(buffer)))
            },
            3 => {
                let mut buffer_len = [0; 4];
                r.read_exact(&mut buffer_len)?;
                let buffer_len = BufferLength::try_from(
                    u32::from_be_bytes(buffer_len))?;

                let mut data = vec![0; u32::from(buffer_len) as usize];

                r.read_exact(&mut data[..])?;

                // can safely unwrap, because the buffer length was _already_ checked.
                Ok(Value::buff_from(data).unwrap())
            },
            4 => Ok(Bool(true)),
            5 => Ok(Bool(false)),
            6 => {
                StandardPrincipalData::deserialize_read(r)
                    .map(Value::from)
            },
            7 => {
                let issuer = StandardPrincipalData::deserialize_read(r)?;
                let name = ContractName::deserialize_read(r)?;
                Ok(Value::from(QualifiedContractIdentifier { issuer, name }))
            },
            8 | 9 => {
                let committed = header[0] == 7;
                let data = Box::new(Value::deserialize_read(r)?);
                Ok(Response(ResponseData { committed, data }))
            },
            10 => Ok(Value::none()),
            11 => Ok(Value::some(Value::deserialize_read(r)?)),
            12 => {
                let mut len = [0; 4];
                r.read_exact(&mut len)?;
                let len = u32::from_be_bytes(len);
                let mut items = Vec::with_capacity(len as usize);
                for _i in 0..len {
                    items.push(Value::deserialize_read(r)?);
                }
                Value::list_from(items)
                    .map_err(|_| "Illegal list type".into())
            },
            13 => {
                let mut len = [0; 4];
                r.read_exact(&mut len)?;
                let len = u32::from_be_bytes(len);
                let mut items = Vec::with_capacity(len as usize);
                for _i in 0..len {
                    let key = ClarityName::deserialize_read(r)?;
                    let value = Value::deserialize_read(r)?;
                    items.push((key, value))
                }
                TupleData::from_data(items)
                    .map_err(|_| "Illegal tuple type".into())
                    .map(Value::from)
            },
            _ => {
                panic!("Foo")
            }
        }

    }

    fn serialize_write<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
        use super::Value::*;
        use super::PrincipalData::*;

        w.write_all(&[type_prefix(self)])?;
        match self {
            Int(value) => w.write_all(&value.to_be_bytes())?,
            UInt(value) => w.write_all(&value.to_be_bytes())?,
            Buffer(value) => {
                w.write_all(&(u32::from(value.len()).to_be_bytes()))?;
                w.write_all(&value.data)?
            }
            Principal(Standard(data)) => {
                data.serialize_write(w)?
            },
            Principal(Contract(contract_identifier)) => {
                contract_identifier.issuer.serialize_write(w)?;
                contract_identifier.name.serialize_write(w)?;
            },
            Response(response) => {
                response.data.serialize_write(w)?
            },
            // Bool types don't need any more data.
            Bool(_) => {},
            // None types don't need any more data.
            Optional(OptionalData{ data: None }) => {},
            Optional(OptionalData{ data: Some(value) }) => {
                value.serialize_write(w)?;
            },
            List(data) => {
                w.write_all(&data.len().to_be_bytes())?;
                for item in data.data.iter() {
                    item.serialize_write(w)?;
                }
            },
            Tuple(data) => {
                w.write_all(&u32::try_from(data.data_map.len())
                            .unwrap()
                            .to_be_bytes())?;
                for (key, value) in data.data_map.iter() {
                    key.serialize_write(w)?;
                    value.serialize_write(w)?;
                }
            }
        };

        Ok(())
    }
}

impl ClaritySerializable for Value {
    fn serialize(&self) -> String {
        use super::Value::*;
        use super::PrincipalData::*;

        match self {
            Int(value) => json_simple_object(TYPE_I128, &i128_to_hex(*value)),
            UInt(value) => json_simple_object(TYPE_U128, &u128_to_hex(*value)),
            Buffer(value) => json_simple_object(TYPE_BUFF, &hash::bytes_to_hex(&value.data)),
            Bool(value) => {
                let str_value = if *value {
                    "true"
                } else {
                    "false"
                };
                json_recursive_object(TYPE_BOOL, str_value)
            },
            Principal(Standard(data)) => {
                json_simple_object(TYPE_STANDARD_PRINCIPAL, &data.to_address())
            },
            Principal(Contract(contract_identifier)) => {
                format!(
                    r#"{{ "type": "{}", "issuer": "{}", "name": "{}" }}"#,
                    TYPE_CONTRACT_PRINCIPAL, contract_identifier.issuer.to_address(), contract_identifier.name.to_string())
            },
            Response(response) => {
                let type_name = if response.committed {
                    TYPE_RESP_OK
                } else {
                    TYPE_RESP_ERR
                };
                let value = response.data.serialize();
                json_recursive_object(type_name, &value)
            },
            Optional(OptionalData{ data: None }) => {
                format!(r#"{{ "type": "{}" }}"#, TYPE_OPT_NONE)
            },
            Optional(OptionalData{ data: Some(value) }) => {
                json_recursive_object(TYPE_OPT_SOME, &value.serialize()) 
           },
            List(data) => {
                let entries: Vec<String> = data.data
                    .iter().map(|x| x.serialize())
                    .collect();
                let entries_str = entries.join(", ");
                format!(
                    r#"{{ "type": "{}", "entries": [ {} ] }}"#,
                    TYPE_LIST, entries_str)
            },
            Tuple(data) => {
                let entries: Vec<String> = data.data_map
                    .iter().map(|(key, value)|
                                format!(r#""{}": {}"#, &**key, value.serialize()))
                    .collect();
                let entries_str = entries.join(", ");
                format!(
                    r#"{{ "type": "{}", "entries": {{ {} }} }}"#,
                    TYPE_TUPLE, entries_str)
            }
        }
    }
}

macro_rules! check_match {
    ($item:expr, $Pattern:pat) => {
        match $item {
            None => Ok(()),
            Some($Pattern) => Ok(()),
            Some(x) => Err(InterpreterError::DeserializeExpected(x.clone()))
        }
    }
}


impl Value {
    /// This function attempts to deserialize a JSONParser struct into a Clarity Value.
    ///   The `expected_type` parameter determines whether or not the deserializer should expect (and enforce)
    ///   a particular type. `ClarityDB` uses this to ensure that lists, tuples, etc. loaded from the database
    ///   have their max-length and other type information set by the type declarations in the contract.
    ///   If passed `None`, the deserializer will construct the values as if they were literals in the contract, e.g.,
    ///     list max length = the length of the list.
    fn try_deserialize_parsed(json: JSONParser, expected_type: Option<&TypeSignature>) -> InterpreterResult<Value> {
        match json {
            JSONParser::Simple { type_n, value } => {
                match type_n.as_str() {
                    TYPE_I128 => {
                        check_match!(expected_type, TypeSignature::IntType)?;
                        let value = i128::from_str_radix(&value, 16)
                            .map_err(|_| RuntimeErrorType::ParseError("Failed to parse hexstring as integer".into()))?;
                        Ok(Value::Int(value))
                    },
                    TYPE_U128 => {
                        check_match!(expected_type, TypeSignature::UIntType)?;
                        let value = u128::from_str_radix(&value, 16)
                            .map_err(|_| RuntimeErrorType::ParseError("Failed to parse hexstring as integer".into()))?;
                        Ok(Value::UInt(value))
                    },
                    TYPE_STANDARD_PRINCIPAL => {
                        check_match!(expected_type, TypeSignature::PrincipalType)?;
                        PrincipalData::parse_standard_principal(&value)
                            .map(|principal| Value::from(principal))
                    },
                    TYPE_BUFF => {
                        let bytes = hash::hex_bytes(&value)
                            .map_err(|_| RuntimeErrorType::ParseError("Bad hex string".into()))?;

                        match expected_type {
                            None => {},
                            Some(x) => {
                                let passed_test = match x {
                                    TypeSignature::BufferType(buff_len) => {
                                        bytes.len() <= (u32::from(buff_len) as usize)
                                    },
                                    _ => false
                                };
                                if !passed_test {
                                    return Err(InterpreterError::DeserializeExpected(x.clone()).into())
                                }
                            }
                        };

                        Value::buff_from(bytes)
                    },
                    _ => Err(InterpreterError::DeserializeUnexpectedTypeField(type_n).into())
                }
            },
            JSONParser::Bool { type_n, value } => {
                check_match!(expected_type, TypeSignature::BoolType)?;

                if type_n == TYPE_BOOL {
                    Ok(Value::Bool(value))
                } else {
                    Err(InterpreterError::DeserializeUnexpectedTypeField(type_n).into())
                }
            },
            JSONParser::None { type_n } => {
                check_match!(expected_type, TypeSignature::OptionalType(_))?;
                if type_n == TYPE_OPT_NONE {
                    Ok(Value::none())
                } else {
                    Err(InterpreterError::DeserializeUnexpectedTypeField(type_n).into())
                }
            },
            JSONParser::Container { type_n, value } => {
                let outer_type = match type_n.as_str() {
                    TYPE_RESP_OK => Ok(ContainerTypes::RESP_OK),
                    TYPE_RESP_ERR => Ok(ContainerTypes::RESP_ERR),
                    TYPE_OPT_SOME => Ok(ContainerTypes::OPT_SOME),
                    _ => Err(InterpreterError::DeserializeUnexpectedTypeField(type_n))
                }?;

                let expect_contained_type = match expected_type {
                    None => None,
                    Some(x) => {
                        let contained_type = match (&outer_type, x) {
                            (ContainerTypes::RESP_OK,  TypeSignature::ResponseType(types)) => Ok(&types.0),
                            (ContainerTypes::RESP_ERR, TypeSignature::ResponseType(types)) => Ok(&types.1),
                            (ContainerTypes::OPT_SOME, TypeSignature::OptionalType(some_type)) => Ok(some_type.as_ref()),
                            _ => Err(InterpreterError::DeserializeExpected(x.clone()))
                        }?;
                        Some(contained_type)
                    }
                };

                let deserialized_value = Value::try_deserialize_parsed(*value, expect_contained_type)?;
                match outer_type {
                    ContainerTypes::RESP_OK => Ok(Value::okay(deserialized_value)),
                    ContainerTypes::RESP_ERR => Ok(Value::error(deserialized_value)),
                    ContainerTypes::OPT_SOME => Ok(Value::some(deserialized_value))
                }
            },
            JSONParser::List { type_n, mut entries } => {
                if type_n != TYPE_LIST {
                    return Err(InterpreterError::DeserializeUnexpectedTypeField(type_n).into())
                }

                let (list_type, entry_type) = match expected_type {
                    None => (None, None),
                    Some(TypeSignature::ListType(list_type)) => (Some(list_type), Some(list_type.get_list_item_type())),
                    Some(x) => return Err(InterpreterError::DeserializeExpected(x.clone()).into())
                };

                let items: InterpreterResult<_> = entries
                    .drain(..)
                    .map(|value| Value::try_deserialize_parsed(value, entry_type))
                    .collect();

                if let Some(list_type) = list_type {
                    Value::list_with_type(items?, list_type.clone())
                } else {
                    Value::list_from(items?)
                }
            },
            JSONParser::Tuple { type_n, mut entries } => {
                if type_n != TYPE_TUPLE {
                    return Err(InterpreterError::DeserializeUnexpectedTypeField(type_n).into())
                }
                let tuple_type = match expected_type {
                    None => None,
                    Some(TypeSignature::TupleType(tuple_type)) => Some(tuple_type),
                    Some(x) => return Err(InterpreterError::DeserializeExpected(x.clone()).into())
                };

                let deserialized_entries: InterpreterResult<_> = entries
                    .drain()
                    .map(|(key, json_val)| {
                        let expected_field_type = match tuple_type {
                            None => None,
                            Some(some_tuple) => Some(
                                some_tuple
                                    .field_type(&key)
                                    .ok_or_else(|| RuntimeErrorType::ParseError(
                                        format!("Expected tuple type does not contain field '{}' but JSON does.", key)))?)
                        };
                        Ok((ClarityName::try_from(key)?, Value::try_deserialize_parsed(json_val, expected_field_type)?))
                    })
                    .collect();
                if let Some(tuple_type) = tuple_type {
                    TupleData::from_data_typed(deserialized_entries?, tuple_type)
                        .map(Value::from)
                } else {
                    TupleData::from_data(deserialized_entries?)
                        .map(Value::from)
                }
            },
            JSONParser::ContractPrincipal { type_n, issuer, name } => {
                if type_n != TYPE_CONTRACT_PRINCIPAL {
                    return Err(InterpreterError::DeserializeUnexpectedTypeField(type_n).into())
                }
                check_match!(expected_type, TypeSignature::PrincipalType)?;
                let name = name.try_into()?;
                let issuer = PrincipalData::parse_standard_principal(&issuer)?;
                let contract_identifier = QualifiedContractIdentifier::new(issuer, name);

                Ok(Value::from(PrincipalData::Contract(contract_identifier)))
            }
        }
    }

    pub fn try_deserialize(json: &str, expected: &TypeSignature) -> InterpreterResult<Value> {
        let data: JSONParser = serde_json::from_str(json)?;
        Value::try_deserialize_parsed(data, Some(expected))
    }

    pub fn try_deserialize_untyped(json: &str) -> InterpreterResult<Value> {
        let data: JSONParser = serde_json::from_str(json)?;
        Value::try_deserialize_parsed(data, None)
    }
}

impl Value {
    pub fn deserialize(json: &str, expected: &TypeSignature) -> Self {
        Value::try_deserialize(json, expected)
            .expect("ERROR: Failed to parse Clarity JSON")
    }
}


#[cfg(test)]
mod tests {
    use vm::database::ClaritySerializable;
    use vm::errors::Error;
    use super::super::*;
    use vm::types::TypeSignature::{IntType, BoolType};

    fn buff_type(size: u32) -> TypeSignature {
        TypeSignature::BufferType(size.try_into().unwrap()).into()
    }

    #[test]
    fn test_lists() {
        let serialized_0 = r#"
            { "type": "list",
              "entries": [ { "type": "list", "entries": [ { "type": "i128", "value": "1" }, 
                                                          { "type": "i128", "value": "2" }, 
                                                          { "type": "i128", "value": "3" } ] },
                           { "type": "list", "entries": [ { "type": "i128", "value": "1" }, 
                                                          { "type": "i128", "value": "2" }, 
                                                          { "type": "i128", "value": "3" } ] } ] }"#;

        let serialized_1 = r#"
            { "type": "list",
              "entries": [ { "type": "list", "entries": [ { "type": "i128", "value": "1" }, 
                                                          { "type": "i128", "value": "3" } ] },
                           { "type": "list", "entries": [ { "type": "i128", "value": "1" }, 
                                                          { "type": "i128", "value": "3" } ] },
                           { "type": "list", "entries": [ { "type": "i128", "value": "1" }, 
                                                          { "type": "i128", "value": "3" } ] } ] }"#;

        // Should be legal!
        Value::try_deserialize(
            serialized_0, &TypeSignature::from("(list 2 (list 3 int))")).unwrap();
        Value::try_deserialize(
            serialized_0, &TypeSignature::from("(list 3 (list 4 int))")).unwrap();

        assert_eq!(
            Value::try_deserialize(
                serialized_0, &TypeSignature::from("(list 2 (list 3 int))")).unwrap(),
            Value::try_deserialize_untyped(serialized_0).unwrap());

        // Fail because the atomic type isn't correct
        //  leads to an unexpected attempt to deserialize an int as bool.
        assert_eq!(Value::try_deserialize(
            serialized_0, &TypeSignature::from("(list 2 (list 3 bool))")).unwrap_err(),
                   InterpreterError::DeserializeExpected(
                       TypeSignature::BoolType).into());
        
        // Fail because the max_len isn't enough for the sublists
        assert_eq!(Value::try_deserialize(
            serialized_0, &TypeSignature::from("(list 2 (list 2 int))")).unwrap_err(),
                   InterpreterError::FailureConstructingListWithType.into());
        
        // Fail because the max_len isn't enough for the outer-list
        assert_eq!(Value::try_deserialize(
            serialized_0, &TypeSignature::from("(list 1 (list 3 int))")).unwrap_err(),
                   InterpreterError::FailureConstructingListWithType.into());
        
        // Fail because dimension is bad
        //  leads to an unexpected attempt to deserialize an int as list.
        assert!(match Value::try_deserialize(
            serialized_1, &TypeSignature::from("(list 3 (list 3 (list 3 int)))")).unwrap_err() {
            Error::Interpreter(InterpreterError::DeserializeExpected(_)) => true,
            _ => false
        });
        
        // Fail because we look like a list but the "TYPE" field is wrong
        assert!(match Value::try_deserialize(
            r#"{ "type": "listtt", "entries": []}"#,
            &TypeSignature::IntType).unwrap_err() {
            Error::Interpreter(InterpreterError::DeserializeUnexpectedTypeField(_)) => true,
            _ => false
        });

        assert!(match Value::try_deserialize_untyped(
            r#"{ "type": "listtt", "entries": []}"#).unwrap_err() {
            Error::Interpreter(InterpreterError::DeserializeUnexpectedTypeField(_)) => true,
            _ => false
        });

        // Fail because we look like a list but the expected type is not a list
        assert!(match Value::try_deserialize(
            r#"{ "type": "list", "entries": []}"#,
            &TypeSignature::IntType).unwrap_err() {
            Error::Interpreter(InterpreterError::DeserializeExpected(_)) => true,
            _ => false
        });
    }

    #[test]
    fn test_bools() {
        assert_eq!(Value::Bool(false).serialize(), r#"{ "type": "bool", "value": false }"#);
        assert_eq!(Value::Bool(true).serialize(), r#"{ "type": "bool", "value": true }"#);

        assert!(match Value::try_deserialize(
            r#"{ "type": "bol", "value": false}"#,
            &TypeSignature::BoolType).unwrap_err() {
            Error::Interpreter(InterpreterError::DeserializeUnexpectedTypeField(_)) => true,
            _ => false
        });

        assert!(match Value::try_deserialize_untyped(
            r#"{ "type": "bol", "value": false}"#).unwrap_err() {
            Error::Interpreter(InterpreterError::DeserializeUnexpectedTypeField(_)) => true,
            _ => false
        });

        assert!(match Value::try_deserialize(
            r#"{ "type": "bool", "value": false}"#,
            &TypeSignature::IntType).unwrap_err() {
            Error::Interpreter(InterpreterError::DeserializeExpected(_)) => true,
            _ => false
        });

        assert_eq!(
            Value::try_deserialize(
                r#"{ "type": "bool", "value": false}"#,
                &TypeSignature::BoolType).unwrap(),
            Value::try_deserialize_untyped(
                r#"{ "type": "bool", "value": false}"#).unwrap());
    }

    #[test]
    fn test_ints() {
        assert_eq!(Value::Int(-1).serialize(), r#"{ "type": "i128", "value": "-1" }"#);
        assert_eq!(Value::Int(15).serialize(), r#"{ "type": "i128", "value": "f" }"#);

        assert!(match Value::try_deserialize(
            r#"{ "type": "i125", "value": "-f"}"#,
            &TypeSignature::IntType).unwrap_err() {
            Error::Interpreter(InterpreterError::DeserializeUnexpectedTypeField(_)) => true,
            _ => false
        });

        assert!(match Value::try_deserialize_untyped(
            r#"{ "type": "i125", "value": "-f"}"#).unwrap_err() {
            Error::Interpreter(InterpreterError::DeserializeUnexpectedTypeField(_)) => true,
            _ => false
        });

        assert!(match Value::try_deserialize(
            r#"{ "type": "i128", "value": "-f"}"#,
            &TypeSignature::BoolType).unwrap_err() {
            Error::Interpreter(InterpreterError::DeserializeExpected(_)) => true,
            _ => false
        });

        assert!(match Value::try_deserialize(
            r#"{ "type": "i128", "value": "-xf"}"#,
            &TypeSignature::IntType).unwrap_err() {
            Error::Runtime(RuntimeErrorType::ParseError(_),_) => true,
            _ => false
        });

        assert!(match Value::try_deserialize_untyped(
            r#"{ "type": "i128", "value": "-xf"}"#).unwrap_err() {
            Error::Runtime(RuntimeErrorType::ParseError(_),_) => true,
            _ => false
        });

        assert_eq!(
            Value::try_deserialize(
                r#"{ "type": "i128", "value": "-1"}"#,
                &TypeSignature::IntType).unwrap(),
            Value::Int(-1));
        assert_eq!(
            Value::try_deserialize_untyped(
                r#"{ "type": "i128", "value": "-1"}"#).unwrap(),
            Value::Int(-1));
    }

    #[test]
    fn test_uints() {
        assert_eq!(Value::UInt(1).serialize(), r#"{ "type": "u128", "value": "1" }"#);
        assert_eq!(Value::UInt(15).serialize(), r#"{ "type": "u128", "value": "f" }"#);

        assert!(match Value::try_deserialize(
            r#"{ "type": "u128", "value": "-f"}"#,
            &TypeSignature::BoolType).unwrap_err() {
            Error::Interpreter(InterpreterError::DeserializeExpected(_)) => true,
            _ => false
        });

        assert!(match Value::try_deserialize(
            r#"{ "type": "u128", "value": "-f"}"#,
            &TypeSignature::UIntType).unwrap_err() {
            Error::Runtime(RuntimeErrorType::ParseError(_),_) => true,
            _ => false
        });

        assert!(match Value::try_deserialize(
            r#"{ "type": "u128", "value": "xf"}"#,
            &TypeSignature::UIntType).unwrap_err() {
            Error::Runtime(RuntimeErrorType::ParseError(_),_) => true,
            _ => false
        });

        assert_eq!(
            Value::try_deserialize(
                r#"{ "type": "u128", "value": "1"}"#,
                &TypeSignature::UIntType).unwrap(),
            Value::UInt(1));
        assert_eq!(
            Value::try_deserialize_untyped(
                r#"{ "type": "u128", "value": "1"}"#).unwrap(),
            Value::UInt(1));
    }

    #[test]
    fn test_opts() {
        let none =  r#"{ "type": "none" }"#;
        let some_int = r#"{ "type": "some", "value": { "type": "i128", "value": "f" } }"#;

        assert_eq!(Value::some(Value::Int(15)).serialize(), some_int);
        assert_eq!(Value::none().serialize(), none);

        assert!(match Value::try_deserialize(
            none,
            &TypeSignature::IntType).unwrap_err() {
            Error::Interpreter(InterpreterError::DeserializeExpected(_)) => true,
            _ => false
        });

        assert!(match Value::try_deserialize(
            some_int,
            &IntType).unwrap_err() {
            Error::Interpreter(InterpreterError::DeserializeExpected(_)) => true,
            _ => false
        });

        assert!(match Value::try_deserialize(
            some_int,
            &TypeSignature::from("(list 2 int)")).unwrap_err() {
            Error::Interpreter(InterpreterError::DeserializeExpected(_)) => true,
            _ => false
        });

        assert!(match Value::try_deserialize(
            r#"{ "type": "s0me", "value": { "type": "i128", "value": "f" } }"#,
            &TypeSignature::new_option(TypeSignature::IntType)).unwrap_err() {
            Error::Interpreter(InterpreterError::DeserializeUnexpectedTypeField(_)) => true,
            _ => false
        });

        assert!(match Value::try_deserialize_untyped(
            r#"{ "type": "s0me", "value": { "type": "i128", "value": "f" } }"#).unwrap_err() {
            Error::Interpreter(InterpreterError::DeserializeUnexpectedTypeField(_)) => true,
            _ => false
        });

        assert!(match Value::try_deserialize_untyped(
            r#"{ "type": "n0ne" }"#).unwrap_err() {
            Error::Interpreter(InterpreterError::DeserializeUnexpectedTypeField(_)) => true,
            _ => false
        });


        assert!(match Value::try_deserialize(
            r#"{ "type": "n0ne" }"#,
            &TypeSignature::new_option(TypeSignature::IntType)).unwrap_err() {
            Error::Interpreter(InterpreterError::DeserializeUnexpectedTypeField(_)) => true,
            _ => false
        });

        // Bad expected _contained_ type
        assert!(match Value::try_deserialize(
            some_int,
            &TypeSignature::new_option(TypeSignature::BoolType)).unwrap_err() {
            Error::Interpreter(InterpreterError::DeserializeExpected(x)) => x == TypeSignature::BoolType,
            _ => false
        });

        assert_eq!(
            Value::try_deserialize(
                some_int,
                &TypeSignature::new_option(TypeSignature::IntType)).unwrap(),
            Value::some(Value::Int(15)));
        assert_eq!(
            Value::try_deserialize(
                none,
                &TypeSignature::new_option(TypeSignature::IntType)).unwrap(),
            Value::none());
        assert_eq!(
            Value::try_deserialize(
                some_int,
                &TypeSignature::new_option(TypeSignature::IntType)).unwrap(),
            Value::some(Value::Int(15)));
        assert_eq!(
            Value::try_deserialize_untyped(some_int).unwrap(),
            Value::some(Value::Int(15)));
        assert_eq!(
            Value::try_deserialize_untyped(none).unwrap(),
            Value::none());

    }

    #[test]
    fn test_resp() {
        let ok_int =  r#"{ "type": "ok", "value": { "type": "i128", "value": "f" } }"#;
        let err_int = r#"{ "type": "err", "value": { "type": "i128", "value": "f" } }"#;

        assert_eq!(Value::okay(Value::Int(15)).serialize(), ok_int);
        assert_eq!(Value::error(Value::Int(15)).serialize(), err_int);

        // Bad expected types.

        assert!(match Value::try_deserialize(
            err_int,
            &TypeSignature::IntType).unwrap_err() {
            Error::Interpreter(InterpreterError::DeserializeExpected(_)) => true,
            _ => false
        });

        assert!(match Value::try_deserialize(
            ok_int,
            &TypeSignature::IntType).unwrap_err() {
            Error::Interpreter(InterpreterError::DeserializeExpected(_)) => true,
            _ => false
        });

        // Bad expected _contained_ type.

        assert!(match Value::try_deserialize(
            ok_int,
            &TypeSignature::new_response(TypeSignature::BoolType, TypeSignature::IntType)).unwrap_err() {
            Error::Interpreter(InterpreterError::DeserializeExpected(x)) => x == TypeSignature::BoolType,
            _ => false
        });

        assert!(match Value::try_deserialize(
            err_int,
            &TypeSignature::new_response(TypeSignature::IntType, TypeSignature::BoolType)).unwrap_err() {
            Error::Interpreter(InterpreterError::DeserializeExpected(x)) => x == TypeSignature::BoolType,
            _ => false
        });

        assert_eq!(
            Value::try_deserialize(
                ok_int,
                &TypeSignature::new_response(TypeSignature::IntType, TypeSignature::IntType)).unwrap(),
            Value::okay(Value::Int(15)));
        assert_eq!(
            Value::try_deserialize(
                err_int,
                &TypeSignature::new_response(TypeSignature::IntType, TypeSignature::IntType)).unwrap(),
            Value::error(Value::Int(15)));
        assert_eq!(
            Value::try_deserialize_untyped(ok_int).unwrap(),
            Value::okay(Value::Int(15)));
        assert_eq!(
            Value::try_deserialize_untyped(err_int).unwrap(),
            Value::error(Value::Int(15)));

    }

    #[test]
    fn test_hex() {
        use super::{i128_to_hex as to_hex};
        assert_eq!(&to_hex(-0xdeadbeef), "-deadbeef");
        assert_eq!(&to_hex(0xdeadbeef), "deadbeef");
        assert_eq!(&to_hex(0xdeadbdf), "deadbdf");
        assert_eq!(&to_hex(0xdadbc0ef), "dadbc0ef");
        assert_eq!(&to_hex(0xf8743000), "f8743000");
        assert_eq!(&to_hex(-0x00), "0");
    }

    #[test]
    fn test_buffs() {
        assert_eq!(Value::buff_from(vec![0,0,0,0]).unwrap().serialize(), 
                   r#"{ "type": "buff", "value": "00000000" }"#);
        assert_eq!(Value::buff_from(vec![0xde,0xad,0xbe,0xef]).unwrap().serialize(), 
                   r#"{ "type": "buff", "value": "deadbeef" }"#);
        assert_eq!(Value::buff_from(vec![0,0xde,0xad,0xbe,0xef,0]).unwrap().serialize(),
                   r#"{ "type": "buff", "value": "00deadbeef00" }"#);
        
        assert!(match Value::try_deserialize(
            r#"{ "type": "buff", "value": "00deadbeef00" }"#,
            &TypeSignature::BoolType).unwrap_err() {
            Error::Interpreter(InterpreterError::DeserializeExpected(_)) => true,
             _ => false
        });

        // fail because we expect a shorter buffer
        assert!(match Value::try_deserialize(
            r#"{ "type": "buff", "value": "00deadbeef00" }"#,
            &buff_type(4)).unwrap_err() {
            Error::Interpreter(InterpreterError::DeserializeExpected(_)) => true,
             _ => false
        });
        
        // fail because its a bad hex-string
        assert!(match Value::try_deserialize(
            r#"{ "type": "buff", "value": "00deadbeef0" }"#,
            &buff_type(6)).unwrap_err() {
            Error::Runtime(RuntimeErrorType::ParseError(_),_) => true,
            _ => false
        });

        assert_eq!(
            Value::try_deserialize(
            r#"{ "type": "buff", "value": "00deadbeef00" }"#,
            &buff_type(6)).unwrap(),
            Value::buff_from(vec![0,0xde,0xad,0xbe,0xef,0]).unwrap());
        assert_eq!(
            Value::try_deserialize_untyped(
                r#"{ "type": "buff", "value": "00deadbeef00" }"#).unwrap(),
            Value::buff_from(vec![0,0xde,0xad,0xbe,0xef,0]).unwrap());
    }

    #[test]
    fn test_tuples() {
        let t_1 = Value::from(TupleData::from_data(vec![
            ("a".into(), Value::Int(1)),
            ("b".into(), Value::Int(1))]).unwrap());
        let t_0 = Value::from(TupleData::from_data(vec![
            ("b".into(), Value::Int(1)),
            ("a".into(), Value::Int(1))]).unwrap());
        let t_2 = Value::from(TupleData::from_data(vec![
            ("a".into(), Value::Int(1)),
            ("b".into(), Value::Bool(true))]).unwrap());
        let t_3 = Value::from(TupleData::from_data(vec![
            ("a".into(), Value::Int(1))]).unwrap());
        assert_eq!(t_0.serialize(), r#"{ "type": "tuple", "entries": { "a": { "type": "i128", "value": "1" }, "b": { "type": "i128", "value": "1" } } }"#);
        assert_eq!(t_1.serialize(), r#"{ "type": "tuple", "entries": { "a": { "type": "i128", "value": "1" }, "b": { "type": "i128", "value": "1" } } }"#);
        assert_eq!(t_2.serialize(), r#"{ "type": "tuple", "entries": { "a": { "type": "i128", "value": "1" }, "b": { "type": "bool", "value": true } } }"#);
        assert_eq!(t_3.serialize(), r#"{ "type": "tuple", "entries": { "a": { "type": "i128", "value": "1" } } }"#);

        // JSON struct looks like tuple, but has bad type field.
        assert!(match Value::try_deserialize(
            r#"{ "type": "tople", "entries": {} }"#,
            &TypeSignature::type_of(&t_1)).unwrap_err() {
            Error::Interpreter(InterpreterError::DeserializeUnexpectedTypeField(_)) => true,
             _ => false
        });

        // bad expected type
        assert!(match Value::try_deserialize(
            r#"{ "type": "tuple", "entries": { "a": { "type": "i128", "value": "1" } } }"#,
            &TypeSignature::IntType).unwrap_err() {
            Error::Interpreter(InterpreterError::DeserializeExpected(_)) => true,
             _ => false
        });

        // non-existent field ("b" is in serialization, but not in expected type)
        assert!(match Value::try_deserialize(&t_0.serialize(), &TypeSignature::type_of(&t_3)).unwrap_err() {
            Error::Runtime(RuntimeErrorType::ParseError(_), _) => true,
             _ => false
        });

        // bad field type ("b" is int in serialization, but bool in expected type)
        assert!(match Value::try_deserialize(&t_0.serialize(), &TypeSignature::type_of(&t_2)).unwrap_err() {
            Error::Interpreter(InterpreterError::DeserializeExpected(x)) => x == TypeSignature::BoolType,
             _ => false
        });


        assert_eq!(&t_0, &t_1);
        assert_eq!(&Value::try_deserialize(&t_0.serialize(), &TypeSignature::type_of(&t_1)).unwrap(), &t_0);
        assert_eq!(&Value::try_deserialize(&t_0.serialize(), &TypeSignature::type_of(&t_0)).unwrap(), &t_0);
        assert_eq!(&Value::try_deserialize(&t_1.serialize(), &TypeSignature::type_of(&t_1)).unwrap(), &t_0);
        assert_eq!(&Value::try_deserialize(&t_1.serialize(), &TypeSignature::type_of(&t_0)).unwrap(), &t_0);
        assert_eq!(&Value::try_deserialize(&t_2.serialize(), &TypeSignature::type_of(&t_2)).unwrap(), &t_2);
        assert_eq!(&Value::try_deserialize(&t_3.serialize(), &TypeSignature::type_of(&t_3)).unwrap(), &t_3);
        assert_eq!(Value::try_deserialize(&t_3.serialize(), &TypeSignature::type_of(&t_3)).unwrap(), 
                   Value::try_deserialize_untyped(&t_3.serialize()).unwrap());
        assert_eq!(Value::try_deserialize(&t_2.serialize(), &TypeSignature::type_of(&t_2)).unwrap(), 
                   Value::try_deserialize_untyped(&t_2.serialize()).unwrap());
        assert_eq!(Value::try_deserialize(&t_1.serialize(), &TypeSignature::type_of(&t_1)).unwrap(), 
                   Value::try_deserialize_untyped(&t_1.serialize()).unwrap());
        assert_eq!(Value::try_deserialize(&t_0.serialize(), &TypeSignature::type_of(&t_0)).unwrap(), 
                   Value::try_deserialize_untyped(&t_0.serialize()).unwrap());
    }

    #[test]
    fn test_principals() {
        let issuer = PrincipalData::parse_standard_principal("SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G").unwrap();
        let standard_p = Value::from(issuer.clone());

        let contract_identifier = QualifiedContractIdentifier::new(issuer, "foo".into());
        let contract_p2 = Value::from(PrincipalData::Contract(contract_identifier));

        assert_eq!(standard_p.serialize(), r#"{ "type": "principal", "value": "SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G" }"#);
        assert_eq!(contract_p2.serialize(), r#"{ "type": "contract_principal", "issuer": "SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G", "name": "foo" }"#);
        
        assert!(match Value::try_deserialize(
            r#"{ "type": "principal", "value": "SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G" }"#,
            &TypeSignature::BoolType).unwrap_err() {
            Error::Interpreter(InterpreterError::DeserializeExpected(_)) => true,
             _ => false
        });

        // fail because it looks like a contract principal, but has the wrong type field.
        assert!(match Value::try_deserialize(
            r#"{ "type": "contract__principal", "issuer": "SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G", "name": "foo" }"#,
            &TypeSignature::PrincipalType).unwrap_err() {
            Error::Interpreter(InterpreterError::DeserializeUnexpectedTypeField(_)) => true,
             _ => false
        });

        // fail because of expected type mismatch
        assert!(match Value::try_deserialize(
            r#"{ "type": "contract_principal", "issuer": "SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G", "name": "foo" }"#,
            &TypeSignature::BoolType).unwrap_err() {
            Error::Interpreter(InterpreterError::DeserializeExpected(_)) => true,
             _ => false
        });

        // fail because its a bad address
        assert!(match Value::try_deserialize(
            r#"{ "type": "principal", "value": "SM2J6ZY48GV1EZ5V2V5RB9MP63SW86PYKKQVX8X0G" }"#,
            &TypeSignature::PrincipalType).unwrap_err() {
            Error::Runtime(RuntimeErrorType::ParseError(_),_) => true,
            _ => false
        });

        assert!(match Value::try_deserialize(
            r#"{ "type": "contract_principal", "issuer": "SM2J6ZY48GV1EZ5V2V5RB9MP62SW86PYKKQVX8X0G", "name": "foo" }"#,
            &TypeSignature::PrincipalType).unwrap_err() {
            Error::Runtime(RuntimeErrorType::ParseError(_),_) => true,
             _ => false
        });

        assert_eq!(
            &(Value::try_deserialize(
                r#"{ "type": "principal", "value": "SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G" }"#,
                &TypeSignature::PrincipalType).unwrap()),
            &standard_p);

        assert_eq!(
            &(Value::try_deserialize(
                r#"{ "type": "contract_principal", "issuer": "SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G", "name": "foo" }"#,
                &TypeSignature::PrincipalType).unwrap()),
            &contract_p2);

        assert_eq!(
            Value::try_deserialize_untyped(
                r#"{ "type": "principal", "value": "SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G" }"#).unwrap(),
            standard_p);

        assert_eq!(
            Value::try_deserialize_untyped(
                r#"{ "type": "contract_principal", "issuer": "SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G", "name": "foo" }"#).unwrap(),
            contract_p2);
    }

}
