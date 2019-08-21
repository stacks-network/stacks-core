use vm::errors::{RuntimeErrorType, InterpreterResult};
use vm::types::{Value, OptionalData, PrincipalData};
use vm::database::{ClaritySerializable, ClarityDeserializable};

use std::collections::HashMap;
use serde_json::{Value as JSONValue};
use util::hash;

const TYPE_I128: &str = "i128";
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

fn to_hex(val: &i128) -> String {
    if *val >= 0 {
        format!("{:x}", val)
    } else {
        format!("-{:x}", -val)
    }
}

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

impl ClaritySerializable for Value {
    fn serialize(&self) -> String {
        use super::Value::*;
        use super::PrincipalData::*;

        match self {
            Int(value) => json_simple_object(TYPE_I128, &to_hex(value)),
            Buffer(value) => json_simple_object(TYPE_BUFF, &hash::bytes_to_hex(&value.data)),
            Bool(value) => {
                let str_value = if *value {
                    "true"
                } else {
                    "false"
                };
                json_recursive_object(TYPE_BOOL, str_value)
            },
            Principal(StandardPrincipal(data)) => {
                json_simple_object(TYPE_STANDARD_PRINCIPAL, &data.to_address())
            },
            Principal(ContractPrincipal(simple_name)) => {
                // NOTE: this should eventually panic, since "unresolved" contract principals
                //       should never be materialized to the database.
                format!(
                    r#"{{ "type": "{}", "issuer": ":none:", "name": "{}" }}"#,
                    TYPE_CONTRACT_PRINCIPAL, simple_name)
            },
            Principal(QualifiedContractPrincipal{ sender, name }) => {
                format!(
                    r#"{{ "type": "{}", "issuer": "{}", "name": "{}" }}"#,
                    TYPE_CONTRACT_PRINCIPAL, sender.to_address(), name)
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
                                format!(r#""{}": {}"#, key, value.serialize()))
                    .collect();
                let entries_str = entries.join(", ");
                format!(
                    r#"{{ "type": "{}", "entries": {{ {} }} }}"#,
                    TYPE_TUPLE, entries_str)
            }
        }
    }
}

fn parse_error(expected: &str, found: &str) -> RuntimeErrorType {
    RuntimeErrorType::ParseError(
        format!("Expected JSON object type = '{}' but found '{}'", expected, found))
}

impl Value {
    fn try_deserialize_parsed(json: JSONParser) -> InterpreterResult<Value> {
        match json {
            JSONParser::Simple { type_n, value } => {
                match type_n.as_str() {
                    TYPE_I128 => Ok(Value::Int(i128::from_str_radix(&value, 16).unwrap())),
                    TYPE_STANDARD_PRINCIPAL => Ok(Value::from(PrincipalData::parse_standard_principal(&value)?)),
                    TYPE_BUFF => Ok(Value::from(hash::hex_bytes(&value)
                                                .map_err(|e| RuntimeErrorType::ParseError("Bad hex string".into()))?)),
                    _ => Err(parse_error("i128|principal|buff", &type_n).into())
                }
            },
            JSONParser::Bool { type_n, value } => {
                if type_n == TYPE_BOOL {
                    Ok(Value::Bool(value))
                } else {
                    Err(parse_error("bool", &type_n).into())
                }
            },
            JSONParser::None { type_n } => {
                if type_n == TYPE_OPT_NONE {
                    Ok(Value::none())
                } else {
                    Err(parse_error("none", &type_n).into())
                }
            },
            JSONParser::Container { type_n, value } => {
                let deserialized_value = Value::try_deserialize_parsed(*value)?;
                match type_n.as_str() {
                    TYPE_RESP_OK => Ok(Value::okay(deserialized_value)),
                    TYPE_RESP_ERR => Ok(Value::error(deserialized_value)),
                    TYPE_OPT_SOME => Ok(Value::some(deserialized_value)),
                    _ => Err(parse_error("ok|err|some", &type_n).into())
                }
            },
            JSONParser::List { type_n, mut entries } => {
                if type_n == TYPE_LIST {
                    let items: InterpreterResult<_> = entries.drain(..).map(Value::try_deserialize_parsed).collect();
                    Ok(Value::list_from(items?)?)
                } else {
                    Err(parse_error("list", &type_n).into())
                }
            },
            JSONParser::Tuple { type_n, mut entries } => {
                if type_n == TYPE_TUPLE {
                    let deserialized_entries: InterpreterResult<_> = entries
                        .drain()
                        .map(|(key, json_val)| {
                            match Value::try_deserialize_parsed(json_val) {
                                Ok(value) => Ok((key, value)),
                                Err(x) => Err(x)
                            }
                        })
                        .collect();
                    Value::tuple_from_data(deserialized_entries?)
                } else {
                    Err(parse_error("tuple", &type_n).into())
                }
            },
            JSONParser::ContractPrincipal { type_n, issuer, name } => {
                if type_n == TYPE_CONTRACT_PRINCIPAL {
                    Ok(Value::from(
                        if issuer == ":none:" {
                            PrincipalData::ContractPrincipal(name)
                        } else {
                            PrincipalData::QualifiedContractPrincipal {
                                sender: PrincipalData::parse_standard_principal(&issuer)?,
                                name }
                        }
                    ))
                } else {
                    Err(parse_error("contract_principal", &type_n).into())
                }
            }
        }
    }

    fn try_deserialize(json: &str) -> InterpreterResult<Value> {
        let data: JSONParser = serde_json::from_str(json)?;
        Value::try_deserialize_parsed(data)
    }
}

impl ClarityDeserializable<Value> for Value {
    fn deserialize(json: &str) -> Self {
        Value::try_deserialize(json)
            .expect("ERROR: Failed to parse Clarity JSON")
    }
}
