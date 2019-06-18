use std::collections::BTreeMap;

use vm::types::{TypeSignature, FunctionArg, AtomTypeIdentifier, TupleTypeSignature};
use vm::checker::typecheck::FunctionType;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContractInterfaceFunctionAccess {
    private,
    public,
    read_only,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractInterfaceTupleType {
    pub name: String,
    pub r#type: ContractInterfaceAtomType,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContractInterfaceAtomType {
    none,
    int128,
    bool,
    buffer { length: u32 },
    principal,
    tuple { types: Vec<ContractInterfaceTupleType> },
    optional { r#type: Box<ContractInterfaceAtomType> },
    response { ok: Box<ContractInterfaceAtomType>, error: Box<ContractInterfaceAtomType> },
    list { r#type: Box<ContractInterfaceAtomType>, max_len: u32, dimension: u8 },
}

impl ContractInterfaceAtomType {

    pub fn from_tuple_type(tuple_type: &TupleTypeSignature) -> ContractInterfaceAtomType {
        ContractInterfaceAtomType::tuple { 
            types: tuple_type.type_map.iter().map(|(name, sig)| 
                ContractInterfaceTupleType { 
                    name: name.to_string(), 
                    r#type: Self::from_type_signature(sig)
                }
            ).collect()
        }
    }

    pub fn from_atom_type(atom_type: &AtomTypeIdentifier) -> ContractInterfaceAtomType {
        match atom_type {
            AtomTypeIdentifier::AnyType => panic!("Contract functions should never return `{}`", atom_type),
            AtomTypeIdentifier::NoType => ContractInterfaceAtomType::none,
            AtomTypeIdentifier::IntType => ContractInterfaceAtomType::int128,
            AtomTypeIdentifier::BoolType => ContractInterfaceAtomType::bool,
            AtomTypeIdentifier::BufferType(len) => ContractInterfaceAtomType::buffer { length: *len },
            AtomTypeIdentifier::PrincipalType => ContractInterfaceAtomType::principal,
            AtomTypeIdentifier::TupleType(sig) => Self::from_tuple_type(sig),
            AtomTypeIdentifier::OptionalType(sig) => ContractInterfaceAtomType::optional { 
                r#type: Box::new(Self::from_type_signature(&sig)) 
            },
            AtomTypeIdentifier::ResponseType(sig) => ContractInterfaceAtomType::response { 
                ok: Box::new(Self::from_type_signature(&sig.0)), 
                error: Box::new(Self::from_type_signature(&sig.1))
            },
        }
    }

    pub fn from_type_signature(sig: &TypeSignature) -> ContractInterfaceAtomType {
        match sig {
            TypeSignature::Atom(atom_type) => {
                Self::from_atom_type(atom_type)
            },
            TypeSignature::List(atom_type, list_data) => {
                ContractInterfaceAtomType::list {
                    r#type: Box::new(Self::from_atom_type(atom_type)),
                    max_len: list_data.max_len,
                    dimension: list_data.dimension
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractInterfaceFunctionArg {
    pub name: String,
    pub r#type: ContractInterfaceAtomType,
}

impl ContractInterfaceFunctionArg {
    pub fn from_function_args(fnArgs: &Vec<FunctionArg>) -> Vec<ContractInterfaceFunctionArg> {
        let mut args: Vec<ContractInterfaceFunctionArg> = Vec::new();
        for ref fnArg in fnArgs.iter() {
            args.push(ContractInterfaceFunctionArg { 
                name: fnArg.name.to_string(), 
                r#type: ContractInterfaceAtomType::from_type_signature(&fnArg.signature)
            });
        }
        args
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractInterfaceFunctionOutput {
    pub r#type: ContractInterfaceAtomType,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractInterfaceFunction {
    pub name: String,
    pub access: ContractInterfaceFunctionAccess,
    pub args: Vec<ContractInterfaceFunctionArg>,
    pub r#return: ContractInterfaceFunctionOutput,
}

impl ContractInterfaceFunction {
    pub fn from_map(map: &BTreeMap<String, FunctionType>, access: ContractInterfaceFunctionAccess) -> Vec<ContractInterfaceFunction> {
        map.iter().map(|(name, function_type)| {
            ContractInterfaceFunction {
                name: name.to_string(),
                access: access.to_owned(),
                r#return: ContractInterfaceFunctionOutput { 
                    r#type: match function_type {
                        FunctionType::Fixed(_, fnType) => {
                            ContractInterfaceAtomType::from_type_signature(&fnType)
                        },
                        FunctionType::Variadic(_, _) => panic!("Contract functions should never have a variadic return type!")
                    }
                },
                args: match function_type {
                    FunctionType::Fixed(fnArgs, _) => {
                        ContractInterfaceFunctionArg::from_function_args(&fnArgs)
                    },
                    FunctionType::Variadic(_, _) => panic!("Contract functions should never have variadic arguments!")
                }
            }
        }).collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContractInterfaceVariableAccess {
    constant,
    variable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractInterfaceVariable { 
    pub name: String,
    pub r#type: ContractInterfaceAtomType,
    pub access: ContractInterfaceVariableAccess,
}

impl ContractInterfaceVariable {
    pub fn from_map(map: &BTreeMap<String, TypeSignature>, access: ContractInterfaceVariableAccess) -> Vec<ContractInterfaceVariable> {
        map.iter().map(|(name, type_sig)| {
            ContractInterfaceVariable {
                name: name.to_string(),
                access: access.to_owned(),
                r#type: ContractInterfaceAtomType::from_type_signature(type_sig),
            }
        }).collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractInterfaceMap {
    pub name: String,
    pub key_name: String,
    pub key_type: ContractInterfaceAtomType,
    pub value_name: String,
    pub value_type: ContractInterfaceAtomType,
}

impl ContractInterfaceMap {
    pub fn from_map(map: &BTreeMap<String, (TypeSignature, TypeSignature)>) -> Vec<ContractInterfaceMap> {
        map.iter().map(|(name, (key_sig, val_sig))| {

            let key_map = match key_sig {
                TypeSignature::Atom(AtomTypeIdentifier::TupleType(tuple_sig)) => &tuple_sig.type_map,
                _ => panic!("Contract map key should always be a tuple type!")
            };
            let (key_name, key_type) = key_map.iter().nth(0)
                .expect("Contract map key tuple should have a first entry!");

            let val_map = match val_sig {
                TypeSignature::Atom(AtomTypeIdentifier::TupleType(tuple_sig)) => &tuple_sig.type_map,
                _ => panic!("Contract map value should always be a tuple type!")
            };
            let (val_name, val_type) = val_map.iter().nth(0)
                .expect("Contract map value tuple should have a first entry!");

            ContractInterfaceMap {
                name: name.to_string(),
                key_name: key_name.to_string(),
                key_type: ContractInterfaceAtomType::from_type_signature(&key_type),
                value_name: val_name.to_string(),
                value_type: ContractInterfaceAtomType::from_type_signature(&val_type),
            }
        }).collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractInterface {
    pub functions: Vec<ContractInterfaceFunction>,
    pub variables: Vec<ContractInterfaceVariable>,
    pub maps: Vec<ContractInterfaceMap>,
}

impl ContractInterface {
    pub fn serialize(&self) -> String {
        serde_json::to_string(self).expect("Failed to serialize contract interface")
    }
}