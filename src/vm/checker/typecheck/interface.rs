use std::collections::BTreeMap;

use vm::types::{TypeSignature, FunctionArg, AtomTypeIdentifier, TupleTypeSignature};
use vm::checker::typecheck::FunctionType;

#[derive(Debug, Serialize, Clone)]
pub enum ContractInterfaceFunctionAccess {
    private,
    public,
    read_only,
}

#[derive(Debug, Serialize)]
pub struct ContractInterfaceTupleType {
    pub name: String,
    #[serde(rename = "type")]
    pub type_f: ContractInterfaceAtomType,
}

#[derive(Debug, Serialize)]
pub enum ContractInterfaceAtomType {
    none,
    int128,
    bool,
    principal,
    buffer { length: u32 },
    tuple(Vec<ContractInterfaceTupleType>),
    optional(Box<ContractInterfaceAtomType>),
    response { ok: Box<ContractInterfaceAtomType>, error: Box<ContractInterfaceAtomType> },
    list { 
        #[serde(rename = "type")]
        type_f: Box<ContractInterfaceAtomType>, 
        length: u32, 
        dimension: u8 
    },
}

impl ContractInterfaceAtomType {

    pub fn from_tuple_type(tuple_type: &TupleTypeSignature) -> ContractInterfaceAtomType {
        ContractInterfaceAtomType::tuple( 
            Self::vec_from_tuple_type(&tuple_type)
        )
    }

    pub fn vec_from_tuple_type(tuple_type: &TupleTypeSignature) -> Vec<ContractInterfaceTupleType> {
        tuple_type.type_map.iter().map(|(name, sig)| 
            ContractInterfaceTupleType { 
                name: name.to_string(), 
                type_f: Self::from_type_signature(sig)
            }
        ).collect()
    }

    pub fn from_atom_type(atom_type: &AtomTypeIdentifier) -> ContractInterfaceAtomType {
        match atom_type {
            AtomTypeIdentifier::NoType => ContractInterfaceAtomType::none,
            AtomTypeIdentifier::IntType => ContractInterfaceAtomType::int128,
            AtomTypeIdentifier::BoolType => ContractInterfaceAtomType::bool,
            AtomTypeIdentifier::PrincipalType => ContractInterfaceAtomType::principal,
            AtomTypeIdentifier::BufferType(len) => ContractInterfaceAtomType::buffer { length: *len },
            AtomTypeIdentifier::TupleType(sig) => Self::from_tuple_type(sig),
            AtomTypeIdentifier::OptionalType(sig) => ContractInterfaceAtomType::optional(
                Box::new(Self::from_type_signature(&sig)) 
            ),
            AtomTypeIdentifier::ResponseType(boxed_sig) => {
                let (ok_sig, err_sig) = boxed_sig.as_ref();
                ContractInterfaceAtomType::response { 
                    ok: Box::new(Self::from_type_signature(&ok_sig)), 
                    error: Box::new(Self::from_type_signature(&err_sig))
                }
            }
        }
    }

    pub fn from_type_signature(sig: &TypeSignature) -> ContractInterfaceAtomType {
        match sig {
            TypeSignature::Atom(atom_type) => {
                Self::from_atom_type(atom_type)
            },
            TypeSignature::List(atom_type, list_data) => {
                ContractInterfaceAtomType::list {
                    type_f: Box::new(Self::from_atom_type(atom_type)),
                    length: list_data.max_len,
                    dimension: list_data.dimension
                }
            }
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ContractInterfaceFunctionArg {
    pub name: String,
    #[serde(rename = "type")]
    pub type_f: ContractInterfaceAtomType,
}

impl ContractInterfaceFunctionArg {
    pub fn from_function_args(fnArgs: &Vec<FunctionArg>) -> Vec<ContractInterfaceFunctionArg> {
        let mut args: Vec<ContractInterfaceFunctionArg> = Vec::new();
        for ref fnArg in fnArgs.iter() {
            args.push(ContractInterfaceFunctionArg { 
                name: fnArg.name.to_string(), 
                type_f: ContractInterfaceAtomType::from_type_signature(&fnArg.signature)
            });
        }
        args
    }
}

#[derive(Debug, Serialize)]
pub struct ContractInterfaceFunctionOutput {
    #[serde(rename = "type")]
    pub type_f: ContractInterfaceAtomType,
}

#[derive(Debug, Serialize)]
pub struct ContractInterfaceFunction {
    pub name: String,
    pub access: ContractInterfaceFunctionAccess,
    pub args: Vec<ContractInterfaceFunctionArg>,
    pub outputs: ContractInterfaceFunctionOutput,
}

impl ContractInterfaceFunction {
    pub fn from_map(map: &BTreeMap<String, FunctionType>, access: ContractInterfaceFunctionAccess) -> Vec<ContractInterfaceFunction> {
        map.iter().map(|(name, function_type)| {
            ContractInterfaceFunction {
                name: name.to_string(),
                access: access.to_owned(),
                outputs: ContractInterfaceFunctionOutput { 
                    type_f: match function_type {
                        FunctionType::Fixed(_, fnType) => {
                            ContractInterfaceAtomType::from_type_signature(&fnType)
                        },
                        FunctionType::Variadic(_, _) => panic!("Contract functions should never have a variadic return type!"),
                        FunctionType::UnionArgs(_, _) => panic!("Contract functions should never have a union return type!"),
                    }
                },
                args: match function_type {
                    FunctionType::Fixed(fnArgs, _) => {
                        ContractInterfaceFunctionArg::from_function_args(&fnArgs)
                    },
                    FunctionType::Variadic(_, _) => panic!("Contract functions should never have variadic arguments!"),
                    FunctionType::UnionArgs(_, _) => panic!("Contract functions should never have union arguments!"),
                }
            }
        }).collect()
    }
}

#[derive(Debug, Serialize, Clone)]
pub enum ContractInterfaceVariableAccess {
    constant,
    variable,
}

#[derive(Debug, Serialize)]
pub struct ContractInterfaceVariable { 
    pub name: String,
    #[serde(rename = "type")]
    pub type_f: ContractInterfaceAtomType,
    pub access: ContractInterfaceVariableAccess,
}

impl ContractInterfaceVariable {
    pub fn from_map(map: &BTreeMap<String, TypeSignature>, access: ContractInterfaceVariableAccess) -> Vec<ContractInterfaceVariable> {
        map.iter().map(|(name, type_sig)| {
            ContractInterfaceVariable {
                name: name.to_string(),
                access: access.to_owned(),
                type_f: ContractInterfaceAtomType::from_type_signature(type_sig),
            }
        }).collect()
    }
}

#[derive(Debug, Serialize)]
pub struct ContractInterfaceMap {
    pub name: String,
    pub key: Vec<ContractInterfaceTupleType>,
    pub value: Vec<ContractInterfaceTupleType>,
}

impl ContractInterfaceMap {
    pub fn from_map(map: &BTreeMap<String, (TypeSignature, TypeSignature)>) -> Vec<ContractInterfaceMap> {
        map.iter().map(|(name, (key_sig, val_sig))| {

            let key_type = match key_sig {
                TypeSignature::Atom(AtomTypeIdentifier::TupleType(tuple_sig)) => ContractInterfaceAtomType::vec_from_tuple_type(&tuple_sig),
                _ => panic!("Contract map key should always be a tuple type!")
            };

            let val_type = match val_sig {
                TypeSignature::Atom(AtomTypeIdentifier::TupleType(tuple_sig)) => ContractInterfaceAtomType::vec_from_tuple_type(&tuple_sig),
                _ => panic!("Contract map value should always be a tuple type!")
            };

            ContractInterfaceMap {
                name: name.to_string(),
                key: key_type,
                value: val_type,
            }
        }).collect()
    }
}

#[derive(Debug, Serialize)]
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

