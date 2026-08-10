// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! The JSON contract-interface (ABI) types. These are serialized inside the
//! stored contract analysis, so their shape is kernel-owned; the builder
//! that derives an interface from an engine's analysis stays with the
//! engine.

use std::collections::{BTreeMap, BTreeSet};

use clarity_types::types::signatures::CallableSubtype;
use clarity_types::types::{TupleTypeSignature, TypeSignature};
use clarity_types::{ClarityName, ClarityVersion};
use stacks_common::types::StacksEpochId;

use crate::errors::analysis::{StaticCheckError, StaticCheckErrorKind};
use crate::signatures::{FixedFunction, FunctionArg, FunctionType};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ContractInterfaceFunctionAccess {
    private,
    public,
    read_only,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContractInterfaceTupleEntryType {
    pub name: String,
    #[serde(rename = "type")]
    pub type_f: ContractInterfaceAtomType,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ContractInterfaceAtomType {
    none,
    int128,
    uint128,
    bool,
    principal,
    buffer {
        length: u32,
    },
    #[serde(rename = "string-utf8")]
    string_utf8 {
        length: u32,
    },
    #[serde(rename = "string-ascii")]
    string_ascii {
        length: u32,
    },
    tuple(Vec<ContractInterfaceTupleEntryType>),
    optional(Box<ContractInterfaceAtomType>),
    response {
        ok: Box<ContractInterfaceAtomType>,
        error: Box<ContractInterfaceAtomType>,
    },
    list {
        #[serde(rename = "type")]
        type_f: Box<ContractInterfaceAtomType>,
        length: u32,
    },
    trait_reference,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContractInterfaceFungibleTokens {
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContractInterfaceNonFungibleTokens {
    pub name: String,
    #[serde(rename = "type")]
    pub type_f: ContractInterfaceAtomType,
}

impl ContractInterfaceAtomType {
    pub fn from_tuple_type(tuple_type: &TupleTypeSignature) -> ContractInterfaceAtomType {
        ContractInterfaceAtomType::tuple(Self::vec_from_tuple_type(tuple_type))
    }

    pub fn vec_from_tuple_type(
        tuple_type: &TupleTypeSignature,
    ) -> Vec<ContractInterfaceTupleEntryType> {
        let mut out: Vec<_> = tuple_type
            .get_type_map()
            .iter()
            .map(|(name, sig)| ContractInterfaceTupleEntryType {
                name: name.to_string(),
                type_f: Self::from_type_signature(sig),
            })
            .collect();
        out.sort_unstable_by(|ty1, ty2| ty1.name.cmp(&ty2.name));
        out
    }

    pub fn from_type_signature(sig: &TypeSignature) -> ContractInterfaceAtomType {
        use clarity_types::types::SequenceSubtype::*;
        use clarity_types::types::StringSubtype::*;
        use clarity_types::types::TypeSignature::*;

        match sig {
            NoType => ContractInterfaceAtomType::none,
            IntType => ContractInterfaceAtomType::int128,
            UIntType => ContractInterfaceAtomType::uint128,
            BoolType => ContractInterfaceAtomType::bool,
            PrincipalType => ContractInterfaceAtomType::principal,
            CallableType(CallableSubtype::Principal(_)) => ContractInterfaceAtomType::principal,
            CallableType(CallableSubtype::Trait(_)) | TraitReferenceType(_) => {
                ContractInterfaceAtomType::trait_reference
            }
            ListUnionType(_) => ContractInterfaceAtomType::principal,
            TupleType(sig) => ContractInterfaceAtomType::from_tuple_type(sig),
            SequenceType(StringType(ASCII(len))) => {
                ContractInterfaceAtomType::string_ascii { length: len.into() }
            }
            SequenceType(StringType(UTF8(len))) => {
                ContractInterfaceAtomType::string_utf8 { length: len.into() }
            }
            SequenceType(BufferType(len)) => {
                ContractInterfaceAtomType::buffer { length: len.into() }
            }
            SequenceType(ListType(list_data)) => {
                let (type_f, length) = list_data.clone().destruct();
                ContractInterfaceAtomType::list {
                    type_f: Box::new(Self::from_type_signature(&type_f)),
                    length,
                }
            }
            OptionalType(sig) => {
                ContractInterfaceAtomType::optional(Box::new(Self::from_type_signature(sig)))
            }
            TypeSignature::ResponseType(boxed_sig) => {
                let (ok_sig, err_sig) = boxed_sig.as_ref();
                ContractInterfaceAtomType::response {
                    ok: Box::new(Self::from_type_signature(ok_sig)),
                    error: Box::new(Self::from_type_signature(err_sig)),
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContractInterfaceFunctionArg {
    pub name: String,
    #[serde(rename = "type")]
    pub type_f: ContractInterfaceAtomType,
}

impl ContractInterfaceFunctionArg {
    pub fn from_function_args(fnArgs: &[FunctionArg]) -> Vec<ContractInterfaceFunctionArg> {
        fnArgs
            .iter()
            .map(|fnArg| ContractInterfaceFunctionArg {
                name: fnArg.name.to_string(),
                type_f: ContractInterfaceAtomType::from_type_signature(&fnArg.signature),
            })
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContractInterfaceFunctionOutput {
    #[serde(rename = "type")]
    pub type_f: ContractInterfaceAtomType,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContractInterfaceFunction {
    pub name: String,
    pub access: ContractInterfaceFunctionAccess,
    pub args: Vec<ContractInterfaceFunctionArg>,
    pub outputs: ContractInterfaceFunctionOutput,
}

impl ContractInterfaceFunction {
    pub fn from_map(
        map: &BTreeMap<ClarityName, FunctionType>,
        access: ContractInterfaceFunctionAccess,
    ) -> Result<Vec<ContractInterfaceFunction>, StaticCheckError> {
        map.iter()
            .map(|(name, function_type)| {
                Ok(ContractInterfaceFunction {
                    name: name.clone().into(),
                    access: access.to_owned(),
                    outputs: ContractInterfaceFunctionOutput {
                        type_f: match function_type {
                            FunctionType::Fixed(FixedFunction { returns, .. }) => {
                                ContractInterfaceAtomType::from_type_signature(returns)
                            }
                            _ => return Err(StaticCheckErrorKind::Unreachable(
                                "Contract functions should only have fixed function return types!"
                                    .into(),
                            )
                            .into()),
                        },
                    },
                    args: match function_type {
                        FunctionType::Fixed(FixedFunction { args, .. }) => {
                            ContractInterfaceFunctionArg::from_function_args(args)
                        }
                        _ => {
                            return Err(StaticCheckErrorKind::Unreachable(
                                "Contract functions should only have fixed function arguments!"
                                    .into(),
                            )
                            .into());
                        }
                    },
                })
            })
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ContractInterfaceVariableAccess {
    constant,
    variable,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContractInterfaceVariable {
    pub name: String,
    #[serde(rename = "type")]
    pub type_f: ContractInterfaceAtomType,
    pub access: ContractInterfaceVariableAccess,
}

impl ContractInterfaceFungibleTokens {
    pub fn from_set(tokens: &BTreeSet<ClarityName>) -> Vec<Self> {
        tokens
            .iter()
            .map(|name| Self {
                name: name.to_string(),
            })
            .collect()
    }
}

impl ContractInterfaceNonFungibleTokens {
    pub fn from_map(assets: &BTreeMap<ClarityName, TypeSignature>) -> Vec<Self> {
        assets
            .iter()
            .map(|(name, type_sig)| Self {
                name: name.clone().into(),
                type_f: ContractInterfaceAtomType::from_type_signature(type_sig),
            })
            .collect()
    }
}

impl ContractInterfaceVariable {
    pub fn from_map(
        map: &BTreeMap<ClarityName, TypeSignature>,
        access: ContractInterfaceVariableAccess,
    ) -> Vec<ContractInterfaceVariable> {
        map.iter()
            .map(|(name, type_sig)| ContractInterfaceVariable {
                name: name.clone().into(),
                access: access.to_owned(),
                type_f: ContractInterfaceAtomType::from_type_signature(type_sig),
            })
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContractInterfaceMap {
    pub name: String,
    pub key: ContractInterfaceAtomType,
    pub value: ContractInterfaceAtomType,
}

impl ContractInterfaceMap {
    pub fn from_map(
        map: &BTreeMap<ClarityName, (TypeSignature, TypeSignature)>,
    ) -> Vec<ContractInterfaceMap> {
        map.iter()
            .map(|(name, (key_sig, val_sig))| ContractInterfaceMap {
                name: name.clone().into(),
                key: ContractInterfaceAtomType::from_type_signature(key_sig),
                value: ContractInterfaceAtomType::from_type_signature(val_sig),
            })
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContractInterface {
    pub functions: Vec<ContractInterfaceFunction>,
    pub variables: Vec<ContractInterfaceVariable>,
    pub maps: Vec<ContractInterfaceMap>,
    pub fungible_tokens: Vec<ContractInterfaceFungibleTokens>,
    pub non_fungible_tokens: Vec<ContractInterfaceNonFungibleTokens>,
    pub epoch: StacksEpochId,
    pub clarity_version: ClarityVersion,
}

impl ContractInterface {
    pub fn new(epoch: StacksEpochId, clarity_version: ClarityVersion) -> Self {
        Self {
            functions: Vec::new(),
            variables: Vec::new(),
            maps: Vec::new(),
            fungible_tokens: Vec::new(),
            non_fungible_tokens: Vec::new(),
            epoch,
            clarity_version,
        }
    }

    pub fn serialize(&self) -> Result<String, StaticCheckError> {
        serde_json::to_string(self).map_err(|_| {
            StaticCheckErrorKind::Unreachable("Failed to serialize contract interface".into())
                .into()
        })
    }
}

#[test]
fn test_string_rename_ascii() {
    let arg = ContractInterfaceFunctionArg {
        name: "test-name".into(),
        type_f: ContractInterfaceAtomType::string_ascii { length: 32 },
    };
    assert_eq!(
        serde_json::to_string(&arg).unwrap(),
        "{\"name\":\"test-name\",\"type\":{\"string-ascii\":{\"length\":32}}}"
    );
}

#[test]
fn test_string_rename_utf8() {
    let arg = ContractInterfaceFunctionArg {
        name: "test-utf8".into(),
        type_f: ContractInterfaceAtomType::string_utf8 { length: 32 },
    };
    assert_eq!(
        serde_json::to_string(&arg).unwrap(),
        "{\"name\":\"test-utf8\",\"type\":{\"string-utf8\":{\"length\":32}}}"
    );
}
