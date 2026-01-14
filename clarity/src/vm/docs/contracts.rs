// Copyright (C) 2026 Stacks Open Internet Foundation
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
use std::collections::{BTreeMap, HashMap, HashSet};

use stacks_common::consts::CHAIN_ID_TESTNET;
use stacks_common::types::StacksEpochId;

use crate::vm::analysis::{ContractAnalysis, mem_type_check};
use crate::vm::ast::build_ast;
use crate::vm::contexts::GlobalContext;
use crate::vm::costs::LimitedCostTracker;
use crate::vm::database::MemoryBackingStore;
use crate::vm::docs::{get_input_type_string, get_output_type_string, get_signature};
use crate::vm::types::{FunctionType, QualifiedContractIdentifier, Value};
use crate::vm::version::ClarityVersion;
use crate::vm::{self, ContractContext};

const DOCS_GENERATION_EPOCH: StacksEpochId = StacksEpochId::Epoch2_05;

#[derive(Serialize)]
pub struct ContractRef {
    public_functions: Vec<FunctionRef>,
    read_only_functions: Vec<FunctionRef>,
    error_codes: Vec<ErrorCode>,
}

#[derive(Serialize)]
struct FunctionRef {
    name: String,
    input_type: String,
    output_type: String,
    signature: String,
    description: String,
}

#[derive(Serialize)]
struct ErrorCode {
    name: String,
    #[serde(rename = "type")]
    value_type: String,
    value: String,
}

pub struct ContractSupportDocs {
    pub descriptions: HashMap<&'static str, &'static str>,
    pub skip_func_display: HashSet<&'static str>,
}

#[allow(clippy::expect_used)]
fn make_func_ref(func_name: &str, func_type: &FunctionType, description: &str) -> FunctionRef {
    let input_type = get_input_type_string(func_type);
    let output_type = get_output_type_string(func_type);
    let signature = get_signature(func_name, func_type)
        .expect("BUG: failed to build signature for boot contract");
    FunctionRef {
        input_type,
        output_type,
        signature,
        name: func_name.to_string(),
        description: description.to_string(),
    }
}

#[allow(clippy::expect_used)]
fn get_constant_value(var_name: &str, contract_content: &str) -> Value {
    let to_eval = format!("{contract_content}\n{var_name}");
    doc_execute(&to_eval)
        .expect("BUG: failed to evaluate contract for constant value")
        .expect("BUG: failed to return constant value")
}

fn doc_execute(program: &str) -> Result<Option<Value>, vm::VmExecutionError> {
    let contract_id = QualifiedContractIdentifier::transient();
    let mut contract_context = ContractContext::new(contract_id.clone(), ClarityVersion::Clarity2);
    let mut marf = MemoryBackingStore::new();
    let conn = marf.as_clarity_db();
    let mut global_context = GlobalContext::new(
        false,
        CHAIN_ID_TESTNET,
        conn,
        LimitedCostTracker::new_free(),
        DOCS_GENERATION_EPOCH,
    );
    global_context.execute(|g| {
        let parsed = build_ast(
            &contract_id,
            program,
            &mut (),
            ClarityVersion::latest(),
            StacksEpochId::latest(),
        )?
        .expressions;
        vm::eval_all(&parsed, &mut contract_context, g, None)
    })
}

#[allow(clippy::expect_used)]
pub fn make_docs(
    content: &str,
    support_docs: &ContractSupportDocs,
    version: ClarityVersion,
) -> ContractRef {
    let (_, contract_analysis) = mem_type_check(content, version, StacksEpochId::latest())
        .expect("BUG: failed to type check boot contract");

    let ContractAnalysis {
        public_function_types,
        read_only_function_types,
        variable_types,
        ..
    } = contract_analysis;
    let public_functions: Vec<_> = public_function_types
        .iter()
        .filter(|(func_name, _)| !support_docs.skip_func_display.contains(func_name.as_str()))
        .map(|(func_name, func_type)| {
            let description = support_docs
                .descriptions
                .get(func_name.as_str())
                .unwrap_or_else(|| panic!("BUG: no description for {}", func_name.as_str()));
            make_func_ref(func_name, func_type, description)
        })
        .collect();

    let read_only_functions: Vec<_> = read_only_function_types
        .iter()
        .filter(|(func_name, _)| !support_docs.skip_func_display.contains(func_name.as_str()))
        .map(|(func_name, func_type)| {
            let description = support_docs
                .descriptions
                .get(func_name.as_str())
                .unwrap_or_else(|| panic!("BUG: no description for {}", func_name.as_str()));
            make_func_ref(func_name, func_type, description)
        })
        .collect();

    let ecode_names = variable_types
        .iter()
        .filter_map(|(var_name, _)| {
            if var_name.starts_with("ERR_") {
                Some(format!("{}: {}", var_name.as_str(), var_name.as_str()))
            } else {
                None
            }
        })
        .collect::<Vec<_>>()
        .join(", ");
    let ecode_to_eval = format!("{content}\n {{ {ecode_names} }}");
    let ecode_result = doc_execute(&ecode_to_eval)
        .expect("BUG: failed to evaluate contract for constant value")
        .expect("BUG: failed to return constant value")
        .expect_tuple()
        .expect("BUG: failed to build tuple");

    let error_codes = variable_types
        .iter()
        .filter_map(|(var_name, type_signature)| {
            if var_name.starts_with("ERR_") {
                let value = ecode_result
                    .get(var_name)
                    .expect("BUG: failed to fetch tuple entry from ecode output")
                    .to_string();
                Some(ErrorCode {
                    name: var_name.to_string(),
                    value,
                    value_type: type_signature.to_string(),
                })
            } else {
                None
            }
        })
        .collect();

    ContractRef {
        public_functions,
        read_only_functions,
        error_codes,
    }
}

/// Produce a set of documents for multiple contracts, supplied as a list of `(contract_name, contract_content)` pairs,
///  and a map from `contract_name` to corresponding `ContractSupportDocs`
pub fn produce_docs_refs<A: AsRef<str>, B: AsRef<str>>(
    contracts: &[(A, B)],
    support_docs: &HashMap<&str, ContractSupportDocs>,
    version: ClarityVersion,
) -> BTreeMap<String, ContractRef> {
    let mut docs = BTreeMap::new();

    for (contract_name, content) in contracts.iter() {
        if let Some(contract_support) = support_docs.get(contract_name.as_ref()) {
            let contract_ref = make_docs(content.as_ref(), contract_support, version);

            docs.insert(contract_name.as_ref().to_string(), contract_ref);
        }
    }

    docs
}
