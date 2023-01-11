use crate::vm::analysis::ContractAnalysis;
use crate::vm::docs::{get_input_type_string, get_output_type_string, get_signature};
use crate::vm::types::{FunctionType, Value};

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::types::StacksEpochId;
use crate::vm::ast::{build_ast_with_rules, ASTRules};
use crate::vm::contexts::GlobalContext;
use crate::vm::costs::LimitedCostTracker;
use crate::vm::types::QualifiedContractIdentifier;
use crate::vm::version::ClarityVersion;
use crate::vm::{self, ContractContext};

use stacks_common::consts::CHAIN_ID_TESTNET;

pub const DOCS_GENERATION_EPOCH: StacksEpochId = StacksEpochId::Epoch2_05;

#[derive(Serialize)]
pub struct ContractRef {
    pub public_functions: Vec<FunctionRef>,
    pub read_only_functions: Vec<FunctionRef>,
    pub error_codes: Vec<ErrorCode>,
}

#[derive(Serialize)]
pub struct FunctionRef {
    name: String,
    input_type: String,
    output_type: String,
    signature: String,
    description: String,
}

#[derive(Serialize)]
pub struct ErrorCode {
    pub name: String,
    #[serde(rename = "type")]
    pub value_type: String,
    pub value: String,
}

pub fn make_func_ref(func_name: &str, func_type: &FunctionType, description: &str) -> FunctionRef {
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
