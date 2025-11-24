mod trait_counter;
use std::collections::HashMap;

use clarity_types::types::{CharType, SequenceData};
pub use trait_counter::{
    TraitCount, TraitCountCollector, TraitCountContext, TraitCountPropagator, TraitCountVisitor,
};

// Import types from analysis.rs
use crate::vm::costs::analysis::{
    CostAnalysisNode, CostExprNode, StaticCost, SummingExecutionCost,
};
use crate::vm::costs::cost_functions::{linear, CostValues};
use crate::vm::costs::costs_3::Costs3;
use crate::vm::costs::ExecutionCost;
use crate::vm::errors::VmExecutionError;
use crate::vm::functions::NativeFunctions;
use crate::vm::representations::ClarityName;
use crate::vm::{ClarityVersion, Value};

const STRING_COST_BASE: u64 = 36;
const STRING_COST_MULTIPLIER: u64 = 3;

/// Convert a NativeFunctions enum variant to its corresponding cost function
/// TODO: This assumes Costs3 but should find a way to use the clarity version passed in
pub(crate) fn get_cost_function_for_native(
    function: NativeFunctions,
    _clarity_version: &ClarityVersion,
) -> Option<fn(u64) -> Result<ExecutionCost, VmExecutionError>> {
    use crate::vm::functions::NativeFunctions::*;

    // Map NativeFunctions enum variants to their cost functions
    match function {
        Add => Some(Costs3::cost_add),
        Subtract => Some(Costs3::cost_sub),
        Multiply => Some(Costs3::cost_mul),
        Divide => Some(Costs3::cost_div),
        Modulo => Some(Costs3::cost_mod),
        Power => Some(Costs3::cost_pow),
        Sqrti => Some(Costs3::cost_sqrti),
        Log2 => Some(Costs3::cost_log2),
        ToInt | ToUInt => Some(Costs3::cost_int_cast),
        Equals => Some(Costs3::cost_eq),
        CmpGeq => Some(Costs3::cost_geq),
        CmpLeq => Some(Costs3::cost_leq),
        CmpGreater => Some(Costs3::cost_ge),
        CmpLess => Some(Costs3::cost_le),
        BitwiseXor | BitwiseXor2 => Some(Costs3::cost_xor),
        Not | BitwiseNot => Some(Costs3::cost_not),
        And | BitwiseAnd => Some(Costs3::cost_and),
        Or | BitwiseOr => Some(Costs3::cost_or),
        Concat => Some(Costs3::cost_concat),
        Len => Some(Costs3::cost_len),
        AsMaxLen => Some(Costs3::cost_as_max_len),
        ListCons => Some(Costs3::cost_list_cons),
        ElementAt | ElementAtAlias => Some(Costs3::cost_element_at),
        IndexOf | IndexOfAlias => Some(Costs3::cost_index_of),
        Fold => Some(Costs3::cost_fold),
        Map => Some(Costs3::cost_map),
        Filter => Some(Costs3::cost_filter),
        Append => Some(Costs3::cost_append),
        TupleGet => Some(Costs3::cost_tuple_get),
        TupleMerge => Some(Costs3::cost_tuple_merge),
        TupleCons => Some(Costs3::cost_tuple_cons),
        ConsSome => Some(Costs3::cost_some_cons),
        ConsOkay => Some(Costs3::cost_ok_cons),
        ConsError => Some(Costs3::cost_err_cons),
        DefaultTo => Some(Costs3::cost_default_to),
        UnwrapRet => Some(Costs3::cost_unwrap_ret),
        UnwrapErrRet => Some(Costs3::cost_unwrap_err_or_ret),
        IsOkay => Some(Costs3::cost_is_okay),
        IsNone => Some(Costs3::cost_is_none),
        IsErr => Some(Costs3::cost_is_err),
        IsSome => Some(Costs3::cost_is_some),
        Unwrap => Some(Costs3::cost_unwrap),
        UnwrapErr => Some(Costs3::cost_unwrap_err),
        TryRet => Some(Costs3::cost_try_ret),
        If => Some(Costs3::cost_if),
        Match => Some(Costs3::cost_match),
        Begin => Some(Costs3::cost_begin),
        Let => Some(Costs3::cost_let),
        Asserts => Some(Costs3::cost_asserts),
        Hash160 => Some(Costs3::cost_hash160),
        Sha256 => Some(Costs3::cost_sha256),
        Sha512 => Some(Costs3::cost_sha512),
        Sha512Trunc256 => Some(Costs3::cost_sha512t256),
        Keccak256 => Some(Costs3::cost_keccak256),
        Secp256k1Recover => Some(Costs3::cost_secp256k1recover),
        Secp256k1Verify => Some(Costs3::cost_secp256k1verify),
        Print => Some(Costs3::cost_print),
        ContractCall => Some(Costs3::cost_contract_call),
        ContractOf => Some(Costs3::cost_contract_of),
        PrincipalOf => Some(Costs3::cost_principal_of),
        AtBlock => Some(Costs3::cost_at_block),
        // => Some(Costs3::cost_create_map),
        // => Some(Costs3::cost_create_var),
        // ContractStorage => Some(Costs3::cost_contract_storage),
        FetchEntry => Some(Costs3::cost_fetch_entry),
        SetEntry => Some(Costs3::cost_set_entry),
        FetchVar => Some(Costs3::cost_fetch_var),
        SetVar => Some(Costs3::cost_set_var),
        GetBlockInfo => Some(Costs3::cost_block_info),
        GetBurnBlockInfo => Some(Costs3::cost_burn_block_info),
        GetStxBalance => Some(Costs3::cost_stx_balance),
        StxTransfer => Some(Costs3::cost_stx_transfer),
        StxTransferMemo => Some(Costs3::cost_stx_transfer_memo),
        StxGetAccount => Some(Costs3::cost_stx_account),
        MintToken => Some(Costs3::cost_ft_mint),
        MintAsset => Some(Costs3::cost_nft_mint),
        TransferToken => Some(Costs3::cost_ft_transfer),
        GetTokenBalance => Some(Costs3::cost_ft_balance),
        GetTokenSupply => Some(Costs3::cost_ft_get_supply),
        BurnToken => Some(Costs3::cost_ft_burn),
        TransferAsset => Some(Costs3::cost_nft_transfer),
        GetAssetOwner => Some(Costs3::cost_nft_owner),
        BurnAsset => Some(Costs3::cost_nft_burn),
        BuffToIntLe => Some(Costs3::cost_buff_to_int_le),
        BuffToUIntLe => Some(Costs3::cost_buff_to_uint_le),
        BuffToIntBe => Some(Costs3::cost_buff_to_int_be),
        BuffToUIntBe => Some(Costs3::cost_buff_to_uint_be),
        ToConsensusBuff => Some(Costs3::cost_to_consensus_buff),
        FromConsensusBuff => Some(Costs3::cost_from_consensus_buff),
        IsStandard => Some(Costs3::cost_is_standard),
        PrincipalDestruct => Some(Costs3::cost_principal_destruct),
        PrincipalConstruct => Some(Costs3::cost_principal_construct),
        AsContract | AsContractSafe => Some(Costs3::cost_as_contract),
        StringToInt => Some(Costs3::cost_string_to_int),
        StringToUInt => Some(Costs3::cost_string_to_uint),
        IntToAscii => Some(Costs3::cost_int_to_ascii),
        IntToUtf8 => Some(Costs3::cost_int_to_utf8),
        BitwiseLShift => Some(Costs3::cost_bitwise_left_shift),
        BitwiseRShift => Some(Costs3::cost_bitwise_right_shift),
        Slice => Some(Costs3::cost_slice),
        ReplaceAt => Some(Costs3::cost_replace_at),
        GetStacksBlockInfo => Some(Costs3::cost_block_info),
        GetTenureInfo => Some(Costs3::cost_block_info),
        ContractHash => Some(Costs3::cost_contract_hash),
        ToAscii => Some(Costs3::cost_to_ascii),
        InsertEntry => Some(Costs3::cost_set_entry),
        DeleteEntry => Some(Costs3::cost_set_entry),
        StxBurn => Some(Costs3::cost_stx_transfer),
        Secp256r1Verify => Some(Costs3::cost_secp256r1verify),
        RestrictAssets => None,        // TODO: add cost function
        AllowanceWithStx => None,      // TODO: add cost function
        AllowanceWithFt => None,       // TODO: add cost function
        AllowanceWithNft => None,      // TODO: add cost function
        AllowanceWithStacking => None, // TODO: add cost function
        AllowanceAll => None,          // TODO: add cost function
    }
}

// Calculate function cost with lazy evaluation support
pub(crate) fn calculate_function_cost(
    function_name: String,
    cost_map: &HashMap<String, Option<StaticCost>>,
    _clarity_version: &ClarityVersion,
) -> Result<StaticCost, String> {
    match cost_map.get(&function_name) {
        Some(Some(cost)) => {
            // Cost already computed
            Ok(cost.clone())
        }
        Some(None) => {
            // Should be impossible but alas..
            // Function exists but cost not yet computed - this indicates a circular dependency
            // For now, return zero cost to avoid infinite recursion
            println!(
                "Circular dependency detected for function: {}",
                function_name
            );
            Ok(StaticCost::ZERO)
        }
        None => {
            // Function not found
            Ok(StaticCost::ZERO)
        }
    }
}

/// Determine if a function name represents a branching function
pub(crate) fn is_branching_function(function_name: &ClarityName) -> bool {
    match function_name.as_str() {
        "if" | "match" => true,
        "unwrap!" | "unwrap-err!" => false, // XXX: currently unwrap and
        // unwrap-err traverse both branches regardless of result, so until this is
        // fixed in clarity we'll set this to false
        _ => false,
    }
}

/// Helper function to determine if a node represents a branching operation
/// This is used in tests and cost calculation
pub(crate) fn is_node_branching(node: &CostAnalysisNode) -> bool {
    match &node.expr {
        CostExprNode::NativeFunction(NativeFunctions::If)
        | CostExprNode::NativeFunction(NativeFunctions::Match) => true,
        CostExprNode::UserFunction(name) => is_branching_function(name),
        _ => false,
    }
}

/// Calculate the cost for a string based on its length
fn string_cost(length: usize) -> StaticCost {
    let cost = linear(length as u64, STRING_COST_BASE, STRING_COST_MULTIPLIER);
    let execution_cost = ExecutionCost::runtime(cost);
    StaticCost {
        min: execution_cost.clone(),
        max: execution_cost,
    }
}

/// Calculate cost for a value (used for literal values)
pub(crate) fn calculate_value_cost(value: &Value) -> Result<StaticCost, String> {
    match value {
        Value::Sequence(SequenceData::String(CharType::UTF8(data))) => {
            Ok(string_cost(data.data.len()))
        }
        Value::Sequence(SequenceData::String(CharType::ASCII(data))) => {
            Ok(string_cost(data.data.len()))
        }
        _ => Ok(StaticCost::ZERO),
    }
}

pub(crate) fn calculate_function_cost_from_native_function(
    native_function: NativeFunctions,
    arg_count: u64,
    clarity_version: &ClarityVersion,
) -> Result<StaticCost, String> {
    let cost_function = match get_cost_function_for_native(native_function, clarity_version) {
        Some(cost_fn) => cost_fn,
        None => {
            // TODO: zero cost for now
            return Ok(StaticCost::ZERO);
        }
    };

    let cost = get_costs(cost_function, arg_count)?;
    Ok(StaticCost {
        min: cost.clone(),
        max: cost,
    })
}

/// Calculate total cost using SummingExecutionCost to handle branching properly
pub(crate) fn calculate_total_cost_with_summing(node: &CostAnalysisNode) -> SummingExecutionCost {
    let mut summing_cost = SummingExecutionCost::from_single(node.cost.min.clone());

    for child in &node.children {
        let child_summing = calculate_total_cost_with_summing(child);
        summing_cost.add_summing(&child_summing);
    }

    summing_cost
}

pub(crate) fn calculate_total_cost_with_branching(node: &CostAnalysisNode) -> SummingExecutionCost {
    let mut summing_cost = SummingExecutionCost::new();

    // Check if this is a branching function by examining the node's expression
    let is_branching = is_node_branching(node);

    if is_branching {
        match &node.expr {
            CostExprNode::NativeFunction(NativeFunctions::If)
            | CostExprNode::NativeFunction(NativeFunctions::Match) => {
                // TODO match?
                if node.children.len() >= 2 {
                    let condition_cost = calculate_total_cost_with_summing(&node.children[0]);
                    let condition_total = condition_cost.add_all();

                    // Add the root cost + condition cost to each branch
                    let mut root_and_condition = node.cost.min.clone();
                    let _ = root_and_condition.add(&condition_total);

                    for child_cost_node in node.children.iter().skip(1) {
                        let branch_cost = calculate_total_cost_with_summing(child_cost_node);
                        let branch_total = branch_cost.add_all();

                        let mut path_cost = root_and_condition.clone();
                        let _ = path_cost.add(&branch_total);

                        summing_cost.add_cost(path_cost);
                    }
                }
            }
            _ => {
                // For other branching functions, fall back to sequential processing
                let mut total_cost = node.cost.min.clone();
                for child_cost_node in &node.children {
                    let child_summing = calculate_total_cost_with_summing(child_cost_node);
                    let combined_cost = child_summing.add_all();
                    let _ = total_cost.add(&combined_cost);
                }
                summing_cost.add_cost(total_cost);
            }
        }
    } else {
        // For non-branching, add all costs sequentially
        let mut total_cost = node.cost.min.clone();
        for child_cost_node in &node.children {
            let child_summing = calculate_total_cost_with_summing(child_cost_node);
            let combined_cost = child_summing.add_all();
            let _ = total_cost.add(&combined_cost);
        }
        summing_cost.add_cost(total_cost);
    }

    summing_cost
}

impl From<SummingExecutionCost> for StaticCost {
    fn from(summing: SummingExecutionCost) -> Self {
        StaticCost {
            min: summing.min(),
            max: summing.max(),
        }
    }
}

/// Helper: calculate min & max costs for a given cost function
/// This is likely tooo simplistic but for now it'll do
fn get_costs(
    cost_fn: fn(u64) -> Result<ExecutionCost, VmExecutionError>,
    arg_count: u64,
) -> Result<ExecutionCost, String> {
    let cost = cost_fn(arg_count).map_err(|e| format!("Cost calculation error: {:?}", e))?;
    Ok(cost)
}
