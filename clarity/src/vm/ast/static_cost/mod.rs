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
use crate::vm::costs::costs_1::Costs1;
use crate::vm::costs::costs_2::Costs2;
use crate::vm::costs::costs_3::Costs3;
use crate::vm::costs::costs_4::Costs4;
use crate::vm::costs::ExecutionCost;
use crate::vm::errors::VmExecutionError;
use crate::vm::functions::NativeFunctions;
use crate::vm::representations::ClarityName;
use crate::vm::{ClarityVersion, Value};

const STRING_COST_BASE: u64 = 36;
const STRING_COST_MULTIPLIER: u64 = 3;

/// Macro to dispatch to the correct Costs module based on clarity version
/// returns a function pointer to the appropriate cost function
macro_rules! dispatch_cost {
    ($version:expr, $cost_fn:ident) => {
        match $version {
            ClarityVersion::Clarity1 => Costs1::$cost_fn,
            ClarityVersion::Clarity2 => Costs2::$cost_fn,
            ClarityVersion::Clarity3 => Costs3::$cost_fn,
            ClarityVersion::Clarity4 => Costs4::$cost_fn,
        }
    };
}

/// NativeFunctions -> cost via appropriate cost fn
pub(crate) fn get_cost_function_for_native(
    function: NativeFunctions,
    clarity_version: &ClarityVersion,
) -> Option<fn(u64) -> Result<ExecutionCost, VmExecutionError>> {
    use crate::vm::functions::NativeFunctions::*;

    // Map NativeFunctions enum to cost functions
    match function {
        Add => Some(dispatch_cost!(clarity_version, cost_add)),
        Subtract => Some(dispatch_cost!(clarity_version, cost_sub)),
        Multiply => Some(dispatch_cost!(clarity_version, cost_mul)),
        Divide => Some(dispatch_cost!(clarity_version, cost_div)),
        Modulo => Some(dispatch_cost!(clarity_version, cost_mod)),
        Power => Some(dispatch_cost!(clarity_version, cost_pow)),
        Sqrti => Some(dispatch_cost!(clarity_version, cost_sqrti)),
        Log2 => Some(dispatch_cost!(clarity_version, cost_log2)),
        ToInt | ToUInt => Some(dispatch_cost!(clarity_version, cost_int_cast)),
        Equals => Some(dispatch_cost!(clarity_version, cost_eq)),
        CmpGeq => Some(dispatch_cost!(clarity_version, cost_geq)),
        CmpLeq => Some(dispatch_cost!(clarity_version, cost_leq)),
        CmpGreater => Some(dispatch_cost!(clarity_version, cost_ge)),
        CmpLess => Some(dispatch_cost!(clarity_version, cost_le)),
        BitwiseXor | BitwiseXor2 => Some(dispatch_cost!(clarity_version, cost_xor)),
        Not | BitwiseNot => Some(dispatch_cost!(clarity_version, cost_not)),
        And | BitwiseAnd => Some(dispatch_cost!(clarity_version, cost_and)),
        Or | BitwiseOr => Some(dispatch_cost!(clarity_version, cost_or)),
        Concat => Some(dispatch_cost!(clarity_version, cost_concat)),
        Len => Some(dispatch_cost!(clarity_version, cost_len)),
        AsMaxLen => Some(dispatch_cost!(clarity_version, cost_as_max_len)),
        ListCons => Some(dispatch_cost!(clarity_version, cost_list_cons)),
        ElementAt | ElementAtAlias => Some(dispatch_cost!(clarity_version, cost_element_at)),
        IndexOf | IndexOfAlias => Some(dispatch_cost!(clarity_version, cost_index_of)),
        Fold => Some(dispatch_cost!(clarity_version, cost_fold)),
        Map => Some(dispatch_cost!(clarity_version, cost_map)),
        Filter => Some(dispatch_cost!(clarity_version, cost_filter)),
        Append => Some(dispatch_cost!(clarity_version, cost_append)),
        TupleGet => Some(dispatch_cost!(clarity_version, cost_tuple_get)),
        TupleMerge => Some(dispatch_cost!(clarity_version, cost_tuple_merge)),
        TupleCons => Some(dispatch_cost!(clarity_version, cost_tuple_cons)),
        ConsSome => Some(dispatch_cost!(clarity_version, cost_some_cons)),
        ConsOkay => Some(dispatch_cost!(clarity_version, cost_ok_cons)),
        ConsError => Some(dispatch_cost!(clarity_version, cost_err_cons)),
        DefaultTo => Some(dispatch_cost!(clarity_version, cost_default_to)),
        UnwrapRet => Some(dispatch_cost!(clarity_version, cost_unwrap_ret)),
        UnwrapErrRet => Some(dispatch_cost!(clarity_version, cost_unwrap_err_or_ret)),
        IsOkay => Some(dispatch_cost!(clarity_version, cost_is_okay)),
        IsNone => Some(dispatch_cost!(clarity_version, cost_is_none)),
        IsErr => Some(dispatch_cost!(clarity_version, cost_is_err)),
        IsSome => Some(dispatch_cost!(clarity_version, cost_is_some)),
        Unwrap => Some(dispatch_cost!(clarity_version, cost_unwrap)),
        UnwrapErr => Some(dispatch_cost!(clarity_version, cost_unwrap_err)),
        TryRet => Some(dispatch_cost!(clarity_version, cost_try_ret)),
        If => Some(dispatch_cost!(clarity_version, cost_if)),
        Match => Some(dispatch_cost!(clarity_version, cost_match)),
        Begin => Some(dispatch_cost!(clarity_version, cost_begin)),
        Let => Some(dispatch_cost!(clarity_version, cost_let)),
        Asserts => Some(dispatch_cost!(clarity_version, cost_asserts)),
        Hash160 => Some(dispatch_cost!(clarity_version, cost_hash160)),
        Sha256 => Some(dispatch_cost!(clarity_version, cost_sha256)),
        Sha512 => Some(dispatch_cost!(clarity_version, cost_sha512)),
        Sha512Trunc256 => Some(dispatch_cost!(clarity_version, cost_sha512t256)),
        Keccak256 => Some(dispatch_cost!(clarity_version, cost_keccak256)),
        Secp256k1Recover => Some(dispatch_cost!(clarity_version, cost_secp256k1recover)),
        Secp256k1Verify => Some(dispatch_cost!(clarity_version, cost_secp256k1verify)),
        Print => Some(dispatch_cost!(clarity_version, cost_print)),
        ContractCall => Some(dispatch_cost!(clarity_version, cost_contract_call)),
        ContractOf => Some(dispatch_cost!(clarity_version, cost_contract_of)),
        PrincipalOf => Some(dispatch_cost!(clarity_version, cost_principal_of)),
        AtBlock => Some(dispatch_cost!(clarity_version, cost_at_block)),
        // => Some(dispatch_cost!(clarity_version, cost_create_map)),
        // => Some(dispatch_cost!(clarity_version, cost_create_var)),
        // ContractStorage => Some(dispatch_cost!(clarity_version, cost_contract_storage)),
        FetchEntry => Some(dispatch_cost!(clarity_version, cost_fetch_entry)),
        SetEntry => Some(dispatch_cost!(clarity_version, cost_set_entry)),
        FetchVar => Some(dispatch_cost!(clarity_version, cost_fetch_var)),
        SetVar => Some(dispatch_cost!(clarity_version, cost_set_var)),
        GetBlockInfo => Some(dispatch_cost!(clarity_version, cost_block_info)),
        GetBurnBlockInfo => Some(dispatch_cost!(clarity_version, cost_burn_block_info)),
        GetStxBalance => Some(dispatch_cost!(clarity_version, cost_stx_balance)),
        StxTransfer => Some(dispatch_cost!(clarity_version, cost_stx_transfer)),
        StxTransferMemo => Some(dispatch_cost!(clarity_version, cost_stx_transfer_memo)),
        StxGetAccount => Some(dispatch_cost!(clarity_version, cost_stx_account)),
        MintToken => Some(dispatch_cost!(clarity_version, cost_ft_mint)),
        MintAsset => Some(dispatch_cost!(clarity_version, cost_nft_mint)),
        TransferToken => Some(dispatch_cost!(clarity_version, cost_ft_transfer)),
        GetTokenBalance => Some(dispatch_cost!(clarity_version, cost_ft_balance)),
        GetTokenSupply => Some(dispatch_cost!(clarity_version, cost_ft_get_supply)),
        BurnToken => Some(dispatch_cost!(clarity_version, cost_ft_burn)),
        TransferAsset => Some(dispatch_cost!(clarity_version, cost_nft_transfer)),
        GetAssetOwner => Some(dispatch_cost!(clarity_version, cost_nft_owner)),
        BurnAsset => Some(dispatch_cost!(clarity_version, cost_nft_burn)),
        BuffToIntLe => Some(dispatch_cost!(clarity_version, cost_buff_to_int_le)),
        BuffToUIntLe => Some(dispatch_cost!(clarity_version, cost_buff_to_uint_le)),
        BuffToIntBe => Some(dispatch_cost!(clarity_version, cost_buff_to_int_be)),
        BuffToUIntBe => Some(dispatch_cost!(clarity_version, cost_buff_to_uint_be)),
        ToConsensusBuff => Some(dispatch_cost!(clarity_version, cost_to_consensus_buff)),
        FromConsensusBuff => Some(dispatch_cost!(clarity_version, cost_from_consensus_buff)),
        IsStandard => Some(dispatch_cost!(clarity_version, cost_is_standard)),
        PrincipalDestruct => Some(dispatch_cost!(clarity_version, cost_principal_destruct)),
        PrincipalConstruct => Some(dispatch_cost!(clarity_version, cost_principal_construct)),
        AsContract | AsContractSafe => Some(dispatch_cost!(clarity_version, cost_as_contract)),
        StringToInt => Some(dispatch_cost!(clarity_version, cost_string_to_int)),
        StringToUInt => Some(dispatch_cost!(clarity_version, cost_string_to_uint)),
        IntToAscii => Some(dispatch_cost!(clarity_version, cost_int_to_ascii)),
        IntToUtf8 => Some(dispatch_cost!(clarity_version, cost_int_to_utf8)),
        BitwiseLShift => Some(dispatch_cost!(clarity_version, cost_bitwise_left_shift)),
        BitwiseRShift => Some(dispatch_cost!(clarity_version, cost_bitwise_right_shift)),
        Slice => Some(dispatch_cost!(clarity_version, cost_slice)),
        ReplaceAt => Some(dispatch_cost!(clarity_version, cost_replace_at)),
        GetStacksBlockInfo => Some(dispatch_cost!(clarity_version, cost_block_info)),
        GetTenureInfo => Some(dispatch_cost!(clarity_version, cost_block_info)),
        ContractHash => Some(dispatch_cost!(clarity_version, cost_contract_hash)),
        ToAscii => Some(dispatch_cost!(clarity_version, cost_to_ascii)),
        InsertEntry => Some(dispatch_cost!(clarity_version, cost_set_entry)),
        DeleteEntry => Some(dispatch_cost!(clarity_version, cost_set_entry)),
        StxBurn => Some(dispatch_cost!(clarity_version, cost_stx_transfer)),
        Secp256r1Verify => Some(dispatch_cost!(clarity_version, cost_secp256r1verify)),
        RestrictAssets => Some(dispatch_cost!(clarity_version, cost_restrict_assets)),
        AllowanceWithStx => None,      // TODO: add cost function
        AllowanceWithFt => None,       // TODO: add cost function
        AllowanceWithNft => None,      // TODO: add cost function
        AllowanceWithStacking => None, // TODO: add cost function
        AllowanceAll => None,          // TODO: add cost function
    }
}

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
            // Should be impossible..
            // Function exists but cost not yet computed, circular dependency?
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

pub(crate) fn is_node_branching(node: &CostAnalysisNode) -> bool {
    match &node.expr {
        CostExprNode::NativeFunction(NativeFunctions::If)
        | CostExprNode::NativeFunction(NativeFunctions::Match) => true,
        CostExprNode::UserFunction(name) => is_branching_function(name),
        _ => false,
    }
}

/// string cost based on length
fn string_cost(length: usize) -> StaticCost {
    let cost = linear(length as u64, STRING_COST_BASE, STRING_COST_MULTIPLIER);
    let execution_cost = ExecutionCost::runtime(cost);
    StaticCost {
        min: execution_cost.clone(),
        max: execution_cost,
    }
}

/// Strings are the only Value's with costs associated
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
            return Ok(StaticCost::ZERO);
        }
    };

    let cost = get_costs(cost_function, arg_count)?;
    Ok(StaticCost {
        min: cost.clone(),
        max: cost,
    })
}

/// total cost handling branching
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

/// get min & max costs for a given cost function
fn get_costs(
    cost_fn: fn(u64) -> Result<ExecutionCost, VmExecutionError>,
    arg_count: u64,
) -> Result<ExecutionCost, String> {
    let cost = cost_fn(arg_count).map_err(|e| format!("Cost calculation error: {:?}", e))?;
    Ok(cost)
}
