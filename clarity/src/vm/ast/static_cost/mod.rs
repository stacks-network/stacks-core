mod trait_counter;
use std::collections::HashMap;

use clarity_types::representations::SymbolicExpression;
use clarity_types::types::{CharType, SequenceData};
use stacks_common::types::StacksEpochId;
pub use trait_counter::{
    TraitCount, TraitCountCollector, TraitCountContext, TraitCountPropagator, TraitCountVisitor,
};

use crate::vm::callables::CallableType;
use crate::vm::costs::analysis::{
    CostAnalysisNode, CostExprNode, StaticCost, SummingExecutionCost,
};
use crate::vm::costs::cost_functions::{linear, ClarityCostFunction};
use crate::vm::costs::ExecutionCost;
use crate::vm::errors::VmExecutionError;
use crate::vm::functions::{lookup_reserved_functions, special_costs, NativeFunctions};
use crate::vm::representations::ClarityName;
use crate::vm::{ClarityVersion, Value};

const STRING_COST_BASE: u64 = 36;
const STRING_COST_MULTIPLIER: u64 = 3;

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

/// Add lookup function cost to an execution cost
/// This cost is charged when looking up native functions during expression evaluation
fn add_lookup_cost(mut cost: ExecutionCost, epoch: StacksEpochId) -> ExecutionCost {
    let lookup_cost = ClarityCostFunction::LookupFunction
        .eval_for_epoch(0, epoch)
        .unwrap_or_else(|_| ExecutionCost::ZERO);
    cost.add(&lookup_cost).ok();
    cost
}

pub(crate) fn calculate_function_cost_from_native_function(
    native_function: NativeFunctions,
    arg_count: u64,
    args: &[SymbolicExpression],
    epoch: StacksEpochId,
    user_args: Option<&crate::vm::costs::analysis::UserArgumentsContext>,
) -> Result<StaticCost, String> {
    // Derive clarity_version from epoch for lookup_reserved_functions
    let clarity_version = ClarityVersion::default_for_epoch(epoch);

    match lookup_reserved_functions(native_function.to_string().as_str(), &clarity_version) {
        Some(CallableType::NativeFunction(_, _, cost_fn)) => {
            let cost = cost_fn
                .eval_for_epoch(arg_count, epoch)
                .map_err(|e| format!("Cost calculation error: {:?}", e))?;
            let cost_with_lookup = add_lookup_cost(cost, epoch);
            Ok(StaticCost {
                min: cost_with_lookup.clone(),
                max: cost_with_lookup,
            })
        }
        Some(CallableType::NativeFunction205(_, _, cost_fn, _)) => {
            let cost = cost_fn
                .eval_for_epoch(arg_count, epoch)
                .map_err(|e| format!("Cost calculation error: {:?}", e))?;
            let cost_with_lookup = add_lookup_cost(cost, epoch);
            Ok(StaticCost {
                min: cost_with_lookup.clone(),
                max: cost_with_lookup,
            })
        }
        Some(CallableType::SpecialFunction(_, _)) => {
            let cost = special_costs::get_cost_for_special_function(
                native_function,
                args,
                epoch,
                user_args,
            );
            let cost_with_lookup = add_lookup_cost(cost, epoch);
            Ok(StaticCost {
                min: cost_with_lookup.clone(),
                max: cost_with_lookup,
            })
        }
        Some(CallableType::UserFunction(_)) => Ok(StaticCost::ZERO), // TODO ?
        None => Ok(StaticCost::ZERO),
    }
}

/// total cost handling branching
/// For non-branching we combine all paths
pub(crate) fn calculate_total_cost_with_summing(node: &CostAnalysisNode) -> SummingExecutionCost {
    let mut summing_cost = SummingExecutionCost::from_single(node.cost.min.clone());

    for child in &node.children {
        let child_summing = calculate_total_cost_with_summing(child);
        // Combine each existing path with each child path (cartesian product)
        let current_paths = summing_cost.costs.clone();
        summing_cost = SummingExecutionCost::new();
        for current_path in current_paths {
            for child_path in &child_summing.costs {
                let mut combined_path = current_path.clone();
                let _ = combined_path.add(child_path);
                summing_cost.add_cost(combined_path);
            }
        }
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
                        // For each path in the branch, add root_and_condition to create a full path
                        // This preserves all branch paths so we can correctly compute min/max
                        for branch_path in &branch_cost.costs {
                            let mut path_cost = root_and_condition.clone();
                            let _ = path_cost.add(branch_path);
                            summing_cost.add_cost(path_cost);
                        }
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
        // For non-branching, recursively process children (which may be branching)
        let mut total_cost = node.cost.min.clone();
        let mut has_branching_children = false;
        for child_cost_node in &node.children {
            // Recursively call calculate_total_cost_with_branching on children
            // so that branching children (like If) are handled correctly
            let child_summing = calculate_total_cost_with_branching(child_cost_node);

            if is_node_branching(child_cost_node) {
                // For branching children, preserve all paths by combining each path
                // with the current total_cost
                has_branching_children = true;
                for child_path_cost in &child_summing.costs {
                    let mut combined_path = total_cost.clone();
                    let _ = combined_path.add(child_path_cost);
                    summing_cost.add_cost(combined_path);
                }
                // Update total_cost to the max child path for sequential addition with remaining children
                let child_static_cost: StaticCost = child_summing.into();
                let _ = total_cost.add(&child_static_cost.max);
            } else {
                // For non-branching children, add sequentially
                let child_static_cost: StaticCost = child_summing.into();
                let combined_cost = child_static_cost.max;
                let _ = total_cost.add(&combined_cost);
            }
        }
        // Only add total_cost if we didn't have any branching children
        // (if we had branching children, we already added all paths above)
        if !has_branching_children {
            summing_cost.add_cost(total_cost);
        }
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
