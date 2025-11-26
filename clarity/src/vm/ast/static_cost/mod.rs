mod trait_counter;
use std::collections::HashMap;

use clarity_types::types::{CharType, SequenceData};
pub use trait_counter::{
    TraitCount, TraitCountCollector, TraitCountContext, TraitCountPropagator, TraitCountVisitor,
};

use crate::vm::callables::CallableType;
use crate::vm::costs::analysis::{
    CostAnalysisNode, CostExprNode, StaticCost, SummingExecutionCost,
};
use crate::vm::costs::cost_functions::linear;
use crate::vm::costs::costs_1::Costs1;
use crate::vm::costs::costs_2::Costs2;
use crate::vm::costs::costs_3::Costs3;
use crate::vm::costs::costs_4::Costs4;
use crate::vm::costs::ExecutionCost;
use crate::vm::errors::VmExecutionError;
use crate::vm::functions::{lookup_reserved_functions, NativeFunctions};
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

pub(crate) fn calculate_function_cost_from_native_function(
    native_function: NativeFunctions,
    arg_count: u64,
    clarity_version: &ClarityVersion,
) -> Result<StaticCost, String> {
    let cost_function =
        match lookup_reserved_functions(native_function.to_string().as_str(), clarity_version) {
            Some(CallableType::NativeFunction(_, _, cost_fn)) => cost_fn,
            Some(CallableType::NativeFunction205(_, _, cost_fn, _)) => cost_fn,
            Some(CallableType::SpecialFunction(_, _)) => return Ok(StaticCost::ZERO),
            Some(CallableType::UserFunction(_)) => return Ok(StaticCost::ZERO), // TODO ?
            None => {
                return Ok(StaticCost::ZERO);
            }
        };

    let cost = match clarity_version {
        ClarityVersion::Clarity1 => cost_function.eval::<Costs1>(arg_count),
        ClarityVersion::Clarity2 => cost_function.eval::<Costs2>(arg_count),
        ClarityVersion::Clarity3 => cost_function.eval::<Costs3>(arg_count),
        ClarityVersion::Clarity4 => cost_function.eval::<Costs4>(arg_count),
    }
    .map_err(|e| format!("Cost calculation error: {:?}", e))?;
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
