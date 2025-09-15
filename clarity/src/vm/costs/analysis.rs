// Static cost analysis for Clarity expressions

use crate::vm::ast::parser::v2::parse;
use crate::vm::costs::cost_functions::CostValues;
use crate::vm::costs::costs_3::Costs3;
use crate::vm::costs::ExecutionCost;
use crate::vm::errors::InterpreterResult;
use crate::vm::representations::{ClarityName, PreSymbolicExpression, PreSymbolicExpressionType};

// TODO:
// variable traverse for
//   - if, is-*, match, etc
// contract-call? - how to handle?
// type-checking
// lookups

#[derive(Debug, Clone)]
pub struct StaticCostNode {
    pub function: Vec<PreSymbolicExpression>,
    pub cost: StaticCost,
    pub children: Vec<StaticCostNode>,
}

impl StaticCostNode {
    pub fn new(
        function: Vec<PreSymbolicExpression>,
        cost: StaticCost,
        children: Vec<StaticCostNode>,
    ) -> Self {
        Self {
            function,
            cost,
            children,
        }
    }

    pub fn leaf(function: Vec<PreSymbolicExpression>, cost: StaticCost) -> Self {
        Self {
            function,
            cost,
            children: vec![],
        }
    }
}

#[derive(Debug, Clone)]
pub struct StaticCost {
    pub min: ExecutionCost,
    pub max: ExecutionCost,
}

impl StaticCost {
    pub const ZERO: StaticCost = StaticCost {
        min: ExecutionCost::ZERO,
        max: ExecutionCost::ZERO,
    };
}

/// Parse Clarity source code and calculate its static execution cost
///
/// This function takes a Clarity expression as a string, parses it into symbolic
/// expressions, builds a cost tree, and returns the min and max execution cost.
/// theoretically you could inspect the tree at any node to get the spot cost
pub fn static_cost(source: &str) -> Result<StaticCost, String> {
    let pre_expressions = parse(source).map_err(|e| format!("Parse error: {:?}", e))?;

    if pre_expressions.is_empty() {
        return Err("No expressions found".to_string());
    }

    let pre_expr = &pre_expressions[0];
    let cost_tree = build_cost_tree(pre_expr)?;

    Ok(calculate_total_cost(&cost_tree))
}

// TODO: Needs alternative traversals to get min/max
fn build_cost_tree(expr: &PreSymbolicExpression) -> Result<StaticCostNode, String> {
    match &expr.pre_expr {
        PreSymbolicExpressionType::List(list) => {
            if list.is_empty() {
                return Err("Empty list expression".to_string());
            }

            let function_name = match &list[0].pre_expr {
                PreSymbolicExpressionType::Atom(name) => name,
                _ => {
                    return Err("First element of list must be an atom (function name)".to_string())
                }
            };

            // TODO this is wrong
            let args = &list[1..];
            let mut children = Vec::new();

            for arg in args {
                children.push(build_cost_tree(arg)?);
            }

            let cost = calculate_function_cost(function_name, args.len() as u64)?;

            Ok(StaticCostNode::new(list.clone(), cost, children))
        }
        PreSymbolicExpressionType::AtomValue(_value) => {
            Ok(StaticCostNode::leaf(vec![expr.clone()], StaticCost::ZERO))
        }
        PreSymbolicExpressionType::Atom(_name) => {
            Ok(StaticCostNode::leaf(vec![expr.clone()], StaticCost::ZERO))
        }
        PreSymbolicExpressionType::Tuple(tuple) => {
            let function_name = match &tuple[0].pre_expr {
                PreSymbolicExpressionType::Atom(name) => name,
                _ => {
                    return Err("First element of tuple must be an atom (function name)".to_string())
                }
            };

            let args = &tuple[1..];
            let mut children = Vec::new();

            for arg in args {
                children.push(build_cost_tree(arg)?);
            }

            let cost = calculate_function_cost(function_name, args.len() as u64)?;

            Ok(StaticCostNode::new(tuple.clone(), cost, children))
        }
        _ => Err("Unsupported expression type for cost analysis".to_string()),
    }
}

fn calculate_function_cost(
    function_name: &ClarityName,
    arg_count: u64,
) -> Result<StaticCost, String> {
    let cost_function = match get_cost_function_for_name(function_name) {
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

/// Convert a function name to its corresponding cost function
fn get_cost_function_for_name(
    name: &ClarityName,
) -> Option<fn(u64) -> InterpreterResult<ExecutionCost>> {
    let name_str = name.as_str();

    // Map function names to their cost functions using the existing enum structure
    match name_str {
        "+" | "add" => Some(Costs3::cost_add),
        "-" | "sub" => Some(Costs3::cost_sub),
        "*" | "mul" => Some(Costs3::cost_mul),
        "/" | "div" => Some(Costs3::cost_div),
        "mod" => Some(Costs3::cost_mod),
        "pow" => Some(Costs3::cost_pow),
        "sqrti" => Some(Costs3::cost_sqrti),
        "log2" => Some(Costs3::cost_log2),
        "to-int" | "to-uint" | "int-cast" => Some(Costs3::cost_int_cast),
        "is-eq" | "=" | "eq" => Some(Costs3::cost_eq),
        ">=" | "geq" => Some(Costs3::cost_geq),
        "<=" | "leq" => Some(Costs3::cost_leq),
        ">" | "ge" => Some(Costs3::cost_ge),
        "<" | "le" => Some(Costs3::cost_le),
        "xor" => Some(Costs3::cost_xor),
        "not" => Some(Costs3::cost_not),
        "and" => Some(Costs3::cost_and),
        "or" => Some(Costs3::cost_or),
        "concat" => Some(Costs3::cost_concat),
        "len" => Some(Costs3::cost_len),
        "as-max-len?" => Some(Costs3::cost_as_max_len),
        "list" => Some(Costs3::cost_list_cons),
        "element-at" | "element-at?" => Some(Costs3::cost_element_at),
        "index-of" | "index-of?" => Some(Costs3::cost_index_of),
        "fold" => Some(Costs3::cost_fold),
        "map" => Some(Costs3::cost_map),
        "filter" => Some(Costs3::cost_filter),
        "append" => Some(Costs3::cost_append),
        "tuple-get" => Some(Costs3::cost_tuple_get),
        "tuple-merge" => Some(Costs3::cost_tuple_merge),
        "tuple" => Some(Costs3::cost_tuple_cons),
        "some" => Some(Costs3::cost_some_cons),
        "ok" => Some(Costs3::cost_ok_cons),
        "err" => Some(Costs3::cost_err_cons),
        "default-to" => Some(Costs3::cost_default_to),
        "unwrap!" => Some(Costs3::cost_unwrap_ret),
        "unwrap-err!" => Some(Costs3::cost_unwrap_err_or_ret),
        "is-ok" => Some(Costs3::cost_is_okay),
        "is-none" => Some(Costs3::cost_is_none),
        "is-err" => Some(Costs3::cost_is_err),
        "is-some" => Some(Costs3::cost_is_some),
        "unwrap-panic" => Some(Costs3::cost_unwrap),
        "unwrap-err-panic" => Some(Costs3::cost_unwrap_err),
        "try!" => Some(Costs3::cost_try_ret),
        "if" => Some(Costs3::cost_if),
        "match" => Some(Costs3::cost_match),
        "begin" => Some(Costs3::cost_begin),
        "let" => Some(Costs3::cost_let),
        "asserts!" => Some(Costs3::cost_asserts),
        "hash160" => Some(Costs3::cost_hash160),
        "sha256" => Some(Costs3::cost_sha256),
        "sha512" => Some(Costs3::cost_sha512),
        "sha512/256" => Some(Costs3::cost_sha512t256),
        "keccak256" => Some(Costs3::cost_keccak256),
        "secp256k1-recover?" => Some(Costs3::cost_secp256k1recover),
        "secp256k1-verify" => Some(Costs3::cost_secp256k1verify),
        "print" => Some(Costs3::cost_print),
        "contract-call?" => Some(Costs3::cost_contract_call),
        "contract-of" => Some(Costs3::cost_contract_of),
        "principal-of?" => Some(Costs3::cost_principal_of),
        "at-block" => Some(Costs3::cost_at_block),
        "load-contract" => Some(Costs3::cost_load_contract),
        "create-map" => Some(Costs3::cost_create_map),
        "create-var" => Some(Costs3::cost_create_var),
        "create-non-fungible-token" => Some(Costs3::cost_create_nft),
        "create-fungible-token" => Some(Costs3::cost_create_ft),
        "map-get?" => Some(Costs3::cost_fetch_entry),
        "map-set!" => Some(Costs3::cost_set_entry),
        "var-get" => Some(Costs3::cost_fetch_var),
        "var-set!" => Some(Costs3::cost_set_var),
        "contract-storage" => Some(Costs3::cost_contract_storage),
        "get-block-info?" => Some(Costs3::cost_block_info),
        "get-burn-block-info?" => Some(Costs3::cost_burn_block_info),
        "stx-get-balance" => Some(Costs3::cost_stx_balance),
        "stx-transfer?" => Some(Costs3::cost_stx_transfer),
        "stx-transfer-memo?" => Some(Costs3::cost_stx_transfer_memo),
        "stx-account" => Some(Costs3::cost_stx_account),
        "ft-mint?" => Some(Costs3::cost_ft_mint),
        "ft-transfer?" => Some(Costs3::cost_ft_transfer),
        "ft-get-balance" => Some(Costs3::cost_ft_balance),
        "ft-get-supply" => Some(Costs3::cost_ft_get_supply),
        "ft-burn?" => Some(Costs3::cost_ft_burn),
        "nft-mint?" => Some(Costs3::cost_nft_mint),
        "nft-transfer?" => Some(Costs3::cost_nft_transfer),
        "nft-get-owner?" => Some(Costs3::cost_nft_owner),
        "nft-burn?" => Some(Costs3::cost_nft_burn),
        "buff-to-int-le?" => Some(Costs3::cost_buff_to_int_le),
        "buff-to-uint-le?" => Some(Costs3::cost_buff_to_uint_le),
        "buff-to-int-be?" => Some(Costs3::cost_buff_to_int_be),
        "buff-to-uint-be?" => Some(Costs3::cost_buff_to_uint_be),
        "to-consensus-buff?" => Some(Costs3::cost_to_consensus_buff),
        "from-consensus-buff?" => Some(Costs3::cost_from_consensus_buff),
        "is-standard?" => Some(Costs3::cost_is_standard),
        "principal-destruct" => Some(Costs3::cost_principal_destruct),
        "principal-construct?" => Some(Costs3::cost_principal_construct),
        "as-contract" => Some(Costs3::cost_as_contract),
        "string-to-int?" => Some(Costs3::cost_string_to_int),
        "string-to-uint?" => Some(Costs3::cost_string_to_uint),
        "int-to-ascii" => Some(Costs3::cost_int_to_ascii),
        "int-to-utf8?" => Some(Costs3::cost_int_to_utf8),
        _ => None, // Unknown function name
    }
}

fn get_max_input_size_for_function_name(function_name: &ClarityName, arg_count: u64) -> u64 {
    let name_str = function_name.as_str();

    match name_str {
        "concat" => {
            // For string concatenation, max size is the sum of max string lengths
            // Each string can be up to MAX_VALUE_SIZE (1MB), so for n strings it's n * MAX_VALUE_SIZE
            arg_count * 1024 * 1024
        }
        "len" => {
            // For length, maximum string length
            1024 * 1024 // MAX_VALUE_SIZE
        }
        _ => {
            // Default case - use a fixed max size to match original behavior
            // The original code used 2000 as the max input size for arithmetic operations
            2000
        }
    }
}

fn calculate_total_cost(node: &StaticCostNode) -> StaticCost {
    let mut min_total = node.cost.min.clone();
    let mut max_total = node.cost.max.clone();

    // Add costs from all children
    // TODO: this should traverse different paths to get min and max costs
    for child in &node.children {
        let child_cost = calculate_total_cost(child);
        let _ = min_total.add(&child_cost.min);
        let _ = max_total.add(&child_cost.max);
    }

    StaticCost {
        min: min_total,
        max: max_total,
    }
}

/// Helper: calculate min & max costs for a given cost function
/// This is likely tooo simplistic but for now it'll do
fn get_costs(
    cost_fn: fn(u64) -> InterpreterResult<ExecutionCost>,
    arg_count: u64,
) -> Result<ExecutionCost, String> {
    let cost = cost_fn(arg_count).map_err(|e| format!("Cost calculation error: {:?}", e))?;
    Ok(cost)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant() {
        let source = "u2";
        let cost = static_cost(source).unwrap();
        assert_eq!(cost.min.runtime, 0);
        assert_eq!(cost.max.runtime, 0);
    }

    #[test]
    fn test_simple_addition() {
        let source = "(+ u1 u2)";
        let cost = static_cost(source).unwrap();

        // Min: linear(2, 11, 125) = 11*2 + 125 = 147
        assert_eq!(cost.min.runtime, 147);
        assert_eq!(cost.max.runtime, 147);
    }

    #[test]
    fn test_arithmetic() {
        let source = "(- u4 (+ u1 u2))";
        let cost = static_cost(source).unwrap();
        assert_eq!(cost.min.runtime, 147 + 147);
        assert_eq!(cost.max.runtime, 147 + 147);
    }

    #[test]
    fn test_nested_operations() {
        let source = "(* (+ u1 u2) (- u3 u4))";
        let cost = static_cost(source).unwrap();
        // multiplication: 13*2 + 125 = 151
        assert_eq!(cost.min.runtime, 151 + 147 + 147);
        assert_eq!(cost.max.runtime, 151 + 147 + 147);
    }

    #[test]
    fn test_string_concat_min_max() {
        let source = "(concat \"hello\" \"world\")";
        let cost = static_cost(source).unwrap();

        // For concat with 2 arguments:
        // linear(2, 37, 220) = 37*2 + 220 = 294
        assert_eq!(cost.min.runtime, 294);
        assert_eq!(cost.max.runtime, 294);
    }

    #[test]
    fn test_string_len_min_max() {
        let source = "(len \"hello\")";
        let cost = static_cost(source).unwrap();

        // cost: 429 (constant) - len doesn't depend on string size
        assert_eq!(cost.min.runtime, 429);
        assert_eq!(cost.max.runtime, 429);
    }
}
