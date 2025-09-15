// Static cost analysis for Clarity expressions

use clarity_serialization::representations::ContractName;
use clarity_serialization::types::TraitIdentifier;
use clarity_serialization::Value;

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
// unwrap evaluates both branches (https://github.com/clarity-lang/reference/issues/59)

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

    // TODO what happens if multiple expressions are selected?
    let pre_expr = &pre_expressions[0];
    let _expr_tree = build_expr_tree(pre_expr)?;
    let cost_tree = build_cost_tree(pre_expr)?;

    Ok(calculate_total_cost(&cost_tree))
}

#[derive(Debug, Clone)]
pub enum ExprNode {
    If,
    Match,
    Unwrap,
    Ok,
    Err,
    GT,
    LT,
    GE,
    LE,
    EQ,
    Add,
    Sub,
    Mul,
    Div,
    // Other functions
    Function(ClarityName),
    // Values
    AtomValue(Value),
    Atom(ClarityName),
    // Placeholder for sugared identifiers
    SugaredContractIdentifier(ContractName),
    SugaredFieldIdentifier(ContractName, ClarityName),
    FieldIdentifier(TraitIdentifier),
    TraitReference(ClarityName),
}

#[derive(Debug, Clone)]
pub struct ExprTree {
    pub expr: ExprNode,
    pub children: Vec<ExprTree>,
    pub branching: bool,
}

/// Build an expression tree, skipping comments and placeholders
fn build_expr_tree(expr: &PreSymbolicExpression) -> Result<ExprTree, String> {
    match &expr.pre_expr {
        PreSymbolicExpressionType::List(list) => build_listlike_expr_tree(list, "list"),
        PreSymbolicExpressionType::AtomValue(value) => Ok(ExprTree {
            expr: ExprNode::AtomValue(value.clone()),
            children: vec![],
            branching: false,
        }),
        PreSymbolicExpressionType::Atom(name) => Ok(ExprTree {
            expr: ExprNode::Atom(name.clone()),
            children: vec![],
            branching: false,
        }),
        PreSymbolicExpressionType::Tuple(tuple) => build_listlike_expr_tree(tuple, "tuple"),
        PreSymbolicExpressionType::SugaredContractIdentifier(contract_name) => {
            // TODO: Look up the source for this contract identifier
            Ok(ExprTree {
                expr: ExprNode::SugaredContractIdentifier(contract_name.clone()),
                children: vec![],
                branching: false,
            })
        }
        PreSymbolicExpressionType::SugaredFieldIdentifier(contract_name, field_name) => {
            // TODO: Look up the source for this field identifier
            Ok(ExprTree {
                expr: ExprNode::SugaredFieldIdentifier(contract_name.clone(), field_name.clone()),
                children: vec![],
                branching: false,
            })
        }
        PreSymbolicExpressionType::FieldIdentifier(field_name) => Ok(ExprTree {
            expr: ExprNode::FieldIdentifier(field_name.clone()),
            children: vec![],
            branching: false,
        }),
        PreSymbolicExpressionType::TraitReference(trait_name) => {
            // TODO: Look up the source for this trait reference
            Ok(ExprTree {
                expr: ExprNode::TraitReference(trait_name.clone()),
                children: vec![],
                branching: false,
            })
        }
        // Comments and placeholders should be filtered out during traversal
        PreSymbolicExpressionType::Comment(_comment) => {
            Err("hit an irrelevant comment expr type".to_string())
        }
        PreSymbolicExpressionType::Placeholder(_placeholder) => {
            Err("hit an irrelevant placeholder expr type".to_string())
        }
    }
}

/// Helper function to build expression trees for both lists and tuples
fn build_listlike_expr_tree(
    items: &[PreSymbolicExpression],
    container_type: &str,
) -> Result<ExprTree, String> {
    let function_name = match &items[0].pre_expr {
        PreSymbolicExpressionType::Atom(name) => name,
        _ => {
            return Err(format!(
                "First element of {} must be an atom (function name)",
                container_type
            ));
        }
    };

    let args = &items[1..];
    let mut children = Vec::new();

    // Build children for all arguments, skipping comments and placeholders
    for arg in args {
        match &arg.pre_expr {
            PreSymbolicExpressionType::Comment(_) | PreSymbolicExpressionType::Placeholder(_) => {
                // Skip comments and placeholders
                continue;
            }
            _ => {
                children.push(build_expr_tree(arg)?);
            }
        }
    }

    // Determine if this is a branching function
    let branching = is_branching_function(function_name);

    // Create the appropriate ExprNode
    let expr_node = match function_name.as_str() {
        "if" => ExprNode::If,
        "match" => ExprNode::Match,
        "unwrap!" | "unwrap-err!" | "unwrap-panic" | "unwrap-err-panic" => ExprNode::Unwrap,
        "ok" => ExprNode::Ok,
        "err" => ExprNode::Err,
        ">" => ExprNode::GT,
        "<" => ExprNode::LT,
        ">=" => ExprNode::GE,
        "<=" => ExprNode::LE,
        "=" | "is-eq" | "eq" => ExprNode::EQ,
        "+" | "add" => ExprNode::Add,
        "-" | "sub" => ExprNode::Sub,
        "*" | "mul" => ExprNode::Mul,
        "/" | "div" => ExprNode::Div,
        _ => ExprNode::Function(function_name.clone()),
    };

    Ok(ExprTree {
        expr: expr_node,
        children,
        branching,
    })
}

/// Determine if a function name represents a branching function
fn is_branching_function(function_name: &ClarityName) -> bool {
    match function_name.as_str() {
        "if" | "match" | "unwrap!" | "unwrap-err!" => true,
        _ => false,
    }
}

// TODO: Needs alternative traversals to get min/max
fn build_cost_tree(expr: &PreSymbolicExpression) -> Result<StaticCostNode, String> {
    match &expr.pre_expr {
        PreSymbolicExpressionType::List(list) => {
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

    #[test]
    fn test_build_expr_tree_if_expression() {
        let source = "(if (> 3 0) (ok true) (ok false))";
        let pre_expressions = parse(source).unwrap();
        let pre_expr = &pre_expressions[0];
        let expr_tree = build_expr_tree(pre_expr).unwrap();

        // Root should be an If node with branching=true
        assert!(matches!(expr_tree.expr, ExprNode::If));
        assert!(expr_tree.branching);
        assert_eq!(expr_tree.children.len(), 3); // condition, then, else

        // First child should be GT comparison
        let gt_node = &expr_tree.children[0];
        assert!(matches!(gt_node.expr, ExprNode::GT));
        assert!(!gt_node.branching);
        assert_eq!(gt_node.children.len(), 2); // 3 and 0

        // GT children should be AtomValue(3) and AtomValue(0)
        let left_val = &gt_node.children[0];
        let right_val = &gt_node.children[1];
        assert!(matches!(left_val.expr, ExprNode::AtomValue(_)));
        assert!(matches!(right_val.expr, ExprNode::AtomValue(_)));

        // Second child should be Ok(true)
        let ok_true_node = &expr_tree.children[1];
        assert!(matches!(ok_true_node.expr, ExprNode::Ok));
        assert!(!ok_true_node.branching);
        assert_eq!(ok_true_node.children.len(), 1);

        // Third child should be Ok(false)
        let ok_false_node = &expr_tree.children[2];
        assert!(matches!(ok_false_node.expr, ExprNode::Ok));
        assert!(!ok_false_node.branching);
        assert_eq!(ok_false_node.children.len(), 1);
    }

    #[test]
    fn test_build_expr_tree_arithmetic() {
        let source = "(+ (* 2 3) (- 5 1))";
        let pre_expressions = parse(source).unwrap();
        let pre_expr = &pre_expressions[0];
        let expr_tree = build_expr_tree(pre_expr).unwrap();

        // Root should be Add node
        assert!(matches!(expr_tree.expr, ExprNode::Add));
        assert!(!expr_tree.branching);
        assert_eq!(expr_tree.children.len(), 2);

        // First child should be Mul
        let mul_node = &expr_tree.children[0];
        assert!(matches!(mul_node.expr, ExprNode::Mul));
        assert_eq!(mul_node.children.len(), 2);

        // Second child should be Sub
        let sub_node = &expr_tree.children[1];
        assert!(matches!(sub_node.expr, ExprNode::Sub));
        assert_eq!(sub_node.children.len(), 2);
    }

    #[test]
    fn test_build_expr_tree_with_comments() {
        let source = "(+ 1 ;; this is a comment\n 2)";
        let pre_expressions = parse(source).unwrap();
        let pre_expr = &pre_expressions[0];
        let expr_tree = build_expr_tree(pre_expr).unwrap();

        assert!(matches!(expr_tree.expr, ExprNode::Add));
        assert!(!expr_tree.branching);
        assert_eq!(expr_tree.children.len(), 2);

        for child in &expr_tree.children {
            assert!(matches!(child.expr, ExprNode::AtomValue(_)));
        }
    }
}
