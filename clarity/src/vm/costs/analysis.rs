// Static cost analysis for Clarity expressions

use clarity_serialization::representations::ContractName;
use clarity_serialization::types::{CharType, SequenceData, TraitIdentifier};
use clarity_serialization::Value;

use crate::vm::ast::parser::v2::parse;
use crate::vm::costs::cost_functions::{linear, CostValues};
use crate::vm::costs::costs_3::Costs3;
use crate::vm::costs::ExecutionCost;
use crate::vm::errors::InterpreterResult;
use crate::vm::representations::{ClarityName, PreSymbolicExpression, PreSymbolicExpressionType};

// TODO:
// variable traverse for
//   - if, unwrap-*, match, etc
// contract-call? - get source from database
// type-checking
// lookups
// unwrap evaluates both branches (https://github.com/clarity-lang/reference/issues/59)

/// Calculate the cost for a string based on its length
fn string_cost(length: usize) -> StaticCost {
    let cost = linear(length as u64, 36, 3);
    let execution_cost = ExecutionCost::runtime(cost);
    StaticCost {
        min: execution_cost.clone(),
        max: execution_cost,
    }
}

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

/// A type to track summed execution costs for different paths
/// This allows us to compute min and max costs across different execution paths
#[derive(Debug, Clone)]
pub struct SummingExecutionCost {
    pub costs: Vec<ExecutionCost>,
}

impl SummingExecutionCost {
    pub fn new() -> Self {
        Self { costs: Vec::new() }
    }

    pub fn from_single(cost: ExecutionCost) -> Self {
        Self { costs: vec![cost] }
    }

    pub fn add_cost(&mut self, cost: ExecutionCost) {
        self.costs.push(cost);
    }

    pub fn add_summing(&mut self, other: &SummingExecutionCost) {
        self.costs.extend(other.costs.clone());
    }

    /// Get the minimum cost across all paths
    pub fn min(&self) -> ExecutionCost {
        if self.costs.is_empty() {
            ExecutionCost::ZERO
        } else {
            self.costs
                .iter()
                .fold(self.costs[0].clone(), |acc, cost| ExecutionCost {
                    runtime: acc.runtime.min(cost.runtime),
                    write_length: acc.write_length.min(cost.write_length),
                    write_count: acc.write_count.min(cost.write_count),
                    read_length: acc.read_length.min(cost.read_length),
                    read_count: acc.read_count.min(cost.read_count),
                })
        }
    }

    /// Get the maximum cost across all paths
    pub fn max(&self) -> ExecutionCost {
        if self.costs.is_empty() {
            ExecutionCost::ZERO
        } else {
            self.costs
                .iter()
                .fold(self.costs[0].clone(), |acc, cost| ExecutionCost {
                    runtime: acc.runtime.max(cost.runtime),
                    write_length: acc.write_length.max(cost.write_length),
                    write_count: acc.write_count.max(cost.write_count),
                    read_length: acc.read_length.max(cost.read_length),
                    read_count: acc.read_count.max(cost.read_count),
                })
        }
    }

    /// Combine costs by adding them (for non-branching operations)
    pub fn add_all(&self) -> ExecutionCost {
        self.costs
            .iter()
            .fold(ExecutionCost::ZERO, |mut acc, cost| {
                let _ = acc.add(cost);
                acc
            })
    }
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
    let expr_tree = build_expr_tree(pre_expr)?;
    let cost_tree = build_cost_tree(&expr_tree)?;

    // Use branching-aware cost calculation
    let summing_cost = calculate_total_cost_with_branching(&expr_tree, &cost_tree);
    Ok(summing_cost.into())
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
    // User function arguments
    UserArgument(ClarityName, ClarityName), // (argument_name, argument_type)
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
        PreSymbolicExpressionType::List(list) => {
            // Check if this is a function definition
            if let Some(function_name) = list.first().and_then(|first| first.match_atom()) {
                if function_name.as_str() == "define-public"
                    || function_name.as_str() == "define-private"
                    || function_name.as_str() == "define-read-only"
                {
                    return build_function_definition_expr_tree(list);
                }
            }
            build_listlike_expr_tree(list, "list")
        }
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

/// Build an expression tree for function definitions like (define-public (foo (a u64)) (ok a))
fn build_function_definition_expr_tree(list: &[PreSymbolicExpression]) -> Result<ExprTree, String> {
    if list.len() < 3 {
        return Err(
            "Function definition must have at least 3 elements: define type, signature, and body"
                .to_string(),
        );
    }

    let define_type = list[0]
        .match_atom()
        .ok_or("First element must be define type")?;
    let signature = list[1]
        .match_list()
        .ok_or("Second element must be function signature")?;
    let body = &list[2];

    // Parse the function signature: (foo (a u64))
    if signature.is_empty() {
        return Err("Function signature cannot be empty".to_string());
    }

    let _function_name = signature[0]
        .match_atom()
        .ok_or("Function name must be an atom")?;
    let mut children = Vec::new();

    // Process function arguments: (a u64)
    for arg_expr in signature.iter().skip(1) {
        if let Some(arg_list) = arg_expr.match_list() {
            if arg_list.len() == 2 {
                let arg_name = arg_list[0]
                    .match_atom()
                    .ok_or("Argument name must be an atom")?;

                // Handle both atom types and atom values for the type
                let arg_type = match &arg_list[1].pre_expr {
                    PreSymbolicExpressionType::Atom(type_name) => type_name.clone(),
                    PreSymbolicExpressionType::AtomValue(value) => {
                        // Convert the value to a string representation
                        ClarityName::from(value.to_string().as_str())
                    }
                    _ => return Err("Argument type must be an atom or atom value".to_string()),
                };

                // Create UserArgument node
                children.push(ExprTree {
                    expr: ExprNode::UserArgument(arg_name.clone(), arg_type),
                    children: vec![],
                    branching: false,
                });
            } else {
                return Err(
                    "Function argument must have exactly 2 elements: name and type".to_string(),
                );
            }
        } else {
            return Err("Function argument must be a list".to_string());
        }
    }

    // Process the function body
    let body_tree = build_expr_tree(body)?;
    children.push(body_tree);

    // Create the function definition node
    Ok(ExprTree {
        expr: ExprNode::Function(define_type.clone()),
        children,
        branching: false,
    })
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
        "if" | "match" => true,
        "unwrap!" | "unwrap-err!" => false, // XXX: currently unwrap and
        // unwrap-err traverse both branches regardless of result, so until this is
        // fixed in clarity we'll set this to false
        _ => false,
    }
}

/// Build a cost tree from an expression tree, using branching logic for min/max calculation
fn build_cost_tree(expr_tree: &ExprTree) -> Result<StaticCostNode, String> {
    let function_name = match &expr_tree.expr {
        ExprNode::If => "if",
        ExprNode::Match => "match",
        ExprNode::Unwrap => "unwrap!",
        ExprNode::Ok => "ok",
        ExprNode::Err => "err",
        ExprNode::GT => ">",
        ExprNode::LT => "<",
        ExprNode::GE => ">=",
        ExprNode::LE => "<=",
        ExprNode::EQ => "=",
        ExprNode::Add => "+",
        ExprNode::Sub => "-",
        ExprNode::Mul => "*",
        ExprNode::Div => "/",
        ExprNode::Function(name) => name.as_str(),
        ExprNode::AtomValue(value) => {
            // String literals have cost based on length only when they're standalone (not function arguments)
            // TODO: not sure if /utf8 and ascii are treated the same cost-wise..
            if let Value::Sequence(SequenceData::String(CharType::UTF8(data))) = value {
                return Ok(StaticCostNode::leaf(vec![], string_cost(data.data.len())));
            } else if let Value::Sequence(SequenceData::String(CharType::ASCII(data))) = value {
                return Ok(StaticCostNode::leaf(vec![], string_cost(data.data.len())));
            }
            // Other atom values have zero cost
            return Ok(StaticCostNode::leaf(vec![], StaticCost::ZERO));
        }
        ExprNode::Atom(_)
        | ExprNode::SugaredContractIdentifier(_)
        | ExprNode::SugaredFieldIdentifier(_, _)
        | ExprNode::FieldIdentifier(_)
        | ExprNode::TraitReference(_)
        | ExprNode::UserArgument(_, _) => {
            // Leaf nodes have zero cost
            return Ok(StaticCostNode::leaf(vec![], StaticCost::ZERO));
        }
    };

    let mut children = Vec::new();
    for child_expr in &expr_tree.children {
        // For certain functions like concat and len, string arguments should have zero cost
        // since the function cost includes their processing
        if function_name == "concat" || function_name == "len" {
            if let ExprNode::AtomValue(Value::Sequence(SequenceData::String(_))) = &child_expr.expr
            {
                // String arguments to concat and len have zero cost
                children.push(StaticCostNode::leaf(vec![], StaticCost::ZERO));
                continue;
            }
        }
        children.push(build_cost_tree(child_expr)?);
    }

    let cost = calculate_function_cost_from_name(function_name, expr_tree.children.len() as u64)?;

    // Create a representative PreSymbolicExpression for the node
    let function_expr = PreSymbolicExpression {
        pre_expr: PreSymbolicExpressionType::Atom(ClarityName::from(function_name)),
        id: 0, // We don't need accurate IDs for cost analysis
    };
    let mut expr_list = vec![function_expr];

    // Add placeholder expressions for children (we don't need the actual child expressions)
    for _ in &expr_tree.children {
        expr_list.push(PreSymbolicExpression {
            pre_expr: PreSymbolicExpressionType::Atom(ClarityName::from("placeholder")),
            id: 0,
        });
    }

    Ok(StaticCostNode::new(expr_list, cost, children))
}

fn calculate_function_cost_from_name(
    function_name: &str,
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

/// Convert a function name string to its corresponding cost function
fn get_cost_function_for_name(name: &str) -> Option<fn(u64) -> InterpreterResult<ExecutionCost>> {
    // Map function names to their cost functions using the existing enum structure
    match name {
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

fn calculate_total_cost(node: &StaticCostNode) -> StaticCost {
    calculate_total_cost_with_summing(node).into()
}

/// Calculate total cost using SummingExecutionCost to handle branching properly
fn calculate_total_cost_with_summing(node: &StaticCostNode) -> SummingExecutionCost {
    let mut summing_cost = SummingExecutionCost::from_single(node.cost.min.clone());

    // For each child, calculate its cost and combine appropriately
    for child in &node.children {
        let child_summing = calculate_total_cost_with_summing(child);
        summing_cost.add_summing(&child_summing);
    }

    summing_cost
}

/// Calculate total cost using branching logic from ExprTree
fn calculate_total_cost_with_branching(
    expr_tree: &ExprTree,
    cost_node: &StaticCostNode,
) -> SummingExecutionCost {
    let mut summing_cost = SummingExecutionCost::new();

    if expr_tree.branching {
        // Handle different types of branching functions
        match &expr_tree.expr {
            ExprNode::If | ExprNode::Match => {
                // For if and match, we need to create separate execution paths
                // The first child is the condition, the rest are the branches
                if cost_node.children.len() >= 2 {
                    let condition_cost = calculate_total_cost_with_summing(&cost_node.children[0]);
                    let condition_total = condition_cost.add_all();

                    // Add the root cost + condition cost to each branch
                    let mut root_and_condition = cost_node.cost.min.clone();
                    let _ = root_and_condition.add(&condition_total);

                    // For each branch (children 1+), create a complete path
                    for child_cost_node in cost_node.children.iter().skip(1) {
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
                let mut total_cost = cost_node.cost.min.clone();
                for child_cost_node in &cost_node.children {
                    let child_summing = calculate_total_cost_with_summing(child_cost_node);
                    let combined_cost = child_summing.add_all();
                    let _ = total_cost.add(&combined_cost);
                }
                summing_cost.add_cost(total_cost);
            }
        }
    } else {
        // For non-branching, add all costs sequentially
        let mut total_cost = cost_node.cost.min.clone();
        for child_cost_node in &cost_node.children {
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
    fn test_branching() {
        let source = "(if (> 3 0) (ok (concat \"hello\" \"world\")) (ok \"asdf\"))";
        let cost = static_cost(source).unwrap();
        // min: 147 raw string
        // max: 294 (concat)

        // ok = 199
        // if = 168
        // ge = (linear(n, 7, 128)))
        let base_cost = 168 + ((2 * 7) + 128) + 199;
        assert_eq!(cost.min.runtime, base_cost + 147);
        assert_eq!(cost.max.runtime, base_cost + 294);
    }
    #[test]
    fn test_function_arguments() {
        let src = r#"(define-public (foo (a u64)) (ok a))"#;
        let pre_expressions = parse(src).unwrap();
        let pre_expr = &pre_expressions[0];
        let expr_tree = build_expr_tree(pre_expr).unwrap();

        // The root should be a Function node with "define-public"
        assert!(matches!(expr_tree.expr, ExprNode::Function(_)));
        if let ExprNode::Function(name) = &expr_tree.expr {
            assert_eq!(name.as_str(), "define-public");
        }

        // Should have 2 children: UserArgument for (a u64) and the body (ok a)
        assert_eq!(expr_tree.children.len(), 2);

        // First child should be UserArgument for (a u64)
        let user_arg = &expr_tree.children[0];
        assert!(matches!(user_arg.expr, ExprNode::UserArgument(_, _)));
        if let ExprNode::UserArgument(arg_name, arg_type) = &user_arg.expr {
            assert_eq!(arg_name.as_str(), "a");
            assert_eq!(arg_type.as_str(), "u64");
        }

        // Second child should be the function body (ok a)
        let body = &expr_tree.children[1];
        assert!(matches!(body.expr, ExprNode::Ok));
        assert_eq!(body.children.len(), 1);

        // The body should reference the argument 'a'
        let arg_ref = &body.children[0];
        assert!(matches!(arg_ref.expr, ExprNode::Atom(_)));
        if let ExprNode::Atom(name) = &arg_ref.expr {
            assert_eq!(name.as_str(), "a");
        }
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
