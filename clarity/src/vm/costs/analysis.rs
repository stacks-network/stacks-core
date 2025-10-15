// Static cost analysis for Clarity expressions

use std::collections::HashMap;

use crate::vm::Value;
use clarity_types::types::{CharType, SequenceData, TraitIdentifier};

use crate::vm::ast::build_ast;
use crate::vm::costs::cost_functions::{linear, CostValues};
use crate::vm::costs::costs_3::Costs3;
use crate::vm::costs::ExecutionCost;
use crate::vm::errors::InterpreterResult;
use crate::vm::functions::NativeFunctions;
use crate::vm::representations::{ClarityName, SymbolicExpression, SymbolicExpressionType};
use crate::vm::types::QualifiedContractIdentifier;
use crate::vm::ClarityVersion;
use stacks_common::types::StacksEpochId;

// TODO:
// contract-call? - get source from database
// type-checking
// lookups
// unwrap evaluates both branches (https://github.com/clarity-lang/reference/issues/59)

const STRING_COST_BASE: u64 = 36;
const STRING_COST_MULTIPLIER: u64 = 3;

/// Functions where string arguments have zero cost because the function
/// cost includes their processing
const FUNCTIONS_WITH_ZERO_STRING_ARG_COST: &[&str] = &["concat", "len"];

#[derive(Debug, Clone)]
pub enum CostExprNode {
    // Native Clarity functions
    NativeFunction(NativeFunctions),
    // Non-native expressions
    AtomValue(Value),
    Atom(ClarityName),
    FieldIdentifier(TraitIdentifier),
    TraitReference(ClarityName),
    // User function arguments
    UserArgument(ClarityName, ClarityName), // (argument_name, argument_type)
    // User-defined functions
    UserFunction(ClarityName),
}

#[derive(Debug, Clone)]
pub struct CostAnalysisNode {
    pub expr: CostExprNode,
    pub cost: StaticCost,
    pub children: Vec<CostAnalysisNode>,
}

impl CostAnalysisNode {
    pub fn new(expr: CostExprNode, cost: StaticCost, children: Vec<CostAnalysisNode>) -> Self {
        Self {
            expr,
            cost,
            children,
        }
    }

    pub fn leaf(expr: CostExprNode, cost: StaticCost) -> Self {
        Self {
            expr,
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

#[derive(Debug, Clone)]
pub struct UserArgumentsContext {
    /// Map from argument name to argument type
    pub arguments: HashMap<ClarityName, ClarityName>,
}

impl UserArgumentsContext {
    pub fn new() -> Self {
        Self {
            arguments: HashMap::new(),
        }
    }

    pub fn add_argument(&mut self, name: ClarityName, arg_type: ClarityName) {
        self.arguments.insert(name, arg_type);
    }

    pub fn is_user_argument(&self, name: &ClarityName) -> bool {
        self.arguments.contains_key(name)
    }

    pub fn get_argument_type(&self, name: &ClarityName) -> Option<&ClarityName> {
        self.arguments.get(name)
    }
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

    /// minimum cost across all paths
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

    /// maximum cost across all paths
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
/// theoretically you could inspect the tree at any node to get the spot cost
pub fn static_cost(source: &str, clarity_version: &ClarityVersion) -> Result<StaticCost, String> {
    let contract_identifier = QualifiedContractIdentifier::transient();
    let mut cost_tracker = ();
    let epoch = StacksEpochId::latest(); // XXX this should be matched with the clarity version

    let ast = build_ast(
        &contract_identifier,
        source,
        &mut cost_tracker,
        *clarity_version,
        epoch,
    )
    .map_err(|e| format!("Parse error: {:?}", e))?;

    if ast.expressions.is_empty() {
        return Err("No expressions found".to_string());
    }

    // TODO what happens if multiple expressions are selected?
    let expr = &ast.expressions[0];
    let user_args = UserArgumentsContext::new();
    let cost_analysis_tree = build_cost_analysis_tree(expr, &user_args, clarity_version)?;

    let summing_cost = calculate_total_cost_with_branching(&cost_analysis_tree);
    Ok(summing_cost.into())
}

fn build_cost_analysis_tree(
    expr: &SymbolicExpression,
    user_args: &UserArgumentsContext,
    clarity_version: &ClarityVersion,
) -> Result<CostAnalysisNode, String> {
    match &expr.expr {
        SymbolicExpressionType::List(list) => {
            if let Some(function_name) = list.first().and_then(|first| first.match_atom()) {
                if function_name.as_str() == "define-public"
                    || function_name.as_str() == "define-private"
                    || function_name.as_str() == "define-read-only"
                {
                    return build_function_definition_cost_analysis_tree(
                        list,
                        user_args,
                        clarity_version,
                    );
                }
            }
            build_listlike_cost_analysis_tree(list, "list", user_args, clarity_version)
        }
        SymbolicExpressionType::AtomValue(value) => {
            let cost = calculate_value_cost(value)?;
            Ok(CostAnalysisNode::leaf(
                CostExprNode::AtomValue(value.clone()),
                cost,
            ))
        }
        SymbolicExpressionType::LiteralValue(value) => {
            let cost = calculate_value_cost(value)?;
            Ok(CostAnalysisNode::leaf(
                CostExprNode::AtomValue(value.clone()),
                cost,
            ))
        }
        SymbolicExpressionType::Atom(name) => {
            let expr_node = parse_atom_expression(name, user_args)?;
            Ok(CostAnalysisNode::leaf(expr_node, StaticCost::ZERO))
        }
        SymbolicExpressionType::Field(field_identifier) => Ok(CostAnalysisNode::leaf(
            CostExprNode::FieldIdentifier(field_identifier.clone()),
            StaticCost::ZERO,
        )),
        SymbolicExpressionType::TraitReference(trait_name, _trait_definition) => {
            Ok(CostAnalysisNode::leaf(
                CostExprNode::TraitReference(trait_name.clone()),
                StaticCost::ZERO,
            ))
        }
    }
}

/// Parse an atom expression into an ExprNode
fn parse_atom_expression(
    name: &ClarityName,
    user_args: &UserArgumentsContext,
) -> Result<CostExprNode, String> {
    // Check if this atom is a user-defined function argument
    if user_args.is_user_argument(name) {
        if let Some(arg_type) = user_args.get_argument_type(name) {
            Ok(CostExprNode::UserArgument(name.clone(), arg_type.clone()))
        } else {
            Ok(CostExprNode::Atom(name.clone()))
        }
    } else {
        Ok(CostExprNode::Atom(name.clone()))
    }
}

/// Build an expression tree for function definitions like (define-public (foo (a u64)) (ok a))
fn build_function_definition_cost_analysis_tree(
    list: &[SymbolicExpression],
    _user_args: &UserArgumentsContext,
    clarity_version: &ClarityVersion,
) -> Result<CostAnalysisNode, String> {
    let define_type = list[0]
        .match_atom()
        .ok_or("Expected atom for define type")?;
    let signature = list[1]
        .match_list()
        .ok_or("Expected list for function signature")?;
    let body = &list[2];

    let mut children = Vec::new();
    let mut function_user_args = UserArgumentsContext::new();

    // Process function arguments: (a u64)
    for arg_expr in signature.iter().skip(1) {
        if let Some(arg_list) = arg_expr.match_list() {
            if arg_list.len() == 2 {
                let arg_name = arg_list[0]
                    .match_atom()
                    .ok_or("Expected atom for argument name")?;

                let arg_type = match &arg_list[1].expr {
                    SymbolicExpressionType::Atom(type_name) => type_name.clone(),
                    SymbolicExpressionType::AtomValue(value) => {
                        ClarityName::from(value.to_string().as_str())
                    }
                    SymbolicExpressionType::LiteralValue(value) => {
                        ClarityName::from(value.to_string().as_str())
                    }
                    _ => return Err("Argument type must be an atom or atom value".to_string()),
                };

                // Add to function's user arguments context
                function_user_args.add_argument(arg_name.clone(), arg_type.clone());

                // Create UserArgument node
                children.push(CostAnalysisNode::leaf(
                    CostExprNode::UserArgument(arg_name.clone(), arg_type),
                    StaticCost::ZERO,
                ));
            }
        }
    }

    // Process the function body with the function's user arguments context
    let body_tree = build_cost_analysis_tree(body, &function_user_args, clarity_version)?;
    children.push(body_tree);

    // Create the function definition node with zero cost (function definitions themselves don't have execution cost)
    Ok(CostAnalysisNode::new(
        CostExprNode::UserFunction(define_type.clone()),
        StaticCost::ZERO,
        children,
    ))
}

/// Helper function to build expression trees for both lists and tuples
fn build_listlike_cost_analysis_tree(
    items: &[SymbolicExpression],
    container_type: &str,
    user_args: &UserArgumentsContext,
    clarity_version: &ClarityVersion,
) -> Result<CostAnalysisNode, String> {
    let function_name = match &items[0].expr {
        SymbolicExpressionType::Atom(name) => name,
        _ => {
            return Err(format!(
                "First element of {} must be an atom (function name)",
                container_type
            ));
        }
    };

    let args = &items[1..];
    let mut children = Vec::new();

    // Build children for all arguments
    for arg in args {
        children.push(build_cost_analysis_tree(arg, user_args, clarity_version)?);
    }

    // Try to lookup the function as a native function first
    let expr_node = if let Some(native_function) =
        NativeFunctions::lookup_by_name_at_version(function_name.as_str(), clarity_version)
    {
        CostExprNode::NativeFunction(native_function)
    } else {
        // If not a native function, treat as user-defined function
        CostExprNode::UserFunction(function_name.clone())
    };

    let cost = calculate_function_cost_from_name(function_name.as_str(), children.len() as u64)?;

    // Handle special cases for string arguments to functions that include their processing cost
    if FUNCTIONS_WITH_ZERO_STRING_ARG_COST.contains(&function_name.as_str()) {
        for child in &mut children {
            if let CostExprNode::AtomValue(Value::Sequence(SequenceData::String(_))) = &child.expr {
                child.cost = StaticCost::ZERO;
            }
        }
    }

    Ok(CostAnalysisNode::new(expr_node, cost, children))
}

/// This function is no longer needed - we now use NativeFunctions::lookup_by_name_at_version
/// directly in build_listlike_cost_analysis_tree

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

/// Helper function to determine if a node represents a branching operation
/// This is used in tests and cost calculation
fn is_node_branching(node: &CostAnalysisNode) -> bool {
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
fn calculate_value_cost(value: &Value) -> Result<StaticCost, String> {
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
        _ => None, // TODO
    }
}

/// Calculate total cost using SummingExecutionCost to handle branching properly
fn calculate_total_cost_with_summing(node: &CostAnalysisNode) -> SummingExecutionCost {
    let mut summing_cost = SummingExecutionCost::from_single(node.cost.min.clone());

    for child in &node.children {
        let child_summing = calculate_total_cost_with_summing(child);
        summing_cost.add_summing(&child_summing);
    }

    summing_cost
}

fn calculate_total_cost_with_branching(node: &CostAnalysisNode) -> SummingExecutionCost {
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
    cost_fn: fn(u64) -> InterpreterResult<ExecutionCost>,
    arg_count: u64,
) -> Result<ExecutionCost, String> {
    let cost = cost_fn(arg_count).map_err(|e| format!("Cost calculation error: {:?}", e))?;
    Ok(cost)
}

#[cfg(test)]
mod tests {

    use super::*;

    fn build_test_ast(src: &str) -> crate::vm::ast::ContractAST {
        let contract_identifier = QualifiedContractIdentifier::transient();
        let mut cost_tracker = ();
        let ast = build_ast(
            &contract_identifier,
            src,
            &mut cost_tracker,
            ClarityVersion::Clarity1,
            StacksEpochId::latest(),
        )
        .unwrap();
        ast
    }

    #[test]
    fn test_constant() {
        let source = "9001";
        let cost = static_cost(source, &ClarityVersion::Clarity1).unwrap();
        assert_eq!(cost.min.runtime, 0);
        assert_eq!(cost.max.runtime, 0);
    }

    #[test]
    fn test_simple_addition() {
        let source = "(+ 1 2)";
        let cost = static_cost(source, &ClarityVersion::Clarity1).unwrap();

        // Min: linear(2, 11, 125) = 11*2 + 125 = 147
        assert_eq!(cost.min.runtime, 147);
        assert_eq!(cost.max.runtime, 147);
    }

    #[test]
    fn test_arithmetic() {
        let source = "(- u4 (+ u1 u2))";
        let cost = static_cost(source, &ClarityVersion::Clarity1).unwrap();
        assert_eq!(cost.min.runtime, 147 + 147);
        assert_eq!(cost.max.runtime, 147 + 147);
    }

    #[test]
    fn test_nested_operations() {
        let source = "(* (+ u1 u2) (- u3 u4))";
        let cost = static_cost(source, &ClarityVersion::Clarity1).unwrap();
        // multiplication: 13*2 + 125 = 151
        assert_eq!(cost.min.runtime, 151 + 147 + 147);
        assert_eq!(cost.max.runtime, 151 + 147 + 147);
    }

    #[test]
    fn test_string_concat_min_max() {
        let source = r#"(concat "hello" "world")"#;
        let cost = static_cost(source, &ClarityVersion::Clarity1).unwrap();

        // For concat with 2 arguments:
        // linear(2, 37, 220) = 37*2 + 220 = 294
        assert_eq!(cost.min.runtime, 294);
        assert_eq!(cost.max.runtime, 294);
    }

    #[test]
    fn test_string_len_min_max() {
        let source = r#"(len "hello")"#;
        let cost = static_cost(source, &ClarityVersion::Clarity1).unwrap();

        // cost: 429 (constant) - len doesn't depend on string size
        assert_eq!(cost.min.runtime, 429);
        assert_eq!(cost.max.runtime, 429);
    }

    #[test]
    fn test_branching() {
        let source = "(if (> 3 0) (ok (concat \"hello\" \"world\")) (ok \"asdf\"))";
        let cost = static_cost(source, &ClarityVersion::Clarity1).unwrap();
        // min: 147 raw string
        // max: 294 (concat)

        // ok = 199
        // if = 168
        // ge = (linear(n, 7, 128)))
        let base_cost = 168 + ((2 * 7) + 128) + 199;
        assert_eq!(cost.min.runtime, base_cost + 147);
        assert_eq!(cost.max.runtime, base_cost + 294);
    }

    //  ----  ExprTreee building specific tests
    #[test]
    fn test_build_cost_analysis_tree_if_expression() {
        let src = "(if (> 3 0) (ok true) (ok false))";
        let ast = build_test_ast(src);
        let expr = &ast.expressions[0];
        let user_args = UserArgumentsContext::new();
        let cost_tree =
            build_cost_analysis_tree(expr, &user_args, &ClarityVersion::Clarity1).unwrap();

        // Root should be an If node with branching=true
        assert!(matches!(
            cost_tree.expr,
            CostExprNode::NativeFunction(NativeFunctions::If)
        ));
        assert!(is_node_branching(&cost_tree));
        assert_eq!(cost_tree.children.len(), 3);

        let gt_node = &cost_tree.children[0];
        assert!(matches!(
            gt_node.expr,
            CostExprNode::NativeFunction(NativeFunctions::CmpGreater)
        ));
        assert_eq!(gt_node.children.len(), 2);

        let left_val = &gt_node.children[0];
        let right_val = &gt_node.children[1];
        assert!(matches!(left_val.expr, CostExprNode::AtomValue(_)));
        assert!(matches!(right_val.expr, CostExprNode::AtomValue(_)));

        let ok_true_node = &cost_tree.children[1];
        assert!(matches!(
            ok_true_node.expr,
            CostExprNode::NativeFunction(NativeFunctions::ConsOkay)
        ));
        assert_eq!(ok_true_node.children.len(), 1);

        let ok_false_node = &cost_tree.children[2];
        assert!(matches!(
            ok_false_node.expr,
            CostExprNode::NativeFunction(NativeFunctions::ConsOkay)
        ));
        assert_eq!(ok_false_node.children.len(), 1);
    }

    #[test]
    fn test_build_cost_analysis_tree_arithmetic() {
        let src = "(+ (* 2 3) (- 5 1))";
        let ast = build_test_ast(src);
        let expr = &ast.expressions[0];
        let user_args = UserArgumentsContext::new();
        let cost_tree =
            build_cost_analysis_tree(expr, &user_args, &ClarityVersion::Clarity1).unwrap();

        assert!(matches!(
            cost_tree.expr,
            CostExprNode::NativeFunction(NativeFunctions::Add)
        ));
        assert!(!is_node_branching(&cost_tree));
        assert_eq!(cost_tree.children.len(), 2);

        let mul_node = &cost_tree.children[0];
        assert!(matches!(
            mul_node.expr,
            CostExprNode::NativeFunction(NativeFunctions::Multiply)
        ));
        assert_eq!(mul_node.children.len(), 2);

        let sub_node = &cost_tree.children[1];
        assert!(matches!(
            sub_node.expr,
            CostExprNode::NativeFunction(NativeFunctions::Subtract)
        ));
        assert_eq!(sub_node.children.len(), 2);
    }

    #[test]
    fn test_build_cost_analysis_tree_with_comments() {
        let src = ";; This is a comment\n(+ 5 ;; another comment\n7)";
        let ast = build_test_ast(src);
        let expr = &ast.expressions[0];
        let user_args = UserArgumentsContext::new();
        let cost_tree =
            build_cost_analysis_tree(expr, &user_args, &ClarityVersion::Clarity1).unwrap();

        assert!(matches!(
            cost_tree.expr,
            CostExprNode::NativeFunction(NativeFunctions::Add)
        ));
        assert!(!is_node_branching(&cost_tree));
        assert_eq!(cost_tree.children.len(), 2);

        for child in &cost_tree.children {
            assert!(matches!(child.expr, CostExprNode::AtomValue(_)));
        }
    }

    #[test]
    fn test_function_with_multiple_arguments() {
        let src = r#"(define-public (add-two (x uint) (y uint)) (+ x y))"#;
        let ast = build_test_ast(src);
        let expr = &ast.expressions[0];
        let user_args = UserArgumentsContext::new();
        let cost_tree =
            build_cost_analysis_tree(expr, &user_args, &ClarityVersion::Clarity1).unwrap();

        // Should have 3 children: UserArgument for (x uint), UserArgument for (y uint), and the body (+ x y)
        assert_eq!(cost_tree.children.len(), 3);

        // First child should be UserArgument for (x uint)
        let user_arg_x = &cost_tree.children[0];
        assert!(matches!(user_arg_x.expr, CostExprNode::UserArgument(_, _)));
        if let CostExprNode::UserArgument(arg_name, arg_type) = &user_arg_x.expr {
            assert_eq!(arg_name.as_str(), "x");
            assert_eq!(arg_type.as_str(), "uint");
        }

        // Second child should be UserArgument for (y u64)
        let user_arg_y = &cost_tree.children[1];
        assert!(matches!(user_arg_y.expr, CostExprNode::UserArgument(_, _)));
        if let CostExprNode::UserArgument(arg_name, arg_type) = &user_arg_y.expr {
            assert_eq!(arg_name.as_str(), "y");
            assert_eq!(arg_type.as_str(), "uint");
        }

        // Third child should be the function body (+ x y)
        let body_node = &cost_tree.children[2];
        assert!(matches!(
            body_node.expr,
            CostExprNode::NativeFunction(NativeFunctions::Add)
        ));
        assert_eq!(body_node.children.len(), 2);

        // Both arguments in the body should be UserArguments
        let arg_x_ref = &body_node.children[0];
        let arg_y_ref = &body_node.children[1];
        assert!(matches!(arg_x_ref.expr, CostExprNode::UserArgument(_, _)));
        assert!(matches!(arg_y_ref.expr, CostExprNode::UserArgument(_, _)));

        if let CostExprNode::UserArgument(name, arg_type) = &arg_x_ref.expr {
            assert_eq!(name.as_str(), "x");
            assert_eq!(arg_type.as_str(), "uint");
        }
        if let CostExprNode::UserArgument(name, arg_type) = &arg_y_ref.expr {
            assert_eq!(name.as_str(), "y");
            assert_eq!(arg_type.as_str(), "uint");
        }
    }
}
