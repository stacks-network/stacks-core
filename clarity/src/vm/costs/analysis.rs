// Static cost analysis for Clarity contracts

use std::collections::HashMap;

use clarity_types::types::TraitIdentifier;
use stacks_common::types::StacksEpochId;

use crate::vm::ast::build_ast;
// #[cfg(feature = "developer-mode")]
use crate::vm::ast::static_cost::{
    calculate_function_cost, calculate_function_cost_from_native_function,
    calculate_total_cost_with_branching, calculate_value_cost, TraitCount, TraitCountCollector,
    TraitCountContext, TraitCountPropagator, TraitCountVisitor,
};
use crate::vm::contexts::Environment;
use crate::vm::costs::cost_functions::ClarityCostFunction;
use crate::vm::costs::ExecutionCost;
use crate::vm::functions::NativeFunctions;
use crate::vm::representations::{ClarityName, SymbolicExpression, SymbolicExpressionType};
use crate::vm::types::QualifiedContractIdentifier;
use crate::vm::{ClarityVersion, Value};
// TODO:
// contract-call? - get source from database
// type-checking
// lookups
// unwrap evaluates both branches (https://github.com/clarity-lang/reference/issues/59)
// split up trait counting and expr node tree impl into separate module?

const STRING_COST_BASE: u64 = 36;
const STRING_COST_MULTIPLIER: u64 = 3;

/// Functions where string arguments have zero cost because the function
/// cost includes their processing
const FUNCTIONS_WITH_ZERO_STRING_ARG_COST: &[&str] = &["concat", "len"];

const FUNCTION_DEFINITION_KEYWORDS: &[&str] =
    &["define-public", "define-private", "define-read-only"];

pub(crate) fn is_function_definition(function_name: &str) -> bool {
    FUNCTION_DEFINITION_KEYWORDS.contains(&function_name)
}

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
    UserArgument(ClarityName, SymbolicExpressionType), // (argument_name, argument_type)
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
    pub arguments: HashMap<ClarityName, SymbolicExpressionType>,
}

impl UserArgumentsContext {
    pub fn new() -> Self {
        Self {
            arguments: HashMap::new(),
        }
    }

    pub fn add_argument(&mut self, name: ClarityName, arg_type: SymbolicExpressionType) {
        self.arguments.insert(name, arg_type);
    }

    pub fn is_user_argument(&self, name: &ClarityName) -> bool {
        self.arguments.contains_key(name)
    }

    pub fn get_argument_type(&self, name: &ClarityName) -> Option<&SymbolicExpressionType> {
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

fn make_ast(
    source: &str,
    epoch: StacksEpochId,
    clarity_version: &ClarityVersion,
) -> Result<crate::vm::ast::ContractAST, String> {
    let contract_identifier = QualifiedContractIdentifier::transient();
    let mut cost_tracker = ();
    let ast = build_ast(
        &contract_identifier,
        source,
        &mut cost_tracker,
        *clarity_version,
        epoch,
    )
    .map_err(|e| format!("Parse error: {:?}", e))?;
    Ok(ast)
}

/// STatic execution cost for functions within Environment
/// returns the top level cost for specific functions
/// {some-function-name: (CostAnalysisNode, Some({some-function-name: (1,1)}))}
pub fn static_cost(
    env: &mut Environment,
    contract_identifier: &QualifiedContractIdentifier,
) -> Result<HashMap<String, (CostAnalysisNode, Option<TraitCount>)>, String> {
    let contract_source = env
        .global_context
        .database
        .get_contract_src(contract_identifier)
        .ok_or_else(|| {
            format!(
                "Contract source ({:?}) not found in database",
                contract_identifier.to_string(),
            )
        })?;

    let contract = env
        .global_context
        .database
        .get_contract(contract_identifier)
        .map_err(|e| format!("Failed to get contract: {:?}", e))?;

    let clarity_version = contract.contract_context.get_clarity_version();

    let epoch = env.global_context.epoch_id;
    let ast = make_ast(&contract_source, epoch, clarity_version)?;

    static_cost_tree_from_ast(&ast, clarity_version, epoch)
}

/// same idea as `static_cost` but returns the root of the cost analysis tree for each function
/// Useful if you need to analyze specific nodes in the cost tree
pub fn static_cost_tree(
    env: &mut Environment,
    contract_identifier: &QualifiedContractIdentifier,
) -> Result<HashMap<String, (CostAnalysisNode, Option<TraitCount>)>, String> {
    let contract_source = env
        .global_context
        .database
        .get_contract_src(contract_identifier)
        .ok_or_else(|| {
            format!(
                "Contract source ({:?}) not found in database",
                contract_identifier.to_string(),
            )
        })?;

    let contract = env
        .global_context
        .database
        .get_contract(contract_identifier)
        .map_err(|e| format!("Failed to get contract: {:?}", e))?;

    let clarity_version = contract.contract_context.get_clarity_version();

    let epoch = env.global_context.epoch_id;
    let ast = make_ast(&contract_source, epoch, clarity_version)?;

    static_cost_tree_from_ast(&ast, clarity_version, epoch)
}

/// Compute overhead costs for executing a function.
///
/// When a function is called, there are three types of overhead costs that are charged
/// before the function body is executed:
///
/// 1. **Contract Loading Cost** (`cost_load_contract`):
///    - Charged when loading the contract from storage to execute a function
///
/// 2. **Function Lookup Cost** (`cost_lookup_function`):
///    - Charged when looking up the function definition in the contract
///    - This is separate from variable lookups inside the function body
///
/// 3. **Function Application Cost** (`cost_user_function_application`):
///    - Charged when applying a user-defined function (not native functions)
///
/// These overhead costs are added to the function body cost to get the total execution cost.
/// Note: `cost_inner_type_check_cost` for argument type checking is part of the function
/// body cost, not overhead since it depends on the actual argument values/types.
fn compute_function_overhead_costs(
    contract_size: Option<u64>,
    arg_count: u64,
    epoch: StacksEpochId,
) -> ExecutionCost {
    let mut overhead = ExecutionCost::ZERO;

    // cost_load_contract
    if let Some(size) = contract_size {
        let load_cost = ClarityCostFunction::LoadContract
            .eval_for_epoch(size, epoch)
            .unwrap_or_else(|_| ExecutionCost::ZERO);
        overhead.add(&load_cost).ok();
    }

    // cost_lookup_function
    let lookup_cost = ClarityCostFunction::LookupFunction
        .eval_for_epoch(0, epoch)
        .unwrap_or_else(|_| ExecutionCost::ZERO);
    overhead.add(&lookup_cost).ok();

    // cost_user_function_application
    let application_cost = ClarityCostFunction::UserFunctionApplication
        .eval_for_epoch(arg_count, epoch)
        .unwrap_or_else(|_| ExecutionCost::ZERO);
    overhead.add(&application_cost).ok();

    overhead
}

/// Extract function argument count from a function definition expression
fn extract_function_arg_count(expr: &SymbolicExpression) -> Option<u64> {
    expr.match_list().and_then(|list| {
        if list.len() >= 2 {
            list[1].match_list().map(|signature| {
                // Skip the first element: function name
                (signature.len().saturating_sub(1)) as u64
            })
        } else {
            None
        }
    })
}

pub fn static_cost_from_ast(
    contract_ast: &crate::vm::ast::ContractAST,
    clarity_version: &ClarityVersion,
    epoch: StacksEpochId,
) -> Result<HashMap<String, (StaticCost, Option<TraitCount>)>, String> {
    static_cost_from_ast_with_source(contract_ast, clarity_version, epoch, None)
}

pub fn static_cost_from_ast_with_source(
    contract_ast: &crate::vm::ast::ContractAST,
    clarity_version: &ClarityVersion,
    epoch: StacksEpochId,
    contract_source: Option<&str>,
) -> Result<HashMap<String, (StaticCost, Option<TraitCount>)>, String> {
    // Use actual contract source size if provided, otherwise estimate
    let contract_size = contract_source.map(|s| s.len() as u64);

    let cost_trees_with_traits = static_cost_tree_from_ast(contract_ast, clarity_version, epoch)?;

    let trait_count = cost_trees_with_traits
        .values()
        .next()
        .and_then(|(_, trait_count)| trait_count.clone());

    // Convert CostAnalysisNode to StaticCost and add overhead costs
    let costs: HashMap<String, StaticCost> = cost_trees_with_traits
        .iter()
        .filter_map(|(name, (cost_analysis_node, _))| {
            let arg_count = contract_ast.expressions.iter()
                .find_map(|expr| {
                    if let Some(function_name) = extract_function_name(expr) {
                        if function_name == *name {
                            return extract_function_arg_count(expr);
                        }
                    }
                    None
                })
                .unwrap_or(0);

            let summing_cost = calculate_total_cost_with_branching(cost_analysis_node);
            let mut static_cost: StaticCost = summing_cost.into();

            // Add overhead costs to both min and max
            let overhead = compute_function_overhead_costs(
                contract_size,
                arg_count,
                epoch,
            );
            static_cost.min.add(&overhead).ok()?;
            static_cost.max.add(&overhead).ok()?;

            Some((name.clone(), static_cost))
        })
        .collect();

    Ok(costs
        .into_iter()
        .map(|(name, cost)| (name, (cost, trait_count.clone())))
        .collect())
}

pub(crate) fn static_cost_tree_from_ast(
    ast: &crate::vm::ast::ContractAST,
    clarity_version: &ClarityVersion,
    epoch: StacksEpochId,
) -> Result<HashMap<String, (CostAnalysisNode, Option<TraitCount>)>, String> {
    let exprs = &ast.expressions;
    let user_args = UserArgumentsContext::new();
    let costs_map: HashMap<String, Option<StaticCost>> = HashMap::new();
    let mut costs: HashMap<String, Option<CostAnalysisNode>> = HashMap::new();
    // first pass extracts the function names
    for expr in exprs {
        if let Some(function_name) = extract_function_name(expr) {
            costs.insert(function_name, None);
        }
    }
    // second pass computes the cost
    for expr in exprs {
        if let Some(function_name) = extract_function_name(expr) {
            let (_, cost_analysis_tree) =
                build_cost_analysis_tree(expr, &user_args, &costs_map, clarity_version, epoch)?;
            costs.insert(function_name, Some(cost_analysis_tree));
        }
    }

    // Build the final map with cost analysis nodes
    let cost_trees: HashMap<String, CostAnalysisNode> = costs
        .into_iter()
        .filter_map(|(name, cost)| cost.map(|c| (name, c)))
        .collect();

    // Compute trait_count while creating the root CostAnalysisNode
    let trait_count = get_trait_count(&cost_trees);

    // Return each node with its trait_count
    Ok(cost_trees
        .into_iter()
        .map(|(name, node)| (name, (node, trait_count.clone())))
        .collect())
}

/// Extract function name from a symbolic expression
fn extract_function_name(expr: &SymbolicExpression) -> Option<String> {
    expr.match_list().and_then(|list| {
        list.first()
            .and_then(|first| first.match_atom())
            .filter(|atom| is_function_definition(atom.as_str()))
            .and_then(|_| list.get(1))
            .and_then(|sig| sig.match_list())
            .and_then(|signature| signature.first())
            .and_then(|name| name.match_atom())
            .map(|name| name.to_string())
    })
}

pub fn build_cost_analysis_tree(
    expr: &SymbolicExpression,
    user_args: &UserArgumentsContext,
    cost_map: &HashMap<String, Option<StaticCost>>,
    clarity_version: &ClarityVersion,
    epoch: StacksEpochId,
) -> Result<(Option<String>, CostAnalysisNode), String> {
    match &expr.expr {
        SymbolicExpressionType::List(list) => {
            if let Some(function_name) = list.first().and_then(|first| first.match_atom()) {
                if is_function_definition(function_name.as_str()) {
                    let (returned_function_name, cost_analysis_tree) =
                        build_function_definition_cost_analysis_tree(
                            list,
                            user_args,
                            cost_map,
                            clarity_version,
                            epoch,
                        )?;
                    Ok((Some(returned_function_name), cost_analysis_tree))
                } else {
                    let cost_analysis_tree = build_listlike_cost_analysis_tree(
                        list,
                        user_args,
                        cost_map,
                        clarity_version,
                        epoch,
                    )?;
                    Ok((None, cost_analysis_tree))
                }
            } else {
                let cost_analysis_tree = build_listlike_cost_analysis_tree(
                    list,
                    user_args,
                    cost_map,
                    clarity_version,
                    epoch,
                )?;
                Ok((None, cost_analysis_tree))
            }
        }
        SymbolicExpressionType::AtomValue(value) => {
            let cost = calculate_value_cost(value)?;
            Ok((
                None,
                CostAnalysisNode::leaf(CostExprNode::AtomValue(value.clone()), cost),
            ))
        }
        SymbolicExpressionType::LiteralValue(value) => {
            let cost = calculate_value_cost(value)?;
            Ok((
                None,
                CostAnalysisNode::leaf(CostExprNode::AtomValue(value.clone()), cost),
            ))
        }
        SymbolicExpressionType::Atom(name) => {
            let expr_node = parse_atom_expression(name, user_args)?;
            Ok((None, CostAnalysisNode::leaf(expr_node, StaticCost::ZERO)))
        }
        SymbolicExpressionType::Field(field_identifier) => Ok((
            None,
            CostAnalysisNode::leaf(
                CostExprNode::FieldIdentifier(field_identifier.clone()),
                StaticCost::ZERO,
            ),
        )),
        SymbolicExpressionType::TraitReference(trait_name, _trait_definition) => Ok((
            None,
            CostAnalysisNode::leaf(
                CostExprNode::TraitReference(trait_name.clone()),
                StaticCost::ZERO,
            ),
        )),
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
    cost_map: &HashMap<String, Option<StaticCost>>,
    clarity_version: &ClarityVersion,
    epoch: StacksEpochId,
) -> Result<(String, CostAnalysisNode), String> {
    let define_type = list[0]
        .match_atom()
        .ok_or("Expected atom for define type")?;
    let signature = list[1]
        .match_list()
        .ok_or("Expected list for function signature")?;
    println!("signature: {:?}", signature);
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

                let arg_type = arg_list[1].clone();

                // Add to function's user arguments context
                function_user_args.add_argument(arg_name.clone(), arg_type.clone().expr);

                // Create UserArgument node
                children.push(CostAnalysisNode::leaf(
                    CostExprNode::UserArgument(arg_name.clone(), arg_type.clone().expr),
                    StaticCost::ZERO,
                ));
            }
        }
    }

    // Process the function body with the function's user arguments context
    let (_, body_tree) =
        build_cost_analysis_tree(body, &function_user_args, cost_map, clarity_version, epoch)?;
    children.push(body_tree);

    // Get the function name from the signature
    let function_name = signature[0]
        .match_atom()
        .ok_or("Expected atom for function name")?;

    // Create the function definition node with zero cost (function definitions themselves don't have execution cost)
    Ok((
        function_name.clone().to_string(),
        CostAnalysisNode::new(
            CostExprNode::UserFunction(define_type.clone()),
            StaticCost::ZERO,
            children,
        ),
    ))
}

fn get_function_name(expr: &SymbolicExpression) -> Result<ClarityName, String> {
    match &expr.expr {
        SymbolicExpressionType::Atom(name) => Ok(name.clone()),
        _ => Err("First element must be an atom (function name)".to_string()),
    }
}

/// Helper function to build expression trees for both lists and tuples
fn build_listlike_cost_analysis_tree(
    exprs: &[SymbolicExpression],
    user_args: &UserArgumentsContext,
    cost_map: &HashMap<String, Option<StaticCost>>,
    clarity_version: &ClarityVersion,
    epoch: StacksEpochId,
) -> Result<CostAnalysisNode, String> {
    let mut children = Vec::new();

    // Build children for all exprs
    for expr in exprs[1..].iter() {
        let (_, child_tree) =
            build_cost_analysis_tree(expr, user_args, cost_map, clarity_version, epoch)?;
        children.push(child_tree);
    }

    let (expr_node, cost) = match &exprs[0].expr {
        SymbolicExpressionType::List(_) => {
            // Recursively analyze the nested list structure
            let (_, nested_tree) =
                build_cost_analysis_tree(&exprs[0], user_args, cost_map, clarity_version, epoch)?;
            // Add the nested tree as a child (its cost will be included when summing children)
            children.insert(0, nested_tree);
            // The root cost is zero - the actual cost comes from the nested expression
            let expr_node = CostExprNode::Atom(ClarityName::from("nested-expression"));
            (expr_node, StaticCost::ZERO)
        }
        SymbolicExpressionType::Atom(name) => {
            // Try to get function name from first element
            // lookup the function as a native function first
            // special functions
            //   - let, etc use bindings lengths not argument lengths
            if let Some(native_function) =
                NativeFunctions::lookup_by_name_at_version(name.as_str(), clarity_version)
            {
                    let cost = calculate_function_cost_from_native_function(
                        native_function,
                        children.len() as u64,
                        &exprs[1..],
                        epoch,
                    )?;

                (CostExprNode::NativeFunction(native_function), cost)
            } else {
                // If not a native function, treat as user-defined function and look it up
                let expr_node = CostExprNode::UserFunction(name.clone());
                let cost = calculate_function_cost(name.to_string(), cost_map, clarity_version)?;
                (expr_node, cost)
            }
        }
        SymbolicExpressionType::AtomValue(value) => {
            // It's an atom value - calculate its cost
            let cost = calculate_value_cost(value)?;
            (CostExprNode::AtomValue(value.clone()), cost)
        }
        SymbolicExpressionType::TraitReference(trait_name, _trait_definition) => (
            CostExprNode::TraitReference(trait_name.clone()),
            StaticCost::ZERO,
        ),
        SymbolicExpressionType::Field(field_identifier) => (
            CostExprNode::FieldIdentifier(field_identifier.clone()),
            StaticCost::ZERO,
        ),
        SymbolicExpressionType::LiteralValue(value) => {
            let cost = calculate_value_cost(value)?;
            // TODO not sure if LiteralValue is needed in the CostExprNode types
            (CostExprNode::AtomValue(value.clone()), cost)
        }
    };

    Ok(CostAnalysisNode::new(expr_node, cost, children))
}

pub(crate) fn get_trait_count(costs: &HashMap<String, CostAnalysisNode>) -> Option<TraitCount> {
    // First pass: collect trait counts and trait names
    let mut collector = TraitCountCollector::new();
    for (name, cost_analysis_node) in costs.iter() {
        let context = TraitCountContext::new(name.clone(), (1, 1));
        collector.visit(cost_analysis_node, &context);
    }

    // Second pass: propagate trait counts through function calls
    // If function A calls function B and uses a map, filter, or fold with
    // traits, the maximum will reflect that in A's trait call counts
    let mut propagator =
        TraitCountPropagator::new(&mut collector.trait_counts, &collector.trait_names);
    for (name, cost_analysis_node) in costs.iter() {
        let context = TraitCountContext::new(name.clone(), (1, 1));
        propagator.visit(cost_analysis_node, &context);
    }

    Some(collector.trait_counts)
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::vm::ast::static_cost::is_node_branching;

    fn static_cost_native_test(
        source: &str,
        clarity_version: &ClarityVersion,
    ) -> Result<StaticCost, String> {
        let cost_map: HashMap<String, Option<StaticCost>> = HashMap::new();

        let epoch = StacksEpochId::latest(); // XXX this should be matched with the clarity version
        let ast = make_ast(source, epoch, clarity_version)?;
        let exprs = &ast.expressions;
        let user_args = UserArgumentsContext::new();
        let expr = &exprs[0];
        let (_, cost_analysis_tree) =
            build_cost_analysis_tree(&expr, &user_args, &cost_map, clarity_version, epoch)?;

        let summing_cost = calculate_total_cost_with_branching(&cost_analysis_tree);
        Ok(summing_cost.into())
    }

    fn static_cost_test(
        source: &str,
        clarity_version: &ClarityVersion,
    ) -> Result<HashMap<String, StaticCost>, String> {
        let epoch = StacksEpochId::latest();
        let ast = make_ast(source, epoch, clarity_version)?;
        let costs = static_cost_from_ast(&ast, clarity_version, epoch)?;
        Ok(costs
            .into_iter()
            .map(|(name, (cost, _trait_count))| (name, cost))
            .collect())
    }

    fn build_test_ast(src: &str) -> crate::vm::ast::ContractAST {
        let contract_identifier = QualifiedContractIdentifier::transient();
        let mut cost_tracker = ();
        let ast = build_ast(
            &contract_identifier,
            src,
            &mut cost_tracker,
            ClarityVersion::Clarity3,
            StacksEpochId::latest(),
        )
        .unwrap();
        ast
    }

    #[test]
    fn test_constant() {
        let source = "9001";
        let cost = static_cost_native_test(source, &ClarityVersion::Clarity3).unwrap();
        assert_eq!(cost.min.runtime, 0);
        assert_eq!(cost.max.runtime, 0);
    }

    #[test]
    fn test_simple_addition() {
        let source = "(+ 1 2)";
        let cost = static_cost_native_test(source, &ClarityVersion::Clarity3).unwrap();

        // Min: linear(2, 11, 125) = 11*2 + 125 = 147
        assert_eq!(cost.min.runtime, 147);
        assert_eq!(cost.max.runtime, 147);
    }

    #[test]
    fn test_arithmetic() {
        let source = "(- u4 (+ u1 u2))";
        let cost = static_cost_native_test(source, &ClarityVersion::Clarity3).unwrap();
        assert_eq!(cost.min.runtime, 147 + 147);
        assert_eq!(cost.max.runtime, 147 + 147);
    }

    #[test]
    fn test_nested_operations() {
        let source = "(* (+ u1 u2) (- u3 u4))";
        let cost = static_cost_native_test(source, &ClarityVersion::Clarity3).unwrap();
        // multiplication: 13*2 + 125 = 151
        assert_eq!(cost.min.runtime, 151 + 147 + 147);
        assert_eq!(cost.max.runtime, 151 + 147 + 147);
    }

    #[test]
    fn test_string_concat_min_max() {
        let source = r#"(concat "hello" "world")"#;
        let cost = static_cost_native_test(source, &ClarityVersion::Clarity3).unwrap();

        assert_eq!(cost.min.runtime, 366);
        assert_eq!(cost.max.runtime, 366);
    }

    #[test]
    fn test_string_len_min_max() {
        let source = r#"(len "hello")"#;
        let cost = static_cost_native_test(source, &ClarityVersion::Clarity3).unwrap();

        assert_eq!(cost.min.runtime, 612);
        assert_eq!(cost.max.runtime, 612);
    }

    #[test]
    fn test_branching() {
        let source = "(if (> 3 0) (ok (concat \"hello\" \"world\")) (ok \"asdf\"))";
        let cost = static_cost_native_test(source, &ClarityVersion::Clarity3).unwrap();
        // min: raw string
        // max: concat

        assert_eq!(cost.min.runtime, 346);
        assert_eq!(cost.max.runtime, 565);
    }

    //  ----  ExprTreee building specific tests
    #[test]
    fn test_build_cost_analysis_tree_if_expression() {
        let src = "(if (> 3 0) (ok true) (ok false))";
        let ast = build_test_ast(src);
        let expr = &ast.expressions[0];
        let user_args = UserArgumentsContext::new();
        let cost_map = HashMap::new(); // Empty cost map for tests
        let epoch = StacksEpochId::Epoch32;
        let (_, cost_tree) = build_cost_analysis_tree(
            expr,
            &user_args,
            &cost_map,
            &ClarityVersion::Clarity3,
            epoch,
        )
        .unwrap();

        // Root should be an If node
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

        // The comparison node has 3 children: the function name, left operand, right operand
        let left_val = &gt_node.children[0];
        let right_val = &gt_node.children[1];
        assert!(matches!(left_val.expr, CostExprNode::AtomValue(_)));
        assert!(matches!(right_val.expr, CostExprNode::AtomValue(_)));

        let ok_true_node = &cost_tree.children[2];
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
        let cost_map = HashMap::new(); // Empty cost map for tests
        let epoch = StacksEpochId::Epoch32;
        let (_, cost_tree) = build_cost_analysis_tree(
            expr,
            &user_args,
            &cost_map,
            &ClarityVersion::Clarity3,
            epoch,
        )
        .unwrap();

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
        let cost_map = HashMap::new(); // Empty cost map for tests
        let epoch = StacksEpochId::Epoch32;
        let (_, cost_tree) = build_cost_analysis_tree(
            expr,
            &user_args,
            &cost_map,
            &ClarityVersion::Clarity3,
            epoch,
        )
        .unwrap();

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
        let cost_map = HashMap::new(); // Empty cost map for tests
        let epoch = StacksEpochId::Epoch32;
        let (_, cost_tree) = build_cost_analysis_tree(
            expr,
            &user_args,
            &cost_map,
            &ClarityVersion::Clarity3,
            epoch,
        )
        .unwrap();

        assert_eq!(cost_tree.children.len(), 3);

        // First child should be UserArgument for (x uint)
        let user_arg_x = &cost_tree.children[0];
        assert!(matches!(user_arg_x.expr, CostExprNode::UserArgument(_, _)));
        if let CostExprNode::UserArgument(arg_name, arg_type) = &user_arg_x.expr {
            assert_eq!(arg_name.as_str(), "x");
            assert!(matches!(arg_type, SymbolicExpressionType::Atom(_)));
        }

        // Second child should be UserArgument for (y u64)
        let user_arg_y = &cost_tree.children[1];
        assert!(matches!(user_arg_y.expr, CostExprNode::UserArgument(_, _)));
        if let CostExprNode::UserArgument(arg_name, arg_type) = &user_arg_y.expr {
            assert_eq!(arg_name.as_str(), "y");
            assert!(matches!(arg_type, SymbolicExpressionType::Atom(_)));
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
            assert!(matches!(arg_type, SymbolicExpressionType::Atom(_)));
        }
        if let CostExprNode::UserArgument(name, arg_type) = &arg_y_ref.expr {
            assert_eq!(name.as_str(), "y");
            assert!(matches!(arg_type, SymbolicExpressionType::Atom(_)));
        }
    }

    #[test]
    fn test_static_cost_simple_addition() {
        let source = "(define-public (add (a uint) (b uint)) (+ a b))";
        let ast_cost = static_cost_test(source, &ClarityVersion::Clarity3).unwrap();

        assert_eq!(ast_cost.len(), 1);
        assert!(ast_cost.contains_key("add"));

        let add_cost = ast_cost.get("add").unwrap();
        assert!(add_cost.min.runtime > 0);
        assert!(add_cost.max.runtime > 0);
    }

    #[test]
    fn test_static_cost_multiple_functions() {
        let source = r#"
            (define-public (func1 (x uint)) (+ x 1))
            (define-private (func2 (y uint)) (* y 2))
        "#;
        let ast_cost = static_cost_test(source, &ClarityVersion::Clarity3).unwrap();

        assert_eq!(ast_cost.len(), 2);

        assert!(ast_cost.contains_key("func1"));
        assert!(ast_cost.contains_key("func2"));

        let func1_cost = ast_cost.get("func1").unwrap();
        let func2_cost = ast_cost.get("func2").unwrap();
        assert!(func1_cost.min.runtime > 0);
        assert!(func2_cost.min.runtime > 0);
    }

    #[test]
    fn test_extract_function_name_define_public() {
        let src = "(define-public (my-func (x uint)) (ok x))";
        let ast = build_test_ast(src);
        let expr = &ast.expressions[0];
        let result = extract_function_name(expr);
        assert_eq!(result, Some("my-func".to_string()));
    }

    #[test]
    fn test_extract_function_name_function_call_not_definition() {
        // function call (not a definition) should return None
        let src = "(my-func arg1 arg2)";
        let ast = build_test_ast(src);
        let expr = &ast.expressions[0];
        let result = extract_function_name(expr);
        assert_eq!(result, None);
    }
}
