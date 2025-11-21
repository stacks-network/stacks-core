// Static cost analysis for Clarity contracts

use std::collections::HashMap;

use clarity_types::types::{CharType, SequenceData, TraitIdentifier};
use stacks_common::types::StacksEpochId;

use crate::vm::ast::build_ast;
use crate::vm::contexts::Environment;
use crate::vm::costs::cost_functions::{linear, CostValues};
use crate::vm::costs::costs_3::Costs3;
use crate::vm::costs::ExecutionCost;
use crate::vm::errors::InterpreterResult;
use crate::vm::functions::NativeFunctions;
use crate::vm::representations::{ClarityName, SymbolicExpression, SymbolicExpressionType};
use crate::vm::types::QualifiedContractIdentifier;
use crate::vm::{ClarityVersion, Value};

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

const FUNCTION_DEFINITION_KEYWORDS: &[&str] =
    &["define-public", "define-private", "define-read-only"];

fn is_function_definition(function_name: &str) -> bool {
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

/// somewhat of a passthrough since we don't have to build the whole context we
/// can jsut return the cost of the single expression
fn static_cost_native(
    source: &str,
    cost_map: &HashMap<String, Option<StaticCost>>,
    clarity_version: &ClarityVersion,
) -> Result<StaticCost, String> {
    let epoch = StacksEpochId::latest(); // XXX this should be matched with the clarity version
    let ast = make_ast(source, epoch, clarity_version)?;
    let exprs = &ast.expressions;
    let user_args = UserArgumentsContext::new();
    let expr = &exprs[0];
    let (_, cost_analysis_tree) =
        build_cost_analysis_tree(&expr, &user_args, cost_map, clarity_version)?;

    let summing_cost = calculate_total_cost_with_branching(&cost_analysis_tree);
    Ok(summing_cost.into())
}

type MinMaxTraitCount = (u64, u64);
type TraitCount = HashMap<String, MinMaxTraitCount>;

/// Context passed to visitors during trait count analysis
struct TraitCountContext {
    containing_fn_name: String,
    multiplier: (u64, u64),
}

impl TraitCountContext {
    fn new(containing_fn_name: String, multiplier: (u64, u64)) -> Self {
        Self {
            containing_fn_name,
            multiplier,
        }
    }

    fn with_multiplier(&self, multiplier: (u64, u64)) -> Self {
        Self {
            containing_fn_name: self.containing_fn_name.clone(),
            multiplier,
        }
    }

    fn with_fn_name(&self, fn_name: String) -> Self {
        Self {
            containing_fn_name: fn_name,
            multiplier: self.multiplier,
        }
    }
}

/// Extract the list size multiplier from a list expression (for map/filter/fold operations)
/// Expects a list in the form `(list <size>)` where size is an integer literal
fn extract_list_multiplier(list: &[SymbolicExpression]) -> (u64, u64) {
    if list.is_empty() {
        return (1, 1);
    }

    let is_list_atom = list[0]
        .match_atom()
        .map(|a| a.as_str() == "list")
        .unwrap_or(false);
    if !is_list_atom || list.len() < 2 {
        return (1, 1);
    }

    match &list[1].expr {
        SymbolicExpressionType::LiteralValue(Value::Int(value)) => (0, *value as u64),
        _ => (1, 1),
    }
}

/// Increment trait count for a function
fn increment_trait_count(trait_counts: &mut TraitCount, fn_name: &str, multiplier: (u64, u64)) {
    trait_counts
        .entry(fn_name.to_string())
        .and_modify(|(min, max)| {
            *min += multiplier.0;
            *max += multiplier.1;
        })
        .or_insert(multiplier);
}

/// Propagate trait count from one function to another with a multiplier
fn propagate_trait_count(
    trait_counts: &mut TraitCount,
    from_fn: &str,
    to_fn: &str,
    multiplier: (u64, u64),
) {
    if let Some(called_trait_count) = trait_counts.get(from_fn).cloned() {
        trait_counts
            .entry(to_fn.to_string())
            .and_modify(|(min, max)| {
                *min += called_trait_count.0 * multiplier.0;
                *max += called_trait_count.1 * multiplier.1;
            })
            .or_insert((
                called_trait_count.0 * multiplier.0,
                called_trait_count.1 * multiplier.1,
            ));
    }
}

/// Visitor trait for traversing cost analysis nodes and collecting/propagating trait counts
trait TraitCountVisitor {
    fn visit_user_argument(
        &mut self,
        node: &CostAnalysisNode,
        arg_name: &ClarityName,
        arg_type: &SymbolicExpressionType,
        context: &TraitCountContext,
    );
    fn visit_native_function(
        &mut self,
        node: &CostAnalysisNode,
        native_function: &NativeFunctions,
        context: &TraitCountContext,
    );
    fn visit_atom_value(&mut self, node: &CostAnalysisNode, context: &TraitCountContext);
    fn visit_atom(
        &mut self,
        node: &CostAnalysisNode,
        atom: &ClarityName,
        context: &TraitCountContext,
    );
    fn visit_field_identifier(&mut self, node: &CostAnalysisNode, context: &TraitCountContext);
    fn visit_trait_reference(
        &mut self,
        node: &CostAnalysisNode,
        trait_name: &ClarityName,
        context: &TraitCountContext,
    );
    fn visit_user_function(
        &mut self,
        node: &CostAnalysisNode,
        user_function: &ClarityName,
        context: &TraitCountContext,
    );

    fn visit(&mut self, node: &CostAnalysisNode, context: &TraitCountContext) {
        match &node.expr {
            CostExprNode::UserArgument(arg_name, arg_type) => {
                self.visit_user_argument(node, arg_name, arg_type, context);
            }
            CostExprNode::NativeFunction(native_function) => {
                self.visit_native_function(node, native_function, context);
            }
            CostExprNode::AtomValue(_atom_value) => {
                self.visit_atom_value(node, context);
            }
            CostExprNode::Atom(atom) => {
                self.visit_atom(node, atom, context);
            }
            CostExprNode::FieldIdentifier(_field_identifier) => {
                self.visit_field_identifier(node, context);
            }
            CostExprNode::TraitReference(trait_name) => {
                self.visit_trait_reference(node, trait_name, context);
            }
            CostExprNode::UserFunction(user_function) => {
                self.visit_user_function(node, user_function, context);
            }
        }
    }
}

struct TraitCountCollector {
    trait_counts: TraitCount,
    trait_names: HashMap<ClarityName, String>,
}

impl TraitCountCollector {
    fn new() -> Self {
        Self {
            trait_counts: HashMap::new(),
            trait_names: HashMap::new(),
        }
    }
}

impl TraitCountVisitor for TraitCountCollector {
    fn visit_user_argument(
        &mut self,
        _node: &CostAnalysisNode,
        arg_name: &ClarityName,
        arg_type: &SymbolicExpressionType,
        _context: &TraitCountContext,
    ) {
        if let SymbolicExpressionType::TraitReference(name, _) = arg_type {
            self.trait_names
                .insert(arg_name.clone(), name.clone().to_string());
        }
    }

    fn visit_native_function(
        &mut self,
        node: &CostAnalysisNode,
        native_function: &NativeFunctions,
        context: &TraitCountContext,
    ) {
        match native_function {
            NativeFunctions::Map | NativeFunctions::Filter | NativeFunctions::Fold => {
                if node.children.len() > 1 {
                    let list_node = &node.children[1];
                    let multiplier =
                        if let CostExprNode::UserArgument(_, SymbolicExpressionType::List(list)) =
                            &list_node.expr
                        {
                            extract_list_multiplier(list)
                        } else {
                            (1, 1)
                        };
                    let new_context = context.with_multiplier(multiplier);
                    for child in &node.children {
                        self.visit(child, &new_context);
                    }
                }
            }
            _ => {
                for child in &node.children {
                    self.visit(child, context);
                }
            }
        }
    }

    fn visit_atom_value(&mut self, _node: &CostAnalysisNode, _context: &TraitCountContext) {
        // No action needed for atom values
    }

    fn visit_atom(
        &mut self,
        _node: &CostAnalysisNode,
        atom: &ClarityName,
        context: &TraitCountContext,
    ) {
        if self.trait_names.contains_key(atom) {
            increment_trait_count(
                &mut self.trait_counts,
                &context.containing_fn_name,
                context.multiplier,
            );
        }
    }

    fn visit_field_identifier(&mut self, _node: &CostAnalysisNode, _context: &TraitCountContext) {
        // No action needed for field identifiers
    }

    fn visit_trait_reference(
        &mut self,
        _node: &CostAnalysisNode,
        _trait_name: &ClarityName,
        context: &TraitCountContext,
    ) {
        increment_trait_count(
            &mut self.trait_counts,
            &context.containing_fn_name,
            context.multiplier,
        );
    }

    fn visit_user_function(
        &mut self,
        node: &CostAnalysisNode,
        user_function: &ClarityName,
        context: &TraitCountContext,
    ) {
        // Check if this is a trait call (the function name is a trait argument)
        if self.trait_names.contains_key(user_function) {
            increment_trait_count(
                &mut self.trait_counts,
                &context.containing_fn_name,
                context.multiplier,
            );
        }

        // Determine the containing function name for children
        let fn_name = if is_function_definition(user_function.as_str()) {
            context.containing_fn_name.clone()
        } else {
            user_function.to_string()
        };
        let child_context = context.with_fn_name(fn_name);

        for child in &node.children {
            self.visit(child, &child_context);
        }
    }
}

/// Second pass visitor: propagates trait counts through function calls
struct TraitCountPropagator<'a> {
    trait_counts: &'a mut TraitCount,
    trait_names: &'a HashMap<ClarityName, String>,
}

impl<'a> TraitCountPropagator<'a> {
    fn new(
        trait_counts: &'a mut TraitCount,
        trait_names: &'a HashMap<ClarityName, String>,
    ) -> Self {
        Self {
            trait_counts,
            trait_names,
        }
    }
}

impl<'a> TraitCountVisitor for TraitCountPropagator<'a> {
    fn visit_user_argument(
        &mut self,
        _node: &CostAnalysisNode,
        _arg_name: &ClarityName,
        _arg_type: &SymbolicExpressionType,
        _context: &TraitCountContext,
    ) {
        // No propagation needed for arguments
    }

    fn visit_native_function(
        &mut self,
        node: &CostAnalysisNode,
        native_function: &NativeFunctions,
        context: &TraitCountContext,
    ) {
        match native_function {
            NativeFunctions::Map | NativeFunctions::Filter | NativeFunctions::Fold => {
                if node.children.len() > 1 {
                    let list_node = &node.children[1];
                    let multiplier =
                        if let CostExprNode::UserArgument(_, SymbolicExpressionType::List(list)) =
                            &list_node.expr
                        {
                            extract_list_multiplier(list)
                        } else {
                            (1, 1)
                        };

                    // Process the function being called in map/filter/fold
                    let mut skip_first_child = false;
                    if let Some(function_node) = node.children.get(0) {
                        if let CostExprNode::UserFunction(function_name) = &function_node.expr {
                            if !self.trait_names.contains_key(function_name) {
                                // This is a regular function call, not a trait call
                                propagate_trait_count(
                                    self.trait_counts,
                                    &function_name.to_string(),
                                    &context.containing_fn_name,
                                    multiplier,
                                );
                                skip_first_child = true;
                            }
                        }
                    }

                    // Continue traversing children, but skip the function node if we already propagated it
                    for (idx, child) in node.children.iter().enumerate() {
                        if idx == 0 && skip_first_child {
                            continue;
                        }
                        let new_context = context.with_multiplier(multiplier);
                        self.visit(child, &new_context);
                    }
                }
            }
            _ => {
                for child in &node.children {
                    self.visit(child, context);
                }
            }
        }
    }

    fn visit_atom_value(&mut self, _node: &CostAnalysisNode, _context: &TraitCountContext) {}

    fn visit_atom(
        &mut self,
        _node: &CostAnalysisNode,
        _atom: &ClarityName,
        _context: &TraitCountContext,
    ) {
    }

    fn visit_field_identifier(&mut self, _node: &CostAnalysisNode, _context: &TraitCountContext) {}

    fn visit_trait_reference(
        &mut self,
        _node: &CostAnalysisNode,
        _trait_name: &ClarityName,
        _context: &TraitCountContext,
    ) {
        // No propagation needed for trait references (already counted in first pass)
    }

    fn visit_user_function(
        &mut self,
        node: &CostAnalysisNode,
        user_function: &ClarityName,
        context: &TraitCountContext,
    ) {
        if !is_function_definition(user_function.as_str())
            && !self.trait_names.contains_key(user_function)
        {
            // This is a regular function call, not a trait call or function definition
            propagate_trait_count(
                self.trait_counts,
                &user_function.to_string(),
                &context.containing_fn_name,
                context.multiplier,
            );
        }

        // Determine the containing function name for children
        let fn_name = if is_function_definition(user_function.as_str()) {
            context.containing_fn_name.clone()
        } else {
            user_function.to_string()
        };
        let child_context = context.with_fn_name(fn_name);

        for child in &node.children {
            self.visit(child, &child_context);
        }
    }
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

pub fn static_cost_from_ast(
    contract_ast: &crate::vm::ast::ContractAST,
    clarity_version: &ClarityVersion,
) -> Result<HashMap<String, (StaticCost, Option<TraitCount>)>, String> {
    let cost_trees = static_cost_tree_from_ast(contract_ast, clarity_version)?;

    let trait_count = get_trait_count(&cost_trees);
    let costs: HashMap<String, StaticCost> = cost_trees
        .into_iter()
        .map(|(name, cost_analysis_node)| {
            let summing_cost = calculate_total_cost_with_branching(&cost_analysis_node);
            (name, summing_cost.into())
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
) -> Result<HashMap<String, CostAnalysisNode>, String> {
    let exprs = &ast.expressions;
    let user_args = UserArgumentsContext::new();
    let costs_map: HashMap<String, Option<StaticCost>> = HashMap::new();
    let mut costs: HashMap<String, Option<CostAnalysisNode>> = HashMap::new();
    for expr in exprs {
        if let Some(function_name) = extract_function_name(expr) {
            costs.insert(function_name, None);
        }
    }
    for expr in exprs {
        if let Some(function_name) = extract_function_name(expr) {
            let (_, cost_analysis_tree) =
                build_cost_analysis_tree(expr, &user_args, &costs_map, clarity_version)?;
            costs.insert(function_name, Some(cost_analysis_tree));
        }
    }
    Ok(costs
        .into_iter()
        .filter_map(|(name, cost)| cost.map(|c| (name, c)))
        .collect())
}

/// STatic execution cost for functions within Environment
/// returns the top level cost for specific functions
/// {function_name: cost}
pub fn static_cost(
    env: &mut Environment,
    contract_identifier: &QualifiedContractIdentifier,
) -> Result<HashMap<String, StaticCost>, String> {
    let contract_source = env
        .global_context
        .database
        .get_contract_src(contract_identifier)
        .ok_or_else(|| "Contract source not found in database".to_string())?;

    let contract = env
        .global_context
        .database
        .get_contract(contract_identifier)
        .map_err(|e| format!("Failed to get contract: {:?}", e))?;

    let clarity_version = contract.contract_context.get_clarity_version();

    let epoch = env.global_context.epoch_id;
    let ast = make_ast(&contract_source, epoch, clarity_version)?;

    let costs = static_cost_from_ast(&ast, clarity_version)?;
    Ok(costs
        .into_iter()
        .map(|(name, (cost, _trait_count))| (name, cost))
        .collect())
}

/// same idea as `static_cost` but returns the root of the cost analysis tree for each function
/// Useful if you need to analyze specific nodes in the cost tree
pub fn static_cost_tree(
    env: &mut Environment,
    contract_identifier: &QualifiedContractIdentifier,
) -> Result<HashMap<String, CostAnalysisNode>, String> {
    let contract_source = env
        .global_context
        .database
        .get_contract_src(contract_identifier)
        .ok_or_else(|| "Contract source not found in database".to_string())?;

    let contract = env
        .global_context
        .database
        .get_contract(contract_identifier)
        .map_err(|e| format!("Failed to get contract: {:?}", e))?;

    let clarity_version = contract.contract_context.get_clarity_version();

    let epoch = env.global_context.epoch_id;
    let ast = make_ast(&contract_source, epoch, clarity_version)?;

    static_cost_tree_from_ast(&ast, clarity_version)
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
                        )?;
                    Ok((Some(returned_function_name), cost_analysis_tree))
                } else {
                    let cost_analysis_tree = build_listlike_cost_analysis_tree(
                        list,
                        user_args,
                        cost_map,
                        clarity_version,
                    )?;
                    Ok((None, cost_analysis_tree))
                }
            } else {
                let cost_analysis_tree =
                    build_listlike_cost_analysis_tree(list, user_args, cost_map, clarity_version)?;
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
                // let arg_type = match &arg_list[1].expr {
                //     SymbolicExpressionType::Atom(type_name) => type_name.clone(),
                //     SymbolicExpressionType::AtomValue(value) => {
                //         ClarityName::from(value.to_string().as_str())
                //     }
                //     SymbolicExpressionType::LiteralValue(value) => {
                //         ClarityName::from(value.to_string().as_str())
                //     }
                //     SymbolicExpressionType::TraitReference(trait_name, _trait_definition) => {
                //         trait_name.clone()
                //     }
                //     SymbolicExpressionType::List(_) => ClarityName::from("list"),
                //     _ => {
                //         println!("arg: {:?}", arg_list[1].expr);
                //         return Err("Argument type must be an atom or atom value".to_string());
                //     }
                // };

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
        build_cost_analysis_tree(body, &function_user_args, cost_map, clarity_version)?;
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
) -> Result<CostAnalysisNode, String> {
    let mut children = Vec::new();

    // Build children for all exprs
    for expr in exprs[1..].iter() {
        let (_, child_tree) = build_cost_analysis_tree(expr, user_args, cost_map, clarity_version)?;
        children.push(child_tree);
    }

    let function_name = get_function_name(&exprs[0])?;
    // Try to lookup the function as a native function first
    let (expr_node, cost) = if let Some(native_function) =
        NativeFunctions::lookup_by_name_at_version(function_name.as_str(), clarity_version)
    {
        CostExprNode::NativeFunction(native_function);
        let cost = calculate_function_cost_from_native_function(
            native_function,
            children.len() as u64,
            clarity_version,
        )?;
        (CostExprNode::NativeFunction(native_function), cost)
    } else {
        // If not a native function, treat as user-defined function and look it up
        let expr_node = CostExprNode::UserFunction(function_name.clone());
        let cost = calculate_function_cost(function_name.to_string(), cost_map, clarity_version)?;
        (expr_node, cost)
    };

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

// Calculate function cost with lazy evaluation support
fn calculate_function_cost(
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

fn calculate_function_cost_from_native_function(
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

/// Convert a NativeFunctions enum variant to its corresponding cost function
/// TODO: This assumes Costs3 but should find a way to use the clarity version passed in
fn get_cost_function_for_native(
    function: NativeFunctions,
    _clarity_version: &ClarityVersion,
) -> Option<fn(u64) -> InterpreterResult<ExecutionCost>> {
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

    fn static_cost_native_test(
        source: &str,
        clarity_version: &ClarityVersion,
    ) -> Result<StaticCost, String> {
        let cost_map: HashMap<String, Option<StaticCost>> = HashMap::new();
        static_cost_native(source, &cost_map, clarity_version)
    }

    fn static_cost_test(
        source: &str,
        clarity_version: &ClarityVersion,
    ) -> Result<HashMap<String, StaticCost>, String> {
        let epoch = StacksEpochId::latest();
        let ast = make_ast(source, epoch, clarity_version)?;
        let costs = static_cost_from_ast(&ast, clarity_version)?;
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

        // For concat with 2 arguments:
        // linear(2, 37, 220) = 37*2 + 220 = 294
        assert_eq!(cost.min.runtime, 294);
        assert_eq!(cost.max.runtime, 294);
    }

    #[test]
    fn test_string_len_min_max() {
        let source = r#"(len "hello")"#;
        let cost = static_cost_native_test(source, &ClarityVersion::Clarity3).unwrap();

        // cost: 429 (constant) - len doesn't depend on string size
        assert_eq!(cost.min.runtime, 429);
        assert_eq!(cost.max.runtime, 429);
    }

    #[test]
    fn test_branching() {
        let source = "(if (> 3 0) (ok (concat \"hello\" \"world\")) (ok \"asdf\"))";
        let cost = static_cost_native_test(source, &ClarityVersion::Clarity3).unwrap();
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
        let cost_map = HashMap::new(); // Empty cost map for tests
        let (_, cost_tree) =
            build_cost_analysis_tree(expr, &user_args, &cost_map, &ClarityVersion::Clarity3)
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
        let (_, cost_tree) =
            build_cost_analysis_tree(expr, &user_args, &cost_map, &ClarityVersion::Clarity3)
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
        let (_, cost_tree) =
            build_cost_analysis_tree(expr, &user_args, &cost_map, &ClarityVersion::Clarity3)
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
        let (_, cost_tree) =
            build_cost_analysis_tree(expr, &user_args, &cost_map, &ClarityVersion::Clarity3)
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
