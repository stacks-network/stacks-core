use std::collections::HashMap;

use clarity_types::representations::ClarityName;
use clarity_types::types::signatures::CallableSubtype;

use crate::vm::ast::static_cost::{CostAnalysisNode, CostExprNode};
use crate::vm::costs::analysis::is_function_definition;
use crate::vm::functions::NativeFunctions;
use crate::vm::types::{SequenceSubtype, TypeSignature};

type MinMaxTraitCount = (u64, u64);
pub type TraitCount = HashMap<String, MinMaxTraitCount>;

/// Context passed to visitors during trait count analysis
pub struct TraitCountContext {
    containing_fn_name: String,
    multiplier: (u64, u64),
}

impl TraitCountContext {
    pub fn new(containing_fn_name: String, multiplier: (u64, u64)) -> Self {
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

/// Extract the list size multiplier from a TypeSignature (for map/filter/fold operations)
/// Returns (min, max) where min is 0 if the list has a fixed size, 1 otherwise
fn extract_list_multiplier_from_type(type_sig: &TypeSignature) -> (u64, u64) {
    if let TypeSignature::SequenceType(SequenceSubtype::ListType(list_data)) = type_sig {
        let max_len = list_data.get_max_len() as u64;
        // If max_len is 0, it's an empty list, so multiplier is (0, 0)
        // Otherwise, use (0, max_len) to indicate a fixed-size list
        if max_len == 0 {
            (0, 0)
        } else {
            (0, max_len)
        }
    } else {
        // Not a list type, use default multiplier
        (1, 1)
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
pub trait TraitCountVisitor {
    fn visit_user_argument(
        &mut self,
        node: &CostAnalysisNode,
        arg_name: &ClarityName,
        arg_type: &TypeSignature,
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

pub struct TraitCountCollector {
    pub trait_counts: TraitCount,
    pub trait_names: HashMap<ClarityName, String>,
}

impl TraitCountCollector {
    pub fn new() -> Self {
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
        arg_type: &TypeSignature,
        _context: &TraitCountContext,
    ) {
        // Check if this is a trait type (either CallableType::Trait or TraitReferenceType)
        let trait_name = match arg_type {
            TypeSignature::CallableType(CallableSubtype::Trait(trait_id)) => {
                Some(format!("{}", trait_id.name))
            }
            TypeSignature::TraitReferenceType(trait_id) => Some(format!("{}", trait_id.name)),
            _ => None,
        };
        if let Some(name) = trait_name {
            self.trait_names.insert(arg_name.clone(), name);
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
                    let multiplier = match &list_node.expr {
                        CostExprNode::UserArgument(_name, list_type) => {
                            extract_list_multiplier_from_type(list_type)
                        }
                        _ => (1, 1),
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
pub struct TraitCountPropagator<'a> {
    trait_counts: &'a mut TraitCount,
    trait_names: &'a HashMap<ClarityName, String>,
}

impl<'a> TraitCountPropagator<'a> {
    pub fn new(
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
        _arg_type: &TypeSignature,
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
                    let multiplier = match &list_node.expr {
                        CostExprNode::UserArgument(_name, list_type) => {
                            extract_list_multiplier_from_type(list_type)
                        }
                        _ => (1, 1),
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
