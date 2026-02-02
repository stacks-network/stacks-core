use std::collections::{HashMap, HashSet};

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
        if max_len == 0 { (0, 0) } else { (0, max_len) }
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
/// This adds the callee's trait counts to the caller's trait counts.
/// When a function calls another function, it inherits that function's trait counts.
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
    /// Stack of function contexts to handle nested expressions (like let bindings)
    /// When we encounter a non-function context (like a let-bound variable),
    /// we use the top of this stack as the containing function
    function_context_stack: Vec<String>,
    /// Set of function names we've encountered during traversal
    /// This tracks function definitions so we can identify real function calls
    /// even before they're added to trait_counts
    pub visited_functions: HashSet<String>,
}

impl TraitCountCollector {
    pub fn new() -> Self {
        Self {
            trait_counts: HashMap::new(),
            trait_names: HashMap::new(),
            function_context_stack: Vec::new(),
            visited_functions: HashSet::new(),
        }
    }

    /// Get the current function context (top of stack, or fallback to context name)
    fn get_function_context(&self, context_name: &str) -> String {
        self.function_context_stack
            .last()
            .cloned()
            .unwrap_or_else(|| context_name.to_string())
    }

    /// Check if a UserFunction node represents a real function call (not a let-bound variable)
    /// This is used to determine if we should push the function onto the context stack.
    ///
    /// We check:
    /// 1. If it's in trait_counts (functions we've fully processed)
    /// 2. If it's a function definition keyword (like "define-public")
    /// 3. If it's in visited_functions (all function names from the contract, tracked upfront)
    fn is_real_function_call(&self, fn_name: &str) -> bool {
        // Check if it's already in trait_counts (functions we've visited)
        if self.trait_counts.contains_key(fn_name) {
            return true;
        }

        // Check if it's a function definition keyword
        if is_function_definition(fn_name) {
            return true;
        }

        // Check if this is a known function from the contract
        // All function names are tracked upfront in visited_functions from the costs HashMap keys
        self.visited_functions.contains(fn_name)
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
            // Store the trait name, using the argument name as the key
            // This allows us to detect when this argument (by name) is used later
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
            NativeFunctions::TupleGet => {
                // For get field struct, check if struct is a parameter with a trait field
                // The first child is the field identifier, second child is the struct
                // We only count when accessing trait fields from struct parameters
                // function parameters (UserArgument), not let-bound variables (Atom)
                if node.children.len() >= 2 {
                    if let Some(field_node) = node.children.get(0) {
                        // Extract the field name
                        let field_name_opt = match &field_node.expr {
                            CostExprNode::FieldIdentifier(trait_id) => {
                                // FieldIdentifier contains a TraitIdentifier, extract the name
                                Some(trait_id.name.as_str())
                            }
                            CostExprNode::Atom(field_name) => Some(field_name.as_str()),
                            _ => None,
                        };

                        if let Some(field_name) = field_name_opt {
                            if let Some(struct_node) = node.children.get(1) {
                                if let CostExprNode::UserArgument(arg_name, arg_type) =
                                    &struct_node.expr
                                {
                                    // If it's not in trait_names, it's a struct parameter with a trait field
                                    if !self.trait_names.contains_key(arg_name) {
                                        let is_field_identifier = matches!(
                                            &field_node.expr,
                                            CostExprNode::FieldIdentifier(_)
                                        );

                                        let is_trait_reference = matches!(
                                            &field_node.expr,
                                            CostExprNode::TraitReference(_)
                                        );

                                        let is_known_trait_name = self
                                            .trait_names
                                            .values()
                                            .any(|trait_name| trait_name == field_name);

                                        // Check if the struct type is a TupleType and if the field is a trait
                                        // Handle both direct TupleType and wrapped types (OptionalType, ResponseType)
                                        let is_trait_field_by_type = {
                                            let check_tuple = |tuple_sig: &clarity_types::types::signatures::TupleTypeSignature| -> bool {
                                                tuple_sig.get_type_map().iter().any(|(name, field_type)| {
                                                    name.as_str() == field_name && matches!(
                                                        field_type,
                                                        TypeSignature::CallableType(CallableSubtype::Trait(_))
                                                            | TypeSignature::TraitReferenceType(_)
                                                    )
                                                })
                                            };

                                            match arg_type {
                                                TypeSignature::TupleType(tuple_sig) => {
                                                    check_tuple(tuple_sig)
                                                }
                                                TypeSignature::OptionalType(inner_type) => {
                                                    matches!(
                                                        **inner_type,
                                                        TypeSignature::TupleType(_)
                                                    ) && if let TypeSignature::TupleType(
                                                        tuple_sig,
                                                    ) = &**inner_type
                                                    {
                                                        check_tuple(tuple_sig)
                                                    } else {
                                                        false
                                                    }
                                                }
                                                TypeSignature::ResponseType(inner_types) => {
                                                    matches!(
                                                        inner_types.0,
                                                        TypeSignature::TupleType(_)
                                                    ) && if let TypeSignature::TupleType(
                                                        tuple_sig,
                                                    ) = &inner_types.0
                                                    {
                                                        check_tuple(tuple_sig)
                                                    } else {
                                                        false
                                                    }
                                                }
                                                _ => false,
                                            }
                                        };

                                        // Count if:
                                        // - The field node is a FieldIdentifier
                                        // - The field node is a TraitReference
                                        // - The field name matches a known trait name
                                        // - The type signature indicates it's a trait field
                                        if is_field_identifier
                                            || is_trait_reference
                                            || is_known_trait_name
                                            || is_trait_field_by_type
                                        {
                                            // This is a struct parameter being accessed for a trait field
                                            // Count it as a trait usage, using the function context from stack
                                            let target_fn = self
                                                .get_function_context(&context.containing_fn_name);
                                            increment_trait_count(
                                                &mut self.trait_counts,
                                                &target_fn,
                                                context.multiplier,
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                // Visit all children
                for child in &node.children {
                    self.visit(child, context);
                }
            }
            NativeFunctions::ContractCall => {
                // For contract-call?, the first argument is the trait reference or contract identifier
                // We need to check if it's a trait parameter and count it
                // Note: trait parameters passed to contract-call? are represented as UserArgument nodes,
                // not Atom nodes, so we need to handle them specially
                if let Some(first_arg) = node.children.get(0) {
                    // Check if the first argument is a UserArgument with a trait type
                    if let CostExprNode::UserArgument(arg_name, arg_type) = &first_arg.expr {
                        let is_trait = matches!(
                            arg_type,
                            TypeSignature::CallableType(CallableSubtype::Trait(_))
                                | TypeSignature::TraitReferenceType(_)
                        );
                        if is_trait {
                            // Check if this argument name is in trait_names (meaning it's a trait parameter)
                            if self.trait_names.contains_key(arg_name) {
                                let target_fn =
                                    self.get_function_context(&context.containing_fn_name);
                                increment_trait_count(
                                    &mut self.trait_counts,
                                    &target_fn,
                                    context.multiplier,
                                );
                            }
                        }
                    }
                    // Also check if it's an Atom (let-bound variable or trait parameter)
                    // Count all Atoms used as first argument to contract-call? as trait usages
                    else if let CostExprNode::Atom(_atom_name) = &first_arg.expr {
                        // Count all Atoms used as first argument - they represent trait usages
                        // (either function parameters or let-bound variables with trait types)
                        // Note: If the context is not a function (like a let-bound variable name),
                        // use the containing function from the stack
                        let target_fn = self.get_function_context(&context.containing_fn_name);
                        increment_trait_count(
                            &mut self.trait_counts,
                            &target_fn,
                            context.multiplier,
                        );
                    }
                }
                // Also count trait parameters passed as arguments (not just the first argument)
                // We only count UserArgument nodes (function parameters), not Atoms (let-bound variables)
                // because Atoms are already counted when used as the first argument
                for child in node.children.iter().skip(1) {
                    if let CostExprNode::UserArgument(arg_name, arg_type) = &child.expr {
                        let is_trait = matches!(
                            arg_type,
                            TypeSignature::CallableType(CallableSubtype::Trait(_))
                                | TypeSignature::TraitReferenceType(_)
                        );
                        if is_trait && self.trait_names.contains_key(arg_name) {
                            // Count the trait parameter usage
                            let target_fn = self.get_function_context(&context.containing_fn_name);
                            increment_trait_count(
                                &mut self.trait_counts,
                                &target_fn,
                                context.multiplier,
                            );
                        }
                    }
                }
                // Visit all children to handle nested expressions and propagate trait counts
                for child in &node.children {
                    self.visit(child, context);
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
        node: &CostAnalysisNode,
        _atom: &ClarityName,
        context: &TraitCountContext,
    ) {
        // Trait parameters are counted when:
        // 1. Used as first argument to contract-call? (handled in visit_native_function ContractCall)
        // 2. Passed to functions that use traits (handled in propagator visit_user_function)
        // Don't count them here to avoid double-counting
        for child in &node.children {
            self.visit(child, context);
        }
    }

    fn visit_field_identifier(&mut self, _node: &CostAnalysisNode, _context: &TraitCountContext) {
        // FieldIdentifier nodes are handled in TupleGet (NativeFunction::TupleGet)
        // No action needed here
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

        // Push function context onto stack if it's a real function
        // This helps track the actual function context when visiting nested expressions like let bindings
        let is_real_function = self.is_real_function_call(&fn_name);
        if is_real_function {
            self.function_context_stack.push(fn_name.clone());
        }

        let child_context = context.with_fn_name(fn_name.clone());

        for child in &node.children {
            self.visit(child, &child_context);
        }

        // Pop function context from stack
        if is_real_function {
            self.function_context_stack.pop();
        }
    }
}

/// Second pass visitor: propagates trait counts through function calls
pub struct TraitCountPropagator<'a> {
    trait_counts: &'a mut TraitCount,
    trait_names: &'a HashMap<ClarityName, String>,
    /// Set of all function names from the contract (used to distinguish function calls from let-bound variables)
    visited_functions: &'a HashSet<String>,
    /// Map from let-bound variable names to their trait counts
    let_binding_trait_counts: HashMap<String, MinMaxTraitCount>,
    /// Track which function calls have already been processed to avoid double-counting
    processed_calls: std::collections::HashSet<(String, String)>,
}

impl<'a> TraitCountPropagator<'a> {
    pub fn new(
        trait_counts: &'a mut TraitCount,
        trait_names: &'a HashMap<ClarityName, String>,
        visited_functions: &'a HashSet<String>,
    ) -> Self {
        Self {
            trait_counts,
            trait_names,
            visited_functions,
            let_binding_trait_counts: HashMap::new(),
            processed_calls: std::collections::HashSet::new(),
        }
    }

    /// Reset the processed calls set for a new iteration
    pub fn reset_processed_calls(&mut self) {
        self.processed_calls.clear();
    }

    /// Check if a UserFunction node represents a let-bound variable (not a function call)
    /// Let-bound variables appear as UserFunction nodes in the AST but should not change
    /// the context when visiting their children.
    fn is_let_bound_variable(&self, user_function: &ClarityName, fn_name_str: &str) -> bool {
        // It's a let-bound variable if:
        // 1. It's not a function definition keyword
        // 2. It's not a trait call (trait names are in trait_names)
        // 3. It's not a known function from the contract (not in visited_functions or trait_counts)
        !is_function_definition(user_function.as_str())
            && !self.trait_names.contains_key(user_function)
            && !self.trait_counts.contains_key(fn_name_str)
            && !self.visited_functions.contains(fn_name_str)
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
            NativeFunctions::Let => {
                // For let expressions, we need to track trait counts for let-bound variables
                // The first child is the bindings tree, remaining children are body expressions
                // Visit the bindings tree first to propagate trait counts from function calls
                // to the containing function
                if let Some(bindings_tree) = node.children.get(0) {
                    // Visit the bindings tree - this will visit function calls and propagate
                    // their trait counts to the containing function
                    // The bindings tree is typically an Atom("nested-expression") node with children
                    // representing the bindings, so visiting it will traverse to the function calls
                    self.visit(bindings_tree, context);
                }
                // Then visit body expressions
                for child in node.children.iter().skip(1) {
                    self.visit(child, context);
                }
            }
            NativeFunctions::ContractCall => {
                // For contract-call?, we need to visit children to propagate trait counts
                // but we don't count trait parameters here - that's done in the collector.
                // The propagator's job is only to propagate counts from callees to callers.
                for child in &node.children {
                    self.visit(child, context);
                }
            }
            NativeFunctions::Unwrap | NativeFunctions::UnwrapErr | NativeFunctions::TryRet => {
                // For unwrap/try! expressions, visit children to propagate trait counts
                // The function call (like CONTEXT) is inside the unwrap/try!
                for child in &node.children {
                    self.visit(child, context);
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
        node: &CostAnalysisNode,
        _atom: &ClarityName,
        context: &TraitCountContext,
    ) {
        // If this atom node has children (like "nested-expression" for lists),
        // visit them to propagate trait counts
        // This handles cases where let bindings are represented as Atom("nested-expression")
        // with children representing the actual bindings
        for child in &node.children {
            self.visit(child, context);
        }
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
            // Propagate trait counts from the callee to the caller
            let callee_name = user_function.to_string();
            let caller_name = context.containing_fn_name.clone();

            // Propagate trait counts from the callee to the caller
            // Note: We propagate for each call site, so if a function calls another
            // function multiple times, we propagate multiple times (once per call)
            propagate_trait_count(
                self.trait_counts,
                &callee_name,
                &caller_name,
                context.multiplier,
            );

            // Also count trait parameters being passed to this function if the callee uses traits
            // This handles cases like CONTEXT calling call-get-decimals(base-token) where
            // base-token is a trait parameter. We count it in the caller's context because
            // the caller is providing the trait parameter to a function that uses it.
            // We only do this if the callee has trait counts (uses traits in contract-call?),
            // to avoid overcounting in cases like map operations.
            if self.trait_counts.contains_key(&callee_name) {
                for child in &node.children {
                    let is_trait_param = match &child.expr {
                        CostExprNode::UserArgument(arg_name, arg_type) => {
                            let is_trait = matches!(
                                arg_type,
                                TypeSignature::CallableType(CallableSubtype::Trait(_))
                                    | TypeSignature::TraitReferenceType(_)
                            );
                            is_trait && self.trait_names.contains_key(arg_name)
                        }
                        CostExprNode::Atom(atom_name) => self.trait_names.contains_key(atom_name),
                        _ => false,
                    };
                    if is_trait_param {
                        // Count the trait parameter usage in the caller's context
                        increment_trait_count(self.trait_counts, &caller_name, context.multiplier);
                    }
                }
            }
        }

        // Determine the containing function name for children
        // If this is a function definition, use the current context
        // If this is a function call, use the function name as context (for its body)
        // If this is a let-bound variable, keep the current context
        let fn_name_str = user_function.to_string();
        let fn_name = if is_function_definition(user_function.as_str()) {
            context.containing_fn_name.clone()
        } else if self.is_let_bound_variable(user_function, &fn_name_str) {
            // This is a let-bound variable - keep the current context
            // Example: In `(let ((ctx (try! (CONTEXT ...))))`, when visiting CONTEXT,
            // we want to use "mint" as the context, not "ctx"
            context.containing_fn_name.clone()
        } else {
            // This is a real function call - use the function name as context
            fn_name_str
        };
        let child_context = context.with_fn_name(fn_name);

        for child in &node.children {
            self.visit(child, &child_context);
        }
    }
}
