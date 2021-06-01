// Copyright (C) 2013-2021 Blockstack PBC, a public benefit corporation
// Copyright (C) 2021 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use clarity_vm::database::MemoryBackingStore;
use std::collections::HashMap;
use std::convert::TryFrom;
use vm::ast::errors::{ParseError, ParseErrors, ParseResult};
use vm::ast::types::BuildASTPass;
use vm::ast::ContractAST;
use vm::callables::{CallableType, DefinedFunction};
use vm::contexts::GlobalContext;
use vm::costs::cost_functions::ClarityCostFunction;
use vm::costs::LimitedCostTracker;
use vm::functions::define::DefineResult;
use vm::functions::lookup_reserved_functions;
use vm::representations::SymbolicExpressionType::{
    Atom, AtomValue, Field, List, LiteralValue, TraitReference,
};
use vm::types::{PrincipalData, TraitIdentifier, TypeSignature};
use vm::{functions, lookup_variable, CallStack, ClarityName, ContractContext, Environment, SymbolicExpression, LocalContext, variables};


/// Notes on the status of this branch:
/// -> SymbolicCostExpression enum
///     - I foresee this being tweaked to better handle references (references to traits, to other
///       functions in the same contract)
/// -> Trait reference
///     - This will be handled as part of handling the contract-call function call (the dynamic dispatch case)
///     - Determine where else trait references would show up
/// -> Parsing multiple functions in one contract
///     - We are evaluating expression in the contract according to a sorted order (based on dependencies)
///     - We store the symbolic cost expression for expressions we have "parsed"
///     - If there is a reference to another expression in some expression, it gets stored as a
///       FnList, which right now is a copy of the symbolic cost expression of the function, and a
///       parameter list (also cost expressions)
///     - Need to convert the first field in FnList to be a reference to the symbolic cost expression, not a copy
///     - In evaluating the cost expression, will evalaute the costs of the parameters first, then substitute the
///       costs wherever Var(i) appears in the function's cost expression.
/// -> Storing variables/ other env specific information
///     - We need the actual value of certain variables, so these need to be stored in the env/ contract context.
///     - For example, we would need to store a variable defined through a top-level "DefineVariable" expression
/// -> Refactor this & runtime_cost() calls in the evaluation functions (ex: special_contract_call).
///     - Calls to runtime_cost are not straightforward because inputs to cost functions are variable,
///       and can depend on the env (context.depth), or value (value.size())
///     - A possible remedy would be to implement a trait, such as CostSupplier, that would
///       implement methods like .value_size() or .context_depth()
///     - The clarity runtime and the static analysis env could independently implement this trait
///     - We could then have a separate suite of cost functions that takes in an object that implements the CostSupplier trait
///     - These cost functions would be used in both places then
/// -> Matching top-level expressions
///     - Currently only handling DefineFunction, need to expand to handle all other top-level expressions


/// Some Considerations
/// - possibly keep track of call stack depth when evaluating top level expressions
/// - possibly we may need to add Var variants to know how to substitute
///     -> maybe want to substitute with the length of the var, not the var itself ..
/// - consider the case when the contract is invalid - what should we store as the cost then?
/// - i think there are two "levels" of failures
///     - one for failure to compute the static cost altogether => should be a ParseError
///     - a second for contracts/ functions that yield "Invalid" cost expressions (todo: need to think about whether this case is possible)

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SymbolicCostExpression {
    // todo - consider making a second var type, like Parameter (for the unknown inputs to functions)
    Var(u32), // the number stored with this enum variant represents the var name
    Number(u32),
    Sum(Box<SymbolicCostExpression>, Box<SymbolicCostExpression>),
    Mul(Box<SymbolicCostExpression>, Box<SymbolicCostExpression>),
    Max(Box<SymbolicCostExpression>, Box<SymbolicCostExpression>),
    TraitInvocation(TraitIdentifier), // todo: how should we uniquely identify traits?
    // note: maybe switch ClarityCostFunction to ClarityCostFunctionReference
    //todo - add rationale here for Vec v Box
    ClarityCostFn(ClarityCostFunction, Vec<SymbolicCostExpression>), // tuple of (clarity cost fn, input cost expr)
    // tuple of (a) cost expr for a particular function call, (b) list of cost expressions for its args
    // arg i in the list corresponds to Var(i) in the fn cost expression
    // (c) the number is the starting i for the Var terms
    FnList(
        Box<SymbolicCostExpression>,
        Vec<SymbolicCostExpression>,
        u32,
    ),
    Nil, // when there is 0 cost (ex: matching with an AtomValue)
}

pub struct StaticCostAnalyzer {
    // todo - remove - data is stored in contract_context.functions
    user_defined_functions: HashMap<ClarityName, DefinedFunction>,
    user_defined_function_cost_exprs: HashMap<ClarityName, SymbolicCostExpression>,
    next_available_var: u32,
    context_depth: u32,
}

impl BuildASTPass for StaticCostAnalyzer {
    fn run_pass(contract_ast: &mut ContractAST) -> ParseResult<()> {
        let mut pass = StaticCostAnalyzer::new();
        pass.run(contract_ast);
        Ok(())
    }
}

impl StaticCostAnalyzer {
    fn new() -> Self {
        Self {
            user_defined_functions: HashMap::new(),
            // todo -> possibly make into a list, where ith position corresponds to ith in sorted indices
            user_defined_function_cost_exprs: HashMap::new();
            next_available_var: 0,
            // todo: reconsider; alternatively, start the depth at 0, and incr to 1 when entering a fn definition
            context_depth: 1,
        }
    }

    fn run(&mut self, contract_ast: &mut ContractAST) -> ParseResult<()> {
        // env setup
        let mut contract_context = ContractContext::new(contract_ast.contract_identifier.clone());
        let publisher: PrincipalData = contract_context.contract_identifier.issuer.clone().into();
        let mut marf = MemoryBackingStore::new();
        let conn = marf.as_clarity_db();
        let mut global_context = GlobalContext::new(false, conn, LimitedCostTracker::new_free());

        self.user_defined_function_cost_exprs = HashMap::new(); //HashMap<ClarityName, SymbolicCostExpression>
        let sorted_indices = contract_ast
            .top_level_expression_sorting
            .expect("DefinitionSorter pass should have succeeded.");

        for i in sorted_indices.iter() {
            let expr = &contract_ast.expressions[i];
            // q: line below is optional - can delete?
            self.next_available_var = 0;
            match self.eval_top_level_expr(
                expr,
                &mut contract_context,
                &mut global_context,
                &publisher,
            ) {
                Some((clarity_name, cost_expr)) => self.user_defined_function_cost_exprs.insert(clarity_name, cost_expr),
                _ => {}
            }
        }
        // contract_ast.cost_expressions = self.user_defined_function_cost_exprs;

        // put the user defined function cost expressions in the database
        // key: (contract ID, clarity name AKA function name)
        // value: symbolic cost expression that we computed

        Ok(())
    }

    /// Evaluate a top level Clarity expression
    fn eval_top_level_expr(
        &mut self,
        exp: &SymbolicExpression,
        contract_context: &mut ContractContext,
        global_context: &mut GlobalContext,
        publisher: &PrincipalData,
    ) -> ParseResult<Option<(ClarityName, SymbolicCostExpression)>> {
        // run try define
        // get a list of DefineFunctions
        // determine cost expression for each function
        // note: need access to cost DB for external contract calls
        // note: cost functions have two types of vars
        //      (1) Variable(n) => corresponds to the nth input to the function
        //      (2) TraitReference(s) => cost is fetched during function invocation
        let mut call_stack = CallStack::new();
        let mut env = Environment::new(
            context,
            contract_context,
            &mut call_stack,
            Some(publisher.clone()),
            Some(publisher.clone()),
        );
        let try_define =
            global_context.execute(|context| functions::define::evaluate_define(exp, &mut env))?;
        match try_define {
            DefineResult::Function(name, value) => {
                contract_context.functions.insert(name, value);
                let cost_expr =
                    self.get_cost_expr_for_defined_fn(&mut env, &value)?;
                Ok(Some((name.clone(), cost_expr)))
            }
            // todo - handle other cases possibly
            _ => Ok(None),
        }
    }

    fn get_cost_expr_for_defined_fn<'a>(
        &mut self,
        env: &'a mut Environment,
        function: &DefinedFunction,
    ) -> ParseResult<SymbolicCostExpression> {
        let mut args = HashMap::new();
        for (i, (name, arg_type)) in function
            .arguments
            .into_iter()
            .zip(function.arg_types.into_iter()).enumerate()
        {
            args.insert(name, (self.next_available_var + (i as u32), arg_type));
        }
        self.next_available_var += args.len();

        // call recursive helper function that takes in args, an expression, and returns a cost expression
        // todo - might need contract context as well
        self.eval_function_body(env, &function.body, &args)
    }

    // evaluates a non-top level expression, is recursive
    // calls lookup function uses info to lookup function costs
    fn eval_function_body(
        &mut self,
        env: &'a mut Environment,
        expr: &SymbolicExpression,
        original_args: &HashMap<ClarityName, (u32, TypeSignature)>,
    ) -> ParseResult<SymbolicCostExpression> {
        match exp.expr {
            AtomValue(ref value) | LiteralValue(ref value) => {
                Ok(SymbolicCostExpression::Nil)
            }
            Atom(ref value) => {
                // note: this value may be an original arg
                match original_args.get(value) {
                    Some((i, _)) => {
                        // todo - could the arg in question could be type `TraitReferenceType`? if so, should store ref to trait
                        // todo - make sure we are storing the args in the CostExpr type
                        // todo - we might want to store some function of the parameter (ex: length of buffer) - that's what we want to capture
                        //          we aren't trying to directly sub the param value in cost expr
                        //         - maybe not BC any case like this would be encapsulated in a function call (like the List match below)
                        Ok(SymbolicCostExpression::Var(*i))
                    }
                    None => {
                        // todo - same as above, do we want to  have a cost expression based on the actual value of the var here (like length)
                        // todo - pass in local context
                        // store variables as cost expressions too, make it a part of the struct? (like for user defined functions)?
                        self.cost_lookup_variable(&value, context, env)
                    }
                }
            }
            List(ref children) => {
                let (function_variable, rest) =
                    children
                        .split_first()
                        .ok_or(ParseError::new(ParseErrors::CheckError(
                            "Non function application".to_string(),
                        )))?;
                let function_name = function_variable.match_atom().ok_or(ParseError::new(
                    ParseErrors::CheckError("Bad function name".to_string()),
                ))?;
                let next_var = self.next_available_var;
                self.next_available_var += len(rest);

                let (f, incr_depth) = self.lookup_function(function_name, rest, next_var)?;
                if incr_depth {
                    self.context_depth += 1;
                }
                let mut evaluated_args = vec![];
                for arg in rest.iter() {
                    let arg_value =
                        self.eval_function_body(env, arg, original_args)?;
                    evaluated_args.push(arg_value);
                }
                if incr_depth {
                    self.context_depth -= 1;
                }
                //  store the function args as a list, in the symbolic cost expression for a function
                let cost_expr = SymbolicCostExpression::FnList(
                    Box::new(f),
                    evaluated_args,
                    next_var,
                );
                Ok(cost_expr)
            }
            // not sure about the match below
            TraitReference(_, _) | Field(_) => unreachable!("can't be evaluated"),
        }
    }

    // Given a name, returns SymbolicCostExpression (user function, native function, or special function)
    // todo - make sure this always returns a SymbolicCostExpression
    fn lookup_function(&self, name: &str, curr_args: &[SymbolicExpression], next_var: u32) -> ParseResult<(SymbolicCostExpression, bool)> {
        if let Some(result) = lookup_reserved_functions(name) {
            Self::convert_callable_type_to_cost_expr(result, curr_args, next_var)
        } else {
            // need to perform substitution; refresh vars that are in the stored cost expression
            let user_function_opt = self.user_defined_function_cost_exprs.get(name);
            match user_function_opt {
                // todo -> avoid clone?
                Some(user_function) => Ok((user_function.clone(), false)),
                None => Err(ParseError::new(ParseErrors::CostComputationFailed(
                    format!("Unknown user function called: {}", name),
                ))),
            }
        }
    }

    // costs based off of `lookup_variable` in `src/vm/mod.rs`.
    /// Returns the cost of looking up a variable
    fn cost_lookup_variable(&self, name: &str, context: &LocalContext, env: &mut Environment) -> ParseResult<SymbolicCostExpression> {
        // first check if the name is valid. if not, return error
        if name.starts_with(char::is_numeric) || name.starts_with('\'') {
            return Err(ParseError::new(ParseErrors::IllegalVariableName(str_value.to_string())))
        }

        if let Some(_) = variables::lookup_reserved_variable(name, context, env)? {
            Ok(SymbolicCostExpression::Nil)
        } else {
            // add cost of LookupVariableDepth
            let mut lookup_cost = SymbolicCostExpression::ClarityCostFn(
                ClarityCostFunction::LookupVariableDepth,
                vec![SymbolicCostExpression::Number(self.context_depth)]
            );

            // todo - update this variable-fetching logic - are we properly storing vars in the context ...?
            if let Some(value) = context
                .lookup_variable(name)
                .or_else(|| env.contract_context.lookup_variable(name))
            {
            // if we find the variable in the contract context or env, add cost of LookupVariableSize
                let lookup_size_cost = SymbolicCostExpression::ClarityCostFn(
                    ClarityCostFunction::LookupVariableSize,
                    vec![SymbolicCostExpression::Number(value.size())]
                );
                lookup_cost = SymbolicCostExpression::Sum(Box::new(lookup_cost), Box::new(lookup_size_cost));
            }
            // q: in what cases do we not have the value of the var stored? do we want to add an upper bound estimation for
            //    value.size() in that case?

            Ok(lookup_cost)
        }

    }

    // q: i think we need to check # of arguments as is done in special_.. functions?
    // note: cost functions may take in more than 1 input in the future
    /// Returns the symbolic cost expression for the function, as well as a boolean representing whether or not this function
    /// would increase the context depth. Functions that "bind" variables, such as let or match, lead to an increase
    /// in the context depth.
    fn convert_callable_type_to_cost_expr(function: CallableType, curr_args: &[SymbolicExpression], next_var: u32) -> ParseResult<(SymbolicCostExpression, bool)> {
        let num_args = curr_args.len() as u32;
        match function {
            // for native function, number of args is the input
            CallableType::NativeFunction(_, _, cost_function) => {
                let mut input_list = Vec::new();
                // note: might need to change logic in the future if cost fns change
                input_list.push(SymbolicCostExpression::Number(num_args));
                Ok((SymbolicCostExpression::ClarityCostFn(cost_function, input_list), false))
            }
            // runtime cost hidden inside special_{} functions
            // this will include the contract-call edge case as well - would need to pass in `args` to determine var values
            CallableType::SpecialFunction(fn_name, _) => {
                match fn_name {
                    "special_and" => {
                        Ok((SymbolicCostExpression::ClarityCostFn(
                            ClarityCostFunction::And,
                            vec![SymbolicCostExpression::Number(num_args)]
                        ), false))
                    },
                    "special_or" => {
                        Ok((SymbolicCostExpression::ClarityCostFn(
                            ClarityCostFunction::Or,
                            vec![SymbolicCostExpression::Number(num_args)]
                        ), false))

                    },
                    // todo - add rest of the functions
                    "special_contract_call" => {
                        let base_cost = SymbolicCostExpression::ClarityCostFn(
                            ClarityCostFunction::ContractCall,
                            vec![SymbolicCostExpression::Number(0)]
                        );
                        // load contract cost - usually checked in `execute_contract`
                        let contract_size_placeholder = vec![SymbolicCostExpression::Number(0)]; // todo - change this value
                        let load_cost = SymbolicCostExpression::ClarityCostFn(
                            ClarityCostFunction::LoadContract,
                            contract_size_placeholder
                        );

                        // todo - user function application cost - usually checked in `execute_apply`
                        // runtime_cost(
                        //     ClarityCostFunction::UserFunctionApplication,
                        //     env,
                        //     self.arguments.len(),
                        // )?;

                        // todo - inner type check cost - usually checked in `execute_apply`
                        // for arg_type in self.arg_types.iter() {
                        //     runtime_cost(
                        //         ClarityCostFunction::InnerTypeCheckCost,
                        //         env,
                        //         arg_type.size(),
                        //     )?;
                        // }

                        // two cases, (1) static dispatch: known contract ID, (2) dynamic dispatch: trait reference
                        // static

                        // dynamic
                    }
                    _ => unreachable!("Should cover all possible special function names.")
                }
            }
            _ => panic!("Should be unreachable.")
        }
    }

    /// Replace Var(i) (where i = placeholder) with a symbolic expression
    // q: pass actual function, not reference?
    // function is unused & a WIP
    fn replace_var(
        function: &SymbolicCostExpression,
        placeholder: usize,
        new_expr: &SymbolicCostExpression,
    ) -> &SymbolicCostExpression {
        match function {
            SymbolicCostExpression::Var(placeholder) => new_expr,
            num @ SymbolicCostExpression::Number(_) => num,
            SymbolicCostExpression::Sum(cost_expr_first, cost_expr_second) => {
                let replaced_first = replace_var(cost_expr_first, placeholder, new_expr);
                let replaced_second = replace_var(cost_expr_second, placeholder, new_expr);
                SymbolicCostExpression::Sum(replaced_first, replaced_second)
            }
            SymbolicCostExpression::Mul(cost_expr_first, cost_expr_second) => {
                let replaced_first = replace_var(cost_expr_first, placeholder, new_expr);
                let replaced_second = replace_var(cost_expr_second, placeholder, new_expr);
                SymbolicCostExpression::Mul(replaced_first, replaced_second)
            }
            SymbolicCostExpression::Max(cost_expr_first, cost_expr_second) => {
                let replaced_first = replace_var(cost_expr_first, placeholder, new_expr);
                let replaced_second = replace_var(cost_expr_second, placeholder, new_expr);
                SymbolicCostExpression::Max(replaced_first, replaced_second)
            }
            SymbolicCostExpression::TraitInvocation(_) => {}
            SymbolicCostExpression::ClarityCostFn(_, _) => {}
        }
    }
}
