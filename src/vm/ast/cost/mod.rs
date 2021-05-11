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
use vm::{
    functions, lookup_variable, CallStack, ClarityName, ContractContext, Environment,
    SymbolicExpression,
};

/// Overall Considerations
/// - possibly keep track of call stack depth when evaluating top level expressions
/// - possibly we may need to add Var variants to know how to substitute
///     -> maybe want to substitute with the length of the var, not the var itself ..

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SymbolicCostExpression {
    Var(u32), // the number stored with this enum variant represents the var name
    Number(u32),
    Sum(Box<SymbolicCostExpression>, Box<SymbolicCostExpression>),
    Mul(Box<SymbolicCostExpression>, Box<SymbolicCostExpression>),
    Max(Box<SymbolicCostExpression>, Box<SymbolicCostExpression>),
    TraitInvocation(TraitIdentifier), // todo: how should we uniquely identify traits?
    // note: maybe switch ClarityCostFunction to ClarityCostFunctionReference
    //todo - add rationale here for Vec v Box
    ClarityCostFn(Vec<SymbolicCostExpression>, ClarityCostFunction), // tuple of (input cost expr, clarity cost fn)
    // tuple of cost expr for fn, and list of cost expressions for its args
    // arg i corresponds to Var(i) in the fn cost expression
    // the number is the starting i for the Var terms
    FnList(
        Box<SymbolicCostExpression>,
        Vec<SymbolicCostExpression>,
        u32,
    ),
}

pub struct StaticCostAnalyzer {
    // todo - remove - data is stored in contract_context.functions
    user_defined_functions: HashMap<ClarityName, DefinedFunction>,
    user_defined_function_cost_exprs: HashMap<ClarityName, SymbolicCostExpression>,
    next_available_var: u32,
}

impl BuildASTPass for StaticCostAnalyzer {
    fn run_pass(contract_ast: &mut ContractAST) -> ParseResult<()> {
        let pass = StaticCostAnalyzer::new();
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
            // q: line below is optional - can delete
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
        &self,
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

    fn get_cost_expr_for_defined_fn(
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
            args.insert(name, (i as u32, arg_type));
        }
        self.next_available_var += args.len();

        // call recursive helper function that takes in args, an expression, and returns a cost expression
        // todo - might need contract context as well
        self.eval_body_expr(env, &function.body, &args)
    }

    // evaluates a non-top level expression, is recursive
    // calls lookup function uses info to lookup function costs
    fn eval_body_expr(
        &mut self,
        env: &'a mut Environment,
        expr: &SymbolicExpression,
        // todo - possibly make a part of the env / contract context
        original_args: &HashMap<ClarityName, (u32, TypeSignature)>,
    ) -> ParseResult<SymbolicCostExpression> {
        match exp.expr {
            AtomValue(ref value) | LiteralValue(ref value) => {
                // todo - fix
                Ok(SymbolicCostExpression::Number(0))
            }
            Atom(ref value) => {
                // note: this value may be an original arg
                match original_args.get(value) {
                    Some((i, _)) => {
                        Ok(SymbolicCostExpression::Var(*i))
                    }
                    None => {
                        // todo - pass in local context
                        // todo - see if there's a way around passing the env
                        lookup_variable(&value, context, env);
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

                let f = self.lookup_function(function_name, rest, next_var)?;

                let mut evaluated_args = vec![];
                for arg in rest.iter() {
                    let arg_value =
                        self.eval_body_expr(env, arg, original_args)?;
                    evaluated_args.push(arg_value);
                }
                // two options here, going with (1) for now:
                //  (1) store the function args as a list, in the symbolic cost expression for a function
                //  (2) replace the given symbolic expression for the Var(n)'s in the function def
                let cost_expr = SymbolicCostExpression::FnList(
                    Box::new(f),
                    evaluated_args,
                    next_var,
                );
                Ok(cost_expr)
            }
            TraitReference(ref name, ref def) => {
                // todo - refer to the analysis of this trait & store "address" of other analysis in Symbolic Cost Expression enum
            }
            Field(ref id) => {
                // todo - what is the field?
            }
        }
    }

    // Given a name, returns SymbolicCostExpression (user function, native function, or special function)
    // todo - make sure this always returns a SymbolicCostExpression
    fn lookup_function(&self, name: &str, curr_args: &[SymbolicExpression], next_var: u32) -> ParseResult<SymbolicCostExpression> {
        if let Some(result) = lookup_reserved_functions(name) {
            Self::convert_callable_type_to_cost_expr(result, curr_args, next_var)
        } else {
            // need to perform substitution; refresh vars that are in the stored cost expression
            // todo - possibly do the lookup with contract_context.functions
            let user_function_opt = self.user_defined_function_cost_exprs.get(name);
            match user_function_opt {
                // todo -> avoid clone?
                Some(user_function) => Ok(user_function.clone()),
                None => Err(ParseError::new(ParseErrors::CostComputationFailed(
                    format!("Unknown user function called: {}", name),
                ))),
            }
        }
    }

    // note: cost functions may take in more than 1 input in the future
    fn convert_callable_type_to_cost_expr(function: CallableType, curr_args: &[SymbolicExpression], next_var: u32) -> ParseResult<SymbolicCostExpression> {
        let num_args = curr_args.len() as u32;
        match function {
            // for native function, number of args is the input
            CallableType::NativeFunction(_, _, cost_function) => {
                let mut input_list = Vec::new();
                // note: might need to change logic in the future if cost fns change
                input_list.push(SymbolicCostExpression::Number(num_args));
                Ok(SymbolicCostExpression::ClarityCostFn(input_list, cost_function))
            }
            // runtime cost hidden inside special_{} functions
            // this will include the contract-call edge case as well - would need to pass in `args` to determine var values
            CallableType::SpecialFunction(fn_name, _) => {
                match fn_name {
                    "special_and" => {
                        Ok(SymbolicCostExpression::ClarityCostFn(
                            Box::new(SymbolicCostExpression::Number(num_args)),
                            ClarityCostFunction::And
                        ))
                    },
                    "special_or" => {
                        Ok(SymbolicCostExpression::ClarityCostFn(
                            Box::new(SymbolicCostExpression::Number(num_args)),
                            ClarityCostFunction::Or
                        ))

                    },
                    // todo - add rest of the functions
                    "special_contract-call" => {
                        let base_cost = SymbolicCostExpression::ClarityCostFn(
                            Box::new(SymbolicCostExpression::Number(0)),
                            ClarityCostFunction::ContractCall
                        );
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
