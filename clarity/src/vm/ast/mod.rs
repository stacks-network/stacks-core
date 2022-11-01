// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
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

pub mod definition_sorter;
pub mod expression_identifier;
pub mod parser;
pub mod traits_resolver;

pub mod errors;
pub mod stack_depth_checker;
pub mod sugar_expander;
pub mod types;
use crate::vm::costs::{cost_functions, runtime_cost, CostTracker, LimitedCostTracker};
use crate::vm::errors::{Error, RuntimeErrorType};

use crate::vm::representations::SymbolicExpression;
use crate::vm::types::QualifiedContractIdentifier;

use self::definition_sorter::DefinitionSorter;
use self::errors::ParseResult;
use self::expression_identifier::ExpressionIdentifier;
use self::stack_depth_checker::StackDepthChecker;
use self::stack_depth_checker::VaryStackDepthChecker;
use self::sugar_expander::SugarExpander;
use self::traits_resolver::TraitsResolver;
use self::types::BuildASTPass;
pub use self::types::ContractAST;
use crate::vm::costs::cost_functions::ClarityCostFunction;

/// Legacy function
#[cfg(test)]
pub fn parse(
    contract_identifier: &QualifiedContractIdentifier,
    source_code: &str,
) -> Result<Vec<SymbolicExpression>, Error> {
    let ast = build_ast(contract_identifier, source_code, &mut ())?;
    Ok(ast.expressions)
}

// AST parser rulesets to apply.
define_u8_enum!(ASTRules {
    Typical = 0,
    PrecheckSize = 1
});

/// This is the part of the AST parser that runs without respect to cost analysis, specifically
/// pertaining to verifying that the AST is reasonably-sized.
/// Used mainly to filter transactions that might be too costly, as an optimization heuristic.
pub fn ast_check_size(
    contract_identifier: &QualifiedContractIdentifier,
    source_code: &str,
) -> ParseResult<ContractAST> {
    let pre_expressions = parser::parse(source_code)?;
    let mut contract_ast = ContractAST::new(contract_identifier.clone(), pre_expressions);
    StackDepthChecker::run_pass(&mut contract_ast)?;
    VaryStackDepthChecker::run_pass(&mut contract_ast)?;
    Ok(contract_ast)
}

/// Build an AST according to a ruleset
pub fn build_ast_with_rules<T: CostTracker>(
    contract_identifier: &QualifiedContractIdentifier,
    source_code: &str,
    cost_track: &mut T,
    ruleset: ASTRules,
) -> ParseResult<ContractAST> {
    match ruleset {
        ASTRules::Typical => build_ast_typical(contract_identifier, source_code, cost_track),
        ASTRules::PrecheckSize => {
            build_ast_precheck_size(contract_identifier, source_code, cost_track)
        }
    }
}

/// Build an AST with the typical rules
fn build_ast_typical<T: CostTracker>(
    contract_identifier: &QualifiedContractIdentifier,
    source_code: &str,
    cost_track: &mut T,
) -> ParseResult<ContractAST> {
    runtime_cost(
        ClarityCostFunction::AstParse,
        cost_track,
        source_code.len() as u64,
    )?;
    let pre_expressions = parser::parse_no_stack_limit(source_code)?;
    let mut contract_ast = ContractAST::new(contract_identifier.clone(), pre_expressions);
    StackDepthChecker::run_pass(&mut contract_ast)?;
    ExpressionIdentifier::run_pre_expression_pass(&mut contract_ast)?;
    DefinitionSorter::run_pass(&mut contract_ast, cost_track)?;
    TraitsResolver::run_pass(&mut contract_ast)?;
    SugarExpander::run_pass(&mut contract_ast)?;
    ExpressionIdentifier::run_expression_pass(&mut contract_ast)?;
    Ok(contract_ast)
}

/// Built an AST, but pre-check the size of the AST before doing more work
fn build_ast_precheck_size<T: CostTracker>(
    contract_identifier: &QualifiedContractIdentifier,
    source_code: &str,
    cost_track: &mut T,
) -> ParseResult<ContractAST> {
    runtime_cost(
        ClarityCostFunction::AstParse,
        cost_track,
        source_code.len() as u64,
    )?;
    let mut contract_ast = ast_check_size(contract_identifier, source_code)?;
    ExpressionIdentifier::run_pre_expression_pass(&mut contract_ast)?;
    DefinitionSorter::run_pass(&mut contract_ast, cost_track)?;
    TraitsResolver::run_pass(&mut contract_ast)?;
    SugarExpander::run_pass(&mut contract_ast)?;
    ExpressionIdentifier::run_expression_pass(&mut contract_ast)?;
    Ok(contract_ast)
}

/// Test compatibility
#[cfg(any(test, feature = "testing"))]
pub fn build_ast<T: CostTracker>(
    contract_identifier: &QualifiedContractIdentifier,
    source_code: &str,
    cost_track: &mut T,
) -> ParseResult<ContractAST> {
    build_ast_typical(contract_identifier, source_code, cost_track)
}

#[cfg(test)]
mod test {
    use crate::vm::ast::errors::ParseErrors;
    use crate::vm::ast::stack_depth_checker::AST_CALL_STACK_DEPTH_BUFFER;
    use crate::vm::ast::{build_ast, build_ast_with_rules, ASTRules};
    use crate::vm::costs::LimitedCostTracker;
    use crate::vm::costs::*;
    use crate::vm::representations::depth_traverse;
    use crate::vm::types::QualifiedContractIdentifier;
    use crate::vm::ClarityCostFunction;
    use crate::vm::ClarityName;
    use crate::vm::MAX_CALL_STACK_DEPTH;
    use std::collections::HashMap;

    #[derive(PartialEq, Debug)]
    struct UnitTestTracker {
        invoked_functions: Vec<(ClarityCostFunction, Vec<u64>)>,
        invocation_count: u64,
        cost_addition_count: u64,
    }
    impl UnitTestTracker {
        pub fn new() -> Self {
            UnitTestTracker {
                invoked_functions: vec![],
                invocation_count: 0,
                cost_addition_count: 0,
            }
        }
    }
    impl CostTracker for UnitTestTracker {
        fn compute_cost(
            &mut self,
            cost_f: ClarityCostFunction,
            input: &[u64],
        ) -> std::result::Result<ExecutionCost, CostErrors> {
            self.invoked_functions.push((cost_f, input.to_vec()));
            self.invocation_count += 1;
            Ok(ExecutionCost::zero())
        }
        fn add_cost(&mut self, _cost: ExecutionCost) -> std::result::Result<(), CostErrors> {
            self.cost_addition_count += 1;
            Ok(())
        }
        fn add_memory(&mut self, _memory: u64) -> std::result::Result<(), CostErrors> {
            Ok(())
        }
        fn drop_memory(&mut self, _memory: u64) {}
        fn reset_memory(&mut self) {}
        fn short_circuit_contract_call(
            &mut self,
            _contract: &QualifiedContractIdentifier,
            _function: &ClarityName,
            _input: &[u64],
        ) -> Result<bool, CostErrors> {
            Ok(false)
        }
    }

    #[test]
    fn test_cost_tracking_deep_contracts() {
        let stack_limit =
            (AST_CALL_STACK_DEPTH_BUFFER + (MAX_CALL_STACK_DEPTH as u64) + 1) as usize;
        let exceeds_stack_depth_tuple = format!(
            "{}u1 {}",
            "{ a : ".repeat(stack_limit + 1),
            "} ".repeat(stack_limit + 1)
        );

        // for deep lists, a test like this works:
        //   it can assert a limit, that you can also verify
        //   by disabling `VaryStackDepthChecker` and arbitrarily bumping up the parser lexer limits
        //   and see that it produces the same result
        let exceeds_stack_depth_list = format!(
            "{}u1 {}",
            "(list ".repeat(stack_limit + 1),
            ")".repeat(stack_limit + 1)
        );

        // with old rules, this is just ExpressionStackDepthTooDeep
        let mut cost_track = UnitTestTracker::new();
        let err = build_ast_with_rules(
            &QualifiedContractIdentifier::transient(),
            &exceeds_stack_depth_list,
            &mut cost_track,
            ASTRules::Typical,
        )
        .expect_err("Contract should error in parsing");

        let expected_err = ParseErrors::ExpressionStackDepthTooDeep;
        let expected_list_cost_state = UnitTestTracker {
            invoked_functions: vec![(ClarityCostFunction::AstParse, vec![500])],
            invocation_count: 1,
            cost_addition_count: 1,
        };

        assert_eq!(&expected_err, &err.err);
        assert_eq!(expected_list_cost_state, cost_track);

        // with new rules, this is now VaryExpressionStackDepthTooDeep
        let mut cost_track = UnitTestTracker::new();
        let err = build_ast_with_rules(
            &QualifiedContractIdentifier::transient(),
            &exceeds_stack_depth_list,
            &mut cost_track,
            ASTRules::PrecheckSize,
        )
        .expect_err("Contract should error in parsing");

        let expected_err = ParseErrors::VaryExpressionStackDepthTooDeep;
        let expected_list_cost_state = UnitTestTracker {
            invoked_functions: vec![(ClarityCostFunction::AstParse, vec![500])],
            invocation_count: 1,
            cost_addition_count: 1,
        };

        assert_eq!(&expected_err, &err.err);
        assert_eq!(expected_list_cost_state, cost_track);

        // you cannot do the same for tuples!
        // in ASTRules::Typical, this passes
        let mut cost_track = UnitTestTracker::new();
        let _ = build_ast_with_rules(
            &QualifiedContractIdentifier::transient(),
            &exceeds_stack_depth_tuple,
            &mut cost_track,
            ASTRules::Typical,
        )
        .expect("Contract should aprse with ASTRules::Typical");

        // this actually won't even error without
        //  the VaryStackDepthChecker changes.
        let mut cost_track = UnitTestTracker::new();
        let err = build_ast_with_rules(
            &QualifiedContractIdentifier::transient(),
            &exceeds_stack_depth_tuple,
            &mut cost_track,
            ASTRules::PrecheckSize,
        )
        .expect_err("Contract should error in parsing with ASTRules::PrecheckSize");

        let expected_err = ParseErrors::VaryExpressionStackDepthTooDeep;
        let expected_list_cost_state = UnitTestTracker {
            invoked_functions: vec![(ClarityCostFunction::AstParse, vec![571])],
            invocation_count: 1,
            cost_addition_count: 1,
        };

        assert_eq!(&expected_err, &err.err);
        assert_eq!(expected_list_cost_state, cost_track);
    }

    #[test]
    fn test_expression_identification_tuples() {
        let progn = "{ a: (+ 1 2 3),
                       b: 1,
                       c: 3 }";

        let mut cost_track = LimitedCostTracker::new_free();
        let ast = build_ast(
            &QualifiedContractIdentifier::transient(),
            &progn,
            &mut cost_track,
        )
        .unwrap()
        .expressions;

        let mut visited = HashMap::new();

        for expr in ast.iter() {
            depth_traverse::<_, _, ()>(expr, |x| {
                assert!(!visited.contains_key(&x.id));
                visited.insert(x.id, true);
                Ok(())
            })
            .unwrap();
        }
    }
}
