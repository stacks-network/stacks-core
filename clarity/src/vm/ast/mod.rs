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
use vm::costs::{cost_functions, runtime_cost, CostTracker, LimitedCostTracker};
use vm::errors::{Error, RuntimeErrorType};

use vm::representations::SymbolicExpression;
use vm::types::QualifiedContractIdentifier;

use self::definition_sorter::DefinitionSorter;
use self::errors::ParseResult;
use self::expression_identifier::ExpressionIdentifier;
use self::stack_depth_checker::StackDepthChecker;
use self::sugar_expander::SugarExpander;
use self::traits_resolver::TraitsResolver;
use self::types::BuildASTPass;
pub use self::types::ContractAST;
use vm::costs::cost_functions::ClarityCostFunction;
use vm::ClarityVersion;

/// Legacy function
pub fn parse(
    contract_identifier: &QualifiedContractIdentifier,
    source_code: &str,
    version: ClarityVersion,
) -> Result<Vec<SymbolicExpression>, Error> {
    let ast = build_ast(contract_identifier, source_code, &mut (), version)?;
    Ok(ast.expressions)
}

pub fn build_ast<T: CostTracker>(
    contract_identifier: &QualifiedContractIdentifier,
    source_code: &str,
    cost_track: &mut T,
    clarity_version: ClarityVersion,
) -> ParseResult<ContractAST> {
    runtime_cost(
        ClarityCostFunction::AstParse,
        cost_track,
        source_code.len() as u64,
    )?;
    let pre_expressions = parser::parse(source_code)?;
    let mut contract_ast = ContractAST::new(contract_identifier.clone(), pre_expressions);
    StackDepthChecker::run_pass(&mut contract_ast, clarity_version)?;
    ExpressionIdentifier::run_pre_expression_pass(&mut contract_ast, clarity_version)?;
    DefinitionSorter::run_pass(&mut contract_ast, cost_track, clarity_version)?;
    TraitsResolver::run_pass(&mut contract_ast, clarity_version)?;
    SugarExpander::run_pass(&mut contract_ast, clarity_version)?;
    ExpressionIdentifier::run_expression_pass(&mut contract_ast, clarity_version)?;
    Ok(contract_ast)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::chainstate::StacksBlockId;
    use crate::types::proof::ClarityMarfTrieId;
    use clarity_vm::clarity::ClarityInstance;
    use clarity_vm::database::marf::MarfedKV;
    use rstest::rstest;
    use rstest_reuse::{self, *};
    use std::collections::HashMap;

    use vm::ast::build_ast;
    use vm::costs::LimitedCostTracker;
    use vm::representations::depth_traverse;
    use vm::tests::{TEST_BURN_STATE_DB, TEST_HEADER_DB};
    use vm::version::ClarityVersion::Clarity1;
    use vm::types::QualifiedContractIdentifier;

    #[template]
    #[rstest]
    #[case(ClarityVersion::Clarity1)]
    #[case(ClarityVersion::Clarity2)]
    fn test_clarity_versions_ast(#[case] version: ClarityVersion) {}

    fn dependency_edge_counting_runtime(iters: usize, version: ClarityVersion) -> u64 {
        let mut progn = "(define-private (a0) 1)".to_string();
        for i in 1..iters {
            progn.push_str(&format!("\n(define-private (a{}) (begin", i));
            for x in 0..i {
                progn.push_str(&format!(" (a{}) ", x));
            }
            progn.push_str("))");
        }

        let marf = MarfedKV::temporary();
        let mut clarity_instance = ClarityInstance::new(false, marf);

        clarity_instance
            .begin_test_genesis_block(
                &StacksBlockId::sentinel(),
                &StacksBlockId([0 as u8; 32]),
                &TEST_HEADER_DB,
                &TEST_BURN_STATE_DB,
            )
            .commit_block();

        let mut cost_track = clarity_instance
            .begin_block(
                &StacksBlockId([0 as u8; 32]),
                &StacksBlockId([1 as u8; 32]),
                &TEST_HEADER_DB,
                &TEST_BURN_STATE_DB,
            )
            .commit_block();

        build_ast(
            &QualifiedContractIdentifier::transient(),
            &progn,
            &mut cost_track,
            version,
        )
        .unwrap();

        cost_track.get_total().runtime
    }

    #[apply(test_clarity_versions_ast)]
    fn test_edge_counting_runtime(#[case] version: ClarityVersion) {
        let ratio_4_8 = dependency_edge_counting_runtime(8, version)
            / dependency_edge_counting_runtime(4, version);
        let ratio_8_16 = dependency_edge_counting_runtime(16, version)
            / dependency_edge_counting_runtime(8, version);

        // this really is just testing for the non-linearity
        //   in the runtime cost assessment (because the edge count in the dependency graph is going up O(n^2)).
        assert!(ratio_8_16 > ratio_4_8);
    }

    #[apply(test_clarity_versions_ast)]
    fn test_expression_identification_tuples(#[case] version: ClarityVersion) {
        let progn = "{ a: (+ 1 2 3),
                       b: 1,
                       c: 3 }";

        let mut cost_track = LimitedCostTracker::new_free();
        let ast = build_ast(
            &QualifiedContractIdentifier::transient(),
            &progn,
            &mut cost_track,
            version,
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
