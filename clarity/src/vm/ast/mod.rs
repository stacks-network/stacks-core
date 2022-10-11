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
