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
pub mod parser_v2;
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
use self::sugar_expander::SugarExpander;
use self::traits_resolver::TraitsResolver;
use self::types::BuildASTPass;
pub use self::types::ContractAST;
use crate::types::StacksEpochId;
use crate::vm::costs::cost_functions::ClarityCostFunction;
use crate::vm::ClarityVersion;

/// Legacy function
pub fn parse(
    contract_identifier: &QualifiedContractIdentifier,
    source_code: &str,
    version: ClarityVersion,
    epoch: StacksEpochId,
) -> Result<Vec<SymbolicExpression>, Error> {
    let ast = build_ast(contract_identifier, source_code, &mut (), version, epoch)?;
    Ok(ast.expressions)
}

pub fn build_ast<T: CostTracker>(
    contract_identifier: &QualifiedContractIdentifier,
    source_code: &str,
    cost_track: &mut T,
    clarity_version: ClarityVersion,
    epoch: StacksEpochId,
) -> ParseResult<ContractAST> {
    runtime_cost(
        ClarityCostFunction::AstParse,
        cost_track,
        source_code.len() as u64,
    )?;
    let pre_expressions = if epoch >= StacksEpochId::Epoch21 {
        parser_v2::parse(source_code)?
    } else {
        parser::parse(source_code)?
    };
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
mod test {
    use std::collections::HashMap;

    use stacks_common::types::StacksEpochId;

    use crate::vm::ast::build_ast;
    use crate::vm::costs::LimitedCostTracker;
    use crate::vm::representations::depth_traverse;
    use crate::vm::types::QualifiedContractIdentifier;
    use crate::vm::ClarityVersion;

    #[test]
    fn test_expression_identification_tuples() {
        for version in &[ClarityVersion::Clarity1, ClarityVersion::Clarity2, ClarityVersion::Clarity3] {
            for epoch in &[StacksEpochId::Epoch2_05, StacksEpochId::Epoch21, StacksEpochId::Epoch22] {
                let progn = "{ a: (+ 1 2 3),
                           b: 1,
                           c: 3 }";

                let mut cost_track = LimitedCostTracker::new_free();
                let ast = build_ast(
                    &QualifiedContractIdentifier::transient(),
                    &progn,
                    &mut cost_track,
                    *version,
                    *epoch,
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
    }
}
