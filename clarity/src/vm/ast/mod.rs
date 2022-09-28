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
use crate::vm::costs::{runtime_cost, CostTracker};
use crate::vm::errors::Error;

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
use crate::vm::diagnostic::{Diagnostic, Level};
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
    let (contract, _, _) = inner_build_ast(
        contract_identifier,
        source_code,
        cost_track,
        clarity_version,
        epoch,
        true,
    )?;
    Ok(contract)
}

/// Used by developer tools only. Continues on through errors by inserting
/// placeholders into the AST. Collects as many diagnostics as possible.
/// Always returns a ContractAST, a vector of diagnostics, and a boolean
/// that indicates if the build was successful.
pub fn build_ast_with_diagnostics<T: CostTracker>(
    contract_identifier: &QualifiedContractIdentifier,
    source_code: &str,
    cost_track: &mut T,
    clarity_version: ClarityVersion,
    epoch: StacksEpochId,
) -> (ContractAST, Vec<Diagnostic>, bool) {
    inner_build_ast(
        contract_identifier,
        source_code,
        cost_track,
        clarity_version,
        epoch,
        false,
    )
    .unwrap()
}

pub fn inner_build_ast<T: CostTracker>(
    contract_identifier: &QualifiedContractIdentifier,
    source_code: &str,
    cost_track: &mut T,
    clarity_version: ClarityVersion,
    epoch: StacksEpochId,
    error_early: bool,
) -> ParseResult<(ContractAST, Vec<Diagnostic>, bool)> {
    let cost_err = match runtime_cost(
        ClarityCostFunction::AstParse,
        cost_track,
        source_code.len() as u64,
    ) {
        Err(e) if error_early => return Err(e.into()),
        Err(e) => Some(e),
        _ => None,
    };

    let (pre_expressions, mut diagnostics, mut success) = if epoch >= StacksEpochId::Epoch21 {
        if error_early {
            let exprs = parser::v2::parse(source_code)?;
            (exprs, Vec::new(), true)
        } else {
            parser::v2::parse_collect_diagnostics(source_code)
        }
    } else {
        match parser::v1::parse(source_code) {
            Ok(pre_expressions) => (pre_expressions, vec![], true),
            Err(error) if error_early => return Err(error),
            Err(error) => (vec![], vec![error.diagnostic], false),
        }
    };

    if let Some(e) = cost_err {
        diagnostics.insert(
            0,
            Diagnostic {
                level: Level::Error,
                message: format!("runtime_cost error: {:?}", e),
                spans: vec![],
                suggestion: None,
            },
        );
    }
    let mut contract_ast = ContractAST::new(contract_identifier.clone(), pre_expressions);
    match StackDepthChecker::run_pass(&mut contract_ast, clarity_version) {
        Err(e) if error_early => return Err(e),
        Err(e) => {
            diagnostics.push(e.diagnostic);
            success = false;
        }
        _ => (),
    }
    match ExpressionIdentifier::run_pre_expression_pass(&mut contract_ast, clarity_version) {
        Err(e) if error_early => return Err(e),
        Err(e) => {
            diagnostics.push(e.diagnostic);
            success = false;
        }
        _ => (),
    }
    match DefinitionSorter::run_pass(&mut contract_ast, cost_track, clarity_version) {
        Err(e) if error_early => return Err(e),
        Err(e) => {
            diagnostics.push(e.diagnostic);
            success = false;
        }
        _ => (),
    }
    match TraitsResolver::run_pass(&mut contract_ast, clarity_version) {
        Err(e) if error_early => return Err(e),
        Err(e) => {
            diagnostics.push(e.diagnostic);
            success = false;
        }
        _ => (),
    }
    match SugarExpander::run_pass(&mut contract_ast, clarity_version) {
        Err(e) if error_early => return Err(e),
        Err(e) => {
            diagnostics.push(e.diagnostic);
            success = false;
        }
        _ => (),
    }
    match ExpressionIdentifier::run_expression_pass(&mut contract_ast, clarity_version) {
        Err(e) if error_early => return Err(e),
        Err(e) => {
            diagnostics.push(e.diagnostic);
            success = false;
        }
        _ => (),
    }
    Ok((contract_ast, diagnostics, success))
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
        for version in &[ClarityVersion::Clarity1, ClarityVersion::Clarity2] {
            for epoch in &[StacksEpochId::Epoch2_05, StacksEpochId::Epoch21] {
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
