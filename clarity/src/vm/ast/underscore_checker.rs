// Copyright (C) 2025-2026 Stacks Open Internet Foundation
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

//! AST pass that rejects identifiers beginning with `_` for pre-`Clarity6`
//! contracts.
//!
//! The wire-level `ClarityName` regex and the v2 lexer accept underscore-led
//! names unconditionally so that the parser can produce a well-formed AST and
//! report a precise, version-aware diagnostic here rather than a generic
//! "illegal name" lexer error. SIP-04x permits the relaxation only for
//! `ClarityVersion::Clarity6` onwards.

use clarity_types::representations::ClarityName;
use stacks_common::types::StacksEpochId;

use crate::vm::ClarityVersion;
use crate::vm::ast::errors::{ParseError, ParseErrorKind, ParseResult};
use crate::vm::ast::types::{BuildASTPass, ContractAST};
use crate::vm::representations::{PreSymbolicExpression, PreSymbolicExpressionType};

pub struct UnderscoreIdentifierChecker;

impl BuildASTPass for UnderscoreIdentifierChecker {
    fn run_pass(
        contract_ast: &mut ContractAST,
        version: ClarityVersion,
        _epoch: StacksEpochId,
    ) -> ParseResult<()> {
        if version >= ClarityVersion::Clarity6 {
            return Ok(());
        }
        check(&contract_ast.pre_expressions)
    }
}

fn check(exprs: &[PreSymbolicExpression]) -> ParseResult<()> {
    for expr in exprs {
        check_one(expr)?;
    }
    Ok(())
}

fn check_one(expr: &PreSymbolicExpression) -> ParseResult<()> {
    match &expr.pre_expr {
        PreSymbolicExpressionType::Atom(name) => reject_if_underscore(name, expr),
        PreSymbolicExpressionType::TraitReference(name) => reject_if_underscore(name, expr),
        PreSymbolicExpressionType::SugaredFieldIdentifier(_, trait_name) => {
            reject_if_underscore(trait_name, expr)
        }
        PreSymbolicExpressionType::FieldIdentifier(trait_id) => {
            reject_if_underscore(&trait_id.name, expr)
        }
        PreSymbolicExpressionType::List(inner) | PreSymbolicExpressionType::Tuple(inner) => {
            check(inner)
        }
        PreSymbolicExpressionType::AtomValue(_)
        | PreSymbolicExpressionType::SugaredContractIdentifier(_)
        | PreSymbolicExpressionType::Comment(_)
        | PreSymbolicExpressionType::Placeholder(_) => Ok(()),
    }
}

fn reject_if_underscore(name: &ClarityName, expr: &PreSymbolicExpression) -> ParseResult<()> {
    if name.starts_with('_') {
        let mut err = ParseError::new(ParseErrorKind::UnderscoreIdentifierNotAllowed(
            name.to_string(),
        ));
        err.diagnostic.spans = vec![expr.span().clone()];
        return Err(err);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use clarity_types::types::QualifiedContractIdentifier;

    use super::*;
    use crate::vm::ast::build_ast_with_diagnostics;
    use crate::vm::costs::LimitedCostTracker;

    fn parses(source: &str, version: ClarityVersion) -> bool {
        let contract_id = QualifiedContractIdentifier::transient();
        let (_ast, _diag, success) = build_ast_with_diagnostics(
            &contract_id,
            source,
            &mut LimitedCostTracker::new_free(),
            version,
            StacksEpochId::latest(),
        );
        success
    }

    #[test]
    fn underscore_prefix_rejected_pre_clarity6() {
        // Reject `_admin` as a constant name in Clarity 5.
        assert!(!parses(
            "(define-constant _admin 'SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7)",
            ClarityVersion::Clarity5,
        ));
    }

    #[test]
    fn underscore_prefix_accepted_in_clarity6() {
        // Accept `_admin` as a constant name in Clarity 6.
        assert!(parses(
            "(define-constant _admin 'SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7)",
            ClarityVersion::Clarity6,
        ));
    }

    #[test]
    fn underscore_prefix_in_let_binding_pre_clarity6_rejected() {
        assert!(!parses("(let ((_x 1)) (+ _x 1))", ClarityVersion::Clarity5,));
    }

    #[test]
    fn bare_underscore_rejected_pre_clarity6() {
        assert!(!parses("(let ((_ 1)) 0)", ClarityVersion::Clarity5));
    }

    #[test]
    fn bare_underscore_accepted_in_clarity6() {
        assert!(parses("(let ((_ 1)) 0)", ClarityVersion::Clarity6));
    }

    #[test]
    fn underscore_in_function_arg_rejected_pre_clarity6() {
        assert!(!parses(
            "(define-public (foo (_addr principal)) (ok _addr))",
            ClarityVersion::Clarity5,
        ));
    }

    #[test]
    fn nested_underscore_atom_rejected_pre_clarity6() {
        // The check must descend into nested lists.
        assert!(!parses(
            "(define-public (foo) (ok (let ((y 1)) _bad)))",
            ClarityVersion::Clarity5,
        ));
    }

    #[test]
    fn non_underscore_names_still_accepted_pre_clarity6() {
        // Regression guard: legacy identifiers must still parse.
        assert!(parses(
            "(define-constant admin 'SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7)
             (define-public (foo (addr principal)) (ok addr))",
            ClarityVersion::Clarity5,
        ));
    }

    #[test]
    fn interior_underscore_still_accepted_pre_clarity6() {
        // Underscores inside an identifier remain legal pre-Clarity-6;
        // only the leading position is gated.
        assert!(parses(
            "(define-constant my_admin 'SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7)",
            ClarityVersion::Clarity5,
        ));
    }

    #[test]
    fn underscore_trait_reference_rejected_pre_clarity6() {
        // `<_foo>` inside a function signature should be caught too.
        assert!(!parses(
            "(define-trait t ((bar (<_foo>) (response uint uint))))",
            ClarityVersion::Clarity5,
        ));
    }
}
