// Copyright (C) 2025 Stacks Open Internet Foundation
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

use stacks_common::types::StacksEpochId;

use crate::vm::ast::{build_ast_with_rules, ASTRules};
use crate::vm::types::QualifiedContractIdentifier;
use crate::vm::{ClarityVersion, SymbolicExpression};

#[test]
fn same_atom_same_hash() {
    let atom1 = SymbolicExpression::atom("test-atom".into());
    let atom2 = SymbolicExpression::atom("test-atom".into());
    let hash1 = atom1.to_mast_hash();
    let hash2 = atom2.to_mast_hash();
    assert_eq!(hash1, hash2);
}

#[test]
fn different_atom_different_hash() {
    let atom1 = SymbolicExpression::atom("test-atom".into());
    let atom2 = SymbolicExpression::atom("test-ato".into());
    let hash1 = atom1.to_mast_hash();
    let hash2 = atom2.to_mast_hash();
    assert_ne!(hash1, hash2);
}

#[test]
fn same_list_same_hash() {
    let list1 = SymbolicExpression::list(vec![
        SymbolicExpression::atom("a".into()),
        SymbolicExpression::atom("b".into()),
    ]);
    let list2 = SymbolicExpression::list(vec![
        SymbolicExpression::atom("a".into()),
        SymbolicExpression::atom("b".into()),
    ]);
    let hash1 = list1.to_mast_hash();
    let hash2 = list2.to_mast_hash();
    assert_eq!(hash1, hash2);
}

#[test]
fn different_list_different_hash() {
    let list1 = SymbolicExpression::list(vec![
        SymbolicExpression::atom("a".into()),
        SymbolicExpression::atom("b".into()),
    ]);
    let list2 = SymbolicExpression::list(vec![
        SymbolicExpression::atom("a".into()),
        SymbolicExpression::atom("c".into()),
    ]);
    let hash1 = list1.to_mast_hash();
    let hash2 = list2.to_mast_hash();
    assert_ne!(hash1, hash2);
}

#[test]
fn atom_and_list_different_hash() {
    let atom = SymbolicExpression::atom("a".into());
    let list = SymbolicExpression::list(vec![SymbolicExpression::atom("a".into())]);
    let hash_atom = atom.to_mast_hash();
    let hash_list = list.to_mast_hash();
    assert_ne!(hash_atom, hash_list);
}

#[test]
fn nested_list_hash_consistency() {
    let nested1 = SymbolicExpression::list(vec![
        SymbolicExpression::atom("x".into()),
        SymbolicExpression::list(vec![
            SymbolicExpression::atom("y".into()),
            SymbolicExpression::atom("z".into()),
        ]),
    ]);
    let nested2 = SymbolicExpression::list(vec![
        SymbolicExpression::atom("x".into()),
        SymbolicExpression::list(vec![
            SymbolicExpression::atom("y".into()),
            SymbolicExpression::atom("z".into()),
        ]),
    ]);
    let hash1 = nested1.to_mast_hash();
    let hash2 = nested2.to_mast_hash();
    assert_eq!(hash1, hash2);
}

#[test]
fn nested_list_different_hash() {
    let nested1 = SymbolicExpression::list(vec![
        SymbolicExpression::atom("x".into()),
        SymbolicExpression::list(vec![
            SymbolicExpression::atom("y".into()),
            SymbolicExpression::atom("z".into()),
        ]),
    ]);
    let nested2 = SymbolicExpression::list(vec![
        SymbolicExpression::atom("x".into()),
        SymbolicExpression::list(vec![
            SymbolicExpression::atom("y".into()),
            SymbolicExpression::atom("w".into()),
        ]),
    ]);
    let hash1 = nested1.to_mast_hash();
    let hash2 = nested2.to_mast_hash();
    assert_ne!(hash1, hash2);
}

#[test]
fn list_order_consistency() {
    let list1 = SymbolicExpression::list(vec![
        SymbolicExpression::atom("a".into()),
        SymbolicExpression::atom("b".into()),
    ]);
    let list2 = SymbolicExpression::list(vec![
        SymbolicExpression::atom("b".into()),
        SymbolicExpression::atom("a".into()),
    ]);
    let hash1 = list1.to_mast_hash();
    let hash2 = list2.to_mast_hash();
    assert_ne!(hash1, hash2);
}

#[test]
fn whitespace_inconsequential() {
    let src1 = "  (define-constant x    10)  ";
    let src2 = "(define-constant x 10)";

    let ast1 = build_ast_with_rules(
        &QualifiedContractIdentifier::transient(),
        &src1,
        &mut (),
        ClarityVersion::latest(),
        StacksEpochId::latest(),
        ASTRules::PrecheckSize,
    )
    .unwrap_or_else(|e| panic!("Failed to build AST: {e}"));
    let ast2 = build_ast_with_rules(
        &QualifiedContractIdentifier::transient(),
        &src2,
        &mut (),
        ClarityVersion::latest(),
        StacksEpochId::latest(),
        ASTRules::PrecheckSize,
    )
    .unwrap_or_else(|e| panic!("Failed to build AST: {e}"));

    let mast_hash1 = ast1.to_mast_hash();
    let mast_hash2 = ast2.to_mast_hash();
    assert_eq!(mast_hash1, mast_hash2);
}

#[test]
fn comments_inconsequential() {
    let src1 = r#"
;; this is a comment
(define-public (foo)
  (ok 42) ;; inline comment here
)
"#;
    let src2 = "(define-public (foo) (ok 42))";

    let ast1 = build_ast_with_rules(
        &QualifiedContractIdentifier::transient(),
        &src1,
        &mut (),
        ClarityVersion::latest(),
        StacksEpochId::latest(),
        ASTRules::PrecheckSize,
    )
    .unwrap_or_else(|e| panic!("Failed to build AST: {e}"));
    let ast2 = build_ast_with_rules(
        &QualifiedContractIdentifier::transient(),
        &src2,
        &mut (),
        ClarityVersion::latest(),
        StacksEpochId::latest(),
        ASTRules::PrecheckSize,
    )
    .unwrap_or_else(|e| panic!("Failed to build AST: {e}"));

    let mast_hash1 = ast1.to_mast_hash();
    let mast_hash2 = ast2.to_mast_hash();
    assert_eq!(mast_hash1, mast_hash2);
}

#[test]
fn definition_ordering_inconsequential() {
    let src1 = r#"
(define-public (foo)
  (ok (bar))
)
(define-private (bar)
  42
)
"#;
    let src2 = r#"
(define-private (bar)
  42
)
(define-public (foo)
  (ok (bar))
)
"#;

    let ast1 = build_ast_with_rules(
        &QualifiedContractIdentifier::transient(),
        &src1,
        &mut (),
        ClarityVersion::latest(),
        StacksEpochId::latest(),
        ASTRules::PrecheckSize,
    )
    .unwrap_or_else(|e| panic!("Failed to build AST: {e}"));
    let ast2 = build_ast_with_rules(
        &QualifiedContractIdentifier::transient(),
        &src2,
        &mut (),
        ClarityVersion::latest(),
        StacksEpochId::latest(),
        ASTRules::PrecheckSize,
    )
    .unwrap_or_else(|e| panic!("Failed to build AST: {e}"));

    let mast_hash1 = ast1.to_mast_hash();
    let mast_hash2 = ast2.to_mast_hash();
    assert_eq!(mast_hash1, mast_hash2);
}

#[test]
fn expression_ordering_matters() {
    let src1 = r#"
(define-data-var v1 uint u3)
(define-data-var v2 uint u0)
(var-set v1 (var-get v2))
(var-set v2 u5)
"#;
    let src2 = r#"
(define-data-var v1 uint u3)
(define-data-var v2 uint u0)
(var-set v2 u5)
(var-set v1 (var-get v2))
"#;

    let ast1 = build_ast_with_rules(
        &QualifiedContractIdentifier::transient(),
        &src1,
        &mut (),
        ClarityVersion::latest(),
        StacksEpochId::latest(),
        ASTRules::PrecheckSize,
    )
    .unwrap_or_else(|e| panic!("Failed to build AST: {e}"));
    let ast2 = build_ast_with_rules(
        &QualifiedContractIdentifier::transient(),
        &src2,
        &mut (),
        ClarityVersion::latest(),
        StacksEpochId::latest(),
        ASTRules::PrecheckSize,
    )
    .unwrap_or_else(|e| panic!("Failed to build AST: {e}"));

    let mast_hash1 = ast1.to_mast_hash();
    let mast_hash2 = ast2.to_mast_hash();
    assert_ne!(mast_hash1, mast_hash2);
}
