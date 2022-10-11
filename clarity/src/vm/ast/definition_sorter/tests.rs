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

use crate::vm::analysis::mem_type_check as run_analysis_helper;
use crate::vm::ast::definition_sorter::DefinitionSorter;
use crate::vm::ast::errors::ParseErrors;
use crate::vm::ast::errors::ParseResult;
use crate::vm::ast::expression_identifier::ExpressionIdentifier;
use crate::vm::ast::parser;
use crate::vm::ast::types::{BuildASTPass, ContractAST};
use crate::vm::database::MemoryBackingStore;
use crate::vm::types::QualifiedContractIdentifier;

fn run_scoped_parsing_helper(contract: &str) -> ParseResult<ContractAST> {
    let contract_identifier = QualifiedContractIdentifier::transient();
    let pre_expressions = parser::parse(contract)?;
    let mut contract_ast = ContractAST::new(contract_identifier.clone(), pre_expressions);
    ExpressionIdentifier::run_pre_expression_pass(&mut contract_ast)?;
    DefinitionSorter::run_pass(&mut contract_ast, &mut ())?;
    Ok(contract_ast)
}

#[test]
fn should_succeed_sorting_contract_call() {
    let contract = "(define-read-only (foo-function (a int))
           (contract-call? .contract-b foo-function a))";
    run_scoped_parsing_helper(contract).unwrap();
}

#[test]
fn should_fix_2123() {
    let contract = "(define-fungible-token limited-supply-stacks (supply))
    (define-read-only (supply) u100)";
    run_analysis_helper(contract).unwrap();
}

#[test]
fn should_succeed_sorting_contract_case_1() {
    let contract = r#"
        (define-private (wrapped-kv-del (key int))
            (kv-del key))
        (define-private (kv-del (key int))
            (begin 
                (map-delete kv-store { key: key })
                key))
        (define-map kv-store { key: int } { value: int })
    "#;
    run_scoped_parsing_helper(contract).unwrap();
}

#[test]
fn should_succeed_sorting_contract_case_2() {
    let contract = r#"
        (define-private (a (x int)) (b x))
        (define-private (b (x int)) (+ x c))
        (define-constant c 1)
        (define-private (d (x int)) (h x))
        (define-constant e 1)
        (define-private (f (x int)) (+ e x))
        (define-constant g 1)
        (define-private (h (x int)) (a x))
        (+ (a 1) (b 1) c (d 1) e (f 1) g (h 1))
    "#;
    run_scoped_parsing_helper(contract).unwrap();
}

#[test]
fn should_raise_dependency_cycle_case_1() {
    let contract = r#"
        (define-private (a (x int)) (b x))
        (define-private (b (x int)) (c x))
        (define-private (c (x int)) (a x))
    "#;

    let err = run_scoped_parsing_helper(contract).unwrap_err();
    assert!(match err.err {
        ParseErrors::CircularReference(_) => true,
        _ => false,
    });
}

#[test]
fn should_raise_dependency_cycle_case_2() {
    let contract = r#"
        (define-private (a (x int)) (b x))
        (define-private (b (x int)) (c x))
        (define-private (c (x int)) (a x))
        (a 0)
    "#;

    let err = run_scoped_parsing_helper(contract).unwrap_err();
    assert!(match err.err {
        ParseErrors::CircularReference(_) => true,
        _ => false,
    });
}

#[test]
fn should_not_raise_dependency_cycle_case_let() {
    let contract = r#"
        (define-private (foo (x int)) (begin (bar 1) 1))
        (define-private (bar (x int)) (let ((foo 1)) (+ 1 x))) 
    "#;

    run_scoped_parsing_helper(contract).unwrap();
    run_analysis_helper(contract).unwrap();
}

#[test]
fn should_raise_dependency_cycle_case_let() {
    let contract = r#"
        (define-private (foo (x int)) (begin (bar 1) 1))
        (define-private (bar (x int)) (let ((baz (foo 1))) (+ 1 x))) 
    "#;

    let err = run_scoped_parsing_helper(contract).unwrap_err();
    assert!(match err.err {
        ParseErrors::CircularReference(_) => true,
        _ => false,
    })
}

#[test]
fn should_not_raise_dependency_cycle_case_get() {
    let contract = r#"
        (define-private (foo (x int)) (begin (bar 1) 1))
        (define-private (bar (x int)) (get foo (tuple (foo 1) (bar 2))))
    "#;

    run_scoped_parsing_helper(contract).unwrap();
    run_analysis_helper(contract).unwrap();
}

#[test]
fn should_raise_dependency_cycle_case_get() {
    let contract = r#"
        (define-private (foo (x int)) (begin (bar 1) 1))
        (define-private (bar (x int)) (let ((res (foo 1))) (+ 1 x))) 
    "#;

    let err = run_scoped_parsing_helper(contract).unwrap_err();
    assert!(match err.err {
        ParseErrors::CircularReference(_) => true,
        _ => false,
    })
}

#[test]
fn should_not_raise_dependency_cycle_case_fetch_entry() {
    let contract = r#"
        (define-private (foo (x int)) (begin (bar 1) 1))
        (define-private (bar (x int)) (map-get? kv-store { foo: 1 })) 
        (define-map kv-store { foo: int } { bar: int })
    "#;

    run_scoped_parsing_helper(contract).unwrap();
    run_analysis_helper(contract).unwrap();
}

#[test]
fn should_raise_dependency_cycle_case_fetch_entry() {
    let contract = r#"
        (define-private (foo (x int)) (+ (bar x) x))
        (define-private (bar (x int)) (map-get? kv-store { foo: (foo 1) })) 
        (define-map kv-store { foo: int } { bar: int })
    "#;

    let err = run_scoped_parsing_helper(contract).unwrap_err();
    assert!(match err.err {
        ParseErrors::CircularReference(_) => true,
        _ => false,
    })
}

#[test]
fn should_not_raise_dependency_cycle_case_delete_entry() {
    let contract = r#"
        (define-private (foo (x int)) (begin (bar 1) 1))
        (define-private (bar (x int)) (map-delete kv-store (tuple (foo 1)))) 
        (define-map kv-store { foo: int } { bar: int })
    "#;

    run_scoped_parsing_helper(contract).unwrap();
    run_analysis_helper(contract).unwrap();
}

#[test]
fn should_raise_dependency_cycle_case_delete_entry() {
    let contract = r#"
        (define-private (foo (x int)) (+ (bar x) x))
        (define-private (bar (x int)) (map-delete kv-store (tuple (foo (foo 1))))) 
        (define-map kv-store { foo: int } { bar: int })
    "#;

    let err = run_scoped_parsing_helper(contract).unwrap_err();
    assert!(match err.err {
        ParseErrors::CircularReference(_) => true,
        _ => false,
    })
}

#[test]
fn should_not_raise_dependency_cycle_case_set_entry() {
    let contract = r#"
        (define-private (foo (x int)) (begin (bar 1) 1))
        (define-private (bar (x int)) (map-set kv-store { foo: 1 } { bar: 3 })) 
        (define-map kv-store { foo: int } { bar: int })
    "#;

    run_scoped_parsing_helper(contract).unwrap();
    run_analysis_helper(contract).unwrap();
}

#[test]
fn should_raise_dependency_cycle_case_set_entry() {
    let contract = r#"
        (define-private (foo (x int)) (+ (bar x) x))
        (define-private (bar (x int)) (map-set kv-store { foo: 1 } { bar: (foo 1) })) 
        (define-map kv-store { foo: int } { bar: int })
    "#;

    let err = run_scoped_parsing_helper(contract).unwrap_err();
    assert!(match err.err {
        ParseErrors::CircularReference(_) => true,
        _ => false,
    })
}

#[test]
fn should_not_raise_dependency_cycle_case_insert_entry() {
    let contract = r#"
        (define-private (foo (x int)) (begin (bar 1) 1))
        (define-private (bar (x int)) (map-insert kv-store { foo: 1 } { bar: 3 })) 
        (define-map kv-store { foo: int } { bar: int })
    "#;

    run_scoped_parsing_helper(contract).unwrap();
    run_analysis_helper(contract).unwrap();
}

#[test]
fn should_raise_dependency_cycle_case_insert_entry() {
    let contract = r#"
        (define-private (foo (x int)) (+ (bar x) x))
        (define-private (bar (x int)) (map-insert kv-store { foo: (foo 1) } { bar: 3 }))
        (define-map kv-store { foo: int } { bar: int })
    "#;

    let err = run_scoped_parsing_helper(contract).unwrap_err();
    assert!(match err.err {
        ParseErrors::CircularReference(_) => true,
        _ => false,
    })
}

#[test]
fn should_raise_dependency_cycle_case_fetch_contract_entry() {
    let contract = r#"
        (define-private (foo (x int)) (+ (bar x) x))
        (define-private (bar (x int)) (map-get? kv-store { foo: (foo 1) })) 
    "#;

    let err = run_scoped_parsing_helper(contract).unwrap_err();
    assert!(match err.err {
        ParseErrors::CircularReference(_) => true,
        _ => false,
    })
}

#[test]
fn should_not_build_cycle_within_defined_args_types() {
    let contract = r#"
        (define-private (function-1 (function-2 int)) (+ 1 2))
        (define-private (function-2 (function-1 int)) (+ 1 2))
    "#;

    run_scoped_parsing_helper(contract).unwrap();
}

#[test]
fn should_reorder_traits_references() {
    let contract = r#"
        (define-private (foo (function-2 <trait-a>)) (+ 1 2))
        (define-trait trait-a ((get-a () (response uint uint))))
    "#;

    run_scoped_parsing_helper(contract).unwrap();
}

#[test]
fn should_not_conflict_with_atoms_from_trait_definitions() {
    let contract = r#"
        (define-trait foo ((bar (int) (int))))
        (define-trait bar ((foo (int) (int))))
    "#;

    run_scoped_parsing_helper(contract).unwrap();
}
