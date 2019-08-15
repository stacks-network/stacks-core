use vm::parser::parse;
use vm::analysis::{run_analysis, CheckError, CheckResult, CheckErrors, AnalysisDatabaseConnection};
use vm::analysis::types::{ContractAnalysis, AnalysisPass};
use vm::analysis::update_expressions_id::UpdateExpressionId;
use vm::analysis::update_expressions_sorting::UpdateExpressionsSorting;

fn run_scoped_analysis_helper(contract: &str) -> CheckResult<ContractAnalysis> {
    let mut analysis_conn = AnalysisDatabaseConnection::memory();
    let mut db = analysis_conn.begin_save_point();
    let expressions = parse(contract).unwrap();

    let mut contract_analysis = ContractAnalysis::new(expressions.to_vec());
    UpdateExpressionId::run_pass(&mut contract_analysis, &mut db)?;
    UpdateExpressionsSorting::run_pass(&mut contract_analysis, &mut db)?;
    Ok(contract_analysis)
}

fn run_analysis_helper(contract: &str) -> CheckResult<ContractAnalysis> {
    let mut analysis_conn = AnalysisDatabaseConnection::memory();
    let mut db = analysis_conn.begin_save_point();
    let mut expressions = parse(contract).unwrap();

    let contract_analysis = run_analysis("transient", &mut expressions, &mut db, false)?;
    Ok(contract_analysis)
}

#[test]
fn should_succeed_sorting_contract_case_1() {
    let contract = r#"
        (define (wrapped-kv-del (key int))
            (kv-del key))
        (define (kv-del (key int))
            (begin
                (delete-entry! kv-store ((key key)))
                key))
        (define-map kv-store ((key int)) ((value int)))
    "#;

    run_scoped_analysis_helper(contract).unwrap();
}

#[test]
fn should_succeed_sorting_contract_case_2() {
    let contract = r#"
        (define (a (x int)) (b x))
        (define (b (x int)) (+ x c))
        (define c 1)
        (define (d (x int)) (h x))
        (define e 1)
        (define (f (x int)) (+ e x))
        (define g 1)
        (define (h (x int)) (a x))
        (+ (a 1) (b 1) c (d 1) e (f 1) g (h 1))
    "#;

    run_scoped_analysis_helper(contract).unwrap();
}


#[test]
fn should_raise_dependency_cycle_case_1() {
    let contract = r#"
        (define (a (x int)) (b x))
        (define (b (x int)) (c x))
        (define (c (x int)) (a x))
    "#;

    let err = run_scoped_analysis_helper(contract).unwrap_err();
    assert!(match err.err { CheckErrors::CyclingDependencies(_) => true, _ => false });
}

#[test]
fn should_not_raise_dependency_cycle_case_let() {
    let contract = r#"
        (define (foo (x int)) (begin (bar 1) 1))
        (define (bar (x int)) (let ((foo 1)) (+ 1 x))) 
    "#;

    run_scoped_analysis_helper(contract).unwrap();
    run_analysis_helper(contract).unwrap();
}

#[test]
fn should_raise_dependency_cycle_case_let() {
    let contract = r#"
        (define (foo (x int)) (begin (bar 1) 1))
        (define (bar (x int)) (let ((baz (foo 1))) (+ 1 x))) 
    "#;

    let err = run_scoped_analysis_helper(contract).unwrap_err();
    assert!(match err.err { CheckErrors::CyclingDependencies(_) => true, _ => false})
}

#[test]
fn should_not_raise_dependency_cycle_case_get() {
    let contract = r#"
        (define (foo (x int)) (begin (bar 1) 1))
        (define (bar (x int)) (get foo (tuple (foo 1) (bar 2))))
    "#;

    run_scoped_analysis_helper(contract).unwrap();
    run_analysis_helper(contract).unwrap();
}

#[test]
fn should_raise_dependency_cycle_case_get() {
    let contract = r#"
        (define (foo (x int)) (begin (bar 1) 1))
        (define (bar (x int)) (let ((res (foo 1))) (+ 1 x))) 
    "#;

    let err = run_scoped_analysis_helper(contract).unwrap_err();
    assert!(match err.err { CheckErrors::CyclingDependencies(_) => true, _ => false})
}

#[test]
fn should_not_raise_dependency_cycle_case_fetch_entry() {
    let contract = r#"
        (define (foo (x int)) (begin (bar 1) 1))
        (define (bar (x int)) (fetch-entry kv-store ((foo 1)))) 
        (define-map kv-store ((foo int)) ((bar int)))
    "#;

    run_scoped_analysis_helper(contract).unwrap();
    run_analysis_helper(contract).unwrap();
}

#[test]
fn should_raise_dependency_cycle_case_fetch_entry() {
    let contract = r#"
        (define (foo (x int)) (+ (bar x) x))
        (define (bar (x int)) (fetch-entry kv-store ((foo (foo 1))))) 
        (define-map kv-store ((foo int)) ((bar int)))
    "#;

    let err = run_scoped_analysis_helper(contract).unwrap_err();
    assert!(match err.err { CheckErrors::CyclingDependencies(_) => true, _ => false})
}

#[test]
fn should_not_raise_dependency_cycle_case_delete_entry() {
    let contract = r#"
        (define (foo (x int)) (begin (bar 1) 1))
        (define (bar (x int)) (delete-entry! kv-store (tuple (foo 1)))) 
        (define-map kv-store ((foo int)) ((bar int)))
    "#;

    run_scoped_analysis_helper(contract).unwrap();
    run_analysis_helper(contract).unwrap();
}

#[test]
fn should_raise_dependency_cycle_case_delete_entry() {
    let contract = r#"
        (define (foo (x int)) (+ (bar x) x))
        (define (bar (x int)) (delete-entry! kv-store (tuple (foo (foo 1))))) 
        (define-map kv-store ((foo int)) ((bar int)))
    "#;

    let err = run_scoped_analysis_helper(contract).unwrap_err();
    assert!(match err.err { CheckErrors::CyclingDependencies(_) => true, _ => false})
}

#[test]
fn should_not_raise_dependency_cycle_case_set_entry() {
    let contract = r#"
        (define (foo (x int)) (begin (bar 1) 1))
        (define (bar (x int)) (set-entry! kv-store ((foo 1)) ((bar 3)))) 
        (define-map kv-store ((foo int)) ((bar int)))
    "#;

    run_scoped_analysis_helper(contract).unwrap();
    run_analysis_helper(contract).unwrap();
}

#[test]
fn should_raise_dependency_cycle_case_set_entry() {
    let contract = r#"
        (define (foo (x int)) (+ (bar x) x))
        (define (bar (x int)) (set-entry! kv-store ((foo 1)) ((bar (foo 1))))) 
        (define-map kv-store ((foo int)) ((bar int)))
    "#;

    let err = run_scoped_analysis_helper(contract).unwrap_err();
    assert!(match err.err { CheckErrors::CyclingDependencies(_) => true, _ => false})
}

#[test]
fn should_not_raise_dependency_cycle_case_insert_entry() {
    let contract = r#"
        (define (foo (x int)) (begin (bar 1) 1))
        (define (bar (x int)) (insert-entry! kv-store ((foo 1)) ((bar 3)))) 
        (define-map kv-store ((foo int)) ((bar int)))
    "#;

    run_scoped_analysis_helper(contract).unwrap();
    run_analysis_helper(contract).unwrap();
}

#[test]
fn should_raise_dependency_cycle_case_insert_entry() {
    let contract = r#"
        (define (foo (x int)) (+ (bar x) x))
        (define (bar (x int)) (insert-entry! kv-store ((foo (foo 1))) ((bar 3))))
        (define-map kv-store ((foo int)) ((bar int)))
    "#;

    let err = run_scoped_analysis_helper(contract).unwrap_err();
    assert!(match err.err { CheckErrors::CyclingDependencies(_) => true, _ => false})
}

#[test]
fn should_not_raise_dependency_cycle_case_fetch_contract_entry() {
    let contract = r#"
        (define (foo (x int)) (begin (bar 1) 1))
        (define (bar (x int)) (fetch-contract-entry c1 kv-store ((foo 1)))) 
    "#;

    run_scoped_analysis_helper(contract).unwrap();
}

#[test]
fn should_raise_dependency_cycle_case_fetch_contract_entry() {
    let contract = r#"
        (define (foo (x int)) (+ (bar x) x))
        (define (bar (x int)) (fetch-entry kv-store ((foo (foo 1))))) 
    "#;

    let err = run_scoped_analysis_helper(contract).unwrap_err();
    assert!(match err.err { CheckErrors::CyclingDependencies(_) => true, _ => false})
}
