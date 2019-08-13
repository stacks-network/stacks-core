use vm::parser::parse;
use vm::analysis::{type_check, CheckError, CheckErrors, AnalysisDatabaseConnection};

#[test]
fn test_contract_call_define_ordering() {
    let contract = r#"
        (define (wrapped-kv-del (key int))
            (kv-del key))
        (define (kv-del (key int))
            (begin
                (delete-entry! kv-store ((key key)))
                key))
        (define-map kv-store ((key int)) ((value int)))
    "#;

    let mut contract = parse(contract).unwrap();

    let mut analysis_conn = AnalysisDatabaseConnection::memory();
    let mut db = analysis_conn.begin_save_point();

    type_check(&"contract", &mut contract, &mut db, true).unwrap();
}

#[test]
fn test_contract_call_define_ordering_2() {
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

    let mut contract = parse(contract).unwrap();

    let mut analysis_conn = AnalysisDatabaseConnection::memory();
    let mut db = analysis_conn.begin_save_point();

    type_check(&"contract", &mut contract, &mut db, true).unwrap();
}

#[test]
fn test_contract_call_cyclic_graph_call() {
    let contract = r#"
        (define (a (x int)) (b x))
        (define (b (x int)) (c x))
        (define (c (x int)) (a x))
    "#;

    let mut contract = parse(contract).unwrap();

    let mut analysis_conn = AnalysisDatabaseConnection::memory();
    let mut db = analysis_conn.begin_save_point();

    let err = type_check(&"contract", &mut contract, &mut db, true).unwrap_err();
    let cycle = vec!["b".to_string(), "c".to_string(), "a".to_string()];
    assert_eq!(err.err, CheckErrors::CyclingDependencies(cycle))
}

