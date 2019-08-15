use vm::analysis::{CheckErrors, mem_type_check};

#[test]
fn test_contract_call_define_ordering() {
    let contract = r#"
        (define-private (wrapped-kv-del (key int))
            (kv-del key))
        (define-private (kv-del (key int))
            (begin 
                (map-delete! kv-store ((key key)))
                key))
        (define-map kv-store ((key int)) ((value int)))
    "#;

    mem_type_check(contract).unwrap();
}

#[test]
fn test_contract_call_define_ordering_2() {
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

    mem_type_check(contract).unwrap();
}

#[test]
fn test_contract_call_cyclic_graph_call() {
    let contract = r#"
        (define-private (a (x int)) (b x))
        (define-private (b (x int)) (c x))
        (define-private (c (x int)) (a x))
    "#;

    let err = mem_type_check(contract).unwrap_err();
    let cycle = vec!["b".to_string(), "c".to_string(), "a".to_string()];
    assert!(match err.err {
            CheckErrors::CyclingDependencies(_) => true,
            _ => false
    }, "Should have succeed detecting dependencies cycling")
}
