use vm::parser::parse;
use vm::representations::SymbolicExpression;
use vm::checker::typecheck::{TypeResult, TypeChecker, TypingContext};
use vm::checker::{AnalysisDatabase, AnalysisDatabaseConnection, identity_pass};
use vm::checker::errors::CheckErrors;

mod contracts;

fn type_check(exp: &SymbolicExpression) -> TypeResult {
    let mut analysis_conn = AnalysisDatabaseConnection::memory();
    let analysis_db = analysis_conn.begin_save_point();
    let mut type_checker = TypeChecker::new(&analysis_db);
    let contract_context = TypingContext::new();
    type_checker.type_check(exp, &contract_context)
}


#[test]
fn test_get_block_info(){
    let good = ["(get-block-info time 1)",
                "(get-block-info time (* 2 3))"];
    let bad = ["(get-block-info none 1)",
               "(get-block-info time 'true)",
               "(get-block-info time)"];
    for mut good_test in good.iter().map(|x| parse(x).unwrap()) {
        identity_pass::identity_pass(&mut good_test).unwrap();
        type_check(&good_test[0]).unwrap();
    }
    
    for mut bad_test in bad.iter().map(|x| parse(x).unwrap()) {
        identity_pass::identity_pass(&mut bad_test).unwrap();
        assert!(type_check(&bad_test[0]).is_err())
    }
}

#[test]
fn test_simple_arithmetic_checks() {
    let good = ["(>= (+ 1 2 3) (- 1 2))",
                "(eq? (+ 1 2 3) 'true 'false)",
                "(and (or 'true 'false) 'false)"];
    let bad = ["(+ 1 2 3 (>= 5 7))",
               "(-)",
               "(xor 1)",
               "(+ x y z)", // unbound variables.
               "(+ 1 2 3 (eq? 1 2))",
               "(and (or 'true 'false) (+ 1 2 3))"];
    for mut good_test in good.iter().map(|x| parse(x).unwrap()) {
        identity_pass::identity_pass(&mut good_test).unwrap();
        type_check(&good_test[0]).unwrap();
    }
    
    for mut bad_test in bad.iter().map(|x| parse(x).unwrap()) {
        identity_pass::identity_pass(&mut bad_test).unwrap();
        assert!(type_check(&bad_test[0]).is_err())
    }
}

#[test]
fn test_simple_ifs() {
    let good = ["(if (> 1 2) (+ 1 2 3) (- 1 2))",
                "(if 'true 'true 'false)",
                "(if 'true \"abcdef\" \"abc\")",
                "(if 'true \"a\" \"abcdef\")" ];
    let bad = ["(if 'true 'true 1)",
               "(if 'true \"a\" 'false)",
               "(if)",
               "(if 0 1 0)"];
    for mut good_test in good.iter().map(|x| parse(x).unwrap()) {
        identity_pass::identity_pass(&mut good_test).unwrap();
        type_check(&good_test[0]).unwrap();
    }

    for mut bad_test in bad.iter().map(|x| parse(x).unwrap()) {
        identity_pass::identity_pass(&mut bad_test).unwrap();
        assert!(type_check(&bad_test[0]).is_err())
    }
}

#[test]
fn test_simple_lets() {
    let good = ["(let ((x 1) (y 2) (z 3)) (if (> x 2) (+ 1 x y) (- 1 z)))",
                "(let ((x 'true) (y (+ 1 2)) (z 3)) (if x (+ 1 z y) (- 1 z)))"];
    let bad = ["(let ((1)) (+ 1 2))",
               "(let ((1 2)) (+ 1 2))"];
    for mut good_test in good.iter().map(|x| parse(x).unwrap()) {
        identity_pass::identity_pass(&mut good_test).unwrap();
        type_check(&good_test[0]).unwrap();
    }
    
    for mut bad_test in bad.iter().map(|x| parse(x).unwrap()) {
        identity_pass::identity_pass(&mut bad_test).unwrap();
        assert!(type_check(&bad_test[0]).is_err())
    }
}

#[test]
fn test_lists() {
    let good = ["(map hash160 (list 1 2 3 4 5))",
                "(list (list 1 2) (list 3 4) (list 5 1 7))",
                "(fold and (list 'true 'true 'false 'false) 'true)",
                "(map - (list (+ 1 2) 3 (+ 4 5) (* (+ 1 2) 3)))"];
    let bad = [
        "(fold and (list 'true 'false) 2)",
        "(fold hash160 (list 1 2 3 4) 2)",
        "(fold >= (list 1 2 3 4) 2)",
        "(list (list 1 2) (list 'true) (list 5 1 7))",
        "(list 1 2 3 'true 'false 4 5 6)",
        "(map mod (list 1 2 3 4 5))",
        "(map - (list 'true 'false 'true 'false))",
        "(map hash160 (+ 1 2))",];
                   
    for mut good_test in good.iter().map(|x| parse(x).unwrap()) {
        identity_pass::identity_pass(&mut good_test).unwrap();
        type_check(&good_test[0]).unwrap();
    }
    
    for mut bad_test in bad.iter().map(|x| parse(x).unwrap()) {
        identity_pass::identity_pass(&mut bad_test).unwrap();
        assert!(type_check(&bad_test[0]).is_err())
    }
}

#[test]
fn test_tuples() {
    let good = ["(+ 1 2     (get abc (tuple (abc 1) (def 'true))))",
                "(and 'true (get def (tuple (abc 1) (def 'true))))"];
    let bad = ["(+ 1 2      (get def (tuple (abc 1) (def 'true))))",
               "(and 'true  (get abc (tuple (abc 1) (def 'true))))"];
    
    for mut good_test in good.iter().map(|x| parse(x).unwrap()) {
        identity_pass::identity_pass(&mut good_test).unwrap();
        type_check(&good_test[0]).unwrap();
    }
    
    for mut bad_test in bad.iter().map(|x| parse(x).unwrap()) {
        identity_pass::identity_pass(&mut bad_test).unwrap();
        assert!(type_check(&bad_test[0]).is_err())
    }
}

#[test]
fn test_define() {
    use vm::checker::type_check;
    
    let good = ["(define (foo (x int) (y int)) (+ x y))
                     (define (bar (x int) (y bool)) (if y (+ 1 x) 0))
                     (* (foo 1 2) (bar 3 'false))",
    ];
    
    let bad = ["(define (foo ((x int) (y int)) (+ x y)))
                     (define (bar ((x int) (y bool)) (if y (+ 1 x) 0)))
                     (* (foo 1 2) (bar 3 3))",
    ];

    let mut analysis_conn = AnalysisDatabaseConnection::memory();
    let mut analysis_db = analysis_conn.begin_save_point();

    for mut good_test in good.iter().map(|x| parse(x).unwrap()) {
        type_check(&":transient:", &mut good_test, &mut analysis_db, false).unwrap();
    }

    let mut analysis_conn = AnalysisDatabaseConnection::memory();
    let mut analysis_db = analysis_conn.begin_save_point();
    
    for mut bad_test in bad.iter().map(|x| parse(x).unwrap()) {
        assert!(type_check(&":transient:", &mut bad_test, &mut analysis_db, false).is_err());
    }
}

#[test]
fn test_factorial() {
    use vm::checker::type_check;
    let contract = "(define-map factorials ((id int)) ((current int) (index int)))
         (define (init-factorial (id int) (factorial int))
           (print (insert-entry! factorials (tuple (id id)) (tuple (current 1) (index factorial)))))
         (define-public (compute (id int))
           (let ((entry (expects! (fetch-entry factorials (tuple (id id)))
                                 (err 'false))))
                    (let ((current (get current entry))
                          (index   (get index entry)))
                         (if (<= index 1)
                             (ok 'true)
                             (begin
                               (set-entry! factorials (tuple (id id))
                                                      (tuple (current (* current index))
                                                             (index (- index 1))))
                               (ok 'false))))))
        (begin (init-factorial 1337 3)
               (init-factorial 8008 5))
        ";

    let mut contract = parse(contract).unwrap();
    let mut analysis_conn = AnalysisDatabaseConnection::memory();
    let mut analysis_db = analysis_conn.begin_save_point();

    type_check(&":transient:", &mut contract, &mut analysis_db, false).unwrap();
}

#[test]
fn test_tuple_map() {
    use vm::checker::type_check;
    let t = "(define-map tuples ((name int)) 
                            ((contents (tuple ((name (buff 5))
                                               (owner (buff 5)))))))

         (define (add-tuple (name int) (content (buff 5)))
           (insert-entry! tuples (tuple (name name))
                                 (tuple (contents
                                   (tuple (name content)
                                          (owner content))))))
         (define (get-tuple (name int))
            (get name (get contents (fetch-entry tuples (tuple (name name))))))


         (add-tuple 0 \"abcde\")
         (add-tuple 1 \"abcd\")
         (list      (get-tuple 0)
                    (get-tuple 1))
        ";

    let mut t = parse(t).unwrap();
    let mut analysis_conn = AnalysisDatabaseConnection::memory();
    let mut analysis_db = analysis_conn.begin_save_point();

    type_check(&":transient:", &mut t, &mut analysis_db, false).unwrap();
}


#[test]
fn test_explicit_tuple_map() {
    use vm::checker::type_check;
    let contract =
        "(define-map kv-store ((key int)) ((value int)))
          (define (kv-add (key int) (value int))
             (begin
                 (insert-entry! kv-store (tuple (key key))
                                     (tuple (value value)))
             value))
          (define (kv-get (key int))
             (expects! (get value (fetch-entry kv-store (tuple (key key)))) 0))
          (define (kv-set (key int) (value int))
             (begin
                 (set-entry! kv-store (tuple (key key))
                                    (tuple (value value)))
                 value))
          (define (kv-del (key int))
             (begin
                 (delete-entry! kv-store (tuple (key key)))
                 key))
         ";

    let mut contract = parse(contract).unwrap();
    let mut analysis_conn = AnalysisDatabaseConnection::memory();
    let mut analysis_db = analysis_conn.begin_save_point();

    type_check(&":transient:", &mut contract, &mut analysis_db, false).unwrap();
}

#[test]
fn test_implicit_tuple_map() {
    use vm::checker::type_check;
    let contract =
         "(define-map kv-store ((key int)) ((value int)))
          (define (kv-add (key int) (value int))
             (begin
                 (insert-entry! kv-store ((key key))
                                     ((value value)))
             value))
          (define (kv-get (key int))
             (expects! (get value (fetch-entry kv-store ((key key)))) 0))
          (define (kv-set (key int) (value int))
             (begin
                 (set-entry! kv-store ((key key))
                                    ((value value)))
                 value))
          (define (kv-del (key int))
             (begin
                 (delete-entry! kv-store ((key key)))
                 key))
         ";

    let mut contract = parse(contract).unwrap();
    let mut analysis_conn = AnalysisDatabaseConnection::memory();
    let mut analysis_db = analysis_conn.begin_save_point();

    type_check(&":transient:", &mut contract, &mut analysis_db, false).unwrap();
}


#[test]
fn test_bound_tuple_map() {
    use vm::checker::type_check;
    let contract =
        "(define-map kv-store ((key int)) ((value int)))
         (define (kv-add (key int) (value int))
            (begin
                (let ((my-tuple (tuple (key key))))
                (insert-entry! kv-store (tuple (key key))
                                    (tuple (value value))))
            value))
         (define (kv-get (key int))
            (let ((my-tuple (tuple (key key))))
            (expects! (get value (fetch-entry kv-store my-tuple)) 0)))
         (define (kv-set (key int) (value int))
            (begin
                (let ((my-tuple (tuple (key key))))
                (set-entry! kv-store my-tuple
                                   (tuple (value value))))
                value))
         (define (kv-del (key int))
            (begin
                (let ((my-tuple (tuple (key key))))
                (delete-entry! kv-store my-tuple))
                key))
        ";

    let mut contract = parse(contract).unwrap();
    let mut analysis_conn = AnalysisDatabaseConnection::memory();
    let mut analysis_db = analysis_conn.begin_save_point();

    type_check(&":transient:", &mut contract, &mut analysis_db, false).unwrap();
}

#[test]
fn test_fetch_entry_matching_type_signatures() {
    let cases = [
        "fetch-entry kv-store ((key key))",
        "fetch-entry kv-store ((key 0))",
        "fetch-entry kv-store (tuple (key 0))",
        "fetch-entry kv-store (compatible-tuple)",
    ];

    for case in cases.into_iter() {
        let contract_src = format!(
            "(define-map kv-store ((key int)) ((value int)))
             (define (compatible-tuple) (tuple (key 1)))
             (define (kv-get (key int))
                ({}))", case);
        let mut contract = parse(&contract_src).unwrap();
        type_check(&contract[0]).unwrap();
    }
}

#[test]
fn test_fetch_entry_mismatching_type_signatures() {
    let cases = [
        "fetch-entry kv-store ((incomptible-key key))",
        "fetch-entry kv-store ((key unknown-value))",
        "fetch-entry kv-store ((key 'true))",
        "fetch-entry kv-store (incompatible-key)",
    ];

    for case in cases.into_iter() {
        let contract_src = format!(
            "(define-map kv-store ((key int)) ((value int)))
             (define (incompatible-tuple) (tuple (k 1)))
             (define (kv-get (key int))
                ({}))", case);
        let mut contract = parse(&contract_src).unwrap();
        type_check(&contract[0]).unwrap_err();
    }
}


#[test]
fn test_insert_entry_matching_type_signatures() {
    let cases = [
        "insert-entry! kv-store ((key key)) ((value value))",
        "insert-entry! kv-store ((key 0)) ((value 1))",
        "insert-entry! kv-store (tuple (key 0)) (tuple (value 1))",
        "insert-entry! kv-store (compatible-tuple) ((value 1))",
    ];

    for case in cases.into_iter() {
        let contract_src = format!(
            "(define-map kv-store ((key int)) ((value int)))
             (define (compatible-tuple) (tuple (key 1)))
             (define (kv-add (key int) (value int))
                ({}))", case);
        let mut contract = parse(&contract_src).unwrap();
        type_check(&contract[0]).unwrap();
    }
}

#[test]
fn test_insert_entry_mismatching_type_signatures() {
    let cases = [
        "insert-entry! kv-store ((incomptible-key key)) ((value value))",
        "insert-entry! kv-store ((key key)) ((incomptible-key value))",
        "insert-entry! kv-store ((key unknown-value)) ((value 1))",
        "insert-entry! kv-store ((key key)) ((value unknown-value))",
        "insert-entry! kv-store ((key 'true)) ((value 1))",
        "insert-entry! kv-store ((key key)) ((value 'true))",
        "insert-entry! kv-store (incompatible-tuple) ((value 1))",
    ];

    for case in cases.into_iter() {
        let contract_src = format!(
            "(define-map kv-store ((key int)) ((value int)))
             (define (incompatible-tuple) (tuple (k 1)))
             (define (kv-add (key int) (value int))
                ({}))", case);
        let mut contract = parse(&contract_src).unwrap();
        type_check(&contract[0]).unwrap_err();
    }
}

#[test]
fn test_delete_entry_matching_type_signatures() {
    let cases = [
        "delete-entry! kv-store ((key key))",
        "delete-entry! kv-store ((key 1))",
        "delete-entry! kv-store (tuple (key 1))",
        "delete-entry! kv-store (compatible-tuple)",
    ];

    for case in cases.into_iter() {
        let contract_src = format!(
            "(define-map kv-store ((key int)) ((value int)))
             (define (compatible-tuple) (tuple (key 1)))
             (define (kv-del (key int))
                ({}))", case);
        let mut contract = parse(&contract_src).unwrap();
        type_check(&contract[0]).unwrap();
    }
}

#[test]
fn test_delete_entry_mismatching_type_signatures() {
    let cases = [
        "delete-entry! kv-store ((incomptible-key key))",
        "delete-entry! kv-store ((key unknown-value))",
        "delete-entry! kv-store ((key 'true))",
        "delete-entry! kv-store (incompatible-tuple)",
    ];

    for case in cases.into_iter() {
        let contract_src = format!(
            "(define-map kv-store ((key int)) ((value int)))
             (define (incompatible-tuple) (tuple (k 1)))
             (define (kv-del (key int))
                ({}))", case);
        let mut contract = parse(&contract_src).unwrap();
        type_check(&contract[0]).unwrap_err();
    }

}

#[test]
fn test_set_entry_matching_type_signatures() {    
    let cases = [
        "set-entry! kv-store ((key key)) ((value value))",
        "set-entry! kv-store ((key 0)) ((value 1))",
        "set-entry! kv-store (tuple (key 0)) (tuple (value 1))",
        "set-entry! kv-store (tuple (key 0)) (tuple (value known-value))",
        "set-entry! kv-store (compatible-tuple) ((value 1))",
    ];

    for case in cases.into_iter() {
        let contract_src = format!(
            "(define-map kv-store ((key int)) ((value int)))
             (define (compatible-tuple) (tuple (key 1)))
             (define (kv-set (key int) (value int))
                (let ((known-value 2))
                ({})))", case);
        let mut contract = parse(&contract_src).unwrap();
        type_check(&contract[0]).unwrap();
    }
}

#[test]
fn test_set_entry_mismatching_type_signatures() {    
    let cases = [
        "set-entry! kv-store ((incomptible-key key)) ((value value))",
        "set-entry! kv-store ((key key)) ((incomptible-key value))",
        "set-entry! kv-store ((key unknown-value)) ((value 1))",
        "set-entry! kv-store ((key key)) ((value unknown-value))",
        "set-entry! kv-store ((key 'true)) ((value 1))",
        "set-entry! kv-store ((key key)) ((value 'true))",
        "set-entry! kv-store (incompatible-tuple) ((value 1))",
    ];

    for case in cases.into_iter() {
        let contract_src = format!(
            "(define-map kv-store ((key int)) ((value int)))
             (define (incompatible-tuple) (tuple (k 1)))
             (define (kv-set (key int) (value int))
                ({}))", case);
        let mut contract = parse(&contract_src).unwrap();
        type_check(&contract[0]).unwrap_err();
    }
}
