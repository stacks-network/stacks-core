use vm::parser::parse;
use vm::representations::SymbolicExpression;
use vm::checker::typecheck::{TypeResult, TypeChecker, TypingContext, FunctionType};
use vm::checker::{AnalysisDatabase, AnalysisDatabaseConnection, identity_pass};

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
                "(eq? (+ 1 2 3) 6 0)",
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
fn test_eqs() {
    let good = ["(eq? (list 1 2 3 4 5) (list 1 2 3 4 5 6 7))",
                "(eq? (tuple (good 1) (bad 2)) (tuple (good 2) (bad 3)))",
                "(eq? \"abcdef\" \"abc\" \"a\")"];
    let bad = [
        "(eq? 1 2 'false)",
        "(eq? 1 2 3 (list 2))",
        "(list (list 1 2) (list 'true) (list 5 1 7))",
        "(list 1 2 3 'true 'false 4 5 6)",
        "(map mod (list 1 2 3 4 5))",
        "(map - (list 'true 'false 'true 'false))",
        "(map hash160 (+ 1 2))",];
                   
    for mut good_test in good.iter().map(|x| parse(x).unwrap()) {
        identity_pass::identity_pass(&mut good_test).unwrap();
        let t_out = type_check(&good_test[0]);
        match t_out {
            Err(ref t_out) => eprintln!("{}", t_out),
            _ => {}
        }
        t_out.unwrap();
    }
    
    for mut bad_test in bad.iter().map(|x| parse(x).unwrap()) {
        identity_pass::identity_pass(&mut bad_test).unwrap();
        let checked = type_check(&bad_test[0]);
        match checked {
            Err(ref t_out) => eprintln!("{}", t_out),
            _ => {}
        }
        assert!(checked.is_err())
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
#[cfg(feature = "developer-mode")]
fn test_function_arg_names() {
    use vm::checker::type_check;
    
    let functions = vec![
        "(define (test (x int)) (ok 0))
         (define-public (test-pub (x int)) (ok 0))
         (define-read-only (test-ro (x int)) (ok 0))",

        "(define (test (x int) (y bool)) (ok 0))
         (define-public (test-pub (x int) (y bool)) (ok 0))
         (define-read-only (test-ro (x int) (y bool)) (ok 0))",

        "(define (test (name-1 int) (name-2 int) (name-3 int)) (ok 0))
         (define-public (test-pub (name-1 int) (name-2 int) (name-3 int)) (ok 0))
         (define-read-only (test-ro (name-1 int) (name-2 int) (name-3 int)) (ok 0))",

        "(define (test) (ok 0))
         (define-public (test-pub) (ok 0))
         (define-read-only (test-ro) (ok 0))",
    ];

    let expected_arg_names: Vec<Vec<&str>> = vec![
        vec!["x"],
        vec!["x", "y"],
        vec!["name-1", "name-2", "name-3"],
        vec![],
    ];

    let mut analysis_conn = AnalysisDatabaseConnection::memory();
    let mut analysis_db = analysis_conn.begin_save_point();

    for (func_test, arg_names) in functions.iter().zip(expected_arg_names.iter()) {
        let mut func_expr = parse(func_test).unwrap();
        let contract_analysis = type_check(&":transient:", &mut func_expr, &mut analysis_db, false).unwrap();

        let func_type_priv = contract_analysis.get_private_function("test").unwrap();
        let func_type_pub = contract_analysis.get_public_function_type("test-pub").unwrap();
        let func_type_ro = contract_analysis.get_read_only_function_type("test-ro").unwrap();

        for func_type in &[func_type_priv, func_type_pub, func_type_ro] {
            let func_args = match func_type {
                FunctionType::Fixed(args, _) => args,
                _ => panic!("Unexpected function type")
            };
            
            for (expected_name, actual_name) in arg_names.iter().zip(func_args.iter().map(|x| &x.name)) {
                assert_eq!(*expected_name, actual_name);
            }
        }
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
