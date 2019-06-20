use vm::errors::{Error, UncheckedError, RuntimeErrorType};
use vm::types::{Value, PrincipalData, TupleData};
use vm::contexts::{OwnedEnvironment};
use vm::database::{ContractDatabaseConnection};
use vm::execute;

fn assert_executes(expected: Result<Value, Error>, input: &str) {
    assert_eq!(expected.unwrap(), execute(input).unwrap().unwrap());
}

#[test]
fn test_simple_tea_shop() {
    let test1 =
        "(define-map proper-tea ((tea-type int)) ((amount int)))
         (define (stock (tea int) (amount int))
           (set-entry! proper-tea (tuple (tea-type tea)) (tuple (amount amount))))
         (define (consume (tea int))
           (let ((current (expects! 
                            (get amount (fetch-entry proper-tea (tuple (tea-type tea)))) 3)))
              (if (and (>= current 1))
                  (begin
                    (set-entry! proper-tea (tuple (tea-type tea))
                                           (tuple (amount (- current 1))))
                    1)
                  2)))
        (stock 1 3)
        (stock 2 5)
        (list (consume 1)
              (consume 1)
              (consume 2)
              (consume 2)
              (consume 2)
              (consume 1)
              (consume 1)
              (consume 2)
              (consume 2)
              (consume 2)
              (consume 2)
              (consume 3))
        ";

    let expected = Value::list_from(vec![
        Value::Int(1),
        Value::Int(1),
        Value::Int(1),
        Value::Int(1),
        Value::Int(1),
        Value::Int(1),
        Value::Int(2),
        Value::Int(1),
        Value::Int(1),
        Value::Int(2),
        Value::Int(2),
        Value::Int(3)],
    );

    assert_executes(expected, test1);
}

#[test]
fn test_bound_tuple() {
    let test =
        "(define-map kv-store ((key int)) ((value int)))
         (define (kv-add (key int) (value int))
            (begin
                (let ((my-tuple (tuple (key key))))
                (insert-entry! kv-store my-tuple (tuple (value value))))
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

    let mut test_add_set_del = test.to_string();
    test_add_set_del.push_str("(list (kv-add 1 1) (kv-set 1 2) (kv-del 1) (kv-add 1 1))");
    let expected = Value::list_from(vec![
        Value::Int(1),
        Value::Int(2),
        Value::Int(1),
        Value::Int(1)],
    );    
    assert_executes(expected, &test_add_set_del);

    let mut test_get = test.to_string();
    test_get.push_str("(list (kv-get 1))");
    let expected = Value::list_from(vec![Value::Int(0)]);    
    assert_executes(expected, &test_get);
}

#[test]
fn test_explicit_syntax_tuple() {
    let test =
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

    let mut test_add_set_del = test.to_string();
    test_add_set_del.push_str("(list (kv-add 1 1) (kv-set 1 2) (kv-del 1) (kv-add 1 1))");
    let expected = Value::list_from(vec![
        Value::Int(1),
        Value::Int(2),
        Value::Int(1),
        Value::Int(1)],
    );    
    assert_executes(expected, &test_add_set_del);

    let mut test_get = test.to_string();
    test_get.push_str("(list (kv-get 1))");
    let expected = Value::list_from(vec![Value::Int(0)]);    
    assert_executes(expected, &test_get);
}

#[test]
fn test_implicit_syntax_tuple() {
    let test =
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

    let mut test_add_set_del = test.to_string();
    test_add_set_del.push_str("(list (kv-add 1 1) (kv-set 1 2) (kv-del 1) (kv-add 1 1))");
    let expected = Value::list_from(vec![
        Value::Int(1),
        Value::Int(2),
        Value::Int(1),
        Value::Int(1)],
    );    
    assert_executes(expected, &test_add_set_del);

    let mut test_get = test.to_string();
    test_get.push_str("(list (kv-get 1))");
    let expected = Value::list_from(vec![Value::Int(0)]);    
    assert_executes(expected, &test_get);
}


#[test]
fn test_fetch_contract_entry() {
    let kv_store_contract_src = r#"
        (define-map kv-store ((key int)) ((value int)))
        (define-read-only (kv-get (key int))
            (expects! (get value (fetch-entry kv-store ((key key)))) 0))
        (begin (insert-entry! kv-store ((key 42)) ((value 42))))"#;

    let proxy_src = r#"
        (define (fetch-via-conntract-call)
            (contract-call! kv-store-contract kv-get 42))
        (define (fetch-via-fetch-contract-entry-using-explicit-tuple)
            (expects! (get value (fetch-contract-entry kv-store-contract kv-store (tuple (key 42)))) 0))
        (define (fetch-via-fetch-contract-entry-using-implicit-tuple)
            (expects! (get value (fetch-contract-entry kv-store-contract kv-store ((key 42)))) 0))
        (define (fetch-via-fetch-contract-entry-using-bound-tuple)
            (let ((t (tuple (key 42))))
            (expects! (get value (fetch-contract-entry kv-store-contract kv-store t)) 0)))"#;

    let mut conn = ContractDatabaseConnection::memory().unwrap();
    let mut owned_env = OwnedEnvironment::new(&mut conn);

    let mut env = owned_env.get_exec_environment(None);
    let r = env.initialize_contract("kv-store-contract", kv_store_contract_src).unwrap();
    env.initialize_contract("proxy-contract", proxy_src).unwrap();
    env.sender = Some(Value::Principal(PrincipalData::StandardPrincipal
                                       (1, [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1])));

    assert_eq!(Value::Int(42), env.eval_read_only("proxy-contract", "(fetch-via-conntract-call)").unwrap());
    assert_eq!(Value::Int(42), env.eval_read_only("proxy-contract", "(fetch-via-fetch-contract-entry-using-implicit-tuple)").unwrap());
    assert_eq!(Value::Int(42), env.eval_read_only("proxy-contract", "(fetch-via-fetch-contract-entry-using-explicit-tuple)").unwrap());
    assert_eq!(Value::Int(42), env.eval_read_only("proxy-contract", "(fetch-via-fetch-contract-entry-using-bound-tuple)").unwrap());
}

#[test]
fn test_set_int_variable() {
        let contract_src = r#"
        (define-data-var cursor int 0)
        (define (get-cursor)
            (fetch-var cursor))
        (define (set-cursor (value int))
            (if (set-var! cursor value)
                value
                0))
        (define (increment-cursor)
            (begin
                (set-var! cursor (+ 1 (get-cursor)))
                (get-cursor)))
    "#;

    let mut contract_src = contract_src.to_string();
    contract_src.push_str("(list (get-cursor) (set-cursor 8) (get-cursor) (set-cursor 255) (get-cursor) (increment-cursor))");
    let expected = Value::list_from(vec![
        Value::Int(0),
        Value::Int(8),
        Value::Int(8),
        Value::Int(255),
        Value::Int(255),
        Value::Int(256),
    ]);    
    assert_executes(expected, &contract_src);
}

#[test]
fn test_set_bool_variable() {
    let contract_src = r#"
        (define-data-var is-ok bool 'true)
        (define (get-ok)
            (fetch-var is-ok))
        (define (set-ok (new-ok bool))
            (if (set-var! is-ok new-ok)
                new-ok
                (get-ok)))
    "#;

    let mut contract_src = contract_src.to_string();
    contract_src.push_str("(list (get-ok) (set-ok 'false) (get-ok))");
    let expected = Value::list_from(vec![
        Value::Bool(true),
        Value::Bool(false),
        Value::Bool(false)
    ]);    
    assert_executes(expected, &contract_src);
}

#[test]
fn test_set_tuple_variable() {
    let contract_src = r#"
        (define-data-var keys (tuple ((k1 int) (v1 int))) (tuple (k1 1) (v1 1)))
        (define (get-keys)
            (fetch-var keys))
        (define (set-keys (value (tuple ((k1 int) (v1 int)))))
            (if (set-var! keys value)
                value
                (get-keys)))
    "#;
    let mut contract_src = contract_src.to_string();
    contract_src.push_str("(list (get-keys) (set-keys (tuple (k1 2) (v1 0))) (get-keys))");
    let expected = Value::list_from(vec![
        Value::Tuple(TupleData::from_data(vec![("k1".to_string(), Value::Int(1)), ("v1".to_string(), Value::Int(1))]).unwrap()),
        Value::Tuple(TupleData::from_data(vec![("k1".to_string(), Value::Int(2)), ("v1".to_string(), Value::Int(0))]).unwrap()),
        Value::Tuple(TupleData::from_data(vec![("k1".to_string(), Value::Int(2)), ("v1".to_string(), Value::Int(0))]).unwrap()),
    ]);    
    assert_executes(expected, &contract_src);
}

#[test]
fn test_set_list_variable() {
    let contract_src = r#"
        (define-data-var ranking (list 3 int) (list 1 2 3))
        (define (get-ranking)
            (fetch-var ranking))
        (define (set-ranking (new-ranking (list 3 int)))
            (if (set-var! ranking new-ranking)
                new-ranking
                (get-ranking)))
    "#;

    let mut contract_src = contract_src.to_string();
    contract_src.push_str("(list (get-ranking) (set-ranking (list 2 3 1)) (get-ranking))");
    let expected = Value::list_from(vec![
        Value::list_from(vec![Value::Int(1), Value::Int(2), Value::Int(3)]).unwrap(),
        Value::list_from(vec![Value::Int(2), Value::Int(3), Value::Int(1)]).unwrap(),
        Value::list_from(vec![Value::Int(2), Value::Int(3), Value::Int(1)]).unwrap()
    ]);    
    assert_executes(expected, &contract_src);
}

#[test]
fn test_set_buffer_variable() {
    let contract_src = r#"
        (define-data-var name (buff 5) "alice")
        (define (get-name)
            (fetch-var name))
        (define (set-name (new-name (buff 5)))
            (if (set-var! name new-name)
                new-name
                (get-name)))
    "#;

    let mut contract_src = contract_src.to_string();
    contract_src.push_str("(list (get-name) (set-name \"celia\") (get-name))");
    let expected = Value::list_from(vec![
        Value::buff_from("alice".to_string().into_bytes()).unwrap(),
        Value::buff_from("celia".to_string().into_bytes()).unwrap(),
        Value::buff_from("celia".to_string().into_bytes()).unwrap(),
    ]);    
    assert_executes(expected, &contract_src);
}

#[test]
fn test_factorial_contract() {
    let test1 =
        "(define-map factorials ((id int)) ((current int) (index int)))
         (define (init-factorial (id int) (factorial int))
           (insert-entry! factorials (tuple (id id)) (tuple (current 1) (index factorial))))
         (define (compute (id int))
           (let ((entry (expects! (fetch-entry factorials (tuple (id id))) 0)))
                    (let ((current (get current entry))
                          (index   (get index entry)))
                         (if (<= index 1)
                             current
                             (begin
                               (set-entry! factorials (tuple (id id))
                                                      (tuple (current (* current index))
                                                             (index (- index 1))))
                               0)))))
        (init-factorial 1337 3)
        (init-factorial 8008 5)
        (list (compute 1337)
              (compute 1337)
              (compute 1337)
              (compute 1337)
              (compute 1337)
              (compute 8008)
              (compute 8008)
              (compute 8008)
              (compute 8008)
              (compute 8008)
              (compute 8008))
        ";

    let expected = Value::list_from(vec![
        Value::Int(0),
        Value::Int(0),
        Value::Int(6),
        Value::Int(6),
        Value::Int(6),
        Value::Int(0),
        Value::Int(0),
        Value::Int(0),
        Value::Int(0),
        Value::Int(120),
        Value::Int(120),
    ]);
        
    assert_executes(expected, test1);
}

#[test]
fn silly_naming_system() {
    let test1 =
        "(define-map silly-names ((name int)) ((owner int)))
         (define (register (name int) (owner int))
           (if (insert-entry! silly-names (tuple (name name)) (tuple (owner owner)))
               1 0))
         (define (who-owns? (name int))
           (let ((owner (get owner (fetch-entry silly-names (tuple (name name))))))
             (default-to (- 1) owner)))
         (define (invalidate! (name int) (owner int))
           (let ((current-owner (who-owns? name)))
                (if (eq? current-owner owner)
                    (if (delete-entry! silly-names (tuple (name name))) 1 0)
                    0)))
        (list (register 0 0)
              (register 0 1)
              (register 1 1)
              (register 1 0)
              (who-owns? 0)
              (who-owns? 1)
              (invalidate! 0 1)
              (invalidate! 1 1)
              (who-owns? 0)
              (who-owns? 1))
        ";

    let expected = Value::list_from(vec![
        Value::Int(1),
        Value::Int(0),
        Value::Int(1),
        Value::Int(0),
        Value::Int(0),
        Value::Int(1),
        Value::Int(0),
        Value::Int(1),
        Value::Int(0),
        Value::Int(-1),
    ]);

    assert_executes(expected, test1);
}

#[test]
fn datamap_errors() {
    let tests = [
        "(fetch-entry non-existent (tuple (name 1)))",
        "(delete-entry! non-existent (tuple (name 1)))",
    ];

    for program in tests.iter() {
        assert_eq!( Error::Unchecked(UncheckedError::UndefinedMap("non-existent".to_string())),
                    execute(program).unwrap_err() );
    }
}

#[test]
fn lists_system_2() {
    let test = 
        "(define-map lists ((name int)) ((contents (list 5 1 int))))
         (define (add-list (name int) (content (list 5 1 int)))
           (insert-entry! lists (tuple (name name))
                                (tuple (contents content))))
         (define (get-list (name int))
            (get contents (fetch-entry lists (tuple (name name)))))
         (add-list 0 (list 1 2 3 4 5))
         (add-list 1 (list 1 2 3))
         (list      (get-list 0)
                    (get-list 1))
        (insert-entry! lists (tuple (name 1)) (tuple (contentious (list 1 2 6))))";

    match execute(test) {
        Err(Error::Unchecked(UncheckedError::TypeError(_,_))) => true,
        _ => false
    };
}

#[test]
fn lists_system() {
    let test1 =
        "(define-map lists ((name int)) ((contents (list 5 1 int))))
         (define (add-list (name int) (content (list 5 1 int)))
           (insert-entry! lists (tuple (name name))
                                (tuple (contents content))))
         (define (get-list (name int))
            (default-to (list) (get contents (fetch-entry lists (tuple (name name))))))
         (print (add-list 0 (list 1 2 3 4 5)))
         (print (add-list 1 (list 1 2 3)))
         (list      (get-list 0)
                    (get-list 1))
        ";

    let mut test_list_too_big = test1.to_string();
    test_list_too_big.push_str("(add-list 2 (list 1 2 3 4 5 6))");

    let mut test_bad_tuple_1 = test1.to_string();
    test_bad_tuple_1.push_str("(print (insert-entry! lists (tuple (name 1)) (print (tuple (contentious (list 1 2 6))))))");

    let mut test_bad_tuple_2 = test1.to_string();
    test_bad_tuple_2.push_str("(insert-entry! lists (tuple (name 1)) (tuple (contents (list 1 2 6)) (discontents 1)))");

    let mut test_bad_tuple_3 = test1.to_string();
    test_bad_tuple_3.push_str("(insert-entry! lists (tuple (name 1)) (tuple (contents (list 'false 'true 'false))))");

    let mut test_bad_tuple_4 = test1.to_string();
    test_bad_tuple_4.push_str("(insert-entry! lists (tuple (name (list 1))) (tuple (contents (list 1 2 3))))");

    let expected = || {
        let list1 = Value::list_from(vec![
            Value::Int(1),
            Value::Int(2),
            Value::Int(3),
            Value::Int(4),
            Value::Int(5)])?;
        let list2 = Value::list_from(vec![
            Value::Int(1),
            Value::Int(2),
            Value::Int(3)])?;
        Value::list_from(vec![list1, list2])
    };
    
    assert_executes(expected(), test1);

    for test in [test_list_too_big, test_bad_tuple_1, test_bad_tuple_2,
                 test_bad_tuple_3, test_bad_tuple_4].iter() {
    
        let expected_type_error = match execute(test) {
            Err(Error::Unchecked(UncheckedError::TypeError(_,_))) => true,
            _ => false
        };

        assert!(expected_type_error);
    }

}

#[test]
fn tuples_system() {
    let test1 =
        "(define-map tuples ((name int)) 
                            ((contents (tuple ((name (buff 5))
                                               (owner (buff 5)))))))

         (define (add-tuple (name int) (content (buff 5)))
           (insert-entry! tuples (tuple (name name))
                                 (tuple (contents
                                   (tuple (name content)
                                          (owner content))))))
         (define (get-tuple (name int))
            (default-to \"\" (get name (get contents (fetch-entry tuples (tuple (name name)))))))


         (add-tuple 0 \"abcde\")
         (add-tuple 1 \"abcd\")
         (list      (get-tuple 0)
                    (get-tuple 1))
        ";

    let mut test_list_too_big = test1.to_string();
    test_list_too_big.push_str("(add-tuple 2 \"abcdef\")");

    let mut test_bad_tuple_1 = test1.to_string();
    test_bad_tuple_1.push_str("(insert-entry! tuples (tuple (name 1)) (tuple (contents (tuple (name \"abcde\") (owner \"abcdef\")))))");

    let mut test_bad_tuple_2 = test1.to_string();
    test_bad_tuple_2.push_str("(fetch-entry tuples (tuple (names 1)))");

    let mut test_bad_tuple_3 = test1.to_string();
    test_bad_tuple_3.push_str("(set-entry! tuples (tuple (names 1)) (tuple (contents (tuple (name \"abcde\") (owner \"abcde\")))))");

    let mut test_bad_tuple_4 = test1.to_string();
    test_bad_tuple_4.push_str("(set-entry! tuples (tuple (name 1)) (tuple (contents 1)))");

    let mut test_bad_tuple_5 = test1.to_string();
    test_bad_tuple_5.push_str("(delete-entry! tuples (tuple (names 1)))");

    let expected = || {
        let buff1 = Value::buff_from("abcde".to_string().into_bytes())?;
        let buff2 = Value::buff_from("abcd".to_string().into_bytes())?;
        Value::list_from(vec![buff1, buff2])
    };

    assert_executes(expected(), test1);

    let type_error_tests = [test_list_too_big, test_bad_tuple_1, test_bad_tuple_2, test_bad_tuple_3,
                            test_bad_tuple_4, test_bad_tuple_5];

    for test in type_error_tests.iter() {
        let expected_type_error = match execute(test) {
            Err(Error::Unchecked(UncheckedError::TypeError(_,_))) => true,
            _ => {
                println!("{:?}", execute(test));
                false
            }
        };

        assert!(expected_type_error);
    }

}

#[test]
fn bad_define_maps() {
    let test_list_pairs = [
        "(define-map lists ((name int)) ((contents int bool)))",
        "(define-map lists ((name int)) (contents bool))",
        "(define-map lists ((name int)) (contents bool))",
        "(define-map lists ((name int)) contents)"];
    let test_define_args = [
        "(define-map (lists) ((name int)) contents)",
        "(define-map lists ((name int)) contents 5)"];

    let test_bad_type = [
        "(define-map lists ((name int)) ((contents (list 5 0 int))))"];
    
    for test in test_list_pairs.iter() {
        println!("Test: {:?}", test);
        assert_eq!(Error::Unchecked(UncheckedError::ExpectedListPairs), execute(test).unwrap_err());
    }

    for test in test_define_args.iter() {
        assert!(match execute(test) {
            Err(Error::Unchecked(UncheckedError::InvalidArguments(_))) => true,
            _ => false
        })
    }

    for test in test_bad_type.iter() {
        assert!(match execute(test).unwrap_err() {
            Error::Runtime(RuntimeErrorType::InvalidTypeDescription, _) => true,
            _ => false
        })
    }
}

#[test]
fn bad_tuples() {
    let tests = ["(tuple (name 1) (name 3))",
                 "(tuple name 1)",
                 "(tuple (name 1) (blame))",
                 "(get value (tuple (name 1)))",
                 "(get name five (tuple (name 1)))",
                 "(get 1234 (tuple (name 1)))"];

    for test in tests.iter() {
        let outcome = execute(test);
        match outcome {
            Err(Error::Unchecked(UncheckedError::InvalidArguments(_))) => continue,
            _ => {
                println!("Expected InvalidArguments Error, but found {:?}", outcome);
                assert!(false)
            }
        }
    }
}
