use vm::errors::{Error, ErrType};
use vm::types::{Value};

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
fn test_bounded_tuple() {
    let test =
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
        assert_eq!( ErrType::UndefinedMap("non-existent".to_string()),
                    execute(program).unwrap_err().err_type );
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
        Err(Error{
            err_type: ErrType::TypeError(_,_),
            stack_trace: _ }) => true,
        _ => {
            false
        }
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
            Err(Error{
                err_type: ErrType::TypeError(_,_),
                stack_trace: _ }) => true,
            _ => {
                println!("{} -> {:?}", test, execute(test));
                false
            }
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

    let expected = || {
        let buff1 = Value::buff_from("abcde".to_string().into_bytes())?;
        let buff2 = Value::buff_from("abcd".to_string().into_bytes())?;
        Value::list_from(vec![buff1, buff2])
    };

    assert_executes(expected(), test1);

    for test in [test_list_too_big, test_bad_tuple_1].iter() {
        let expected_type_error = match execute(test) {
            Err(Error{
                err_type: ErrType::TypeError(_,_),
                stack_trace: _ }) => true,
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
        assert_eq!(ErrType::ExpectedListPairs, execute(test).unwrap_err().err_type);
    }

    for test in test_define_args.iter() {
        assert!(match execute(test) {
            Err(Error{
                err_type: ErrType::InvalidArguments(_),
                stack_trace: _ }) => true,
            _ => false
        })
    }

    for test in test_bad_type.iter() {
        assert_eq!(ErrType::InvalidTypeDescription, execute(test).unwrap_err().err_type);
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
            Err(Error{
                err_type: ErrType::InvalidArguments(_),
                stack_trace: _ }) => continue,
            _ => {
                println!("Expected InvalidArguments Error, but found {:?}", outcome);
                assert!(false)
            }
        }
    }
}
