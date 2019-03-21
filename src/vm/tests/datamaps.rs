use vm::errors::{Error, ErrType};
use vm::types::{Value};

use vm::execute;

#[test]
fn test_simple_tea_shop() {
    let test1 =
        "(define-map proper-tea ((tea-type int)) ((amount int)))
         (define (stock tea amount)
           (set-entry! proper-tea (tuple (tea-type tea)) (tuple (amount amount))))
         (define (consume tea)
           (let ((current (get amount (fetch-entry proper-tea (tuple (tea-type tea))))))
              (if (and (not (eq? current 'null)) 
                       (>= current 1))
                  (begin
                    (set-entry! proper-tea (tuple (tea-type tea))
                                           (tuple (amount (- current 1))))
                    'true)
                  'false)))
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
        Value::Bool(true),
        Value::Bool(true),
        Value::Bool(true),
        Value::Bool(true),
        Value::Bool(true),
        Value::Bool(true),
        Value::Bool(false),
        Value::Bool(true),
        Value::Bool(true),
        Value::Bool(false),
        Value::Bool(false),
        Value::Bool(false)],
    );

    assert_eq!(expected, execute(test1));
}

#[test]
fn test_factorial_contract() {
    let test1 =
        "(define-map factorials ((id int)) ((current int) (index int)))
         (define (init-factorial id factorial)
           (insert-entry! factorials (tuple (id id)) (tuple (current 1) (index factorial))))
         (define (compute id)
           (let ((entry (fetch-entry factorials (tuple (id id)))))
                (if (eq? entry 'null)
                    0
                    (let ((current (get current entry))
                          (index   (get index entry)))
                         (if (<= index 1)
                             current
                             (begin
                               (set-entry! factorials (tuple (id id))
                                                      (tuple (current (* current index))
                                                             (index (- index 1))))
                               0))))))
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
        
    assert_eq!(expected, execute(test1));
}

#[test]
fn silly_naming_system() {
    let test1 =
        "(define-map silly-names ((name int)) ((owner int)))
         (define (register name owner)
           (if (insert-entry! silly-names (tuple (name name)) (tuple (owner owner)))
               1 0))
         (define (who-owns? name)
           (let ((owner (get owner (fetch-entry silly-names (tuple (name name))))))
                (if (eq? 'null owner) (- 1) owner)))
         (define (invalidate! name owner)
           (let ((current-owner (get owner (fetch-entry silly-names (tuple (name name))))))
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
    assert_eq!(expected, execute(test1));
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
         (define (add-list name content)
           (insert-entry! lists (tuple (name name))
                                (tuple (contents content))))
         (define (get-list name)
            (get contents (fetch-entry lists (tuple (name name)))))
         (add-list 0 (list 1 2 3 4 5))
         (add-list 1 (list 1 2 3))
         (list      (get-list 0)
                    (get-list 1))
        (insert-entry! lists (tuple (name 1)) (tuple (contentious (list 1 2 6))))";

    let expected_type_error = match execute(test) {
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
         (define (add-list name content)
           (insert-entry! lists (tuple (name name))
                                (tuple (contents content))))
         (define (get-list name)
            (get contents (fetch-entry lists (tuple (name name)))))
         (print 10)
         (print (add-list 0 (list 1 2 3 4 5)))
         (print 20)
         (print (add-list 1 (list 1 2 3)))
         (print 30)
         (list      (get-list 0)
                    (get-list 1))
         (print 40)
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
    
//    assert_eq!(expected(), execute(test1));

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

         (define (add-tuple name content)
           (insert-entry! tuples (tuple (name name))
                                 (tuple (contents
                                   (tuple (name content)
                                          (owner content))))))
         (define (get-tuple name)
            (get name (get contents (fetch-entry tuples (tuple (name name))))))


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

    assert_eq!(expected(), execute(test1));

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
        "(define-map lists ((#name int)) (contents bool))",
        "(define-map lists ((name int)) contents)"];
    let test_define_args = [
        "(define-map (lists) ((name #int)) contents)",
        "(define-map lists ((name #int)) contents 5)"];

    let test_bad_type = [
        "(define-map lists ((name int)) ((contents (list 5 0 int))))",
        "(define-map lists ((name #int)) (contents bool))"];
    
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
                 "(tuple (name 'null))",
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
