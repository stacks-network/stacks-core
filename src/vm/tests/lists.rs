use vm::types::{Value, TypeSignature};

use vm::execute;
use vm::errors::{ErrType};

#[test]
fn test_simple_map() {
    let test1 =
        "(define (square (x int)) (* x x))
         (map square (list 1 2 3 4))";

    let expected = Value::list_from(vec![
        Value::Int(1),
        Value::Int(4),
        Value::Int(9),
        Value::Int(16)]).unwrap();

    assert_eq!(expected, execute(test1).unwrap().unwrap());

    // let's test lists of lists.
    let test2 = "(define (multiply (x int) (acc int)) (* x acc))
                 (define (multiply-all (x (list 10 int))) (fold multiply x 1))
                 (map multiply-all (list (list 1 1 1) (list 2 2 1) (list 3 3) (list 2 2 2 2)))";
    assert_eq!(expected, execute(test2).unwrap().unwrap());

    // let's test empty lists.
    let test2 = "(define (double (x int)) (* x 2))
                 (map double (list))";
    assert_eq!(Value::list_from(vec![]).unwrap(), execute(test2).unwrap().unwrap());

}

#[test]
fn test_list_tuple_admission() {
    let test = 
        "(define (bufferize (x int)) (if (eq? x 1) \"abc\" \"ab\"))
         (define (tuplize (x int))
           (tuple (value (bufferize x))))
         (map tuplize (list 0 1 0 1 0 1))";

    let expected_type = 
        "(list (tuple (value \"012\"))
               (tuple (value \"012\"))
               (tuple (value \"012\"))
               (tuple (value \"012\"))
               (tuple (value \"012\"))
               (tuple (value \"012\")))";

    let not_expected_type = 
        "(list (tuple (value \"01\"))
               (tuple (value \"02\"))
               (tuple (value \"12\"))
               (tuple (value \"12\"))
               (tuple (value \"01\"))
               (tuple (value \"02\")))";

    
    let result_type = TypeSignature::type_of(&execute(test).unwrap().unwrap());
    let expected_type = TypeSignature::type_of(&execute(expected_type).unwrap().unwrap());
    let testing_value = &execute(not_expected_type).unwrap().unwrap();
    let not_expected_type = TypeSignature::type_of(testing_value);

    assert_eq!(expected_type, result_type);
    assert!(not_expected_type != result_type);
    assert!(result_type.admits(&testing_value));
}

#[test]
fn test_simple_folds() {
    let test1 =
        "(define (multiply-all (x int) (acc int)) (* x acc))
         (fold multiply-all (list 1 2 3 4) 1)";

    let expected = Value::Int(24);

    assert_eq!(expected, execute(test1).unwrap().unwrap());
}

#[test]
fn test_construct_bad_list() {
    let test1 = "(list 1 2 3 'true)";
    assert!(
        match execute(test1).unwrap_err().err_type {
            ErrType::BadTypeConstruction => true,
            _ => false
        });

    let test2 = "(define (bad-function (x int)) (if (eq? x 1) 'true x))
                 (map bad-function (list 0 1 2 3))";
    assert!(
        match execute(test2).unwrap_err().err_type {
            ErrType::BadTypeConstruction => true,
            _ => false
        });

    let bad_2d_list = "(list (list 1 2 3) (list 'true 'false 'true))";
    let bad_high_order_list = "(list (list 1 2 3) (list (list 1 2 3)))";

    let expected_err_1 = match execute(bad_2d_list).unwrap_err().err_type {
        ErrType::BadTypeConstruction => true,
        _ => false
    };

    assert!(expected_err_1);

    let expected_err_2 = match execute(bad_high_order_list).unwrap_err().err_type {
        ErrType::BadTypeConstruction => true,
        _ => false
    };

   assert!(expected_err_2);
}

#[test]
fn test_eval_func_arg_panic() {
    let test1 = "(fold (lambda (x y) (* x y)) (list 1 2 3 4) 1)";
    assert_eq!(ErrType::InvalidArguments("Fold must be called with a function name. We do not support eval'ing to functions.".to_string()),
               execute(test1).unwrap_err().err_type);

    let test2 = "(map (lambda (x) (* x x)) (list 1 2 3 4))";
    assert_eq!(ErrType::InvalidArguments("Map must be called with a function name. We do not support eval'ing to functions.".to_string()),
               execute(test2).unwrap_err().err_type);

    let test3 = "(map square (list 1 2 3 4) 2)";
    assert_eq!(ErrType::InvalidArguments("Wrong number of arguments (3) to map".to_string()),
               execute(test3).unwrap_err().err_type);

    let test4 = "(define (multiply-all (x int) (acc int)) (* x acc))
         (fold multiply-all (list 1 2 3 4))";
    assert_eq!(ErrType::InvalidArguments("Wrong number of arguments (2) to fold".to_string()),
               execute(test4).unwrap_err().err_type);
}
