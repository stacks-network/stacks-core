use vm::types::{Value};

use vm::execute;
use vm::errors::Error;

#[test]
fn test_simple_map() {
    let test1 =
        "(define (square x) (* x x))
         (map square (list 1 2 3 4))";

    let expected = Value::new_list(vec![
        Value::Int(1),
        Value::Int(4),
        Value::Int(9),
        Value::Int(16)]);

    assert_eq!(expected, execute(test1));

    // let's test lists of lists.
    let test2 = "(define (multiply x acc) (* x acc))
                 (define (multiply-all x) (fold multiply x 1))
                 (map multiply-all (list (list 1 1 1) (list 2 2 1) (list 3 3) (list 2 2 2 2)))";
    assert_eq!(expected, execute(test2));

    // let's test empty lists.
    let test2 = "(define (double x) (* x 2))
                 (map double (list))";
    assert_eq!(Value::new_list(vec![]), execute(test2));

}

#[test]
fn test_simple_folds() {
    let test1 =
        "(define (multiply-all x acc) (* x acc))
         (fold multiply-all (list 1 2 3 4) 1)";

    let expected = Value::Int(24);

    assert_eq!(Ok(expected), execute(test1));
}

#[test]
fn test_construct_bad_list() {
    let test1 = "(list 1 2 3 'true)";
    assert!(
        match execute(test1) {
            Err(Error::InvalidArguments(_)) => true,
            _ => false
        });

    let test2 = "(define (bad-function x) (if (eq? x 1) 'true x))
                 (map bad-function (list 0 1 2 3))";
    assert!(
        match execute(test2) {
            Err(Error::InvalidArguments(_)) => true,
            _ => false
        });

    let bad_2d_list = "(list (list 1 2 3) (list 'true 'false 'true))";
    let bad_high_order_list = "(list (list 1 2 3) (list (list 1 2 3)))";

    let expected_err_1 = match execute(bad_2d_list) {
        Err(Error::InvalidArguments(_)) => true,
        _ => false
    };

    assert!(expected_err_1);

    let expected_err_2 = match execute(bad_high_order_list) {
        Err(Error::InvalidArguments(_)) => true,
        _ => false
    };

   assert!(expected_err_2);
}

#[test]
fn test_eval_func_arg_panic() {
    let test1 = "(fold (lambda (x y) (* x y)) (list 1 2 3 4) 1)";
    assert_eq!(Err(Error::InvalidArguments("Fold must be called with a function name. We do not support eval'ing to functions.".to_string())),
               execute(test1));

    let test2 = "(map (lambda (x) (* x x)) (list 1 2 3 4))";
    assert_eq!(Err(Error::InvalidArguments("Map must be called with a function name. We do not support eval'ing to functions.".to_string())),
               execute(test2));

    let test3 = "(map square (list 1 2 3 4) 2)";
    assert_eq!(Err(Error::InvalidArguments("Wrong number of arguments (3) to map".to_string())),
               execute(test3));

    let test4 = "(define (multiply-all x acc) (* x acc))
         (fold multiply-all (list 1 2 3 4))";
    assert_eq!(Err(Error::InvalidArguments("Wrong number of arguments (2) to fold".to_string())),
               execute(test4));
}
