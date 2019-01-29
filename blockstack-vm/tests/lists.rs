extern crate blockstack_vm;

use blockstack_vm::types::{Value, TypeSignature, AtomTypeIdentifier};

use blockstack_vm::execute;
use blockstack_vm::errors::Error;

#[test]
fn test_simple_map() {
    let test1 =
        "(define (square x) (* x x))
         (map square (list 1 2 3 4))";

    let expected = Value::List(
        vec![
            Value::Int(1),
            Value::Int(4),
            Value::Int(9),
            Value::Int(16)],
        TypeSignature::new(AtomTypeIdentifier::IntType, 1));

    assert_eq!(Ok(expected.clone()), execute(test1));

    // let's test lists of lists.
    let test2 = "(define (multiply x acc) (* x acc))
                 (define (multiply-all x) (fold multiply x 1))
                 (map multiply-all (list (list 1 1 1) (list 2 2 1) (list 3 3) (list 2 2 2 2)))";
    assert_eq!(Ok(expected), execute(test2));
                                       
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
    assert_eq!(Err(Error::InvalidArguments("List must be composed of a single type".to_string())),
               execute(test1));

    let test2 = "(define (bad-function x) (if (eq? x 1) 'true x))
                 (map bad-function (list 0 1 2 3))";
    assert_eq!(Err(Error::InvalidArguments("Results of map must all be of a single type".to_string())),
               execute(test2));
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
