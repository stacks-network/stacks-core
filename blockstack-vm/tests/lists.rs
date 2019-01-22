extern crate blockstack_vm;

use blockstack_vm::types::ValueType;

use blockstack_vm::parser::parse;
use blockstack_vm::eval_all;

#[test]
fn test_simple_map() {
    let tests = parse(&
        "(define (square x) (* x x))
         (map square (list 1 2 3 4))");

    let expected = ValueType::ListType(vec![
        ValueType::IntType(1),
        ValueType::IntType(4),
        ValueType::IntType(9),
        ValueType::IntType(16)]);

    if let Ok(to_eval) = tests {
        assert_eq!(Ok(expected), eval_all(&to_eval));
    } else {
        assert!(false, "Failed to parse function bodies.");
    }
}

#[test]
fn test_simple_folds() {
    let tests = parse(&
        "(define (multiply-all x acc) (* x acc))
         (fold multiply-all (list 1 2 3 4) 1)");

    let expected = ValueType::IntType(24);

    if let Ok(to_eval) = tests {
        assert_eq!(Ok(expected), eval_all(&to_eval));
    } else {
        assert!(false, "Failed to parse function bodies.");
    }
}

#[test]
#[should_panic]
fn test_eval_func_arg_panic() {
    let tests = parse(&
        "(fold (lambda (x y) (* x y)) (list 1 2 3 4) 1)");

    if let Ok(to_eval) = tests {
        assert_eq!(Ok(ValueType::IntType(1)), eval_all(&to_eval));
    } else {
        assert!(false, "Failed to parse function bodies.");
    }
}

#[test]
#[should_panic]
fn test_eval_func_arg_map_panic() {
    let tests = parse(&
        "(map (lambda (x) (* x x)) (list 1 2 3 4))");

    if let Ok(to_eval) = tests {
        assert_eq!(Ok(ValueType::IntType(1)), eval_all(&to_eval));
    } else {
        assert!(false, "Failed to parse function bodies.");
    }
}

#[test]
#[should_panic]
fn test_map_arg_panic() {
    let tests = parse(&
        "(map square (list 1 2 3 4) 2)");

    if let Ok(to_eval) = tests {
        assert_eq!(Ok(ValueType::IntType(1)), eval_all(&to_eval));
    } else {
        assert!(false, "Failed to parse function bodies.");
    }
}

#[test]
#[should_panic]
fn test_fold_arg_panic() {
    let tests = parse(&
        "(define (multiply-all x acc) (* x acc))
         (fold multiply-all (list 1 2 3 4))");

    if let Ok(to_eval) = tests {
        assert_eq!(Ok(ValueType::IntType(1)), eval_all(&to_eval));
    } else {
        assert!(false, "Failed to parse function bodies.");
    }
}
