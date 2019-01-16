extern crate blockstack_vm;

use blockstack_vm::types::ValueType;

use blockstack_vm::parser::parse;
use blockstack_vm::eval_all;

#[test]
fn test_defines() {
    let tests = parse(&
        "(define x 10)
         (define y 15)
         (define (f a b) (+ x y a b))
         (f 3 1)");

    if let Ok(to_eval) = tests {
        assert_eq!(Ok(ValueType::IntType(29)), eval_all(&to_eval));
    } else {
        assert!(false, "Failed to parse function bodies.");
    }
}

#[test]
#[should_panic]
fn test_recursive_panic() {
    let tests = parse(&
        "(define (factorial a)
          (if (eq? a 0)
              1
              (* a (factorial (- a 1)))))
         (factorial 10)");

    if let Ok(to_eval) = tests {
        assert_eq!(Ok(ValueType::IntType(29)), eval_all(&to_eval));
    } else {
        assert!(false, "Failed to parse function bodies.");
    }
}

#[test]
#[should_panic]
fn test_define_parse_panic() {
    let tests = parse(&
        "(define () 1)");

    if let Ok(to_eval) = tests {
        assert_eq!(Ok(ValueType::IntType(29)), eval_all(&to_eval));
    } else {
        assert!(false, "Failed to parse function bodies.");
    }
}

#[test]
#[should_panic]
fn test_define_parse_panic_2() {
    let tests = parse(&
        "(define (a b (d)) 1)");

    if let Ok(to_eval) = tests {
        assert_eq!(Ok(ValueType::IntType(29)), eval_all(&to_eval));
    } else {
        assert!(false, "Failed to parse function bodies.");
    }
}

