extern crate blockstack_vm;

use blockstack_vm::types::ValueType;

use blockstack_vm::parser::parse;
use blockstack_vm::eval_all;
use blockstack_vm::errors::Error;


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
fn test_recursive_panic() {
    let tests = parse(&
        "(define (factorial a)
          (if (eq? a 0)
              1
              (* a (factorial (- a 1)))))
         (factorial 10)");

    if let Ok(to_eval) = tests {
        assert_eq!(Err(Error::RecursionDetected), eval_all(&to_eval));
    } else {
        assert!(false, "Failed to parse function bodies.");
    }
}

#[test]
fn test_define_parse_panic() {
    let tests = parse(&
        "(define () 1)");

    let expected = Err(Error::InvalidArguments("Must supply atleast a name argument to define a function".to_string()));

    if let Ok(to_eval) = tests {
        assert_eq!(expected, eval_all(&to_eval));
    } else {
        assert!(false, "Failed to parse function bodies.");
    }
}

#[test]
fn test_define_parse_panic_2() {
    let tests = parse(&
        "(define (a b (d)) 1)");

    if let Ok(to_eval) = tests {
        assert_eq!(
            Err(Error::InvalidArguments("Non-atomic argument to method signature in define".to_string())),
            eval_all(&to_eval));
    } else {
        assert!(false, "Failed to parse function bodies.");
    }
}

