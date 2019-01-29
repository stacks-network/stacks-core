extern crate blockstack_vm;

use blockstack_vm::execute;
use blockstack_vm::errors::Error;
use blockstack_vm::types::Value;


#[test]
fn test_defines() {
    let tests =
        "(define x 10)
         (define y 15)
         (define (f a b) (+ x y a b))
         (f 3 1)";

    assert_eq!(Ok(Value::Int(29)), execute(&tests));
}

#[test]
fn test_recursive_panic() {
    let tests =
        "(define (factorial a)
          (if (eq? a 0)
              1
              (* a (factorial (- a 1)))))
         (factorial 10)";

    assert_eq!(Err(Error::RecursionDetected), execute(&tests));
}

#[test]
fn test_define_parse_panic() {
    let tests = "(define () 1)";

    let expected = Err(Error::InvalidArguments("Must supply atleast a name argument to define a function".to_string()));
    assert_eq!(expected, execute(&tests));
}

#[test]
fn test_define_parse_panic_2() {
    let tests = "(define (a b (d)) 1)";
    assert_eq!(
        Err(Error::InvalidArguments("Non-atomic argument to method signature in define".to_string())),
        execute(&tests));
}

