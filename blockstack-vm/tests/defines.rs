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

    let tests =
        "1";

    assert_eq!(Ok(Value::Int(1)), execute(&tests));
}

#[test]
fn test_bad_define_names() {
    let test0 =
        "(define tx-sender 1)
         (+ tx-sender tx-sender)";
    let test1 =
        "(define * 1)
         (+ * *)";
    let test2 =
        "(define 1 1)
         (+ 1 1)";
    let test3 =
        "(define foo 1)
         (define foo 2)
         (+ foo foo)";

    assert_eq!(Err(Error::ReservedName("tx-sender".to_string())), execute(&test0));
    assert_eq!(Err(Error::ReservedName("*".to_string())), execute(&test1));
    assert_eq!(Err(Error::InvalidArguments("Illegal operation: attempted to re-define a value type.".to_string())),
               execute(&test2));
    assert_eq!(Err(Error::MultiplyDefined("foo".to_string())),
               execute(&test3));
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

