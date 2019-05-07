use vm::execute;
use vm::errors::{ErrType};
use vm::types::Value;


#[test]
fn test_defines() {
    let tests =
        "(define x 10)
         (define y 15)
         (define (f (a int) (b int)) (+ x y a b))
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

    assert_eq!(ErrType::ReservedName("tx-sender".to_string()), execute(&test0).unwrap_err().err_type);
    assert_eq!(ErrType::ReservedName("*".to_string()), execute(&test1).unwrap_err().err_type);
    assert_eq!(ErrType::InvalidArguments("Illegal operation: attempted to re-define a value type.".to_string()),
               execute(&test2).unwrap_err().err_type);
    assert_eq!(ErrType::VariableDefinedMultipleTimes("foo".to_string()),
               execute(&test3).unwrap_err().err_type);
}

#[test]
fn test_stack_depth() {
    let mut function_defines = Vec::new();
    function_defines.push("(define (foo-0 (x int)) (+ 1 x))".to_string());
    for i in 1..257 {
        function_defines.push(
            format!("(define (foo-{} (x int)) (foo-{} (+ 1 x)))",
                    i, i-1));
    }
    function_defines.push(
        format!("(foo-254 1)"));

    let test0 = function_defines.join("\n");
    function_defines.push(
        format!("(foo-255 2)"));
    let test1 = function_defines.join("\n");

    assert_eq!(Ok(Value::Int(256)), execute(&test0));
    assert_eq!(ErrType::MaxStackDepthReached, execute(&test1).unwrap_err().err_type);
}

#[test]
fn test_recursive_panic() {
    let tests =
        "(define (factorial (a int))
          (if (eq? a 0)
              1
              (* a (factorial (- a 1)))))
         (factorial 10)";

    assert_eq!(ErrType::RecursionDetected, execute(&tests).unwrap_err().err_type);
}

#[test]
fn test_bad_variables() {
    let test0 = "(+ a 1)";
    let expected = ErrType::UndefinedVariable("a".to_string());
    assert_eq!(expected, execute(&test0).unwrap_err().err_type);


    let test1 = "(foo 2 1)";
    let expected = ErrType::UndefinedFunction("foo".to_string());
    assert_eq!(expected, execute(&test1).unwrap_err().err_type);


    let test2 = "((lambda (x y) 1) 2 1)";
    let expected = ErrType::TryEvalToFunction;
    assert_eq!(expected, execute(&test2).unwrap_err().err_type);

    let test4 = "()";
    let expected = Ok(Value::Void);
    assert_eq!(expected, execute(&test4));
}

#[test]
fn test_define_parse_panic() {
    let tests = "(define () 1)";
    let expected = ErrType::InvalidArguments("Must supply atleast a name argument to define a function".to_string());
    assert_eq!(expected, execute(&tests).unwrap_err().err_type);
}

#[test]
fn test_define_parse_panic_2() {
    let tests = "(define (a b (d)) 1)";
    assert_eq!(
        ErrType::ExpectedListPairs,
        execute(&tests).unwrap_err().err_type);
}

