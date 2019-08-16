use vm::execute;
use vm::errors::{UncheckedError, RuntimeErrorType, Error};
use vm::types::Value;

fn assert_eq_err(e1: UncheckedError, e2: Error) {
    let e1: Error = e1.into();
    assert_eq!(e1, e2)
}

#[test]
fn test_defines() {
    let tests =
        "(define-constant x 10)
         (define-constant y 15)
         (define-private (f (a int) (b int)) (+ x y a b))
         (f 3 1)";

    assert_eq!(Ok(Some(Value::Int(29))), execute(&tests));

    let tests =
        "1";

    assert_eq!(Ok(Some(Value::Int(1))), execute(&tests));
}

#[test]
fn test_accept_options() {
    let defun =
        "(define-private (f (b (optional int))) (* 10 (default-to 0 b)))";
    let tests = [
        format!("{} {}", defun, "(f none)"),
        format!("{} {}", defun, "(f (some 1))"),
        format!("{} {}", defun, "(f (some 'true))") ];
    let expectations: &[Result<_, Error>] = &[
        Ok(Some(Value::Int(0))),
        Ok(Some(Value::Int(10))),
        Err(UncheckedError::TypeError("(optional int)".to_string(), Value::some(Value::Bool(true))).into()),
    ];
    
    for (test, expect) in tests.iter().zip(expectations.iter()) {
        assert_eq!(*expect, execute(test));
    }

    let bad_defun =
        "(define-private (f (b (optional int int))) (* 10 (default-to 0 b)))";
    assert_eq!(Error::Runtime(RuntimeErrorType::InvalidTypeDescription, None),
               execute(bad_defun).unwrap_err());
}

#[test]
fn test_bad_define_names() {
    let test0 =
        "(define-constant tx-sender 1)
         (+ tx-sender tx-sender)";
    let test1 =
        "(define-constant * 1)
         (+ * *)";
    let test2 =
        "(define-constant 1 1)
         (+ 1 1)";
    let test3 =
        "(define-constant foo 1)
         (define-constant foo 2)
         (+ foo foo)";

    assert_eq_err(UncheckedError::ReservedName("tx-sender".to_string()), execute(&test0).unwrap_err());
    assert_eq_err(UncheckedError::ReservedName("*".to_string()), execute(&test1).unwrap_err());
    assert_eq_err(UncheckedError::InvalidArguments("Illegal operation: expects a variable name as the first argument.".to_string()),
                   execute(&test2).unwrap_err());
    assert_eq_err(UncheckedError::VariableDefinedMultipleTimes("foo".to_string()),
                   execute(&test3).unwrap_err());
}

#[test]
fn test_expects() {
    let test0 =
        "(define-private (foo) (expects! (ok 1) 2)) (foo)";
    let test1 =
        "(define-private (foo) (expects! (ok 1))) (foo)";
    let test2 =
        "(define-private (foo) (expects! 1 2)) (foo)";
    let test3 =
        "(define-private (foo) (expects-err! 1 2)) (foo)";
    let test4 =
        "(define-private (foo) (expects-err! (err 1) 2)) (foo)";
    let test5 =
        "(define-private (foo) (expects-err! (err 1))) (foo)";

    assert_eq!(Ok(Some(Value::Int(1))), execute(&test0));
    assert_eq_err(UncheckedError::IncorrectArgumentCount(2,1),
                  execute(&test1).unwrap_err());
    assert_eq_err(UncheckedError::TypeError("OptionalType|ResponseType".to_string(), Value::Int(1)),
                  execute(&test2).unwrap_err());
    assert_eq_err(UncheckedError::TypeError("ResponseType".to_string(), Value::Int(1)),
                  execute(&test3).unwrap_err());
    assert_eq!(Ok(Some(Value::Int(1))), execute(&test4));
    assert_eq_err(UncheckedError::IncorrectArgumentCount(2, 1),
                  execute(&test5).unwrap_err());
}

#[test]
fn test_define_read_only() {
    let test0 =
        "(define-read-only (silly) 1) (silly)";
    let test1 =
        "(define-read-only (silly) (map-delete! map-name (tuple (value 1))))  (silly)";
    let test2 =
        "(define-read-only (silly) (map-insert! map-name (tuple (value 1)) (tuple (value 1)))) (silly)";
    let test3 =
        "(define-read-only (silly) (map-set! map-name (tuple (value 1)) (tuple (value 1)))) (silly)";

    assert_eq!(Ok(Some(Value::Int(1))), execute(&test0));
    assert_eq_err(UncheckedError::WriteFromReadOnlyContext, execute(&test1).unwrap_err());
    assert_eq_err(UncheckedError::WriteFromReadOnlyContext, execute(&test2).unwrap_err());
    assert_eq_err(UncheckedError::WriteFromReadOnlyContext, execute(&test3).unwrap_err());
}

#[test]
fn test_stack_depth() {
    let mut function_defines = Vec::new();
    function_defines.push("(define-private (foo-0 (x int)) (+ 1 x))".to_string());
    for i in 1..129 {
        function_defines.push(
            format!("(define-private (foo-{} (x int)) (foo-{} (+ 1 x)))",
                    i, i-1));
    }
    function_defines.push(
        format!("(foo-126 1)"));

    let test0 = function_defines.join("\n");
    function_defines.push(
        format!("(foo-127 2)"));
    let test1 = function_defines.join("\n");

    assert_eq!(Ok(Some(Value::Int(128))), execute(&test0));
    assert!(match execute(&test1).unwrap_err() {
        Error::Runtime(RuntimeErrorType::MaxStackDepthReached, _) => true,
        _ => false
    })
}

#[test]
fn test_recursive_panic() {
    let tests =
        "(define-private (factorial (a int))
          (if (eq? a 0)
              1
              (* a (factorial (- a 1)))))
         (factorial 10)";

    assert_eq_err(UncheckedError::RecursionDetected, execute(&tests).unwrap_err());
}

#[test]
fn test_bad_variables() {
    let test0 = "(+ a 1)";
    let expected = UncheckedError::UndefinedVariable("a".to_string());
    assert_eq_err(expected, execute(&test0).unwrap_err());


    let test1 = "(foo 2 1)";
    let expected = UncheckedError::UndefinedFunction("foo".to_string());
    assert_eq_err(expected, execute(&test1).unwrap_err());


    let test2 = "((lambda (x y) 1) 2 1)";
    let expected = UncheckedError::TryEvalToFunction;
    assert_eq_err(expected, execute(&test2).unwrap_err());

    let test4 = "()";
    let expected = UncheckedError::InvalidArguments(
        "List expressions (...) are function applications, and must be supplied with function names to apply.".to_string());
    assert_eq_err(expected, execute(&test4).unwrap_err());
}

#[test]
fn test_variable_shadowing() {
    let test0 =
        "(let ((cursor 1) (cursor 2)) cursor)";
    let test1 =
        r#"
        (let ((cursor 1))
            (let ((cursor 2))
                cursor))
        "#;
    let test2 =
        r#"
        (define-private (cursor) 0)
        (let ((cursor 1))
            cursor)
        "#;
    let test3 =
        r#"
        (define-private (cursor) 0)
        (define-private (set-cursor (cursor int))
            cursor)
        "#;

    assert_eq_err(UncheckedError::VariableDefinedMultipleTimes("cursor".to_string()), execute(&test0).unwrap_err());
    assert_eq_err(UncheckedError::VariableDefinedMultipleTimes("cursor".to_string()), execute(&test1).unwrap_err());
    assert_eq_err(UncheckedError::VariableDefinedMultipleTimes("cursor".to_string()), execute(&test2).unwrap_err());
    assert_eq_err(UncheckedError::VariableDefinedMultipleTimes("cursor".to_string()), execute(&test3).unwrap_err());
}

#[test]
fn test_define_parse_panic() {
    let tests = "(define-private () 1)";
    let expected = UncheckedError::InvalidArguments("Must supply atleast a name argument to define a function".to_string());
    assert_eq_err(expected, execute(&tests).unwrap_err());
}

#[test]
fn test_define_parse_panic_2() {
    let tests = "(define-private (a b (d)) 1)";
    assert_eq_err(
        UncheckedError::ExpectedListPairs,
        execute(&tests).unwrap_err());
}

