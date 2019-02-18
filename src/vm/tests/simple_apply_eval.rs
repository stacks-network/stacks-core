use vm::{eval, execute};
use vm::database::MemoryContractDatabase;
use vm::errors::Error;
use vm::{Value, LocalContext, GlobalContext, Environment};
use vm::callables::PrivateFunction;
use vm::representations::SymbolicExpression;
use vm::parser::parse;

#[test]
fn test_simple_user_function() {
    //
    //  test program:
    //  (define (do_work x) (+ 5 x))
    //  (define a 59)
    //  (do_work a)
    //

    let content = [ SymbolicExpression::List(
        Box::new([ SymbolicExpression::Atom("do_work".to_string()),
                   SymbolicExpression::Atom("a".to_string()) ])) ];

    let func_body = SymbolicExpression::List(
        Box::new([ SymbolicExpression::Atom("+".to_string()),
                   SymbolicExpression::AtomValue(Value::Int(5)),
                   SymbolicExpression::Atom("x".to_string())]));

    let func_args = vec!["x".to_string()];
    let user_function = PrivateFunction::new(func_args, func_body);

    let context = LocalContext::new();
    let mut global_context = GlobalContext::new();
    let mut db = MemoryContractDatabase::new();

    global_context.variables.insert("a".to_string(), Value::Int(59));
    global_context.functions.insert("do_work".to_string(), user_function);

    let mut env = Environment::new(&global_context, &mut db);
    assert_eq!(Ok(Value::Int(64)), eval(&content[0], &mut env, &context));
}

#[test]
fn test_simple_let() {
    /*
      test program:
      (let ((x 1) (y 2))
        (+ x
           (let ((x 3))
                 (+ x y))
           x))
    */

    let program = "(let ((x 1) (y 2))
                     (+ x
                        (let ((x 3))
                             (+ x y))
                        x))";

    if let Ok(parsed_program) = parse(&program) {
        let context = LocalContext::new();
        let global_context = GlobalContext::new();
        let mut db = MemoryContractDatabase::new();
        let mut env = Environment::new(&global_context, &mut db);

        assert_eq!(Ok(Value::Int(7)), eval(&parsed_program[0], &mut env, &context));        
    } else {
        assert!(false, "Failed to parse program.");
    }

}

#[test]
fn test_buffer_equality() {
    let tests = [
        "(eq? \"a b c\" \"a b c\")",
        "(eq? \"\\\" a b d\"
               \"\\\" a b d\")",
        "(not (eq? \"\\\" a b d\"
                    \" a b d\"))"];
    let expectations = [
        Value::Bool(true),
        Value::Bool(true),
        Value::Bool(true)];

    tests.iter().zip(expectations.iter())
        .for_each(|(program, expectation)| assert_eq!(Ok(expectation.clone()), execute(program)));
}

#[test]
fn test_principal_equality() {
    let tests = [
        "(eq? 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)",
        "(not (eq? 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR
                   'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G))"];
    let expectations = [
        Value::Bool(true),
        Value::Bool(true)];

    tests.iter().zip(expectations.iter())
        .for_each(|(program, expectation)| assert_eq!(Ok(expectation.clone()), execute(program)));
}

#[test]
fn test_simple_if_functions() {
    //
    //  test program:
    //  (define (with_else x) (if (eq? 5 x) 1 0)
    //  (define (without_else x) (if (eq? 5 x) 1)
    //  (with_else 5)
    //  (with_else 3)
    //  (without_else 3)

    let evals = parse(&
        "(with_else 5)
         (without_else 3)
         (with_else 3)");

    let function_bodies = parse(&"(if (eq? 5 x) 1 0)
                                  (if (eq? 5 x) 1)");

    if let Ok(parsed_bodies) = function_bodies {
        let func_args1 = vec!["x".to_string()];
        let func_args2 = vec!["x".to_string()];
        let user_function1 = PrivateFunction::new(func_args1, parsed_bodies[0].clone());
        let user_function2 = PrivateFunction::new(func_args2, parsed_bodies[1].clone());

        let context = LocalContext::new();
        let mut global_context = GlobalContext::new();
        let mut db = MemoryContractDatabase::new();

        global_context.functions.insert("with_else".to_string(), user_function1);
        global_context.functions.insert("without_else".to_string(), user_function2);

        let mut env = Environment::new(&global_context, &mut db);

        if let Ok(tests) = evals {
            assert_eq!(Ok(Value::Int(1)), eval(&tests[0], &mut env, &context));
            assert_eq!(Ok(Value::Void), eval(&tests[1], &mut env, &context));
            assert_eq!(Ok(Value::Int(0)), eval(&tests[2], &mut env, &context));
        } else {
            assert!(false, "Failed to parse function bodies.");
        }
    } else {
        assert!(false, "Failed to parse function bodies.");
    }
}

#[test]
fn test_simple_arithmetic_functions() {
    let tests = [
        "(* 52314 414)",
         "(/ 52314 414)",
         "(* 2 3 4 5)",
         "(/ 10 13)",
         "(mod 51 2)",
         "(- 5 4 1)",
         "(+ 5 4 1)",
         "(eq? (* 2 3)
              (+ 2 2 2))",
         "(> 1 2)",
         "(< 1 2)",
         "(<= 1 1)",
         "(>= 2 1)",
         "(>= 1 1)",
         "(pow 2 16)",
         "(pow 2 32)",
         "(- (pow 2 32))"];

    let expectations = [
        Value::Int(21657996),
        Value::Int(126),
        Value::Int(120),
        Value::Int(0),
        Value::Int(1),
        Value::Int(0),
        Value::Int(10),
        Value::Bool(true),
        Value::Bool(false),
        Value::Bool(true),
        Value::Bool(true),
        Value::Bool(true),
        Value::Bool(true),
        Value::Int(65536),
        Value::Int(u32::max_value() as i128 + 1),
        Value::Int(-1 * (u32::max_value() as i128 + 1)),
    ];

    tests.iter().zip(expectations.iter())
        .for_each(|(program, expectation)| assert_eq!(Ok(expectation.clone()), execute(program)));
}

#[test]
fn test_arithmetic_errors() {
    let tests = [
        "(>= 1)",
        "(+ 1 'true)",
        "(/ 10 0)",
        "(mod 10 0)",
        "(pow 2 128)",
        "(* 10 (pow 2 126))",
        "(+ (pow 2 126) (pow 2 126))",
        "(- 0 (pow 2 126) (pow 2 126) 1)",
        "(-)",
        "(/)",
        "(mod 1)",
        "(pow 1)",
         "(pow 2 (pow 2 32))",
         "(pow 2 (- 1))"];

    let expectations = [
        Err(Error::InvalidArguments("Binary comparison must be called with exactly 2 arguments".to_string())),
        Err(Error::TypeError("IntType".to_string(), Value::Bool(true))),
        Err(Error::Arithmetic("Divide by 0".to_string())),
        Err(Error::Arithmetic("Modulus by 0".to_string())),
        Err(Error::Arithmetic("Overflowed in power".to_string())),
        Err(Error::Arithmetic("Overflowed in multiplication".to_string())),
        Err(Error::Arithmetic("Overflowed in addition".to_string())),
        Err(Error::Arithmetic("Underflowed in subtraction".to_string())),
        Err(Error::InvalidArguments("(- ...) must be called with at least 1 argument".to_string())),
        Err(Error::InvalidArguments("(/ ...) must be called with at least 1 argument".to_string())),
        Err(Error::InvalidArguments("(mod ...) must be called with exactly 2 arguments".to_string())),
        Err(Error::InvalidArguments("(pow ...) must be called with exactly 2 arguments".to_string())),
        Err(Error::Arithmetic("Power argument to (pow ...) must be a u32 integer".to_string())),
        Err(Error::Arithmetic("Power argument to (pow ...) must be a u32 integer".to_string()))
    ];

    for (program, expectation) in tests.iter().zip(expectations.iter()) {
        assert_eq!(*expectation, execute(program));
    }
}

#[test]
fn test_bool_functions() {
    let tests = [
        "'true",
         "(and 'true 'true 'true)",
         "(and 'false 'true 'true)",
         "(and 'false (> 1 (/ 10 0)))",
         "(or 'true (> 1 (/ 10 0)))",
         "(or 'false 'false 'false)",
         "(not 'true)"];

    let expectations = [
        Value::Bool(true),
        Value::Bool(true),
        Value::Bool(false),
        Value::Bool(false),
        Value::Bool(true),
        Value::Bool(false),
        Value::Bool(false)];

    tests.iter().zip(expectations.iter())
        .for_each(|(program, expectation)| assert_eq!(Ok(expectation.clone()), execute(program)));
}

#[test]
fn test_bad_lets() {
    let tests = [
        "(let ((tx-sender 1)) (+ tx-sender tx-sender))",
        "(let ((* 1)) (+ * *))",
        "(let ((a 1) (a 2)) (+ a a))"];

    let expectations: &[Result<Value, Error>] = &[
        Err(Error::ReservedName("tx-sender".to_string())),
        Err(Error::ReservedName("*".to_string())),
        Err(Error::MultiplyDefined("a".to_string()))];

    tests.iter().zip(expectations.iter())
        .for_each(|(program, expectation)| assert_eq!(*expectation, execute(program)));
}
