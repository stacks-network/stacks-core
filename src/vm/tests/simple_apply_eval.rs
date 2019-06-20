use vm::{eval, execute as vm_execute};
use vm::database::ContractDatabaseConnection;
use vm::errors::{UncheckedError, RuntimeErrorType, Error};
use vm::{Value, LocalContext, ContractContext, GlobalContext, Environment, CallStack};
use vm::contexts::{OwnedEnvironment};
use vm::callables::DefinedFunction;
use vm::types::{TypeSignature, AtomTypeIdentifier, BuffData};
use vm::parser::parse;
use util::hash::hex_bytes;

fn execute(s: &str) -> Value {
    vm_execute(s).unwrap().unwrap()
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
        let mut conn = ContractDatabaseConnection::memory().unwrap();
        let mut env = OwnedEnvironment::new(&mut conn);

        assert_eq!(Ok(Value::Int(7)), eval(&parsed_program[0], &mut env.get_exec_environment(None), &context));        
    } else {
        assert!(false, "Failed to parse program.");
    }

}

#[test]
fn test_sha256() {
    let sha256_evals = [
        "(sha256 \"\")",
        "(sha256 0)",
        "(sha256 \"The quick brown fox jumps over the lazy dog\")",
    ];

    fn to_buffer(hex: &str) -> Value {
        return Value::Buffer(BuffData { data: hex_bytes(hex).unwrap() });
    }

    let expectations = [
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "374708fff7719dd5979ec875d56cd2286f6d3cf7ec317a3b25632aab28ec37bb",
        "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
    ];

    sha256_evals.iter().zip(expectations.iter())
        .for_each(|(program, expectation)| assert_eq!(to_buffer(expectation), execute(program)));
}

#[test]
fn test_keccak256() {
    let keccak256_evals = [
        "(keccak256 \"\")",
        "(keccak256 0)",
        "(keccak256 \"The quick brown fox jumps over the lazy dog\")",
    ];

    fn to_buffer(hex: &str) -> Value {
        return Value::Buffer(BuffData { data: hex_bytes(hex).unwrap() });
    }

    let expectations = [
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "f490de2920c8a35fabeb13208852aa28c76f9be9b03a4dd2b3c075f7a26923b4",
        "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15"
    ];

    keccak256_evals.iter().zip(expectations.iter())
        .for_each(|(program, expectation)| assert_eq!(to_buffer(expectation), execute(program)));
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
        .for_each(|(program, expectation)| assert_eq!(expectation.clone(), execute(program)));
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
        .for_each(|(program, expectation)| assert_eq!(expectation.clone(), execute(program)));
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

    use vm::callables::DefineType::Private;

    let evals = parse(&
        "(with_else 5)
         (without_else 3)
         (with_else 3)");

    let function_bodies = parse(&"(if (eq? 5 x) 1 0)
                                  (if (eq? 5 x) 1 3)");

    if let Ok(parsed_bodies) = function_bodies {
        let func_args1 = vec![("x".to_string(), TypeSignature::new_atom(AtomTypeIdentifier::IntType))];
        let func_args2 = vec![("x".to_string(), TypeSignature::new_atom(AtomTypeIdentifier::IntType))];
        let user_function1 = DefinedFunction::new(
            func_args1, parsed_bodies[0].clone(), Private, &"with_else", &"");

        let user_function2 = DefinedFunction::new(
            func_args2, parsed_bodies[1].clone(), Private, &"without_else", &"");

        let context = LocalContext::new();
        let mut contract_context = ContractContext::new(":transient:".to_string());
        let mut conn = ContractDatabaseConnection::memory().unwrap();
        let mut global_context = GlobalContext::begin_from(&mut conn);

        contract_context.functions.insert("with_else".to_string(), user_function1);
        contract_context.functions.insert("without_else".to_string(), user_function2);

        let mut call_stack = CallStack::new();
        let mut env = Environment::new(&mut global_context, &contract_context, &mut call_stack, None);

        if let Ok(tests) = evals {
            assert_eq!(Ok(Value::Int(1)), eval(&tests[0], &mut env, &context));
            assert_eq!(Ok(Value::Int(3)), eval(&tests[1], &mut env, &context));
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
        .for_each(|(program, expectation)| assert_eq!(expectation.clone(), execute(program)));
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
        "(xor 1)",
         "(pow 2 (pow 2 32))",
         "(pow 2 (- 1))"];

    let expectations: &[Error] = &[
        UncheckedError::InvalidArguments("Binary comparison must be called with exactly 2 arguments".to_string()).into(),
        UncheckedError::TypeError("IntType".to_string(), Value::Bool(true)).into(),
        RuntimeErrorType::Arithmetic("Divide by 0".to_string()).into(),
        RuntimeErrorType::Arithmetic("Modulus by 0".to_string()).into(),
        RuntimeErrorType::Arithmetic("Overflowed in power".to_string()).into(),
        RuntimeErrorType::Arithmetic("Overflowed in multiplication".to_string()).into(),
        RuntimeErrorType::Arithmetic("Overflowed in addition".to_string()).into(),
        RuntimeErrorType::Arithmetic("Underflowed in subtraction".to_string()).into(),
        UncheckedError::InvalidArguments("(- ...) must be called with at least 1 argument".to_string()).into(),
        UncheckedError::InvalidArguments("(/ ...) must be called with at least 1 argument".to_string()).into(),
        UncheckedError::InvalidArguments("(mod ...) must be called with exactly 2 arguments".to_string()).into(),
        UncheckedError::InvalidArguments("(pow ...) must be called with exactly 2 arguments".to_string()).into(),
        UncheckedError::InvalidArguments("(xor ...) must be called with exactly 2 arguments".to_string()).into(),
        RuntimeErrorType::Arithmetic("Power argument to (pow ...) must be a u32 integer".to_string()).into(),
        RuntimeErrorType::Arithmetic("Power argument to (pow ...) must be a u32 integer".to_string()).into()
    ];

    for (program, expectation) in tests.iter().zip(expectations.iter()) {
        assert_eq!(*expectation, vm_execute(program).unwrap_err());
    }
}

#[test]
fn test_options_errors() {
    let tests = [
        "(is-none? 2 1)",
        "(is-none? 'true)",
        "(is-ok? 2 1)",
        "(is-ok? 'true)",
        "(ok 2 3)",
        "(some 2 3)",
        "(err 4 5)",
        "(default-to 4 5 7)",
        "(default-to 4 'true)",
        ];

    let expectations: &[Error] = &[
        UncheckedError::InvalidArguments("Wrong number of arguments to is-none? (expects 1)".to_string()).into(),
        UncheckedError::TypeError("OptionalType".to_string(), Value::Bool(true)).into(),
        UncheckedError::InvalidArguments("Wrong number of arguments to is-ok? (expects 1)".to_string()).into(),
        UncheckedError::TypeError("ResponseType".to_string(), Value::Bool(true)).into(),
        UncheckedError::InvalidArguments("Wrong number of arguments to ok (expects 1)".to_string()).into(),
        UncheckedError::InvalidArguments("Wrong number of arguments to some (expects 1)".to_string()).into(),
        UncheckedError::InvalidArguments("Wrong number of arguments to err (expects 1)".to_string()).into(),
        UncheckedError::InvalidArguments("Wrong number of arguments to default-to (expects 2)".to_string()).into(),
        UncheckedError::TypeError("OptionalType".to_string(), Value::Bool(true)).into(),
    ];

    for (program, expectation) in tests.iter().zip(expectations.iter()) {
        assert_eq!(*expectation, vm_execute(program).unwrap_err());
    }
}

#[test]
fn test_some() {
    let tests = [
        "(eq? (some 1) (some 1))",
        "(eq? none none)",
        "(is-none? (some 1))",
        "(eq? (some 1) none)",
        "(eq? none (some 1))",
        "(eq? (some 1) (some 2))",
        ];

    let expectations = [
        Value::Bool(true),
        Value::Bool(true),
        Value::Bool(false),
        Value::Bool(false),
        Value::Bool(false),
        Value::Bool(false),
    ];

    for (program, expectation) in tests.iter().zip(expectations.iter()) {
        assert_eq!(*expectation, vm_execute(program).unwrap().unwrap());
    }
}

#[test]
fn test_hash_errors() {
    let tests = [
        "(sha256 2 1)",
        "(keccak256 3 1)",
        "(hash160 2 1)",
        "(sha256 'true)",
        "(keccak256 'true)",
        "(hash160 'true)",
    ];

    let expectations: &[Error] = &[
        UncheckedError::InvalidArguments("Wrong number of arguments to sha256 (expects 1)".to_string()).into(),
        UncheckedError::InvalidArguments("Wrong number of arguments to keccak256 (expects 1)".to_string()).into(),
        UncheckedError::InvalidArguments("Wrong number of arguments to hash160 (expects 1)".to_string()).into(),
        UncheckedError::TypeError("Int|Buffer".to_string(), Value::Bool(true)).into(),
        UncheckedError::TypeError("Int|Buffer".to_string(), Value::Bool(true)).into(),
        UncheckedError::TypeError("Int|Buffer".to_string(), Value::Bool(true)).into(),
    ];

    for (program, expectation) in tests.iter().zip(expectations.iter()) {
        assert_eq!(*expectation, vm_execute(program).unwrap_err());
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
        .for_each(|(program, expectation)| assert_eq!(expectation.clone(), execute(program)));
}

#[test]
fn test_bad_lets() {
    let tests = [
        "(let ((tx-sender 1)) (+ tx-sender tx-sender))",
        "(let ((* 1)) (+ * *))",
        "(let ((a 1) (a 2)) (+ a a))"];

    let expectations: &[Error] = &[
        UncheckedError::ReservedName("tx-sender".to_string()).into(),
        UncheckedError::ReservedName("*".to_string()).into(),
        UncheckedError::VariableDefinedMultipleTimes("a".to_string()).into()];

    tests.iter().zip(expectations.iter())
        .for_each(|(program, expectation)| assert_eq!((*expectation), vm_execute(program).unwrap_err()));
}
