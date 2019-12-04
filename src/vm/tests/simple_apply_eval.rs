use vm::{eval, execute as vm_execute};
use vm::database::memory_db;
use vm::errors::{CheckErrors, ShortReturnType, RuntimeErrorType, Error};
use vm::{Value, LocalContext, ContractContext, GlobalContext, Environment, CallStack};
use vm::contexts::{OwnedEnvironment};
use vm::callables::DefinedFunction;
use vm::types::{TypeSignature, BuffData, QualifiedContractIdentifier};
use vm::ast::parse;
use util::hash::{hex_bytes, to_hex};

use vm::tests::{execute};

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
                        (let ((z 3))
                             (+ z y))
                        x))";
    let contract_id = QualifiedContractIdentifier::transient();
    if let Ok(parsed_program) = parse(&contract_id, &program) {
        let context = LocalContext::new();
        let mut env = OwnedEnvironment::memory();

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
fn test_sha512() {
    let sha512_evals = [
        "(sha512 \"\")",
        "(sha512 0)",
        "(sha512 \"The quick brown fox jumps over the lazy dog\")",
    ];

    fn p_to_hex(val: Value) -> String {
        match val {
            Value::Buffer(BuffData { data }) => to_hex(&data),
            _ => panic!("Failed")
        }
    }

    let expectations = [
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        "0b6cbac838dfe7f47ea1bd0df00ec282fdf45510c92161072ccfb84035390c4da743d9c3b954eaa1b0f86fc9861b23cc6c8667ab232c11c686432ebb5c8c3f27",
        "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6"
    ];

    sha512_evals.iter().zip(expectations.iter())
        .for_each(|(program, expectation)| assert_eq!(expectation, &p_to_hex(execute(program))));
}

#[test]
fn test_sha512trunc256() {
    let sha512_evals = [
        "(sha512/256 \"\")",
        "(sha512/256 0)",
        "(sha512/256 \"The quick brown fox jumps over the lazy dog\")",
    ];

    fn p_to_hex(val: Value) -> String {
        match val {
            Value::Buffer(BuffData { data }) => to_hex(&data),
            _ => panic!("Failed")
        }
    }

    let expectations = [
        "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a",
        "e41c9660b04714cdf7249f0fd6e6c5556f54a7e04d299958b69a877e0fada2fb",
        "dd9d67b371519c339ed8dbd25af90e976a1eeefd4ad3d889005e532fc5bef04d",
    ];

    sha512_evals.iter().zip(expectations.iter())
        .for_each(|(program, expectation)| assert_eq!(expectation, &p_to_hex(execute(program))));
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
        "(is-eq \"a b c\" \"a b c\")",
        "(is-eq \"\\\" a b d\"
               \"\\\" a b d\")",
        "(not (is-eq \"\\\" a b d\"
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
        "(is-eq 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)",
        "(not (is-eq 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR
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
    //  (define (with_else x) (if (is-eq 5 x) 1 0)
    //  (define (without_else x) (if (is-eq 5 x) 1)
    //  (with_else 5)
    //  (with_else 3)
    //  (without_else 3)

    use vm::callables::DefineType::Private;

    let contract_id = QualifiedContractIdentifier::transient();

    let evals = parse(&contract_id, &
        "(with_else 5)
         (without_else 3)
         (with_else 3)");

    let contract_id = QualifiedContractIdentifier::transient();

    let function_bodies = parse(&contract_id, &"(if (is-eq 5 x) 1 0)
                                  (if (is-eq 5 x) 1 3)");

    if let Ok(parsed_bodies) = function_bodies {
        let func_args1 = vec![("x".into(), TypeSignature::IntType)];
        let func_args2 = vec![("x".into(), TypeSignature::IntType)];
        let user_function1 = DefinedFunction::new(
            func_args1, parsed_bodies[0].clone(), Private, &"with_else".into(), &"");

        let user_function2 = DefinedFunction::new(
            func_args2, parsed_bodies[1].clone(), Private, &"without_else".into(), &"");

        let context = LocalContext::new();
        let mut contract_context = ContractContext::new(QualifiedContractIdentifier::transient());
        let mut global_context = GlobalContext::new(memory_db());

        contract_context.functions.insert("with_else".into(), user_function1);
        contract_context.functions.insert("without_else".into(), user_function2);

        let mut call_stack = CallStack::new();
        let mut env = Environment::new(&mut global_context, &contract_context, &mut call_stack, None, None);

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
         "(is-eq (* 2 3)
              (+ 2 2 2))",
         "(> 1 2)",
         "(< 1 2)",
         "(<= 1 1)",
         "(>= 2 1)",
         "(>= 1 1)",
         "(pow 2 16)",
         "(pow 2 32)",
         "(+ (pow u2 u127) (- (pow u2 u127) u1))",
         "(+ (to-uint 127) u10)",
         "(to-int (- (pow u2 u127) u1))",
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
        Value::UInt(u128::max_value()),
        Value::UInt(137),
        Value::Int(i128::max_value()),
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
        "(pow 2 (- 1))",
        "(is-eq (some 1) (some 'true))"];

    let expectations: &[Error] = &[
        CheckErrors::IncorrectArgumentCount(2,1).into(),
        CheckErrors::TypeValueError(TypeSignature::IntType, Value::Bool(true)).into(),
        RuntimeErrorType::DivisionByZero.into(),
        RuntimeErrorType::DivisionByZero.into(),
        RuntimeErrorType::ArithmeticOverflow.into(),
        RuntimeErrorType::ArithmeticOverflow.into(),
        RuntimeErrorType::ArithmeticOverflow.into(),
        RuntimeErrorType::ArithmeticUnderflow.into(),
        CheckErrors::IncorrectArgumentCount(1,0).into(),
        CheckErrors::IncorrectArgumentCount(1,0).into(),
        CheckErrors::IncorrectArgumentCount(2,1).into(),
        CheckErrors::IncorrectArgumentCount(2,1).into(),
        CheckErrors::IncorrectArgumentCount(2,1).into(),
        RuntimeErrorType::Arithmetic("Power argument to (pow ...) must be a u32 integer".to_string()).into(),
        RuntimeErrorType::Arithmetic("Power argument to (pow ...) must be a u32 integer".to_string()).into(),
        CheckErrors::TypeError(TypeSignature::from("bool"), TypeSignature::from("int")).into() 
    ];

    for (program, expectation) in tests.iter().zip(expectations.iter()) {
        assert_eq!(*expectation, vm_execute(program).unwrap_err());
    }
}

#[test]
fn test_unsigned_arithmetic() {
    let tests = [
        "(- u10)",
        "(- u10 u11)",
        "(> u10 80)",
        "(+ u10 80)",
        "(to-uint -10)",
        "(to-int (pow u2 u127))",
    ];

    let expectations: &[Error] = &[
        RuntimeErrorType::ArithmeticUnderflow.into(),
        RuntimeErrorType::ArithmeticUnderflow.into(),
        CheckErrors::UnionTypeValueError(vec![TypeSignature::IntType, TypeSignature::UIntType], Value::UInt(10)).into(),
        CheckErrors::TypeValueError(TypeSignature::UIntType, Value::Int(80)).into(),
        RuntimeErrorType::ArithmeticUnderflow.into(),
        RuntimeErrorType::ArithmeticOverflow.into(),
    ];

    for (program, expectation) in tests.iter().zip(expectations.iter()) {
        assert_eq!(*expectation, vm_execute(program).unwrap_err());
    }
}

#[test]
fn test_options_errors() {
    let tests = [
        "(is-none 2 1)",
        "(is-none 'true)",
        "(is-ok 2 1)",
        "(is-ok 'true)",
        "(ok 2 3)",
        "(some 2 3)",
        "(err 4 5)",
        "(default-to 4 5 7)",
        "(default-to 4 'true)",
        "(get field-0 (some 1))",
        "(get field-0 1)",
        ];

    let expectations: &[Error] = &[
        CheckErrors::IncorrectArgumentCount(1,2).into(),
        CheckErrors::ExpectedOptionalValue(Value::Bool(true)).into(),
        CheckErrors::IncorrectArgumentCount(1,2).into(),
        CheckErrors::ExpectedResponseValue(Value::Bool(true)).into(),
        CheckErrors::IncorrectArgumentCount(1,2).into(),
        CheckErrors::IncorrectArgumentCount(1,2).into(),
        CheckErrors::IncorrectArgumentCount(1,2).into(),
        CheckErrors::IncorrectArgumentCount(2,3).into(),
        CheckErrors::ExpectedOptionalValue(Value::Bool(true)).into(),
        CheckErrors::ExpectedTuple(TypeSignature::IntType).into(),
        CheckErrors::ExpectedTuple(TypeSignature::IntType).into()
    ];

    for (program, expectation) in tests.iter().zip(expectations.iter()) {
        assert_eq!(*expectation, vm_execute(program).unwrap_err());
    }
}

#[test]
fn test_some() {
    let tests = [
        "(is-eq (some 1) (some 1))",
        "(is-eq none none)",
        "(is-none (some 1))",
        "(is-eq (some 1) none)",
        "(is-eq none (some 1))",
        "(is-eq (some 1) (some 2))",
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
        "(sha512 'true)",
        "(sha512 1 2)",
        "(sha512/256 'true)",
        "(sha512/256 1 2)",
    ];

    let expectations: &[Error] = &[
        CheckErrors::IncorrectArgumentCount(1, 2).into(),
        CheckErrors::IncorrectArgumentCount(1, 2).into(),
        CheckErrors::IncorrectArgumentCount(1, 2).into(),
        CheckErrors::UnionTypeValueError(vec![TypeSignature::IntType, TypeSignature::UIntType, TypeSignature::max_buffer()], Value::Bool(true)).into(),
        CheckErrors::UnionTypeValueError(vec![TypeSignature::IntType, TypeSignature::UIntType, TypeSignature::max_buffer()], Value::Bool(true)).into(),
        CheckErrors::UnionTypeValueError(vec![TypeSignature::IntType, TypeSignature::UIntType, TypeSignature::max_buffer()], Value::Bool(true)).into(),
        CheckErrors::UnionTypeValueError(vec![TypeSignature::IntType, TypeSignature::UIntType, TypeSignature::max_buffer()], Value::Bool(true)).into(),
        CheckErrors::IncorrectArgumentCount(1, 2).into(),
        CheckErrors::UnionTypeValueError(vec![TypeSignature::IntType, TypeSignature::UIntType, TypeSignature::max_buffer()], Value::Bool(true)).into(),
        CheckErrors::IncorrectArgumentCount(1, 2).into(),
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
        "(let ((a 1) (a 2)) (+ a a))",
        "(let ((a 1) (b 2)) (var-set cursor a) (var-set cursor (+ b (var-get cursor))) (+ a b))"];

    let expectations: &[Error] = &[
        CheckErrors::NameAlreadyUsed("tx-sender".to_string()).into(),
        CheckErrors::NameAlreadyUsed("*".to_string()).into(),
        CheckErrors::NameAlreadyUsed("a".to_string()).into(),
        CheckErrors::NoSuchDataVariable("cursor".to_string()).into()];

    tests.iter().zip(expectations.iter())
        .for_each(|(program, expectation)| assert_eq!((*expectation), vm_execute(program).unwrap_err()));
}

#[test]
fn test_lets() {
    let tests = [
        "(let ((a 1) (b 2)) (+ a b))",
        "(define-data-var cursor int 0) (let ((a 1) (b 2)) (var-set cursor a) (var-set cursor (+ b (var-get cursor))) (var-get cursor))"];

    let expectations = [
        Value::Int(3),
        Value::Int(3)];

    tests.iter().zip(expectations.iter())
        .for_each(|(program, expectation)| assert_eq!(expectation.clone(), execute(program)));
}

#[test]
fn test_asserts() {
    let tests = [
        "(begin (asserts! (is-eq 1 1) (err 0)) (ok 1))",
        "(begin (asserts! (is-eq 1 1) (err 0)) (asserts! (is-eq 2 2) (err 1)) (ok 2))"];

    let expectations = [
        Value::okay(Value::Int(1)),
        Value::okay(Value::Int(2))];

    tests.iter().zip(expectations.iter())
        .for_each(|(program, expectation)| assert_eq!(expectation.clone(), execute(program)));
}

#[test]
fn test_asserts_short_circuit() {
    let tests = [
        "(begin (asserts! (is-eq 1 0) (err 0)) (ok 1))",
        "(begin (asserts! (is-eq 1 1) (err 0)) (asserts! (is-eq 2 1) (err 1)) (ok 2))"];

    let expectations: &[Error] = &[
        Error::ShortReturn(ShortReturnType::AssertionFailed(Value::error(Value::Int(0)))),
        Error::ShortReturn(ShortReturnType::AssertionFailed(Value::error(Value::Int(1))))];

    tests.iter().zip(expectations.iter())
        .for_each(|(program, expectation)| assert_eq!((*expectation), vm_execute(program).unwrap_err()));
}
