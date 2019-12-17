use vm::ast::parse;
use vm::representations::SymbolicExpression;
use vm::analysis::type_checker::{TypeResult, TypeChecker, TypingContext};
use vm::analysis::{AnalysisDatabase};
use vm::analysis::errors::CheckErrors;
use vm::analysis::mem_type_check;
use vm::analysis::type_check;
use vm::analysis::types::ContractAnalysis;
use vm::contexts::{OwnedEnvironment};
use vm::types::{Value, PrincipalData, TypeSignature, FunctionType, FixedFunction, BUFF_32, BUFF_64,
                QualifiedContractIdentifier};

use vm::types::TypeSignature::{IntType, BoolType, BufferType, UIntType};
use std::convert::TryInto;

mod assets;
mod contracts;

fn type_check_helper(exp: &str) -> TypeResult {
    mem_type_check(exp).map(|(type_sig_opt, _)| type_sig_opt.unwrap())
}

fn buff_type(size: u32) -> TypeSignature {
    TypeSignature::BufferType(size.try_into().unwrap()).into()
}

#[test]
fn test_get_block_info(){
    let good = ["(get-block-info? time u1)",
                "(get-block-info? time (* u2 u3))",
                "(get-block-info? vrf-seed u1)",
                "(get-block-info? header-hash u1)",
                "(get-block-info? burnchain-header-hash u1)"];
    let expected = [ "(optional uint)", "(optional uint)", "(optional (buff 32))",
                       "(optional (buff 32))", "(optional (buff 32))" ];

    let bad = ["(get-block-info? none u1)",
               "(get-block-info? time 'true)",
               "(get-block-info? time 1)",
               "(get-block-info? time)"];
    let bad_expected = [ CheckErrors::NoSuchBlockInfoProperty("none".to_string()),
                         CheckErrors::TypeError(UIntType, BoolType),
                         CheckErrors::TypeError(UIntType, IntType),
                         CheckErrors::RequiresAtLeastArguments(2, 1) ];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        assert_eq!(expected, &format!("{}", type_check_helper(&good_test).unwrap()));
    }
    
    for (bad_test, expected) in bad.iter().zip(bad_expected.iter()) {
        assert_eq!(expected, &type_check_helper(&bad_test).unwrap_err().err);
    }
}

#[test]
fn test_destructuring_opts(){
    let good = [
        "(unwrap! (some 1) 2)",
        "(unwrap-err! (err 1) 2)",
        "(unwrap! (ok 3) 2)",
        "(unwrap-panic (ok 3))",
        "(unwrap-panic (some 3))",
        "(unwrap-err-panic (err 3))",
        "(match (some 1) inner-value (+ 1 inner-value) (/ 1 0))",
        "(define-private (foo) (if (> 1 0) (ok 1) (err 8)))
         (match (foo) ok-val (+ 1 ok-val) err-val (/ err-val 0))",
        "(define-private (t1 (x uint)) (if (> x u1) (ok x) (err 'false)))
         (define-private (t2 (x uint))
           (if (> x u4)
               (err 'true)
               (ok (+ u2 (try! (t1 x))))))
         (t2 u3)",
        "(define-private (t1 (x uint)) (if (> x u1) (ok x) (err 'false)))
         (define-private (t2 (x uint))
           (if (> x u4)
               (err 'true)
               (ok (> u2 (try! (t1 x))))))
         (t2 u3)",
        "(define-private (t1 (x uint)) (if (> x u1) (some x) none))
         (define-private (t2 (x uint))
           (if (> x u4)
               (some 'false)
               (some (> u2 (try! (t1 x))))))
         (t2 u3)",
    ];

    let expected = [ 
        "int", "int", "int", "int", "int",
        "int", "int", "int",
        "(response uint bool)",
        "(response bool bool)",
        "(optional bool)",
    ];
    
    assert_eq!(expected.len(), good.len());

    let bad = [
        ("(unwrap-err! (some 2) 2)",
         CheckErrors::ExpectedResponseType(TypeSignature::from("(optional int)"))),
        ("(unwrap! (err 3) 2)",
         CheckErrors::CouldNotDetermineResponseOkType),
        ("(unwrap-err-panic (ok 3))",
         CheckErrors::CouldNotDetermineResponseErrType),
        ("(unwrap-panic none)",
         CheckErrors::CouldNotDetermineResponseOkType),
        ("(define-private (foo) (if (> 1 0) none none)) (unwrap-panic (foo))",
         CheckErrors::CouldNotDetermineResponseOkType),
        ("(unwrap-panic (err 3))",
         CheckErrors::CouldNotDetermineResponseOkType),
        ("(match none inner-value (/ 1 0) (+ 1 8))",
         CheckErrors::CouldNotDetermineMatchTypes),
        ("(match (ok 1) ok-val (/ ok-val 0) err-val (+ err-val 7))",
         CheckErrors::CouldNotDetermineMatchTypes),
        ("(match (err 1) ok-val (/ ok-val 0) err-val (+ err-val 7))",
         CheckErrors::CouldNotDetermineMatchTypes),
        ("(define-private (foo) (if (> 1 0) (ok 1) (err u8)))
         (match (foo) ok-val (+ 1 ok-val) err-val (/ err-val u0))",
         CheckErrors::MatchArmsMustMatch(TypeSignature::IntType, TypeSignature::UIntType)),
        ("(match (some 1) inner-value (+ 1 inner-value) (> 1 28))",
         CheckErrors::MatchArmsMustMatch(TypeSignature::IntType, TypeSignature::BoolType)),         
        ("(match (some 1) inner-value (+ 1 inner-value))",
         CheckErrors::IncorrectArgumentCount(4, 3)),
        ("(match (ok 1) inner-value (+ 1 inner-value))",
         CheckErrors::IncorrectArgumentCount(5, 3)),
        ("(match)",
         CheckErrors::RequiresAtLeastArguments(1, 0)),
        ("(match 1 ok-val (/ ok-val 0) err-val (+ err-val 7))",
         CheckErrors::ExpectedOptionalOrResponseType(TypeSignature::from("int"))),
        ("(default-to 3 5)",
         CheckErrors::ExpectedOptionalType(TypeSignature::IntType)),
        ("(define-private (foo (x int))
           (match (some 3)
             x (+ x 2)
             5))",
         CheckErrors::NameAlreadyUsed("x".to_string())),
        ("(define-private (t1 (x uint)) (if (> x u1) (ok x) (err 'false)))
         (define-private (t2 (x uint))
           (if (> x u4)
               (err u3)
               (ok (+ u2 (try! (t1 x))))))",
         CheckErrors::ReturnTypesMustMatch(
             TypeSignature::new_response(TypeSignature::NoType, TypeSignature::BoolType),
             TypeSignature::new_response(TypeSignature::UIntType, TypeSignature::UIntType))),
        ("(define-private (t1 (x uint)) (if (> x u1) (ok x) (err 'false)))
         (define-private (t2 (x uint))
           (> u2 (try! (t1 x))))",
         CheckErrors::ReturnTypesMustMatch(
             TypeSignature::new_response(TypeSignature::NoType, TypeSignature::BoolType),
             TypeSignature::BoolType)),
        ("(try! (ok 3))",
         CheckErrors::CouldNotDetermineResponseErrType),
        ("(try! none)",
         CheckErrors::CouldNotDetermineResponseOkType),
        ("(try! (err 3))",
         CheckErrors::CouldNotDetermineResponseOkType),
        ("(try! 3)",
         CheckErrors::ExpectedOptionalOrResponseType(TypeSignature::IntType)),        
        ("(try! (ok 3) 4)",
         CheckErrors::IncorrectArgumentCount(1, 2)),
    ];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        assert_eq!(expected, &format!("{}", type_check_helper(&good_test).unwrap()));
    }
    
    for (bad_test, expected) in bad.iter() {
        assert_eq!(expected, &mem_type_check(&bad_test).unwrap_err().err);
    }
}


#[test]
fn test_at_block(){
    let good = [("(at-block (sha256 u0) u1)", "uint")];

    let bad = [("(at-block (sha512 u0) u1)", CheckErrors::TypeError(BUFF_32.clone(), BUFF_64.clone())),
               ("(at-block (sha256 u0) u1 u2)", CheckErrors::IncorrectArgumentCount(2, 3))];

    for (good_test, expected) in good.iter() {
        assert_eq!(expected, &format!("{}", type_check_helper(&good_test).unwrap()));
    }
    
    for (bad_test, expected) in bad.iter() {
        assert_eq!(expected, &type_check_helper(&bad_test).unwrap_err().err);
    }
}

#[test]
fn test_simple_arithmetic_checks() {
    let good = ["(>= (+ 1 2 3) (- 1 2))",
                "(is-eq (+ 1 2 3) 6 0)",
                "(and (or 'true 'false) 'false)"];
    let expected = ["bool", "bool", "bool"];
    let bad = ["(+ 1 2 3 (>= 5 7))",
               "(-)",
               "(xor 1)",
               "(+ x y z)", // unbound variables.
               "(+ 1 2 3 (is-eq 1 2))",
               "(and (or 'true 'false) (+ 1 2 3))"];
    let bad_expected = [ CheckErrors::TypeError(IntType, BoolType),
                         CheckErrors::RequiresAtLeastArguments(1, 0),
                         CheckErrors::IncorrectArgumentCount(2, 1),
                         CheckErrors::UndefinedVariable("x".to_string()),
                         CheckErrors::TypeError(IntType, BoolType),
                         CheckErrors::TypeError(BoolType, IntType), ];
                         

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        assert_eq!(expected, &format!("{}", type_check_helper(&good_test).unwrap()));
    }
    
    for (bad_test, expected) in bad.iter().zip(bad_expected.iter()) {
        assert_eq!(expected, &type_check_helper(&bad_test).unwrap_err().err);
    }
}

#[test]
fn test_simple_hash_checks() {
    let good = ["(hash160 u1)",
                "(hash160 1)",
                "(sha512 u10)",
                "(sha512 10)",
                "(sha512/256 u10)",
                "(sha512/256 10)",
                "(sha256 (keccak256 u1))",
                "(sha256 (keccak256 1))"];
    let expected = ["(buff 20)", "(buff 20)", "(buff 64)", "(buff 64)", "(buff 32)", "(buff 32)", "(buff 32)", "(buff 32)" ];

    let bad_types = ["(hash160 'true)",
                     "(sha256 'false)",
                     "(sha512 'false)",
                     "(sha512/256 'false)",
                     "(keccak256 (list 1 2 3))"];
    let invalid_args = ["(sha256 u1 u2 u3)", "(sha512 u1 u2 u3)", "(sha512/256 u1 u2 u3)"];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        assert_eq!(expected, &format!("{}", type_check_helper(&good_test).unwrap()));
    }
    
    for bad_test in bad_types.iter() {
        assert!(match type_check_helper(&bad_test).unwrap_err().err {
            CheckErrors::UnionTypeError(_, _) => true,
            _ => false
        })
    }
    
    for bad_test in invalid_args.iter() {
        assert!(match type_check_helper(&bad_test).unwrap_err().err {
            CheckErrors::IncorrectArgumentCount(_, _) => true,
            _ => false
        })
    }
}

#[test]
fn test_simple_ifs() {
    let good = ["(if (> 1 2) (+ 1 2 3) (- 1 2))",
                "(if 'true 'true 'false)",
                "(if 'true \"abcdef\" \"abc\")",
                "(if 'true \"a\" \"abcdef\")" ];
    let expected = [ "int", "bool", "(buff 6)", "(buff 6)" ];

    let bad = ["(if 'true 'true 1)",
               "(if 'true \"a\" 'false)",
               "(if)",
               "(if 0 1 0)"];

    let bad_expected = [
        CheckErrors::IfArmsMustMatch(BoolType, IntType),
        CheckErrors::IfArmsMustMatch(buff_type(1), BoolType),
        CheckErrors::IncorrectArgumentCount(3, 0),
        CheckErrors::TypeError(BoolType, IntType)
    ];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        assert_eq!(expected, &format!("{}", type_check_helper(&good_test).unwrap()));
    }
    
    for (bad_test, expected) in bad.iter().zip(bad_expected.iter()) {
        assert_eq!(expected, &type_check_helper(&bad_test).unwrap_err().err);
    }
}

#[test]
fn test_simple_lets() {
    let good = ["(let ((x 1) (y 2) (z 3)) (if (> x 2) (+ 1 x y) (- 1 z)))",
                "(let ((x 'true) (y (+ 1 2)) (z 3)) (if x (+ 1 z y) (- 1 z)))",
                "(let ((x 'true) (y (+ 1 2)) (z 3)) (print x) (if x (+ 1 z y) (- 1 z)))"];

    let expected = ["int", "int", "int"];

    let bad = ["(let ((1)) (+ 1 2))",
               "(let ((1 2)) (+ 1 2))"];
    let bad_expected = [ CheckErrors::BadSyntaxBinding,
                         CheckErrors::BadSyntaxBinding ];


    for (good_test, expected) in good.iter().zip(expected.iter()) {
        assert_eq!(expected, &format!("{}", type_check_helper(&good_test).unwrap()));
    }
    
    for (bad_test, expected) in bad.iter().zip(bad_expected.iter()) {
        assert_eq!(expected, &type_check_helper(&bad_test).unwrap_err().err);
    }
}

#[test]
fn test_eqs() {
    let good = ["(is-eq (list 1 2 3 4 5) (list 1 2 3 4 5 6 7))",
                "(is-eq (tuple (good 1) (bad 2)) (tuple (good 2) (bad 3)))",
                "(is-eq \"abcdef\" \"abc\" \"a\")"];

    let expected = ["bool", "bool", "bool"];

    let bad = [
        "(is-eq 1 2 'false)",
        "(is-eq 1 2 3 (list 2))",
        "(is-eq (some 1) (some 'true))" ];

    let bad_expected = [ CheckErrors::TypeError(BoolType, IntType),
                         CheckErrors::TypeError(TypeSignature::list_of(IntType, 1).unwrap(), IntType),
                         CheckErrors::TypeError(TypeSignature::new_option(BoolType), TypeSignature::new_option(IntType)) ];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        assert_eq!(expected, &format!("{}", type_check_helper(&good_test).unwrap()));
    }
    
    for (bad_test, expected) in bad.iter().zip(bad_expected.iter()) {
        assert_eq!(expected, &type_check_helper(&bad_test).unwrap_err().err);
    }
}

#[test]
fn test_asserts() {
    let good = ["(asserts! (is-eq 1 1) 'false)",
                "(asserts! (is-eq 1 1) (err 1))"];

    let expected = ["bool", "bool"];

    let bad = [
        "(asserts! (is-eq 1 0))",
        "(asserts! 1 'false)",
        "(asserts! 1 0 'false)" ];

    let bad_expected = [ CheckErrors::IncorrectArgumentCount(2, 1),
                         CheckErrors::TypeError(BoolType, IntType),
                         CheckErrors::IncorrectArgumentCount(2, 3) ];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        assert_eq!(expected, &format!("{}", type_check_helper(&good_test).unwrap()));
    }

    for (bad_test, expected) in bad.iter().zip(bad_expected.iter()) {
        assert_eq!(expected, &type_check_helper(&bad_test).unwrap_err().err);
    }
}


#[test]
fn test_lists() {
    let good = [
        "(map hash160 (list u1 u2 u3 u4 u5))",
        "(map hash160 (list 1 2 3 4 5))",
        "(list (list 1 2) (list 3 4) (list 5 1 7))",
        "(filter not (list 'false 'true 'false))",
        "(fold and (list 'true 'true 'false 'false) 'true)",
        "(map - (list (+ 1 2) 3 (+ 4 5) (* (+ 1 2) 3)))",
        "(if 'true (list 1 2 3 4) (list))",
        "(if 'true (list) (list 1 2 3 4))",
        "(len (list 1 2 3 4))"];
    let expected = [
        "(list 5 (buff 20))", 
        "(list 5 (buff 20))", 
        "(list 3 (list 3 int))", 
        "(list 3 bool)", 
        "bool", 
        "(list 4 int)",
        "(list 4 int)", 
        "(list 4 int)", 
        "uint"];

    let bad = [
        "(fold and (list 'true 'false) 2)",
        "(fold hash160 (list u1 u2 u3 u4) u2)",
        "(fold hash160 (list 1 2 3 4) 2)",
        "(fold >= (list 1 2 3 4) 2)",
        "(list (list 1 2) (list 'true) (list 5 1 7))",
        "(list 1 2 3 'true 'false 4 5 6)",
        "(filter hash160 (list u1 u2 u3 u4))",
        "(filter hash160 (list 1 2 3 4))",
        "(filter not (list 1 2 3 4))",
        "(filter not (list 1 2 3 4) 1)",
        "(filter ynot (list 1 2 3 4))",
        "(map if (list 1 2 3 4 5))",
        "(map mod (list 1 2 3 4 5))",
        "(map - (list 'true 'false 'true 'false))",
        "(map hash160 (+ u1 u2))",
        "(len 1)"];
    let bad_expected = [
        CheckErrors::TypeError(BoolType, IntType),
        CheckErrors::IncorrectArgumentCount(1, 2),
        CheckErrors::IncorrectArgumentCount(1, 2),
        CheckErrors::TypeError(IntType, BoolType),
        CheckErrors::TypeError(IntType, BoolType),
        CheckErrors::TypeError(IntType, BoolType),
        CheckErrors::TypeError(BoolType, buff_type(20)),
        CheckErrors::TypeError(BoolType, buff_type(20)),
        CheckErrors::TypeError(BoolType, IntType),
        CheckErrors::IncorrectArgumentCount(2, 3),
        CheckErrors::UnknownFunction("ynot".to_string()),
        CheckErrors::IllegalOrUnknownFunctionApplication("if".to_string()),
        CheckErrors::IncorrectArgumentCount(2, 1),
        CheckErrors::UnionTypeError(vec![IntType, UIntType], BoolType),
        CheckErrors::ExpectedListOrBuffer(UIntType),
        CheckErrors::ExpectedListOrBuffer(IntType)];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        assert_eq!(expected, &format!("{}", type_check_helper(&good_test).unwrap()));
    }
    
    for (bad_test, expected) in bad.iter().zip(bad_expected.iter()) {
        assert_eq!(expected, &type_check_helper(&bad_test).unwrap_err().err);
    }
}


#[test]
fn test_buff() {
    let good = [
        "(if 'true \"blockstack\" \"block\")",
        "(if 'true \"block\" \"blockstack\")",
        "(len \"blockstack\")"];
    let expected = [
        "(buff 10)",
        "(buff 10)",
        "uint"];
    let bad = [
        "(fold and (list 'true 'false) 2)",
        "(fold hash160 (list 1 2 3 4) 2)",
        "(fold >= (list 1 2 3 4) 2)",
        "(list (list 1 2) (list 'true) (list 5 1 7))",
        "(list 1 2 3 'true 'false 4 5 6)",
        "(filter hash160 (list 1 2 3 4))",
        "(filter not (list 1 2 3 4))",
        "(filter not (list 1 2 3 4) 1)",
        "(filter ynot (list 1 2 3 4))",
        "(map if (list 1 2 3 4 5))",
        "(map mod (list 1 2 3 4 5))",
        "(map - (list 'true 'false 'true 'false))",
        "(map hash160 (+ u1 u2))",
        "(len 1)"];
    let bad_expected = [
        CheckErrors::TypeError(BoolType, IntType),
        CheckErrors::IncorrectArgumentCount(1, 2),
        CheckErrors::TypeError(IntType, BoolType),
        CheckErrors::TypeError(IntType, BoolType),
        CheckErrors::TypeError(IntType, BoolType),
        CheckErrors::TypeError(BoolType, buff_type(20)),
        CheckErrors::TypeError(BoolType, IntType),
        CheckErrors::IncorrectArgumentCount(2, 3),
        CheckErrors::UnknownFunction("ynot".to_string()),
        CheckErrors::IllegalOrUnknownFunctionApplication("if".to_string()),
        CheckErrors::IncorrectArgumentCount(2, 1),
        CheckErrors::UnionTypeError(vec![IntType, UIntType], BoolType),
        CheckErrors::ExpectedListOrBuffer(UIntType),
        CheckErrors::ExpectedListOrBuffer(IntType)];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        assert_eq!(expected, &format!("{}", type_check_helper(&good_test).unwrap()));
    }
    
    for (bad_test, expected) in bad.iter().zip(bad_expected.iter()) {
        assert_eq!(expected, &type_check_helper(&bad_test).unwrap_err().err);
    }
}

#[test]
fn test_buff_fold() {
    let good = [
        "(define-private (get-len (x (buff 1)) (acc uint)) (+ acc u1))
        (fold get-len \"101010\" u0)",
        "(define-private (slice (x (buff 1)) (acc (tuple (limit uint) (cursor uint) (data (buff 10)))))
            (if (< (get cursor acc) (get limit acc))
                (let ((data (default-to (get data acc) (as-max-len? (concat (get data acc) x) u10))))
                    (tuple (limit (get limit acc)) (cursor (+ u1 (get cursor acc))) (data data))) 
                acc))
        (fold slice \"0123456789\" (tuple (limit u5) (cursor u0) (data \"\")))"];
    let expected = ["uint", "(tuple (cursor uint) (data (buff 10)) (limit uint))"];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        let type_sig = mem_type_check(good_test).unwrap().0.unwrap();
        assert_eq!(expected, &type_sig.to_string());
    }
}

#[test]
fn test_buff_map() {
    let good = [
        "(map hash160 \"12345\")"];
    let expected = ["(list 5 (buff 20))"];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        assert_eq!(expected, &format!("{}", type_check_helper(&good_test).unwrap()));
    }
}

#[test]
fn test_native_as_max_len() {
    let good = [
        "(as-max-len? (list 1 2 3 4) u5)"];
    let expected = ["(optional (list 5 int))"];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        assert_eq!(expected, &format!("{}", type_check_helper(&good_test).unwrap()));
    }
}

#[test]
fn test_buff_as_max_len() {
    let tests = [
        "(as-max-len? \"12345\" u5)",
        "(as-max-len? \"12345\" u8)",
        "(as-max-len? \"12345\" u4)"];
    let expected = [
        "(optional (buff 5))",
        "(optional (buff 8))",
        "(optional (buff 4))"];

    for (test, expected) in tests.iter().zip(expected.iter()) {
        assert_eq!(expected, &format!("{}", type_check_helper(&test).unwrap()));
    }
}

#[test]
fn test_native_append() {
    let good = [
        "(append (list 2 3) 4)",
        "(append (list u0) u0)"];
    let expected = ["(list 3 int)", "(list 2 uint)"];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        assert_eq!(expected, &format!("{}", type_check_helper(&good_test).unwrap()));
    }

    let bad = [
        "(append (list 2 3) u4)",
        "(append (list u0) 1)",
        "(append (list u0))"];

    let bad_expected = [
        CheckErrors::TypeError(IntType, UIntType),
        CheckErrors::TypeError(UIntType, IntType),
        CheckErrors::IncorrectArgumentCount(2, 1),
    ];
    for (bad_test, expected) in bad.iter().zip(bad_expected.iter()) {
        assert_eq!(expected, &type_check_helper(&bad_test).unwrap_err().err);
    }
}

#[test]
fn test_native_concat() {
    let good = [
        "(concat (list 2 3) (list 4 5))"];
    let expected = ["(list 4 int)"];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        assert_eq!(expected, &format!("{}", type_check_helper(&good_test).unwrap()));
    }

    let bad = [
        "(concat (list 2 3) (list u4))",
        "(concat (list u0) (list 1))",
        "(concat (list u0))"];

    let bad_expected = [
        CheckErrors::TypeError(IntType, UIntType),
        CheckErrors::TypeError(UIntType, IntType),
        CheckErrors::IncorrectArgumentCount(2, 1),
    ];
    for (bad_test, expected) in bad.iter().zip(bad_expected.iter()) {
        assert_eq!(expected, &type_check_helper(&bad_test).unwrap_err().err);
    }
}

#[test]
fn test_buff_concat() {
    let good = [
        "(concat \"123\" \"58\")"];
    let expected = ["(buff 5)"];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        assert_eq!(expected, &format!("{}", type_check_helper(&good_test).unwrap()));
    }
}

#[test]
fn test_buff_filter() {
    let good = [
        "(define-private (f (e (buff 1))) (is-eq e \"1\"))
        (filter f \"101010\")"];
    let expected = ["(buff 6)"];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        let type_sig = mem_type_check(good_test).unwrap().0.unwrap();
        assert_eq!(expected, &type_sig.to_string());
    }
}

#[test]
fn test_lists_in_defines() {
    let good = "
    (define-private (test (x int)) (is-eq 0 (mod x 2)))
    (filter test (list 1 2 3 4 5))";
    assert_eq!("(list 5 int)", &format!("{}", mem_type_check(good).unwrap().0.unwrap()));
}

#[test]
fn test_tuples() {
    let good = ["(+ 1 2     (get abc (tuple (abc 1) (def 'true))))",
                "(and 'true (get def (tuple (abc 1) (def 'true))))"];

    let expected = [ "int", "bool" ];

    let bad = ["(+ 1 2      (get def (tuple (abc 1) (def 'true))))",
               "(and 'true  (get abc (tuple (abc 1) (def 'true))))"];

    let bad_expected = [ CheckErrors::TypeError(IntType, BoolType),
                         CheckErrors::TypeError(BoolType, IntType), ];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        assert_eq!(expected, &format!("{}", type_check_helper(&good_test).unwrap()));
    }
    
    for (bad_test, expected) in bad.iter().zip(bad_expected.iter()) {
        assert_eq!(expected, &type_check_helper(&bad_test).unwrap_err().err);
    }
}

#[test]
fn test_empty_tuple_should_fail() {
    let contract_src = r#"
        (define-private (set-cursor (value (tuple)))
            value)
    "#;

    assert_eq!(mem_type_check(contract_src).unwrap_err().err,
               CheckErrors::BadSyntaxBinding);
}

#[test]
fn test_define() {
    let good = ["(define-private (foo (x int) (y int)) (+ x y))
                     (define-private (bar (x int) (y bool)) (if y (+ 1 x) 0))
                     (* (foo 1 2) (bar 3 'false))",
    ];
    
    let bad = ["(define-private (foo ((x int) (y int)) (+ x y)))
                     (define-private (bar ((x int) (y bool)) (if y (+ 1 x) 0)))
                     (* (foo 1 2) (bar 3 3))",
    ];

    for good_test in good.iter() {
        mem_type_check(good_test).unwrap();
    }

    for bad_test in bad.iter() {
        mem_type_check(bad_test).unwrap_err();
    }
}

#[test]
fn test_high_order_map() {
    let good = [
        "(define-private (foo (x int)) (list x x x x x)) 
         (map foo (list 1 2 3))",
        "(define-private (foo (x int)) (list x x x x x)) 
         (map foo (list 1 2 3 4 5 6))",
    ];
    
    let expected = [
        "(list 3 (list 5 int))",
        "(list 6 (list 5 int))",
    ];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        let type_sig = mem_type_check(good_test).unwrap().0.unwrap();
        assert_eq!(expected, &type_sig.to_string());
    }
}

#[test]
fn test_simple_uints() {
    let good = [
        "(define-private (foo (x uint)) (+ x u1)) 
         (foo u2)",
        "(define-private (foo (x uint)) (+ x x)) 
         (foo (foo u0))",
        "(+ u10 (to-uint 15))",
        "(- 10 (to-int u1))",
    ];
    
    let expected = [
        "uint",
        "uint",
        "uint",
        "int"
    ];

    let bad = ["(> u1 1)", "(to-uint 'true)", "(to-int 'false)"];

    let bad_expected = [ CheckErrors::TypeError(UIntType, IntType),
                         CheckErrors::TypeError(IntType, BoolType),
                         CheckErrors::TypeError(UIntType, BoolType) ];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        let type_sig = mem_type_check(good_test).unwrap().0.unwrap();
        assert_eq!(expected, &type_sig.to_string());
    }

    for bad_test in bad.iter() {
        mem_type_check(bad_test).unwrap_err();
    }
}

#[test]
fn test_response_inference() {
    let good = ["(define-private (foo (x int)) (err x))
                 (define-private (bar (x bool)) (ok x))
                 (if 'true (foo 1) (bar 'false))",
                "(define-private (check (x (response bool int))) (is-ok x))
                 (check (err 1))",
                "(define-private (check (x (response bool int))) (is-ok x))
                 (check (ok 'true))",
                "(define-private (check (x (response bool int))) (is-ok x))
                 (check (if 'true (err 1) (ok 'false)))",
                "(define-private (check (x (response int bool)))
                   (if (> 10 (unwrap! x 10)) 
                       2
                       (let ((z (unwrap! x 1))) z)))
                 (check (ok 1))",
                // tests top-level `unwrap!` type-check behavior
                // (i.e., let it default to anything, since it will always cause a tx abort if the expectation is unmet.)
                "(unwrap! (ok 2) 'true)" 
    ];
    
    let expected = [
        "(response bool int)",
        "bool",
        "bool",
        "bool",
        "int",
        "int",
    ];

    let bad = ["(define-private (check (x (response bool int))) (is-ok x))
                (check 'true)",
                "(define-private (check (x (response int bool)))
                   (if (> 10 (unwrap! x 10)) 
                       2
                       (let ((z (unwrap! x 'true))) z)))
                 (check (ok 1))",
               "(unwrap! (err 2) 'true)"
    ];

    let bad_expected = [ CheckErrors::TypeError(TypeSignature::new_response(BoolType, IntType),
                                                BoolType),
                         CheckErrors::ReturnTypesMustMatch(IntType, BoolType),
                         CheckErrors::CouldNotDetermineResponseOkType ];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        let type_sig = mem_type_check(good_test).unwrap().0.unwrap();
        assert_eq!(expected, &type_sig.to_string());
    }

    for (bad_test, expected) in bad.iter().zip(bad_expected.iter()) {
        assert_eq!(&mem_type_check(bad_test).unwrap_err().err,
                   expected);
    }
}

#[test]
fn test_function_arg_names() {
    use vm::analysis::type_check;
    
    let functions = vec![
        "(define-private (test (x int)) (ok 0))
         (define-public (test-pub (x int)) (ok 0))
         (define-read-only (test-ro (x int)) (ok 0))",

        "(define-private (test (x int) (y bool)) (ok 0))
         (define-public (test-pub (x int) (y bool)) (ok 0))
         (define-read-only (test-ro (x int) (y bool)) (ok 0))",

        "(define-private (test (name-1 int) (name-2 int) (name-3 int)) (ok 0))
         (define-public (test-pub (name-1 int) (name-2 int) (name-3 int)) (ok 0))
         (define-read-only (test-ro (name-1 int) (name-2 int) (name-3 int)) (ok 0))",

        "(define-private (test) (ok 0))
         (define-public (test-pub) (ok 0))
         (define-read-only (test-ro) (ok 0))",
    ];

    let expected_arg_names: Vec<Vec<&str>> = vec![
        vec!["x"],
        vec!["x", "y"],
        vec!["name-1", "name-2", "name-3"],
        vec![],
    ];

    for (func_test, arg_names) in functions.iter().zip(expected_arg_names.iter()) {
        let contract_analysis = mem_type_check(func_test).unwrap().1;

        let func_type_priv = contract_analysis.get_private_function("test").unwrap();
        let func_type_pub = contract_analysis.get_public_function_type("test-pub").unwrap();
        let func_type_ro = contract_analysis.get_read_only_function_type("test-ro").unwrap();

        for func_type in &[func_type_priv, func_type_pub, func_type_ro] {
            let func_args = match func_type {
                FunctionType::Fixed(FixedFunction{ args, .. }) => args,
                _ => panic!("Unexpected function type")
            };
            
            for (expected_name, actual_name) in arg_names.iter().zip(func_args.iter().map(|x| &x.name)) {
                assert_eq!(*expected_name, &**actual_name);
            }
        }
    }
}

#[test]
fn test_factorial() {
    let contract = "(define-map factorials ((id int)) ((current int) (index int)))
         (define-private (init-factorial (id int) (factorial int))
           (print (map-insert factorials (tuple (id id)) (tuple (current 1) (index factorial)))))
         (define-public (compute (id int))
           (let ((entry (unwrap! (map-get? factorials (tuple (id id)))
                                 (err 'false))))
                    (let ((current (get current entry))
                          (index   (get index entry)))
                         (if (<= index 1)
                             (ok 'true)
                             (begin
                               (map-set factorials (tuple (id id))
                                                      (tuple (current (* current index))
                                                             (index (- index 1))))
                               (ok 'false))))))
        (begin (init-factorial 1337 3)
               (init-factorial 8008 5))
        ";

    mem_type_check(contract).unwrap();
}

#[test]
fn test_options() {
    let contract = "
         (define-private (foo (id (optional int)))
           (+ 1 (default-to 1 id)))
         (define-private (bar (x int))
           (if (> 0 x)
               (some x)
               none))
         (+ (foo none)
            (foo (bar 1))
            (foo (bar 0)))
         ";

    mem_type_check(contract).unwrap();

    let contract = "
         (define-private (foo (id (optional bool)))
           (if (default-to 'false id)
               1
               0))
         (define-private (bar (x int))
           (if (> 0 x)
               (some x)
               none))
         (+ (foo (bar 1)) 1)
         ";

    assert!(
        match mem_type_check(contract).unwrap_err().err {
            CheckErrors::TypeError(t1, t2) => {
                t1 == TypeSignature::new_option(BoolType) &&
                t2 == TypeSignature::new_option(IntType)
            },
            _ => false
        });

}


#[test]
fn test_list_nones() {
    let contract = "
         (begin
           (let ((a (list none none none))) (print a)))";
    assert_eq!(
        "(list 3 (optional UnknownType))",
        &format!("{}", mem_type_check(contract).unwrap().0.unwrap()));
}

#[test]
fn test_set_int_variable() {
    let contract_src = r#"
        (define-data-var cursor int 0)
        (define-private (get-cursor)
            (var-get cursor))
        (define-private (set-cursor (value int))
            (if (var-set cursor value)
                value
                0))
        (define-private (increment-cursor)
            (begin
                (var-set cursor (+ 1 (get-cursor)))
                (get-cursor)))
    "#;

    mem_type_check(contract_src).unwrap();
}

#[test]
fn test_set_bool_variable() {
    let contract_src = r#"
        (define-data-var is-ok bool 'true)
        (define-private (get-ok)
            (var-get is-ok))
        (define-private (set-cursor (new-ok bool))
            (if (var-set is-ok new-ok)
                new-ok
                (get-ok)))
    "#;

    mem_type_check(contract_src).unwrap();
}

#[test]
fn test_set_tuple_variable() {
    let contract_src = r#"
        (define-data-var cursor (tuple (k1 int) (v1 int)) (tuple (k1 1) (v1 1)))
        (define-private (get-cursor)
            (var-get cursor))
        (define-private (set-cursor (value (tuple (k1 int) (v1 int))))
            (if (var-set cursor value)
                value
                (get-cursor)))
    "#;

    mem_type_check(contract_src).unwrap();
}

#[test]
fn test_set_list_variable() {
    let contract_src = r#"
        (define-data-var ranking (list 3 int) (list 1 2 3))
        (define-private (get-ranking)
            (var-get ranking))
        (define-private (set-ranking (new-ranking (list 3 int)))
            (if (var-set ranking new-ranking)
                new-ranking
                (get-ranking)))
    "#;

    mem_type_check(contract_src).unwrap();
}

#[test]
fn test_set_buffer_variable() {
    let contract_src = r#"
        (define-data-var name (buff 5) "alice")
        (define-private (get-name)
            (var-get name))
        (define-private (set-name (new-name (buff 3)))
            (if (var-set name new-name)
                new-name
                (get-name)))
    "#;

    mem_type_check(contract_src).unwrap();
}

#[test]
fn test_missing_value_on_declaration_should_fail() {
    let contract_src = r#"
        (define-data-var cursor int)
    "#;

    let res = mem_type_check(contract_src).unwrap_err();
    assert!(match &res.err {
        &CheckErrors::IncorrectArgumentCount(_, _) => true,
        _ => false
    });
}

#[test]
fn test_mismatching_type_on_declaration_should_fail() {
    let contract_src = r#"
        (define-data-var cursor int 'true)
    "#;

    let res = mem_type_check(contract_src).unwrap_err();
    assert!(match &res.err {
        &CheckErrors::TypeError(_, _) => true,
        _ => false
    });
}

#[test]
fn test_mismatching_type_on_update_should_fail() {
    let contract_src = r#"
        (define-data-var cursor int 0)
        (define-private (get-cursor)
            (var-get cursor))
        (define-private (set-cursor (value principal))
            (if (var-set cursor value)
                value
                0))
    "#;

    let res = mem_type_check(contract_src).unwrap_err();
    assert!(match &res.err {
        &CheckErrors::TypeError(_, _) => true,
        _ => false
    });
}

#[test]
fn test_direct_access_to_persisted_var_should_fail() {
    let contract_src = r#"
        (define-data-var cursor int 0)
        (define-private (get-cursor)
            cursor)
    "#;

    let res = mem_type_check(contract_src).unwrap_err();
    assert!(match &res.err {
        &CheckErrors::UndefinedVariable(_) => true,
        _ => false
    });
}

#[test]
fn test_data_var_shadowed_by_let_should_fail() {
    let contract_src = r#"
        (define-data-var cursor int 0)
        (define-private (set-cursor (value int))
            (let ((cursor 0))
               (if (var-set cursor value)
                   value
                    0)))
    "#;

    let res = mem_type_check(contract_src).unwrap_err();
    assert!(match &res.err {
        &CheckErrors::NameAlreadyUsed(_) => true,
        _ => false
    });
}

#[test]
fn test_mutating_unknown_data_var_should_fail() {
    let contract_src = r#"
        (define-private (set-cursor (value int))
            (if (var-set cursor value)
                value
                0))
    "#;

    let res = mem_type_check(contract_src).unwrap_err();
    assert!(match &res.err {
        &CheckErrors::NoSuchDataVariable(_) => true,
        _ => false
    });
}

#[test]
fn test_accessing_unknown_data_var_should_fail() {
    let contract_src = r#"
        (define-private (get-cursor)
            (unwrap! (var-get cursor) 0))
    "#;

    let res = mem_type_check(contract_src).unwrap_err();
    assert!(match &res.err {
        &CheckErrors::NoSuchDataVariable(_) => true,
        _ => false
    });
}

#[test]
fn test_let_shadowed_by_let_should_fail() {
    let contract_src = r#"
        (let ((cursor 1) (cursor 2))
            cursor)
    "#;

    let res = mem_type_check(contract_src).unwrap_err();
    assert!(match &res.err {
        &CheckErrors::NameAlreadyUsed(_) => true,
        _ => false
    });
}

#[test]
fn test_let_shadowed_by_nested_let_should_fail() {
    let contract_src = r#"
        (let ((cursor 1))
            (let ((cursor 2))
                cursor))
    "#;

    let res = mem_type_check(contract_src).unwrap_err();
    assert!(match &res.err {
        &CheckErrors::NameAlreadyUsed(_) => true,
        _ => false
    });
}

#[test]
fn test_define_constant_shadowed_by_let_should_fail() {
    let contract_src = r#"
        (define-private (cursor) 0)
        (define-private (set-cursor (value int))
            (let ((cursor 1))
               cursor))
    "#;

    let res = mem_type_check(contract_src).unwrap_err();
    assert!(match &res.err {
        &CheckErrors::NameAlreadyUsed(_) => true,
        _ => false
    });
}

#[test]
fn test_define_constant_shadowed_by_argument_should_fail() {
    let contract_src = r#"
        (define-private (cursor) 0)
        (define-private (set-cursor (cursor int))
            cursor)
    "#;

    let res = mem_type_check(contract_src).unwrap_err();
    assert!(match &res.err {
        &CheckErrors::NameAlreadyUsed(_) => true,
        _ => false
    });
}

#[test]
fn test_tuple_map() {
    let t = "(define-map tuples ((name int)) 
                            ((contents (tuple (name (buff 5))
                                              (owner (buff 5))))))

         (define-private (add-tuple (name int) (content (buff 5)))
           (map-insert tuples (tuple (name name))
                                 (tuple (contents
                                   (tuple (name content)
                                          (owner content))))))
         (define-private (get-tuple (name int))
            (get name (get contents (map-get? tuples (tuple (name name))))))


         (add-tuple 0 \"abcde\")
         (add-tuple 1 \"abcd\")
         (list      (get-tuple 0)
                    (get-tuple 1))
        ";
    mem_type_check(t).unwrap();
}


#[test]
fn test_explicit_tuple_map() {
    let contract =
        "(define-map kv-store ((key int)) ((value int)))
          (define-private (kv-add (key int) (value int))
             (begin
                 (map-insert kv-store (tuple (key key))
                                     (tuple (value value)))
             value))
          (define-private (kv-get (key int))
             (unwrap! (get value (map-get? kv-store (tuple (key key)))) 0))
          (define-private (kv-set (key int) (value int))
             (begin
                 (map-set kv-store (tuple (key key))
                                    (tuple (value value)))
                 value))
          (define-private (kv-del (key int))
             (begin
                 (map-delete kv-store (tuple (key key)))
                 key))
         ";

    mem_type_check(contract).unwrap();
}

#[test]
fn test_implicit_tuple_map() {
    let contract =
         "(define-map kv-store ((key int)) ((value int)))
          (define-private (kv-add (key int) (value int))
             (begin
                 (map-insert kv-store ((key key))
                                     ((value value)))
             value))
          (define-private (kv-get (key int))
             (unwrap! (get value (map-get? kv-store ((key key)))) 0))
          (define-private (kv-set (key int) (value int))
             (begin
                 (map-set kv-store ((key key))
                                    ((value value)))
                 value))
          (define-private (kv-del (key int))
             (begin
                 (map-delete kv-store ((key key)))
                 key))
         ";

    mem_type_check(contract).unwrap();
}


#[test]
fn test_bound_tuple_map() {
    let contract =
        "(define-map kv-store ((key int)) ((value int)))
         (define-private (kv-add (key int) (value int))
            (begin
                (let ((my-tuple (tuple (key key))))
                (map-insert kv-store (tuple (key key))
                                    (tuple (value value))))
            value))
         (define-private (kv-get (key int))
            (let ((my-tuple (tuple (key key))))
            (unwrap! (get value (map-get? kv-store my-tuple)) 0)))
         (define-private (kv-set (key int) (value int))
            (begin
                (let ((my-tuple (tuple (key key))))
                (map-set kv-store my-tuple
                                   (tuple (value value))))
                value))
         (define-private (kv-del (key int))
            (begin
                (let ((my-tuple (tuple (key key))))
                (map-delete kv-store my-tuple))
                key))
        ";

    mem_type_check(contract).unwrap();
}

#[test]
fn test_fetch_entry_matching_type_signatures() {
    let cases = [
        "map-get? kv-store ((key key))",
        "map-get? kv-store ((key 0))",
        "map-get? kv-store (tuple (key 0))",
        "map-get? kv-store (compatible-tuple)",
    ];

    for case in cases.iter() {
        let contract_src = format!(
            "(define-map kv-store ((key int)) ((value int)))
             (define-private (compatible-tuple) (tuple (key 1)))
             (define-private (kv-get (key int))
                ({}))", case);

        mem_type_check(&contract_src).unwrap();
    }
}

#[test]
fn test_fetch_entry_mismatching_type_signatures() {
    let cases = [
        "map-get? kv-store ((incomptible-key key))",
        "map-get? kv-store ((key 'true))",
        "map-get? kv-store (incompatible-tuple)",
    ];

    for case in cases.iter() {
        let contract_src = format!(
            "(define-map kv-store ((key int)) ((value int)))
             (define-private (incompatible-tuple) (tuple (k 1)))
             (define-private (kv-get (key int))
                ({}))", case);
        let res = mem_type_check(&contract_src).unwrap_err();
        assert!(match &res.err {
            &CheckErrors::TypeError(_, _) => true,
            _ => false
        });
    }
}

#[test]
fn test_fetch_entry_unbound_variables() {
    let cases = [
        "map-get? kv-store ((key unknown-value))",
    ];

    for case in cases.iter() {
        let contract_src = format!(
            "(define-map kv-store ((key int)) ((value int)))
             (define-private (kv-get (key int))
                ({}))", case);
        let res = mem_type_check(&contract_src).unwrap_err();
        assert!(match &res.err {
            &CheckErrors::UndefinedVariable(_) => true,
            _ => false
        });
    }
}

#[test]
fn test_insert_entry_matching_type_signatures() {
    let cases = [
        "map-insert kv-store ((key key)) ((value value))",
        "map-insert kv-store ((key 0)) ((value 1))",
        "map-insert kv-store (tuple (key 0)) (tuple (value 1))",
        "map-insert kv-store (compatible-tuple) ((value 1))",
    ];

    for case in cases.iter() {
        let contract_src = format!(
            "(define-map kv-store ((key int)) ((value int)))
             (define-private (compatible-tuple) (tuple (key 1)))
             (define-private (kv-add (key int) (value int))
                ({}))", case);
        mem_type_check(&contract_src).unwrap();
    }
}

#[test]
fn test_insert_entry_mismatching_type_signatures() {
    let cases = [
        "map-insert kv-store ((incomptible-key key)) ((value value))",
        "map-insert kv-store ((key key)) ((incomptible-key value))",
        "map-insert kv-store ((key 'true)) ((value 1))",
        "map-insert kv-store ((key key)) ((value 'true))",
        "map-insert kv-store (incompatible-tuple) ((value 1))",
    ];

    for case in cases.iter() {
        let contract_src = format!(
            "(define-map kv-store ((key int)) ((value int)))
             (define-private (incompatible-tuple) (tuple (k 1)))
             (define-private (kv-add (key int) (value int))
                ({}))", case);
        let res = mem_type_check(&contract_src).unwrap_err();
        assert!(match &res.err {
            &CheckErrors::TypeError(_, _) => true,
            _ => false
        });
    }
}

#[test]
fn test_insert_entry_unbound_variables() {
    let cases = [
        "map-insert kv-store ((key unknown-value)) ((value 1))",
        "map-insert kv-store ((key key)) ((value unknown-value))",
    ];

    for case in cases.iter() {
        let contract_src = format!(
            "(define-map kv-store ((key int)) ((value int)))
             (define-private (kv-add (key int))
                ({}))", case);
        let res = mem_type_check(&contract_src).unwrap_err();
        assert!(match &res.err {
            &CheckErrors::UndefinedVariable(_) => true,
            _ => false
        });
    }
}


#[test]
fn test_delete_entry_matching_type_signatures() {
    let cases = [
        "map-delete kv-store ((key key))",
        "map-delete kv-store ((key 1))",
        "map-delete kv-store (tuple (key 1))",
        "map-delete kv-store (compatible-tuple)",
    ];

    for case in cases.iter() {
        let contract_src = format!(
            "(define-map kv-store ((key int)) ((value int)))
             (define-private (compatible-tuple) (tuple (key 1)))
             (define-private (kv-del (key int))
                ({}))", case);
        mem_type_check(&contract_src).unwrap();
    }
}

#[test]
fn test_delete_entry_mismatching_type_signatures() {
    let cases = [
        "map-delete kv-store ((incomptible-key key))",
        "map-delete kv-store ((key 'true))",
        "map-delete kv-store (incompatible-tuple)",
    ];

    for case in cases.iter() {
        let contract_src = format!(
            "(define-map kv-store ((key int)) ((value int)))
             (define-private (incompatible-tuple) (tuple (k 1)))
             (define-private (kv-del (key int))
                ({}))", case);
        let res = mem_type_check(&contract_src).unwrap_err();
        assert!(match &res.err {
            &CheckErrors::TypeError(_, _) => true,
            _ => false
        });
    }

}

#[test]
fn test_delete_entry_unbound_variables() {    
    let cases = [
        "map-delete kv-store ((key unknown-value))",
    ];

    for case in cases.iter() {
        let contract_src = format!(
            "(define-map kv-store ((key int)) ((value int)))
             (define-private (kv-del (key int))
                ({}))", case);
        let res = mem_type_check(&contract_src).unwrap_err();
        assert!(match &res.err {
            &CheckErrors::UndefinedVariable(_) => true,
            _ => false
        });
    }
}

#[test]
fn test_set_entry_matching_type_signatures() {    
    let cases = [
        "map-set kv-store ((key key)) ((value value))",
        "map-set kv-store ((key 0)) ((value 1))",
        "map-set kv-store (tuple (key 0)) (tuple (value 1))",
        "map-set kv-store (tuple (key 0)) (tuple (value known-value))",
        "map-set kv-store (compatible-tuple) ((value 1))",
    ];

    for case in cases.iter() {
        let contract_src = format!(
            "(define-map kv-store ((key int)) ((value int)))
             (define-private (compatible-tuple) (tuple (key 1)))
             (define-private (kv-set (key int) (value int))
                (let ((known-value 2))
                ({})))", case);
        mem_type_check(&contract_src).unwrap();
    }
}



#[test]
fn test_set_entry_mismatching_type_signatures() {    
    let cases = [
        "map-set kv-store ((incomptible-key key)) ((value value))",
        "map-set kv-store ((key key)) ((incomptible-key value))",
        "map-set kv-store ((key 'true)) ((value 1))",
        "map-set kv-store ((key key)) ((value 'true))",
        "map-set kv-store (incompatible-tuple) ((value 1))",
    ];

    for case in cases.iter() {
        let contract_src = format!(
            "(define-map kv-store ((key int)) ((value int)))
             (define-private (incompatible-tuple) (tuple (k 1)))
             (define-private (kv-set (key int) (value int))
                ({}))", case);
        let res = mem_type_check(&&contract_src).unwrap_err();
        assert!(match &res.err {
            &CheckErrors::TypeError(_, _) => true,
            _ => false
        });
    }
}


#[test]
fn test_set_entry_unbound_variables() {    
    let cases = [
        "map-set kv-store ((key unknown-value)) ((value 1))",
        "map-set kv-store ((key key)) ((value unknown-value))",
    ];

    for case in cases.iter() {
        let contract_src = format!(
            "(define-map kv-store ((key int)) ((value int)))
             (define-private (kv-set (key int) (value int))
                ({}))", case);
        let res = mem_type_check(&&contract_src).unwrap_err();
        assert!(match &res.err {
            &CheckErrors::UndefinedVariable(_) => true,
            _ => false
        });
    }
}

#[test]
fn test_fetch_contract_entry_matching_type_signatures() {    
    let kv_store_contract_src = r#"
        (define-map kv-store ((key int)) ((value int)))
        (define-read-only (kv-get (key int))
            (unwrap! (get value (map-get? kv-store ((key key)))) 0))
        (begin (map-insert kv-store ((key 42)) ((value 42))))"#;

    let mut analysis_db = AnalysisDatabase::memory();

    let contract_id = QualifiedContractIdentifier::local("kv-store-contract").unwrap();

    let mut kv_store_contract = parse(&contract_id, &kv_store_contract_src).unwrap();
    analysis_db.execute(|db| {
        type_check(&contract_id, &mut kv_store_contract, db, true)
    }).unwrap();

    let cases = [
        "contract-map-get? .kv-store-contract kv-store ((key key))",
        "contract-map-get? .kv-store-contract kv-store ((key 0))",
        "contract-map-get? .kv-store-contract kv-store (tuple (key 0))",
        "contract-map-get? .kv-store-contract kv-store (compatible-tuple)",
    ];

    let transient_contract_id = QualifiedContractIdentifier::transient();

    for case in cases.iter() {
        let contract_src = format!(r#"
            (define-private (compatible-tuple) (tuple (key 1)))
            (define-private (kv-get (key int)) ({}))"#, case);
        let mut contract = parse(&transient_contract_id, &contract_src).unwrap();
        analysis_db.execute(|db| {
            type_check(&transient_contract_id, &mut contract, db, false)
        }).unwrap();
    }
}

#[test]
fn test_fetch_contract_entry_mismatching_type_signatures() {
    let kv_store_contract_src = r#"
        (define-map kv-store ((key int)) ((value int)))
        (define-read-only (kv-get (key int))
            (unwrap! (get value (map-get? kv-store ((key key)))) 0))
        (begin (map-insert kv-store ((key 42)) ((value 42))))"#;

    let contract_id = QualifiedContractIdentifier::local("kv-store-contract").unwrap();
    let mut analysis_db = AnalysisDatabase::memory();
    let mut kv_store_contract = parse(&contract_id, &kv_store_contract_src).unwrap();
    analysis_db.execute(|db| {
        type_check(&contract_id, &mut kv_store_contract, db, true)
    }).unwrap();
    
    let cases = [
        "contract-map-get? .kv-store-contract kv-store ((incomptible-key key))",
        "contract-map-get? .kv-store-contract kv-store ((key 'true))",
        "contract-map-get? .kv-store-contract kv-store (incompatible-tuple)",
    ];

    let transient_contract_id = QualifiedContractIdentifier::transient();

    for case in cases.iter() {
        let contract_src = format!(
            "(define-map kv-store ((key int)) ((value int)))
             (define-private (incompatible-tuple) (tuple (k 1)))
             (define-private (kv-get (key int))
                ({}))", case);
        let mut contract = parse(&transient_contract_id, &contract_src).unwrap();
        let res = 
            analysis_db.execute(|db| {
                type_check(&transient_contract_id, &mut contract, db, false)
            }).unwrap_err();

        assert!(match &res.err {
            &CheckErrors::TypeError(_, _) => true,
            _ => false
        });
    }
}

#[test]
fn test_fetch_contract_entry_unbound_variables() {
    let kv_store_contract_src = r#"
        (define-map kv-store ((key int)) ((value int)))
        (define-read-only (kv-get (key int))
            (unwrap! (get value (map-get? kv-store ((key key)))) 0))
        (begin (map-insert kv-store ((key 42)) ((value 42))))"#;

    let contract_id = QualifiedContractIdentifier::local("kv-store-contract").unwrap();
    let mut analysis_db = AnalysisDatabase::memory();
    let mut kv_store_contract = parse(&contract_id, &kv_store_contract_src).unwrap();
    analysis_db.execute(|db| {
        type_check(&contract_id, &mut kv_store_contract, db, true)
    }).unwrap();
    
    let cases = [
        "contract-map-get? .kv-store-contract kv-store ((key unknown-value))",
    ];

    let transient_contract_id = QualifiedContractIdentifier::transient();

    for case in cases.iter() {
        let contract_src = format!(
            "(define-map kv-store ((key int)) ((value int)))
             (define-private (kv-get (key int))
                ({}))", case);
        let mut contract = parse(&transient_contract_id, &contract_src).unwrap();
        let res = 
            analysis_db.execute(|db| {
                type_check(&transient_contract_id, &mut contract, db, false)
            }).unwrap_err();

        assert!(match &res.err {
            &CheckErrors::UndefinedVariable(_) => true,
            _ => false
        });
    }
}
