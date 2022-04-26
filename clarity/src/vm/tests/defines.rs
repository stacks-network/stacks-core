// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#[cfg(test)]
use rstest::rstest;
#[cfg(test)]
use rstest_reuse::{self, *};

#[template]
#[rstest]
#[case(ClarityVersion::Clarity1)]
#[case(ClarityVersion::Clarity2)]
fn test_clarity_versions_defines(#[case] version: ClarityVersion) {}

use crate::vm::ast::build_ast;
use crate::vm::ast::errors::ParseErrors;
use crate::vm::errors::{CheckErrors, Error, RuntimeErrorType};
use crate::vm::types::{QualifiedContractIdentifier, TypeSignature, Value};
use crate::vm::{execute, ClarityVersion};

fn assert_eq_err(e1: CheckErrors, e2: Error) {
    let e1: Error = e1.into();
    assert_eq!(e1, e2)
}

#[test]
fn test_defines() {
    let tests = "(define-constant x 10)
         (define-constant y 15)
         (define-private (f (a int) (b int)) (+ x y a b))
         (f 3 1)";

    assert_eq!(Ok(Some(Value::Int(29))), execute(&tests));

    let tests = "(define-private (f (a int) (b int)) (+ a b))
         (f 3 1 4)";

    assert_eq!(
        execute(&tests).unwrap_err(),
        CheckErrors::IncorrectArgumentCount(2, 3).into()
    );

    let tests = "1";

    assert_eq!(Ok(Some(Value::Int(1))), execute(&tests));
}

#[apply(test_clarity_versions_defines)]
fn test_accept_options(#[case] version: ClarityVersion) {
    let defun = "(define-private (f (b (optional int))) (* 10 (default-to 0 b)))";
    let tests = [
        format!("{} {}", defun, "(f none)"),
        format!("{} {}", defun, "(f (some 1))"),
        format!("{} {}", defun, "(f (some true))"),
    ];
    let expectations: &[Result<_, Error>] = &[
        Ok(Some(Value::Int(0))),
        Ok(Some(Value::Int(10))),
        Err(CheckErrors::TypeValueError(
            TypeSignature::from_string("(optional int)", version),
            Value::some(Value::Bool(true)).unwrap(),
        )
        .into()),
    ];

    for (test, expect) in tests.iter().zip(expectations.iter()) {
        assert_eq!(*expect, execute(test));
    }

    let bad_defun = "(define-private (f (b (optional int int))) (* 10 (default-to 0 b)))";
    assert_eq!(
        execute(bad_defun).unwrap_err(),
        CheckErrors::InvalidTypeDescription.into()
    );
}

#[test]
fn test_bad_define_names() {
    let test0 = "(define-constant tx-sender 1)
         (+ tx-sender tx-sender)";
    let test1 = "(define-constant * 1)
         (+ * *)";
    let test2 = "(define-constant 1 1)
         (+ 1 1)";
    let test3 = "(define-constant foo 1)
         (define-constant foo 2)
         (+ foo foo)";

    assert_eq_err(
        CheckErrors::NameAlreadyUsed("tx-sender".to_string()),
        execute(&test0).unwrap_err(),
    );
    assert_eq_err(
        CheckErrors::NameAlreadyUsed("*".to_string()),
        execute(&test1).unwrap_err(),
    );
    assert_eq_err(CheckErrors::ExpectedName, execute(&test2).unwrap_err());
    assert_eq_err(
        CheckErrors::NameAlreadyUsed("foo".to_string()),
        execute(&test3).unwrap_err(),
    );
}

#[test]
fn test_unwrap_ret() {
    let test0 = "(define-private (foo) (unwrap! (ok 1) 2)) (foo)";
    let test1 = "(define-private (foo) (unwrap! (ok 1))) (foo)";
    let test2 = "(define-private (foo) (unwrap! 1 2)) (foo)";
    let test3 = "(define-private (foo) (unwrap-err! 1 2)) (foo)";
    let test4 = "(define-private (foo) (unwrap-err! (err 1) 2)) (foo)";
    let test5 = "(define-private (foo) (unwrap-err! (err 1))) (foo)";

    assert_eq!(Ok(Some(Value::Int(1))), execute(&test0));
    assert_eq_err(
        CheckErrors::IncorrectArgumentCount(2, 1),
        execute(&test1).unwrap_err(),
    );
    assert_eq_err(
        CheckErrors::ExpectedOptionalOrResponseValue(Value::Int(1)),
        execute(&test2).unwrap_err(),
    );
    assert_eq_err(
        CheckErrors::ExpectedResponseValue(Value::Int(1)),
        execute(&test3).unwrap_err(),
    );
    assert_eq!(Ok(Some(Value::Int(1))), execute(&test4));
    assert_eq_err(
        CheckErrors::IncorrectArgumentCount(2, 1),
        execute(&test5).unwrap_err(),
    );
}

#[test]
fn test_define_read_only() {
    let test0 = "(define-read-only (silly) 1) (silly)";
    let test1 = "(define-read-only (silly) (map-delete map-name (tuple (value 1))))  (silly)";
    let test2 =
        "(define-read-only (silly) (map-insert map-name (tuple (value 1)) (tuple (value 1)))) (silly)";
    let test3 =
        "(define-read-only (silly) (map-set map-name (tuple (value 1)) (tuple (value 1)))) (silly)";

    assert_eq!(Ok(Some(Value::Int(1))), execute(&test0));
    assert_eq_err(
        CheckErrors::WriteAttemptedInReadOnly,
        execute(&test1).unwrap_err(),
    );
    assert_eq_err(
        CheckErrors::WriteAttemptedInReadOnly,
        execute(&test2).unwrap_err(),
    );
    assert_eq_err(
        CheckErrors::WriteAttemptedInReadOnly,
        execute(&test3).unwrap_err(),
    );
}

#[test]
fn test_stack_depth() {
    let mut function_defines = Vec::new();
    function_defines.push("(define-private (foo-0 (x int)) (+ 1 x))".to_string());
    for i in 1..65 {
        function_defines.push(format!(
            "(define-private (foo-{} (x int)) (foo-{} (+ 1 x)))",
            i,
            i - 1
        ));
    }
    function_defines.push(format!("(foo-62 1)"));

    let test0 = function_defines.join("\n");
    function_defines.push(format!("(foo-63 2)"));
    let test1 = function_defines.join("\n");

    assert_eq!(Ok(Some(Value::Int(64))), execute(&test0));
    assert!(match execute(&test1).unwrap_err() {
        Error::Runtime(RuntimeErrorType::MaxStackDepthReached, _) => true,
        _ => false,
    })
}

#[apply(test_clarity_versions_defines)]
fn test_recursive_panic(#[case] version: ClarityVersion) {
    let tests = "(define-private (factorial (a int))
          (if (is-eq a 0)
              1
              (* a (factorial (- a 1)))))
         (factorial 10)";

    let err = build_ast(
        &QualifiedContractIdentifier::transient(),
        tests,
        &mut (),
        version,
    )
    .unwrap_err();
    match err.err {
        ParseErrors::CircularReference(_) => {}
        _ => panic!("{:?}", err),
    }
}

#[test]
fn test_bad_variables() {
    let test0 = "(+ a 1)";
    let expected = CheckErrors::UndefinedVariable("a".to_string());
    assert_eq_err(expected, execute(&test0).unwrap_err());

    let test1 = "(foo 2 1)";
    let expected = CheckErrors::UndefinedFunction("foo".to_string());
    assert_eq_err(expected, execute(&test1).unwrap_err());

    let test2 = "((lambda (x y) 1) 2 1)";
    let expected = CheckErrors::BadFunctionName;
    assert_eq_err(expected, execute(&test2).unwrap_err());

    let test4 = "()";
    let expected = CheckErrors::NonFunctionApplication;
    assert_eq_err(expected, execute(&test4).unwrap_err());
}

#[test]
fn test_variable_shadowing() {
    let test0 = "(let ((cursor 1) (cursor 2)) cursor)";
    let test1 = r#"
        (let ((cursor 1))
            (let ((cursor 2))
                cursor))
        "#;
    let test2 = r#"
        (define-private (cursor) 0)
        (let ((cursor 1))
            cursor)
        "#;
    let test3 = r#"
        (define-private (cursor) 0)
        (define-private (set-cursor (cursor int))
            cursor)
        "#;

    assert_eq_err(
        CheckErrors::NameAlreadyUsed("cursor".to_string()),
        execute(&test0).unwrap_err(),
    );
    assert_eq_err(
        CheckErrors::NameAlreadyUsed("cursor".to_string()),
        execute(&test1).unwrap_err(),
    );
    assert_eq_err(
        CheckErrors::NameAlreadyUsed("cursor".to_string()),
        execute(&test2).unwrap_err(),
    );
    assert_eq_err(
        CheckErrors::NameAlreadyUsed("cursor".to_string()),
        execute(&test3).unwrap_err(),
    );
}

#[test]
fn test_define_parse_panic() {
    let tests = "(define-private () 1)";
    let expected = CheckErrors::DefineFunctionBadSignature;
    assert_eq_err(expected, execute(&tests).unwrap_err());
}

#[test]
fn test_define_parse_panic_2() {
    let tests = "(define-private (a b (d)) 1)";
    assert_eq_err(
        CheckErrors::BadSyntaxExpectedListOfPairs,
        execute(&tests).unwrap_err(),
    );
}
