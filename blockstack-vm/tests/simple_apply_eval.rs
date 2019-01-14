extern crate blockstack_vm;

use std::collections::HashMap;
use blockstack_vm::eval;
use blockstack_vm::Context;
use blockstack_vm::types::ValueType;
use blockstack_vm::types::DefinedFunction;
use blockstack_vm::representations::SymbolicExpression;
use blockstack_vm::parser::parse;

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
                   SymbolicExpression::Atom("5".to_string()),
                   SymbolicExpression::Atom("x".to_string())]));

    let func_args = vec!["x".to_string()];
    let user_function = Box::new(DefinedFunction { body: func_body,
                                                   arguments: func_args });

    let mut context = Context {
        parent: Option::None,
        variables: HashMap::new(),
        functions: HashMap::new() };

    context.variables.insert("a".to_string(), ValueType::IntType(59));
    context.functions.insert("do_work".to_string(), user_function);

    assert_eq!(ValueType::IntType(64), eval(&content[0], &context));
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
        let context = Context::new();
        assert_eq!(ValueType::IntType(7), eval(&parsed_program[0], &context));        
    } else {
        assert!(false, "Failed to parse program.");
    }

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
        let user_function1 = Box::new(DefinedFunction { body: parsed_bodies[0].clone(),
                                                        arguments: func_args1 });
        let user_function2 = Box::new(DefinedFunction { body: parsed_bodies[1].clone(),
                                                        arguments: func_args2 });
        let mut context = Context {
            parent: Option::None,
            variables: HashMap::new(),
            functions: HashMap::new() };

        context.functions.insert("with_else".to_string(), user_function1);
        context.functions.insert("without_else".to_string(), user_function2);

        if let Ok(tests) = evals {
            assert_eq!(ValueType::IntType(1), eval(&tests[0], &context));
            assert_eq!(ValueType::VoidType, eval(&tests[1], &context));
            assert_eq!(ValueType::IntType(0), eval(&tests[2], &context));
        } else {
            assert!(false, "Failed to parse function bodies.");
        }
    } else {
        assert!(false, "Failed to parse function bodies.");
    }
}

#[test]
fn test_simple_arithmetic_functions() {
    let tests = parse(&
        "(* 52314 414)
         (/ 52314 414)
         (* 2 3 4 5)
         (/ 10 13)
         (mod 51 2)
         (- 5 4 1)
         (+ 5 4 1)");

    let expectations = [
        ValueType::IntType(21657996),
        ValueType::IntType(126),
        ValueType::IntType(120),
        ValueType::IntType(0),
        ValueType::IntType(1),
        ValueType::IntType(0),
        ValueType::IntType(10)];


    if let Ok(to_eval) = tests {
        let context = Context::new();
        to_eval.iter().zip(expectations.iter())
            .for_each(|(program, expectation)| assert_eq!(*expectation, eval(program, &context)));
    } else {
        assert!(false, "Failed to parse function bodies.");
    }
}

