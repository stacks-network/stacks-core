extern crate blockstack_vm;

use std::collections::HashMap;
use blockstack_vm::eval;
use blockstack_vm::Context;
use blockstack_vm::types::ValueType;
use blockstack_vm::types::DefinedFunction;
use blockstack_vm::representations::SymbolicExpression;


#[test]
fn test_simple_user_function() {
    //
    //  test program:
    //  (define (do_work x) (+ 5 x))
    //  (define a 59)
    //  (do_work a)
    //

    let content = [ SymbolicExpression { value: "do_work".to_string(),
                                         children:
                                         Some(Box::new([ SymbolicExpression { value: "a".to_string(),
                                                                              children: None } ])) } ];
    let func_body = SymbolicExpression { value: "+".to_string(),
                                         children:
                                         Some(Box::new([ SymbolicExpression { value: "5".to_string(),
                                                                              children: None },
                                                         SymbolicExpression { value: "x".to_string(),
                                                                              children: None }])) };
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
fn test_simple_if_functions() {
    //
    //  test program:
    //  (define (with_else x) (if (eq? 5 x) 1 0)
    //  (define (without_else x) (if (eq? 5 x) 1)
    //  (with_else 5)
    //  (with_else 3)
    //  (without_else 3)

    let evals = [ SymbolicExpression { value: "with_else".to_string(),
                                       children:
                                       Some(Box::new([ SymbolicExpression { value: "5".to_string(),
                                                                            children: None } ])) },
                  SymbolicExpression { value: "without_else".to_string(),
                                       children:
                                       Some(Box::new([ SymbolicExpression { value: "3".to_string(),
                                                                            children: None } ])) },
                  SymbolicExpression { value: "with_else".to_string(),
                                       children:
                                       Some(Box::new([ SymbolicExpression { value: "3".to_string(),
                                                                            children: None } ])) } ];

    let with_else = SymbolicExpression {
        value: "if".to_string(),
        children:
        Some(Box::new([
            SymbolicExpression {
                value: "eq?".to_string(),
                children:
                Some(Box::new([ SymbolicExpression { value: "5".to_string(),
                                                     children: None },
                                SymbolicExpression { value: "x".to_string(),
                                                     children: None }]))},
            SymbolicExpression { value: "1".to_string(), children: None },
            SymbolicExpression { value: "0".to_string(), children: None } ])) };

    let without_else = SymbolicExpression {
        value: "if".to_string(),
        children:
        Some(Box::new([
            SymbolicExpression {
                value: "eq?".to_string(),
                children:
                Some(Box::new([ SymbolicExpression { value: "5".to_string(),
                                                     children: None },
                                SymbolicExpression { value: "x".to_string(),
                                                     children: None }]))},
            SymbolicExpression { value: "1".to_string(), children: None } ])) };


    let func_args1 = vec!["x".to_string()];
    let func_args2 = vec!["x".to_string()];
    let user_function1 = Box::new(DefinedFunction { body: with_else,
                                                    arguments: func_args1 });
    let user_function2 = Box::new(DefinedFunction { body: without_else,
                                                    arguments: func_args2 });

    let mut context = Context {
        parent: Option::None,
        variables: HashMap::new(),
        functions: HashMap::new() };

    context.functions.insert("with_else".to_string(), user_function1);
    context.functions.insert("without_else".to_string(), user_function2);

    assert_eq!(ValueType::IntType(1), eval(&evals[0], &context));
    assert_eq!(ValueType::VoidType, eval(&evals[1], &context));
    assert_eq!(ValueType::IntType(0), eval(&evals[2], &context));
}

