extern crate blockstack_vm;
use blockstack_vm::representations::SymbolicExpression;
use blockstack_vm::errors::Error;
use blockstack_vm::types::Value;

#[test]
fn test_parse_let_expression() {
    let input = "z (let((x 1) (y 2))
                      (+ x 
                         (let ((x 3))
                         (+ x y))     
                         x)) x y";
    let program = vec![
        SymbolicExpression::Atom("z".to_string()),
        SymbolicExpression::List(Box::new([
            SymbolicExpression::Atom("let".to_string()),
            SymbolicExpression::List(Box::new([
                SymbolicExpression::List(Box::new([
                    SymbolicExpression::Atom("x".to_string()),
                    SymbolicExpression::AtomValue(Value::Int(1))])),
                SymbolicExpression::List(Box::new([
                    SymbolicExpression::Atom("y".to_string()),
                    SymbolicExpression::AtomValue(Value::Int(2))]))])),
            SymbolicExpression::List(Box::new([
                SymbolicExpression::Atom("+".to_string()),
                SymbolicExpression::Atom("x".to_string()),
                SymbolicExpression::List(Box::new([
                    SymbolicExpression::Atom("let".to_string()),
                    SymbolicExpression::List(Box::new([
                        SymbolicExpression::List(Box::new([
                            SymbolicExpression::Atom("x".to_string()),
                            SymbolicExpression::AtomValue(Value::Int(3))]))])),
                    SymbolicExpression::List(Box::new([
                        SymbolicExpression::Atom("+".to_string()),
                        SymbolicExpression::Atom("x".to_string()),
                        SymbolicExpression::Atom("y".to_string())]))])),
                SymbolicExpression::Atom("x".to_string())]))])),
        SymbolicExpression::Atom("x".to_string()),
        SymbolicExpression::Atom("y".to_string()),
    ];

    let parsed = blockstack_vm::parser::parse(&input);
    assert_eq!(Ok(program), parsed, "Should match expected symbolic expression");
}

#[test]
fn test_parse_failures() {
    let too_much_closure = "(let ((x 1) (y 2))))";
    let not_enough_closure = "(let ((x 1) (y 2))";
    let middle_hash = "(let ((x 1) (y#not 2)) x)";

    assert!(match blockstack_vm::parser::parse(&too_much_closure) {
        Err(Error::ParseError(_)) => true,
        _ => false
    }, "Should have failed to parse with too many right parens");

    assert!(match blockstack_vm::parser::parse(&not_enough_closure) {
        Err(Error::ParseError(_)) => true,
        _ => false
    }, "Should have failed to parse with too few right parens");

    let x = blockstack_vm::parser::parse(&middle_hash);
    assert!(match x {
        Err(Error::ParseError(_)) => true,
        _ => {
            println!("Expected parser error. Unexpected value is:\n {:?}", x);
            false
        }
    }, "Should have failed to parse with a middle hash");

}
