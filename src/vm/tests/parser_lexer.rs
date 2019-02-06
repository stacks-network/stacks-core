use vm::representations::SymbolicExpression;
use vm::parser;

#[test]
fn test_parse_let_expression() {
    let input = "z (let ((x 1) (y 2))
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
                    SymbolicExpression::Atom("1".to_string())])),
                SymbolicExpression::List(Box::new([
                    SymbolicExpression::Atom("y".to_string()),
                    SymbolicExpression::Atom("2".to_string())]))])),
            SymbolicExpression::List(Box::new([
                SymbolicExpression::Atom("+".to_string()),
                SymbolicExpression::Atom("x".to_string()),
                SymbolicExpression::List(Box::new([
                    SymbolicExpression::Atom("let".to_string()),
                    SymbolicExpression::List(Box::new([
                        SymbolicExpression::List(Box::new([
                            SymbolicExpression::Atom("x".to_string()),
                            SymbolicExpression::Atom("3".to_string())]))])),
                    SymbolicExpression::List(Box::new([
                        SymbolicExpression::Atom("+".to_string()),
                        SymbolicExpression::Atom("x".to_string()),
                        SymbolicExpression::Atom("y".to_string())]))])),
                SymbolicExpression::Atom("x".to_string())]))])),
        SymbolicExpression::Atom("x".to_string()),
        SymbolicExpression::Atom("y".to_string()),
    ];

    if let Ok(parsed) = parser::parse(&input) {
        assert_eq!(program, parsed, "Should match expected symbolic expression");
    } else {
        assert!(false, "Failed to lex and parse input");
    }
}

#[test]
fn test_parse_failures() {
    let too_much_closure = "(let ((x 1) (y 2))))";
    let not_enough_closure = "(let ((x 1) (y 2))";

    match parser::parse(&too_much_closure) {
        Ok(_parsed) => assert!(false, "Should have failed to parse with too many right parens"),
        Err(_s) => assert!(true, "Should have failed to parse with too many right parens")
    }
    match parser::parse(&not_enough_closure) {
        Ok(_parsed) => assert!(false, "Should have failed to parse with too few right parens"),
        Err(_s) => assert!(true, "Should have failed to parse with too few right parens")
    }
}
