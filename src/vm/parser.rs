use regex::{Regex, Captures};
use address::c32::c32_address_decode;
use vm::errors::{Error, InterpreterResult as Result};
use vm::representations::SymbolicExpression;
use vm::types::Value;

#[derive(Debug)]
pub enum LexItem {
    LeftParen,
    RightParen,
    NamedParameter(String),
    LiteralValue(Value),
    Variable(String),
    Whitespace
}

#[derive(Debug)]
enum TokenType {
    LParens, RParens, Whitespace,
    StringLiteral, HexStringLiteral,
    IntLiteral, QuoteLiteral,
    Variable, NamedParameter, PrincipalLiteral
}

struct LexMatcher {
    matcher: Regex,
    handler: TokenType
}

impl LexMatcher {
    fn new(regex_str: &str, handles: TokenType) -> LexMatcher {
        LexMatcher {
            matcher: Regex::new(&format!("^{}", regex_str)).unwrap(),
            handler: handles
        }
    }
}

fn get_value_or_err(input: &str, captures: Captures) -> Result<String> {
    let matched = captures.name("value").ok_or(
        Error::ParseError("Failed to capture value from input".to_string()))?;
    Ok(input[matched.start()..matched.end()].to_string())
}

pub fn lex(input: &str) -> Result<Vec<LexItem>> {
    // Aaron: I'd like these to be static, but that'd require using
    //    lazy_static (or just hand implementing that), and I'm not convinced
    //    it's worth either (1) an extern macro, or (2) the complexity of hand implementing.
    let lex_matchers: &[LexMatcher] = &[
        LexMatcher::new(r##""(?P<value>((\\")|([[:print:]&&[^"\n\r\t]]))*)""##, TokenType::StringLiteral),
        LexMatcher::new(";;[[:print:]&&[^\n\r\t]]*", TokenType::Whitespace), // ;; comments.
        LexMatcher::new("[(]", TokenType::LParens),
        LexMatcher::new("[)]", TokenType::RParens),
        LexMatcher::new("[ \n\t\r]+", TokenType::Whitespace),
        LexMatcher::new("(?P<value>[[:digit:]]+)", TokenType::IntLiteral),
        LexMatcher::new("'(?P<value>true|false|null)", TokenType::QuoteLiteral),
        LexMatcher::new("'(?P<value>[0123456789ABCDEFGHJKMNPQRSTVWXYZ]{40,41})", TokenType::PrincipalLiteral),
        LexMatcher::new("0x(?P<value>[[:xdigit:]])", TokenType::HexStringLiteral),
        LexMatcher::new("#(?P<value>([[:word:]]|[-#!?+<>=/*])+)", TokenType::NamedParameter),
        LexMatcher::new("(?P<value>([[:word:]]|[-#!?+<>=/*])+)", TokenType::Variable),
    ];


    let mut result = Vec::new();
    let mut munch_index = 0;
    let mut did_match = true;
    while did_match && munch_index < input.len() {
        did_match = false;
        let current_slice = &input[munch_index..];
        for matcher in lex_matchers.iter() {
            if let Some(captures) = matcher.matcher.captures(current_slice) {
                let whole_match = captures.get(0).unwrap();
                assert_eq!(whole_match.start(), 0);
                munch_index += whole_match.end();
                let token = match matcher.handler {
                    TokenType::LParens => Ok(LexItem::LeftParen),
                    TokenType::RParens => Ok(LexItem::RightParen),
                    TokenType::Whitespace => Ok(LexItem::Whitespace),
                    TokenType::NamedParameter => {
                        let value = get_value_or_err(current_slice, captures)?;
                        if value.contains("#") {
                            return Err(Error::ParseError(format!("Illegal variable name: '{}'", value)))
                        }
                        Ok(LexItem::NamedParameter(value))
                    },
                    TokenType::Variable => {
                        let value = get_value_or_err(current_slice, captures)?;
                        if value.contains("#") {
                            return Err(Error::ParseError(format!("Illegal variable name: '{}'", value)))
                        }
                        Ok(LexItem::Variable(value))
                    },
                    TokenType::QuoteLiteral => {
                        let str_value = get_value_or_err(current_slice, captures)?;
                        let value = match str_value.as_str() {
                            "null" => Ok(Value::Void),
                            "true" => Ok(Value::Bool(true)),
                            "false" => Ok(Value::Bool(false)),
                            _ => Err(Error::ParseError(format!("Unknown 'quoted value '{}'", str_value)))
                        }?;
                        Ok(LexItem::LiteralValue(value))
                    },
                    TokenType::IntLiteral => {
                        let str_value = get_value_or_err(current_slice, captures)?;
                        let value = match i128::from_str_radix(&str_value, 10) {
                            Ok(parsed) => Ok(Value::Int(parsed)),
                            Err(_e) => Err(Error::ParseError(format!("Failed to parse int literal '{}'", str_value)))
                        }?;
                        Ok(LexItem::LiteralValue(value))
                    },
                    TokenType::PrincipalLiteral => {
                        let str_value = get_value_or_err(current_slice, captures)?;
                        let (version, data) = c32_address_decode(&str_value)
                            .map_err(|x| { Error::ParseError(format!("Invalid principal literal: {}", x)) })?;
                        if data.len() != 20 {
                            Err(Error::ParseError("Invalid principal literal: Expected 20 data bytes.".to_string()))
                        } else {
                            let mut fixed_data = [0; 20];
                            fixed_data.copy_from_slice(&data[..20]);
                            Ok(LexItem::LiteralValue(Value::Principal(version, fixed_data)))
                        }
                    },
                    TokenType::HexStringLiteral => {
                        panic!("Not implemented")
                    },
                    TokenType::StringLiteral => {
                        let str_value = get_value_or_err(current_slice, captures)?;
                        let quote_unescaped = str_value.replace("\\\"","\"");
                        let slash_unescaped = quote_unescaped.replace("\\\\","\\");
                        let byte_vec = slash_unescaped.as_bytes().to_vec();
                        let value = Value::buff_from(byte_vec)?;
                        Ok(LexItem::LiteralValue(value))
                    }
                }?;

                result.push(token);
                did_match = true;
                break;
            }
        }
    }

    if munch_index == input.len() {
        Ok(result)
    } else {
        Err(Error::ParseError(format!("Failed to lex input remainder: {}", &input[munch_index..])))
    }
}

pub fn parse_lexed(mut input: Vec<LexItem>) -> Result<Vec<SymbolicExpression>> {
    let mut parse_stack = Vec::new();

    let mut output_list = Vec::new();

    for item in input.drain(..) {
        match item {
            LexItem::LeftParen => {
                // start new list.
                let new_list = Vec::new();
                parse_stack.push(new_list);
            },
            LexItem::NamedParameter(value) => {
                let symbol_out = SymbolicExpression::NamedParameter(value);
                match parse_stack.last_mut() {
                    None => output_list.push(symbol_out),
                    Some(ref mut list) => list.push(symbol_out)
                };
            },
            LexItem::RightParen => {
                // end current list.
                if let Some(value) = parse_stack.pop() {
                    let expression = SymbolicExpression::List(value.into_boxed_slice());
                    match parse_stack.last_mut() {
                        None => {
                            // no open lists on stack, add current to result.
                            output_list.push(expression)
                        },
                        Some(ref mut list) => {
                            list.push(expression);
                        }
                    };
                } else {
                    return Err(Error::ParseError("Tried to close list which isn't open.".to_string()))
                }
            },
            LexItem::Variable(value) => {
                match parse_stack.last_mut() {
                    None => output_list.push(SymbolicExpression::Atom(value)),
                    Some(ref mut list) => list.push(SymbolicExpression::Atom(value))
                };
            },
            LexItem::LiteralValue(value) => {
                match parse_stack.last_mut() {
                    None => output_list.push(SymbolicExpression::AtomValue(value)),
                    Some(ref mut list) => list.push(SymbolicExpression::AtomValue(value))
                };
            },
            LexItem::Whitespace => ()
        };
    }

    // check unfinished stack:
    if parse_stack.len() > 0 {
        Err(Error::ParseError("List expressions (..) left opened.".to_string()))
    } else {
        Ok(output_list)
    }
}

pub fn parse(input: &str) -> Result<Vec<SymbolicExpression>> {
    let lexed = lex(input)?;
    parse_lexed(lexed)
}


mod test {
    #[test]
    fn test_parse_let_expression() {
        use vm::representations::SymbolicExpression;
        use vm::errors::Error;
        use vm::types::Value;
        use vm::parser;

        let input = "z (let((x 1) (y 2))
                      (+ x ;; \"comments section?\"
                         ;; this is also a comment!
                         (let ((x 3)) ;; more commentary
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

        let parsed = parser::parse(&input);
        assert_eq!(Ok(program), parsed, "Should match expected symbolic expression");
    }

    #[test]
    fn test_parse_failures() {
        use vm::representations::SymbolicExpression;
        use vm::errors::Error;
        use vm::types::Value;
        use vm::parser;

        let too_much_closure = "(let ((x 1) (y 2))))";
        let not_enough_closure = "(let ((x 1) (y 2))";
        let middle_hash = "(let ((x 1) (y#not 2)) x)";
        let unicode = "(let ((x🎶 1)) (eq x🎶 1))";

        assert!(match parser::parse(&too_much_closure) {
            Err(Error::ParseError(_)) => true,
            _ => false
        }, "Should have failed to parse with too many right parens");
        
        assert!(match parser::parse(&not_enough_closure) {
            Err(Error::ParseError(_)) => true,
            _ => false
        }, "Should have failed to parse with too few right parens");
        
        let x = parser::parse(&middle_hash);
        assert!(match x {
            Err(Error::ParseError(_)) => true,
            _ => {
                println!("Expected parser error. Unexpected value is:\n {:?}", x);
                false
            }
        }, "Should have failed to parse with a middle hash");

        assert!(match parser::parse(&unicode) {
            Err(Error::ParseError(_)) => true,
            _ => false
        }, "Should have failed to parse a unicode variable name");

    }

}
