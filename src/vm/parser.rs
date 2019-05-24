use util::hash::hex_bytes;
use regex::{Regex, Captures};
use address::c32::c32_address_decode;
use vm::errors::{Error, ErrType, InterpreterResult as Result};
use vm::representations::SymbolicExpression;
use vm::types::{Value, PrincipalData};

#[derive(Debug)]
pub enum LexItem {
    LeftParen,
    RightParen,
    LiteralValue(Value),
    Variable(String),
    Whitespace
}

#[derive(Debug)]
enum TokenType {
    LParens, RParens, Whitespace,
    StringLiteral, HexStringLiteral,
    IntLiteral, QuoteLiteral,
    Variable, PrincipalLiteral,
    ContractPrincipalLiteral
}

struct LexMatcher {
    matcher: Regex,
    handler: TokenType
}

enum LexContext {
    ExpectNothing,
    ExpectClosing
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
        Error::new(ErrType::ParseError("Failed to capture value from input".to_string())))?;
    Ok(input[matched.start()..matched.end()].to_string())
}

fn get_lines_at(input: &str) -> Vec<usize> {
    let mut out: Vec<_> = input.match_indices("\n")
        .map(|(ix, _)| ix)
        .collect();
    out.reverse();
    out
}

pub fn lex(input: &str) -> Result<Vec<(LexItem, usize)>> {
    // Aaron: I'd like these to be static, but that'd require using
    //    lazy_static (or just hand implementing that), and I'm not convinced
    //    it's worth either (1) an extern macro, or (2) the complexity of hand implementing.

    let lex_matchers: &[LexMatcher] = &[
        LexMatcher::new(r##""(?P<value>((\\")|([[:print:]&&[^"\n\r\t]]))*)""##, TokenType::StringLiteral),
        LexMatcher::new(";;[[:print:]&&[^\n\r\t]]*", TokenType::Whitespace), // ;; comments.
        LexMatcher::new("[(]", TokenType::LParens),
        LexMatcher::new("[)]", TokenType::RParens),
        LexMatcher::new("[ \n\t\r]+", TokenType::Whitespace),
        LexMatcher::new("0x(?P<value>[[:xdigit:]]+)", TokenType::HexStringLiteral),
        LexMatcher::new("(?P<value>[[:digit:]]+)", TokenType::IntLiteral),
        LexMatcher::new("'(?P<value>true|false|null)", TokenType::QuoteLiteral),
        LexMatcher::new("'CT(?P<value>[[:alpha:]]{5,40})", TokenType::ContractPrincipalLiteral),
        LexMatcher::new("'(?P<value>[0123456789ABCDEFGHJKMNPQRSTVWXYZ]{28,41})", TokenType::PrincipalLiteral),
        LexMatcher::new("(?P<value>([[:word:]]|[-#!?+<>=/*])+)", TokenType::Variable),
    ];

    let mut context = LexContext::ExpectNothing;

    let mut line_indices = get_lines_at(input);
    let mut next_line_break = line_indices.pop();
    let mut current_line = 1;

    let mut result = Vec::new();
    let mut munch_index = 0;
    let mut did_match = true;
    while did_match && munch_index < input.len() {
        if let Some(next_line_ix) = next_line_break {
            if munch_index > next_line_ix {
                next_line_break = line_indices.pop();
                current_line += 1;
            }
        }

        did_match = false;
        let current_slice = &input[munch_index..];
        for matcher in lex_matchers.iter() {
            if let Some(captures) = matcher.matcher.captures(current_slice) {
                let whole_match = captures.get(0).unwrap();
                assert_eq!(whole_match.start(), 0);
                munch_index += whole_match.end();

                match context {
                    LexContext::ExpectNothing => Ok(()),
                    LexContext::ExpectClosing => {
                        // expect the next lexed item to be something that typically
                        // "closes" an atom -- i.e., whitespace or a right-parens.
                        // this prevents an atom like 1234abc from getting split into "1234" and "abc"
                        match matcher.handler {
                            TokenType::RParens => Ok(()),
                            TokenType::Whitespace => Ok(()),
                            _ => Err(Error::new(ErrType::ParseError(format!("Expected whitespace or a close parens. Found: '{}'",
                                                                            &current_slice[..whole_match.end()]))))
                        }
                    }
                }?;

                // default to expect a closing
                context = LexContext::ExpectClosing;

                let token = match matcher.handler {
                    TokenType::LParens => { 
                        context = LexContext::ExpectNothing;
                        Ok(LexItem::LeftParen)
                    },
                    TokenType::RParens => {
                        Ok(LexItem::RightParen)
                    },
                    TokenType::Whitespace => {
                        context = LexContext::ExpectNothing;
                        Ok(LexItem::Whitespace)
                    },
                    TokenType::Variable => {
                        let value = get_value_or_err(current_slice, captures)?;
                        if value.contains("#") {
                            return Err(Error::new(ErrType::ParseError(format!("Illegal variable name: '{}'", value))))
                        }
                        Ok(LexItem::Variable(value))
                    },
                    TokenType::QuoteLiteral => {
                        let str_value = get_value_or_err(current_slice, captures)?;
                        let value = match str_value.as_str() {
                            "null" => Ok(Value::Void),
                            "true" => Ok(Value::Bool(true)),
                            "false" => Ok(Value::Bool(false)),
                            _ => Err(Error::new(ErrType::ParseError(format!("Unknown 'quoted value '{}'", str_value))))
                        }?;
                        Ok(LexItem::LiteralValue(value))
                    },
                    TokenType::IntLiteral => {
                        let str_value = get_value_or_err(current_slice, captures)?;
                        let value = match i128::from_str_radix(&str_value, 10) {
                            Ok(parsed) => Ok(Value::Int(parsed)),
                            Err(_e) => Err(Error::new(ErrType::ParseError(format!("Failed to parse int literal '{}'", str_value))))
                        }?;
                        Ok(LexItem::LiteralValue(value))
                    },
                    TokenType::ContractPrincipalLiteral => {
                        let str_value = get_value_or_err(current_slice, captures)?;
                        Ok(LexItem::LiteralValue(Value::Principal(
                            PrincipalData::ContractPrincipal(str_value))))
                    },
                    TokenType::PrincipalLiteral => {
                        let str_value = get_value_or_err(current_slice, captures)?;
                        let (version, data) = c32_address_decode(&str_value)
                            .map_err(|x| { Error::new(ErrType::ParseError(format!("Invalid principal literal: {}", x))) })?;
                        if data.len() != 20 {
                            Err(Error::new(ErrType::ParseError("Invalid principal literal: Expected 20 data bytes.".to_string())))
                        } else {
                            let mut fixed_data = [0; 20];
                            fixed_data.copy_from_slice(&data[..20]);
                            Ok(LexItem::LiteralValue(Value::Principal(
                                PrincipalData::StandardPrincipal(version, fixed_data))))
                        }
                    },
                    TokenType::HexStringLiteral => {
                        let str_value = get_value_or_err(current_slice, captures)?;
                        let byte_vec = hex_bytes(&str_value)
                            .map_err(|x| { Error::new(ErrType::ParseError(format!("Invalid hex-string literal {}: {}", &str_value, x))) })?;
                        let value = Value::buff_from(byte_vec)?;
                        Ok(LexItem::LiteralValue(value))
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

                result.push((token, current_line));
                did_match = true;
                break;
            }
        }
    }

    if munch_index == input.len() {
        Ok(result)
    } else {
        Err(Error::new(ErrType::ParseError(format!("Failed to lex input remainder: {}", &input[munch_index..]))))
    }
}

pub fn parse_lexed(mut input: Vec<(LexItem, usize)>) -> Result<Vec<SymbolicExpression>> {
    let mut parse_stack = Vec::new();

    let mut output_list = Vec::new();

    for (item, line_number) in input.drain(..) {
        match item {
            LexItem::LeftParen => {
                // start new list.
                let new_list = Vec::new();
                parse_stack.push((new_list, line_number));
            },
            LexItem::RightParen => {
                // end current list.
                if let Some((value, starting_line)) = parse_stack.pop() {
                    let mut expression = SymbolicExpression::list(value.into_boxed_slice());
                    expression.set_line_number(starting_line);
                    match parse_stack.last_mut() {
                        None => {
                            // no open lists on stack, add current to result.
                            output_list.push(expression)
                        },
                        Some((ref mut list, _)) => {
                            list.push(expression);
                        }
                    };
                } else {
                    return Err(Error::new(ErrType::ParseError("Tried to close list which isn't open.".to_string())))
                }
            },
            LexItem::Variable(value) => {
                let mut expression = SymbolicExpression::atom(value);
                expression.set_line_number(line_number);

                match parse_stack.last_mut() {
                    None => output_list.push(expression),
                    Some((ref mut list, _)) => list.push(expression)
                };
            },
            LexItem::LiteralValue(value) => {
                let mut expression = SymbolicExpression::atom_value(value);
                expression.set_line_number(line_number);

                match parse_stack.last_mut() {
                    None => output_list.push(expression),
                    Some((ref mut list, _)) => list.push(expression)
                };
            },
            LexItem::Whitespace => ()
        };
    }

    // check unfinished stack:
    if parse_stack.len() > 0 {
        Err(Error::new(ErrType::ParseError("List expressions (..) left opened.".to_string())))
    } else {
        Ok(output_list)
    }
}

pub fn parse(input: &str) -> Result<Vec<SymbolicExpression>> {
    let lexed = lex(input)?;
    parse_lexed(lexed)
}


#[cfg(test)]
mod test {
    use vm::{SymbolicExpression, Value, parser};

    fn make_atom(x: &str, line: usize) -> SymbolicExpression {
        let mut e = SymbolicExpression::atom(x.to_string());
        e.set_line_number(line);
        e
    }

    fn make_atom_value(x: Value, line: usize) -> SymbolicExpression {
        let mut e = SymbolicExpression::atom_value(x);
        e.set_line_number(line);
        e
    }

    fn make_list(line: usize, x: Box<[SymbolicExpression]>) -> SymbolicExpression {
        let mut e = SymbolicExpression::list(x);
        e.set_line_number(line);
        e
    }

    #[test]
    fn test_parse_let_expression() {

        let input = "z (let ((x 1) (y 2))
                      (+ x ;; \"comments section?\"
                         ;; this is also a comment!
                         (let ((x 3)) ;; more commentary
                         (+ x y))     
                         x)) x y";
        let program = vec![
            make_atom("z", 1),
            make_list(1, Box::new([
                make_atom("let", 1),
                make_list(1, Box::new([
                    make_list(1, Box::new([
                        make_atom("x", 1),
                        make_atom_value(Value::Int(1), 1)])),
                    make_list(1, Box::new([
                        make_atom("y", 1),
                        make_atom_value(Value::Int(2), 1)]))])),
                make_list(2, Box::new([
                    make_atom("+", 2),
                    make_atom("x", 2),
                    make_list(4, Box::new([
                        make_atom("let", 4),
                        make_list(4, Box::new([
                            make_list(4, Box::new([
                                make_atom("x", 4),
                                make_atom_value(Value::Int(3), 4)]))])),
                        make_list(5, Box::new([
                            make_atom("+", 5),
                            make_atom("x", 5),
                            make_atom("y", 5)]))])),
                    make_atom("x", 6)]))])),
            make_atom("x", 6),
            make_atom("y", 6),
        ];

        let parsed = parser::parse(&input);
        assert_eq!(Ok(program), parsed, "Should match expected symbolic expression");
    }

    #[test]
    fn test_parse_failures() {
        use vm::errors::ErrType;

        let too_much_closure = "(let ((x 1) (y 2))))";
        let not_enough_closure = "(let ((x 1) (y 2))";
        let middle_hash = "(let ((x 1) (y#not 2)) x)";
        let unicode = "(let ((x🎶 1)) (eq x🎶 1))";
        let split_tokens = "(let ((023ab13 1)))";

        assert!(match parser::parse(&split_tokens).unwrap_err().err_type {
            ErrType::ParseError(_) => true,
            _ => false
        }, "Should have failed to parse with an expectation of whitespace or parens");

        assert!(match parser::parse(&too_much_closure).unwrap_err().err_type {
            ErrType::ParseError(_) => true,
            _ => false
        }, "Should have failed to parse with too many right parens");
        
        assert!(match parser::parse(&not_enough_closure).unwrap_err().err_type {
            ErrType::ParseError(_) => true,
            _ => false
        }, "Should have failed to parse with too few right parens");
        
        let x = parser::parse(&middle_hash).unwrap_err().err_type;
        assert!(match x {
            ErrType::ParseError(_) => true,
            _ => {
                println!("Expected parser error. Unexpected value is:\n {:?}", x);
                false
            }
        }, "Should have failed to parse with a middle hash");

        assert!(match parser::parse(&unicode).unwrap_err().err_type {
            ErrType::ParseError(_) => true,
            _ => false
        }, "Should have failed to parse a unicode variable name");

    }

}
