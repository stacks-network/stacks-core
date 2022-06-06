pub mod lexer;

use std::convert::TryFrom;

use self::lexer::error::LexerError;
use crate::vm::ast::errors::{ParseError, ParseErrors, ParseResult, PlacedError};
use crate::vm::ast::parser_v2::lexer::token::{PlacedToken, Token};
use crate::vm::ast::parser_v2::lexer::Lexer;
use crate::vm::diagnostic::{DiagnosableError, Diagnostic, Level};
use crate::vm::representations::{
    ClarityName, ContractName, PreSymbolicExpression, PreSymbolicExpressionType, Span,
};
use crate::vm::types::{
    CharType, PrincipalData, QualifiedContractIdentifier, SequenceData, StandardPrincipalData,
    TraitIdentifier, UTF8Data, Value,
};

pub struct Parser<'a> {
    lexer: Lexer<'a>,
    tokens: Vec<PlacedToken>,
    next_token: usize,
    comments: Vec<String>,
    diagnostics: Vec<PlacedError>,
    success: bool,
    // `fail_fast` mode indicates that the parser should not report warnings
    // and should exit on the first error. This is useful for parsing in the
    // context of a stacks-node, while normal mode is useful for developers.
    fail_fast: bool,
}

pub const MAX_STRING_LEN: usize = 128;
pub const MAX_CONTRACT_NAME_LEN: usize = 40;

impl<'a> Parser<'a> {
    pub fn new(input: &'a str, fail_fast: bool) -> Result<Self, ParseErrors> {
        let mut p = Self {
            lexer: Lexer::new(input, fail_fast),
            tokens: vec![],
            next_token: 0,
            comments: vec![],
            diagnostics: vec![],
            success: true,
            fail_fast,
        };

        loop {
            let token = match p.lexer.read_token() {
                Ok(token) => token,
                Err(e) => {
                    assert!(
                        fail_fast,
                        "Parser::read_token should not return an error when not in fail_fast mode"
                    );
                    p.success = false;
                    return Err(ParseErrors::Lexer(e));
                }
            };
            if token.token == Token::Eof {
                p.tokens.push(token);
                break;
            }
            p.tokens.push(token);
        }
        p.diagnostics = p
            .lexer
            .diagnostics
            .iter()
            .map(|lex_error| PlacedError {
                e: ParseErrors::Lexer(lex_error.e.clone()),
                span: lex_error.span.clone(),
            })
            .collect();
        p.success = p.lexer.success;
        Ok(p)
    }

    fn add_diagnostic(&mut self, e: ParseErrors, span: Span) -> ParseResult<()> {
        if self.fail_fast {
            return Err(ParseError::new(e));
        } else {
            if e.level() == Level::Error {
                self.success = false;
            }
            self.diagnostics.push(PlacedError { e, span });
        }
        Ok(())
    }

    fn next_token(&mut self) -> Option<PlacedToken> {
        // Early exit in fail_fast mode.
        if !self.success && self.fail_fast {
            return None;
        }

        if self.next_token >= self.tokens.len() {
            return None;
        }
        let token = self.tokens[self.next_token].clone();
        self.next_token = self.next_token + 1;
        Some(token)
    }

    fn ignore_whitespace(&mut self) -> bool {
        let mut found = false;
        loop {
            if self.next_token >= self.tokens.len() {
                return found;
            }
            let token = &self.tokens[self.next_token];
            match &token.token {
                Token::Whitespace => {
                    self.next_token = self.next_token + 1;
                    found = true;
                }
                Token::Comment(comment) => {
                    self.comments.push(comment.clone());
                    self.next_token = self.next_token + 1;
                    found = true;
                }
                _ => return found,
            }
        }
    }

    fn parse_list(&mut self, lparen: PlacedToken) -> ParseResult<PreSymbolicExpression> {
        let mut nodes = vec![];
        let mut span = lparen.span.clone();
        let mut whitespace = true;
        loop {
            if let Some(node) = self.parse_node()? {
                if !whitespace {
                    self.add_diagnostic(ParseErrors::ExpectedWhitespace, node.span.clone())?;
                }
                nodes.push(node);
                whitespace = self.ignore_whitespace();
            } else {
                let token = self.tokens[self.next_token - 1].clone();
                match token.token {
                    Token::Rparen => {
                        span.end_line = token.span.end_line;
                        span.end_column = token.span.end_column;
                        let mut e = PreSymbolicExpression::list(nodes.into_boxed_slice());
                        e.span = span;
                        return Ok(e);
                    }
                    Token::Eof => {
                        // Report an error, but return the list and attempt to continue parsing
                        self.add_diagnostic(
                            ParseErrors::ExpectedClosing(Token::Rparen),
                            token.span.clone(),
                        )?;
                        self.add_diagnostic(
                            ParseErrors::NoteToMatchThis(lparen.token),
                            lparen.span.clone(),
                        )?;
                        span.end_line = token.span.end_line;
                        span.end_column = token.span.end_column;
                        let mut e = PreSymbolicExpression::list(nodes.into_boxed_slice());
                        e.span = span;
                        return Ok(e);
                    }
                    _ => {
                        // Report an error, then skip this token
                        self.add_diagnostic(
                            ParseErrors::UnexpectedToken(token.token.clone()),
                            token.span.clone(),
                        )?;
                        whitespace = self.ignore_whitespace();
                    }
                };
            }
        }
    }

    fn parse_tuple(&mut self, lbrace: PlacedToken) -> ParseResult<PreSymbolicExpression> {
        let mut nodes = vec![];
        let mut span = lbrace.span.clone();
        let mut first = true;

        loop {
            self.ignore_whitespace();
            let token = self.tokens[self.next_token].clone();
            match token.token {
                Token::Comma => {
                    if first {
                        self.add_diagnostic(
                            ParseErrors::UnexpectedToken(token.token),
                            token.span.clone(),
                        )?;
                    }
                    self.next_token();
                }
                Token::Rbrace => {
                    span.end_line = token.span.end_line;
                    span.end_column = token.span.end_column;
                    self.next_token();
                    let mut e = PreSymbolicExpression::tuple(nodes.into_boxed_slice());
                    e.span = span;
                    return Ok(e);
                }
                Token::Eof => (),
                _ if !first => {
                    self.add_diagnostic(ParseErrors::TupleCommaExpectedv2, token.span.clone())?
                }
                _ => (),
            }

            // A comma is allowed after the last pair in the tuple -- check for this case.
            self.ignore_whitespace();
            let token = self.tokens[self.next_token].clone();
            match token.token {
                Token::Rbrace => {
                    span.end_line = token.span.end_line;
                    span.end_column = token.span.end_column;
                    self.next_token();
                    let mut e = PreSymbolicExpression::tuple(nodes.into_boxed_slice());
                    e.span = span;
                    return Ok(e);
                }
                _ => (),
            }

            // Parse key
            let node = match self.parse_node_or_eof()? {
                Some(node) => node,
                None => {
                    self.add_diagnostic(
                        ParseErrors::ExpectedClosing(Token::Rbrace),
                        token.span.clone(),
                    )?;
                    self.add_diagnostic(
                        ParseErrors::NoteToMatchThis(lbrace.token),
                        lbrace.span.clone(),
                    )?;
                    let mut e = PreSymbolicExpression::tuple(nodes.into_boxed_slice());
                    let span_before_eof = &self.tokens[self.tokens.len() - 2].span;
                    span.end_line = span_before_eof.end_line;
                    span.end_column = span_before_eof.end_column;
                    e.span = span;
                    return Ok(e);
                }
            };
            nodes.push(node);

            // Look for ':'
            self.ignore_whitespace();
            let token = self.tokens[self.next_token].clone();
            match token.token {
                Token::Colon => {
                    self.next_token();
                }
                Token::Eof => {
                    // This indicates we have reached the end of the input.
                    // Create a placeholder value so that parsing can continue,
                    // then return.
                    self.add_diagnostic(ParseErrors::TupleColonExpectedv2, token.span.clone())?;
                    let mut placeholder =
                        PreSymbolicExpression::atom(ClarityName::from("placeholder"));
                    placeholder.span = token.span.clone();
                    nodes.push(placeholder); // Placeholder value
                    let mut e = PreSymbolicExpression::tuple(nodes.into_boxed_slice());
                    let span_before_eof = &self.tokens[self.tokens.len() - 2].span;
                    span.end_line = span_before_eof.end_line;
                    span.end_column = span_before_eof.end_column;
                    e.span = span;
                    return Ok(e);
                }
                _ => {
                    // Record an error, then continue to parse
                    self.add_diagnostic(ParseErrors::TupleColonExpectedv2, token.span.clone())?;
                }
            }

            // Parse value
            let node = match self.parse_node_or_eof()? {
                Some(node) => node,
                None => {
                    // This indicates we have reached the end of the input.
                    // Create a placeholder value so that parsing can continue,
                    // then return.
                    let eof_span = self.tokens[self.next_token - 1].span.clone();
                    self.add_diagnostic(ParseErrors::TupleValueExpected, token.span.clone())?;
                    let mut placeholder =
                        PreSymbolicExpression::atom(ClarityName::from("placeholder"));
                    placeholder.span = eof_span;
                    nodes.push(placeholder); // Placeholder value
                    let mut e = PreSymbolicExpression::tuple(nodes.into_boxed_slice());
                    span.end_line = token.span.end_line;
                    span.end_column = token.span.end_column;
                    e.span = span;
                    return Ok(e);
                }
            };
            nodes.push(node);

            first = false;
        }
    }

    // Returns some valid expression. When None is returned, check the current token.
    pub fn parse_node(&mut self) -> ParseResult<Option<PreSymbolicExpression>> {
        self.ignore_whitespace();
        let token = self.next_token();
        if token.is_none() {
            return Ok(None);
        }
        let token = token.unwrap();
        // let mut comment = None;
        let node = match token.token {
            Token::Lparen => Some(self.parse_list(token)?),
            Token::Lbrace => Some(self.parse_tuple(token)?),
            Token::Int(val) => {
                let mut e = PreSymbolicExpression::atom_value(Value::Int(val));
                e.span = token.span;
                Some(e)
            }
            Token::Uint(val) => {
                let mut e = PreSymbolicExpression::atom_value(Value::UInt(val));
                e.span = token.span;
                Some(e)
            }
            Token::AsciiString(val) => {
                let str_val = match Value::string_ascii_from_bytes(val.clone().into_bytes()) {
                    Ok(s) => s,
                    Err(_) => {
                        self.add_diagnostic(
                            ParseErrors::IllegalASCIIString(val),
                            token.span.clone(),
                        )?;
                        Value::string_ascii_from_bytes("placeholder".as_bytes().to_vec()).unwrap()
                    }
                };
                let mut e = PreSymbolicExpression::atom_value(str_val);
                e.span = token.span;
                Some(e)
            }
            Token::Utf8String(data) => {
                let str_val =
                    Value::Sequence(SequenceData::String(CharType::UTF8(UTF8Data { data })));
                let mut e = PreSymbolicExpression::atom_value(str_val);
                e.span = token.span;
                Some(e)
            }
            Token::Ident(mut name) => {
                if name.len() > MAX_STRING_LEN {
                    self.add_diagnostic(
                        ParseErrors::NameTooLong(name.clone()),
                        token.span.clone(),
                    )?;
                    // Continue with a placeholder name
                    name = "placeholder".to_string();
                }
                let cname = match ClarityName::try_from(name.clone()) {
                    Ok(name) => name,
                    Err(_) => {
                        self.add_diagnostic(
                            ParseErrors::IllegalClarityName(name.clone()),
                            token.span.clone(),
                        )?;
                        ClarityName::try_from("placeholder").unwrap()
                    }
                };
                let mut e = PreSymbolicExpression::atom(cname);
                e.span = token.span;
                Some(e)
            }
            Token::TraitIdent(mut name) => {
                if name.len() > MAX_STRING_LEN {
                    self.add_diagnostic(
                        ParseErrors::NameTooLong(name.clone()),
                        token.span.clone(),
                    )?;
                    // Continue with a placeholder name
                    name = "placeholder".to_string();
                }
                let cname = match ClarityName::try_from(name.clone()) {
                    Ok(name) => name,
                    Err(_) => {
                        self.add_diagnostic(
                            ParseErrors::IllegalTraitName(name.clone()),
                            token.span.clone(),
                        )?;
                        ClarityName::try_from("placeholder").unwrap()
                    }
                };
                let mut e = PreSymbolicExpression::trait_reference(cname);
                e.span = token.span;
                Some(e)
            }
            Token::Bytes(data) => {
                let value = match Value::buff_from(data) {
                    Ok(value) => value,
                    _ => {
                        self.add_diagnostic(ParseErrors::InvalidBuffer, token.span.clone())?;
                        Value::buff_from_byte(0)
                    }
                };
                let mut e = PreSymbolicExpression::atom_value(value);
                e.span = token.span;
                Some(e)
            }
            Token::Principal(addr) => {
                let principal = match PrincipalData::parse_standard_principal(&addr) {
                    Ok(principal) => principal,
                    _ => {
                        self.add_diagnostic(
                            ParseErrors::InvalidPrincipalLiteral,
                            token.span.clone(),
                        )?;
                        StandardPrincipalData::transient()
                    }
                };

                // Peek ahead for a '.', indicating a contract identifier
                if self.tokens[self.next_token].token == Token::Dot {
                    let mut span = token.span.clone();
                    self.next_token(); // skip over the dot
                    let mut name = match self.next_token() {
                        Some(PlacedToken {
                            span: contract_span,
                            token: Token::Ident(ident),
                        }) => {
                            span.end_line = contract_span.end_line;
                            span.end_column = contract_span.end_column;
                            ident
                        }
                        _ => {
                            self.add_diagnostic(
                                ParseErrors::ExpectedContractIdentifier,
                                self.tokens[self.next_token - 1].span.clone(),
                            )?;
                            "placeholder".to_string()
                        }
                    };

                    if name.len() > MAX_CONTRACT_NAME_LEN {
                        self.add_diagnostic(
                            ParseErrors::ContractNameTooLong(name),
                            self.tokens[self.next_token - 1].span.clone(),
                        )?;
                        // Continue with a placeholder name
                        name = "placeholder".to_string();
                    }
                    let contract_name = match ContractName::try_from(name.clone()) {
                        Ok(id) => id,
                        Err(_) => {
                            self.add_diagnostic(
                                ParseErrors::IllegalContractName(name.clone()),
                                self.tokens[self.next_token - 1].span.clone(),
                            )?;
                            ContractName::try_from("placeholder".to_string()).unwrap()
                        }
                    };
                    let contract_id = QualifiedContractIdentifier::new(principal, contract_name);

                    // Peek ahead for a '.', indicating a trait identifier
                    if self.tokens[self.next_token].token == Token::Dot {
                        let mut span = token.span.clone();
                        self.next_token(); // skip over the dot
                        let mut name = match self.next_token() {
                            Some(PlacedToken {
                                span: contract_span,
                                token: Token::Ident(ident),
                            }) => {
                                span.end_line = contract_span.end_line;
                                span.end_column = contract_span.end_column;
                                ident
                            }
                            _ => {
                                self.add_diagnostic(
                                    ParseErrors::ExpectedTraitIdentifier,
                                    self.tokens[self.next_token - 1].span.clone(),
                                )?;
                                "placeholder".to_string()
                            }
                        };
                        if name.len() > MAX_STRING_LEN {
                            self.add_diagnostic(
                                ParseErrors::NameTooLong(name.clone()),
                                self.tokens[self.next_token - 1].span.clone(),
                            )?;
                            // Continue with a placeholder name
                            name = "placeholder".to_string();
                        }
                        let trait_name = match ClarityName::try_from(name.clone()) {
                            Ok(id) => id,
                            Err(_) => {
                                self.add_diagnostic(
                                    ParseErrors::IllegalTraitName(name),
                                    self.tokens[self.next_token - 1].span.clone(),
                                )?;
                                ClarityName::try_from("placeholder".to_string()).unwrap()
                            }
                        };
                        let trait_id = TraitIdentifier {
                            name: trait_name,
                            contract_identifier: contract_id,
                        };
                        let mut e = PreSymbolicExpression::field_identifier(trait_id);
                        e.span = span;
                        Some(e)
                    } else {
                        let contract_principal = PrincipalData::Contract(contract_id);
                        let mut e =
                            PreSymbolicExpression::atom_value(Value::Principal(contract_principal));
                        e.span = span;
                        Some(e)
                    }
                } else {
                    let mut e = PreSymbolicExpression::atom_value(Value::Principal(
                        PrincipalData::Standard(principal),
                    ));
                    e.span = token.span;
                    Some(e)
                }
            }
            Token::Dot => {
                let mut span = token.span.clone();
                let name = match self.next_token() {
                    Some(PlacedToken {
                        span: contract_span,
                        token: Token::Ident(ident),
                    }) => {
                        span.end_line = contract_span.end_line;
                        span.end_column = contract_span.end_column;
                        ident
                    }
                    _ => {
                        self.add_diagnostic(
                            ParseErrors::ExpectedContractIdentifier,
                            self.tokens[self.next_token - 1].span.clone(),
                        )?;
                        "placeholder".to_string()
                    }
                };
                let contract_name = match ContractName::try_from(name.clone()) {
                    Ok(id) => id,
                    Err(_) => {
                        self.add_diagnostic(
                            ParseErrors::IllegalContractName(name),
                            self.tokens[self.next_token - 1].span.clone(),
                        )?;
                        ContractName::try_from("placeholder".to_string()).unwrap()
                    }
                };

                // Peek ahead for a '.', indicating a trait identifier
                if self.tokens[self.next_token].token == Token::Dot {
                    let mut span = token.span.clone();
                    self.next_token(); // skip over the dot
                    let mut name = match self.next_token() {
                        Some(PlacedToken {
                            span: contract_span,
                            token: Token::Ident(ident),
                        }) => {
                            span.end_line = contract_span.end_line;
                            span.end_column = contract_span.end_column;
                            ident
                        }
                        _ => {
                            self.add_diagnostic(
                                ParseErrors::ExpectedTraitIdentifier,
                                self.tokens[self.next_token - 1].span.clone(),
                            )?;
                            "placeholder".to_string()
                        }
                    };
                    if name.len() > MAX_STRING_LEN {
                        self.add_diagnostic(
                            ParseErrors::NameTooLong(name.clone()),
                            self.tokens[self.next_token - 1].span.clone(),
                        )?;
                        // Continue with a placeholder name
                        name = "placeholder".to_string();
                    }
                    let trait_name = match ClarityName::try_from(name.clone()) {
                        Ok(id) => id,
                        Err(_) => {
                            self.add_diagnostic(
                                ParseErrors::IllegalTraitName(name),
                                self.tokens[self.next_token - 1].span.clone(),
                            )?;
                            ClarityName::try_from("placeholder".to_string()).unwrap()
                        }
                    };
                    let mut e =
                        PreSymbolicExpression::sugared_field_identifier(contract_name, trait_name);
                    e.span = span;
                    Some(e)
                } else {
                    let mut e = PreSymbolicExpression::sugared_contract_identifier(contract_name);
                    e.span = span;
                    Some(e)
                }
            }
            Token::Plus
            | Token::Minus
            | Token::Multiply
            | Token::Divide
            | Token::Less
            | Token::LessEqual
            | Token::Greater
            | Token::GreaterEqual => {
                let name = ClarityName::try_from(format!("{}", token.token)).unwrap();
                let mut e = PreSymbolicExpression::atom(name);
                e.span = token.span;
                Some(e)
            }
            // TODO: For now, comments are being treated as whitespace. In the future,
            //       they should be attached to the following expression
            // Token::Comment(comment) => {
            //     self.comments.push(comment);
            //     None
            // }
            Token::Eof => None,
            _ => None, // Other tokens should be dealt with by the caller
        };

        Ok(node)
    }

    pub fn parse_node_or_eof(&mut self) -> ParseResult<Option<PreSymbolicExpression>> {
        loop {
            match self.parse_node()? {
                Some(node) => break Ok(Some(node)),
                None => {
                    let token = self.tokens[self.next_token - 1].clone();
                    match token.token {
                        Token::Eof => break Ok(None),
                        _ => {
                            // Report an error, then skip this token
                            self.add_diagnostic(
                                ParseErrors::UnexpectedToken(token.token),
                                token.span,
                            )?;
                        }
                    }
                }
            }
        }
    }

    pub fn parse(&mut self) -> ParseResult<Vec<PreSymbolicExpression>> {
        let mut nodes = vec![];

        loop {
            match self.parse_node_or_eof()? {
                Some(node) => {
                    nodes.push(node);
                }
                None => break,
            }
        }
        Ok(nodes)
    }
}

pub fn parse(input: &str) -> ParseResult<Vec<PreSymbolicExpression>> {
    let mut parser = match Parser::new(input, true) {
        Ok(parser) => parser,
        Err(e) => return Err(ParseError::new(e)),
    };
    let stmts = parser.parse()?;
    if parser.success {
        Ok(stmts)
    } else {
        let err = parser.diagnostics.remove(0);
        Err(ParseError::new(err.e))
    }
}

pub fn parse_collect_diagnostics(
    input: &str,
) -> (Vec<PreSymbolicExpression>, Vec<Diagnostic>, bool) {
    // When not in fail_fast mode, Parser::new always returns Ok.
    let mut parser = Parser::new(input, false).unwrap();

    // When not in fail_fast mode, Parser::parse always returns Ok.
    let stmts = parser.parse().unwrap();
    let diagnostics = parser
        .diagnostics
        .iter()
        .map(|e| Diagnostic {
            level: e.e.level(),
            message: e.e.message(),
            spans: vec![e.span.clone()],
            suggestion: None,
        })
        .collect();
    (stmts, diagnostics, parser.success)
}

#[cfg(test)]
mod tests {
    use crate::vm::{
        diagnostic::Level,
        types::{
            ASCIIData, CharType, PrincipalData, SequenceData, StandardPrincipalData, UTF8Data,
        },
    };

    use super::*;

    #[test]
    fn test_parse_int() {
        let (stmts, diagnostics, success) = parse_collect_diagnostics("    123");
        assert_eq!(success, true);
        assert_eq!(stmts.len(), 1);
        assert_eq!(diagnostics.len(), 0);
        if let Some(Value::Int(123)) = stmts[0].match_atom_value() {
        } else {
            panic!("failed to parse int value");
        }
        assert_eq!(
            stmts[0].span,
            Span {
                start_line: 1,
                start_column: 5,
                end_line: 1,
                end_column: 7
            }
        );

        let (stmts, diagnostics, success) = parse_collect_diagnostics("    -123");
        assert_eq!(success, true);
        assert_eq!(stmts.len(), 1);
        assert_eq!(diagnostics.len(), 0);
        if let Some(Value::Int(-123)) = stmts[0].match_atom_value() {
        } else {
            panic!("failed to parse negative int value");
        }
        assert_eq!(
            stmts[0].span,
            Span {
                start_line: 1,
                start_column: 5,
                end_line: 1,
                end_column: 8
            }
        );

        let (stmts, diagnostics, success) = parse_collect_diagnostics("42g ");
        assert_eq!(success, false);
        assert_eq!(stmts.len(), 1);
        if let Some(Value::Int(42)) = stmts[0].match_atom_value() {
        } else {
            panic!("failed to parse int value with error");
        }
        assert_eq!(
            stmts[0].span,
            Span {
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 3
            }
        );
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].level, Level::Error);
        assert_eq!(
            diagnostics[0].message,
            "invalid character, 'g', in int literal".to_string()
        );
        assert_eq!(
            diagnostics[0].spans[0],
            Span {
                start_line: 1,
                start_column: 3,
                end_line: 1,
                end_column: 3
            }
        );
    }

    #[test]
    fn test_parse_uint() {
        let (stmts, diagnostics, success) = parse_collect_diagnostics("    u98");
        assert_eq!(success, true);
        assert_eq!(stmts.len(), 1);
        assert_eq!(diagnostics.len(), 0);
        if let Some(Value::UInt(98)) = stmts[0].match_atom_value() {
        } else {
            panic!("failed to parse uint value");
        }
        assert_eq!(
            stmts[0].span,
            Span {
                start_line: 1,
                start_column: 5,
                end_line: 1,
                end_column: 7
            }
        );

        let (stmts, diagnostics, success) = parse_collect_diagnostics("\n u2*3");
        assert_eq!(success, false);
        assert_eq!(stmts.len(), 1);
        if let Some(Value::UInt(2)) = stmts[0].match_atom_value() {
        } else {
            panic!("failed to parse uint value with error");
        }
        assert_eq!(
            stmts[0].span,
            Span {
                start_line: 2,
                start_column: 2,
                end_line: 2,
                end_column: 5
            }
        );
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].level, Level::Error);
        assert_eq!(
            diagnostics[0].message,
            "invalid character, '*', in uint literal".to_string()
        );
        assert_eq!(
            diagnostics[0].spans[0],
            Span {
                start_line: 2,
                start_column: 4,
                end_line: 2,
                end_column: 5
            }
        );
    }

    #[test]
    fn test_parse_ascii_string() {
        let (stmts, diagnostics, success) = parse_collect_diagnostics("\"new\\nline\"");
        assert_eq!(success, true);
        assert_eq!(stmts.len(), 1);
        assert_eq!(diagnostics.len(), 0);
        if let Some(v) = stmts[0].match_atom_value() {
            assert_eq!(v.clone().expect_ascii(), "new\nline");
        } else {
            panic!("failed to parse ascii string");
        }
        assert_eq!(
            stmts[0].span,
            Span {
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 11
            }
        );

        let (stmts, diagnostics, success) = parse_collect_diagnostics("\"👎 nope\"");
        assert_eq!(success, false);
        assert_eq!(stmts.len(), 1);
        if let Some(v) = stmts[0].match_atom_value() {
            assert_eq!(v.clone().expect_ascii(), " nope");
        } else {
            panic!("failed to parse ascii value with error");
        }
        assert_eq!(
            stmts[0].span,
            Span {
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 8
            }
        );
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].level, Level::Error);
        assert_eq!(
            diagnostics[0].message,
            "invalid character, '👎', in string literal".to_string()
        );
        assert_eq!(
            diagnostics[0].spans[0],
            Span {
                start_line: 1,
                start_column: 2,
                end_line: 1,
                end_column: 2
            }
        );
    }

    #[test]
    fn test_parse_utf8_string() {
        let (stmts, diagnostics, success) = parse_collect_diagnostics("u\"new\\nline\\u{1f601}\"");
        assert_eq!(success, true);
        assert_eq!(stmts.len(), 1);
        assert_eq!(diagnostics.len(), 0);
        if let Some(v) = stmts[0].match_atom_value() {
            let s = match v {
                Value::Sequence(SequenceData::String(CharType::UTF8(data))) => format!("{}", data),
                _ => panic!("failed to parse UTF8 string "),
            };
            assert_eq!(s, "u\"new\\nline\\u{f09f9881}\"");
        } else {
            panic!("failed to parse utf8 string value");
        }
        assert_eq!(
            stmts[0].span,
            Span {
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 21
            }
        );

        let (stmts, diagnostics, success) = parse_collect_diagnostics("u\"\\m nope\"");
        assert_eq!(success, false);
        assert_eq!(stmts.len(), 1);
        if let Some(v) = stmts[0].match_atom_value() {
            let s = match v {
                Value::Sequence(SequenceData::String(CharType::UTF8(data))) => format!("{}", data),
                _ => panic!("failed to parse UTF8 string "),
            };
            assert_eq!(s, "u\"? nope\"");
        } else {
            panic!("failed to parse utf8 string with error");
        }
        assert_eq!(
            stmts[0].span,
            Span {
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 10
            }
        );
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].level, Level::Error);
        assert_eq!(
            diagnostics[0].message,
            "unknown escape character, 'm'".to_string()
        );
        assert_eq!(
            diagnostics[0].spans[0],
            Span {
                start_line: 1,
                start_column: 3,
                end_line: 1,
                end_column: 4
            }
        );
    }

    #[test]
    fn test_parse_identifier() {
        let (stmts, diagnostics, success) = parse_collect_diagnostics("foo-bar");
        assert_eq!(success, true);
        assert_eq!(stmts.len(), 1);
        assert_eq!(diagnostics.len(), 0);
        if let Some(v) = stmts[0].match_atom() {
            assert_eq!(v.as_str(), "foo-bar");
        } else {
            panic!("failed to parse identifier");
        }
        assert_eq!(
            stmts[0].span,
            Span {
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 7
            }
        );

        let (stmts, diagnostics, success) = parse_collect_diagnostics("veryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryverylong");
        assert_eq!(success, false);
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].level, Level::Error);
        assert_eq!(
            diagnostics[0].message,
            "illegal name (too long), 'veryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryverylong'".to_string()
        );
        assert_eq!(
            diagnostics[0].spans[0],
            Span {
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 132
            }
        );
    }

    #[test]
    fn test_parse_list() {
        let (stmts, diagnostics, success) = parse_collect_diagnostics("(foo 1 u3 \"hel\tlo\")");
        assert_eq!(success, true);
        assert_eq!(stmts.len(), 1);
        assert_eq!(diagnostics.len(), 0);
        assert_eq!(
            stmts[0].span,
            Span {
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 19
            }
        );
        let exprs = stmts[0].match_list().unwrap();
        match &exprs[0].pre_expr {
            PreSymbolicExpressionType::Atom(cname) => assert_eq!(cname.as_str(), "foo"),
            _ => panic!("expected atom 'foo'"),
        }
        assert_eq!(
            exprs[0].span,
            Span {
                start_line: 1,
                start_column: 2,
                end_line: 1,
                end_column: 4
            }
        );
        match exprs[1].pre_expr {
            PreSymbolicExpressionType::AtomValue(Value::Int(1)) => (),
            _ => panic!("expected Value(1)"),
        }
        assert_eq!(
            exprs[1].span,
            Span {
                start_line: 1,
                start_column: 6,
                end_line: 1,
                end_column: 6
            }
        );
        match exprs[2].pre_expr {
            PreSymbolicExpressionType::AtomValue(Value::UInt(3)) => (),
            _ => panic!("expected Value(u3)"),
        }
        assert_eq!(
            exprs[2].span,
            Span {
                start_line: 1,
                start_column: 8,
                end_line: 1,
                end_column: 9
            }
        );
        match &exprs[3].pre_expr {
            PreSymbolicExpressionType::AtomValue(Value::Sequence(SequenceData::String(
                CharType::ASCII(ASCIIData { data: s }),
            ))) => assert_eq!(s, "hel\tlo".as_bytes()), //assert_eq!(val.expect_ascii(), "hel\tlo"),
            _ => panic!("expected Value(\"hel\tlo\")"),
        }
        assert_eq!(
            exprs[3].span,
            Span {
                start_line: 1,
                start_column: 11,
                end_line: 1,
                end_column: 18
            }
        );

        let (stmts, diagnostics, success) = parse_collect_diagnostics("(1 2 3");
        assert_eq!(success, false);
        assert_eq!(stmts.len(), 1);
        let exprs = stmts[0].match_list().unwrap();
        match exprs[0].pre_expr {
            PreSymbolicExpressionType::AtomValue(Value::Int(1)) => (),
            _ => panic!("expected Value(1)"),
        }
        assert_eq!(
            exprs[0].span,
            Span {
                start_line: 1,
                start_column: 2,
                end_line: 1,
                end_column: 2
            }
        );
        match exprs[1].pre_expr {
            PreSymbolicExpressionType::AtomValue(Value::Int(2)) => (),
            _ => panic!("expected Value(2)"),
        }
        assert_eq!(
            exprs[1].span,
            Span {
                start_line: 1,
                start_column: 4,
                end_line: 1,
                end_column: 4
            }
        );
        match exprs[2].pre_expr {
            PreSymbolicExpressionType::AtomValue(Value::Int(3)) => (),
            _ => panic!("expected Value(3)"),
        }
        assert_eq!(
            exprs[2].span,
            Span {
                start_line: 1,
                start_column: 6,
                end_line: 1,
                end_column: 6
            }
        );
        assert_eq!(diagnostics.len(), 2);
        assert_eq!(diagnostics[0].level, Level::Error);
        assert_eq!(diagnostics[0].message, "expected closing ')'".to_string());
        assert_eq!(
            diagnostics[0].spans[0],
            Span {
                start_line: 1,
                start_column: 7,
                end_line: 1,
                end_column: 7
            }
        );

        assert_eq!(diagnostics[1].level, Level::Note);
        assert_eq!(diagnostics[1].message, "to match this '('".to_string());
        assert_eq!(
            diagnostics[1].spans[0],
            Span {
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 1
            }
        );

        let (stmts, diagnostics, success) = parse_collect_diagnostics("(1 2 3\n )");
        assert_eq!(success, true);
        assert_eq!(stmts.len(), 1);
        assert_eq!(diagnostics.len(), 0);
        assert_eq!(
            stmts[0].span,
            Span {
                start_line: 1,
                start_column: 1,
                end_line: 2,
                end_column: 2
            }
        );
        let exprs = stmts[0].match_list().unwrap();
        assert_eq!(exprs.len(), 3);
    }

    #[test]
    fn test_parse_tuple() {
        let (stmts, diagnostics, success) = parse_collect_diagnostics("{foo: bar}");
        assert_eq!(success, true);
        assert_eq!(stmts.len(), 1);
        assert_eq!(diagnostics.len(), 0);
        assert_eq!(
            stmts[0].span,
            Span {
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 10
            }
        );
        let list: &[PreSymbolicExpression] = match stmts[0].pre_expr {
            PreSymbolicExpressionType::Tuple(ref list) => list,
            _ => panic!("failed to parse tuple"),
        };
        assert_eq!(list.len(), 2);
        if let Some(name) = list[0].match_atom() {
            assert_eq!(name.as_str(), "foo");
        } else {
            panic!("failed to parse identifier");
        }
        assert_eq!(
            list[0].span,
            Span {
                start_line: 1,
                start_column: 2,
                end_line: 1,
                end_column: 4
            }
        );

        if let Some(name) = list[1].match_atom() {
            assert_eq!(name.as_str(), "bar");
        } else {
            panic!("failed to parse identifier");
        }
        assert_eq!(
            list[1].span,
            Span {
                start_line: 1,
                start_column: 7,
                end_line: 1,
                end_column: 9,
            }
        );

        let (stmts, diagnostics, success) = parse_collect_diagnostics("{1: u2, 3: u4}");
        assert_eq!(success, true);
        assert_eq!(stmts.len(), 1);
        assert_eq!(diagnostics.len(), 0);
        assert_eq!(
            stmts[0].span,
            Span {
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 14
            }
        );
        let list: &[PreSymbolicExpression] = match stmts[0].pre_expr {
            PreSymbolicExpressionType::Tuple(ref list) => list,
            _ => panic!("failed to parse tuple"),
        };
        assert_eq!(list.len(), 4);
        match list[0].match_atom_value() {
            Some(Value::Int(1)) => (),
            _ => panic!("failed to parse tuple"),
        }
        match list[1].match_atom_value() {
            Some(Value::UInt(2)) => (),
            _ => panic!("failed to parse tuple"),
        }
        match list[2].match_atom_value() {
            Some(Value::Int(3)) => (),
            _ => panic!("failed to parse tuple"),
        }
        match list[3].match_atom_value() {
            Some(Value::UInt(4)) => (),
            _ => panic!("failed to parse tuple"),
        }

        let (stmts, diagnostics, success) = parse_collect_diagnostics("{, foo: bar}");
        assert_eq!(success, false);
        assert_eq!(stmts.len(), 1);
        let list: &[PreSymbolicExpression] = match stmts[0].pre_expr {
            PreSymbolicExpressionType::Tuple(ref list) => list,
            _ => panic!("failed to parse tuple"),
        };
        assert_eq!(list.len(), 2);
        if let Some(name) = list[0].match_atom() {
            assert_eq!(name.as_str(), "foo");
        } else {
            panic!("failed to parse identifier");
        }
        assert_eq!(
            list[0].span,
            Span {
                start_line: 1,
                start_column: 4,
                end_line: 1,
                end_column: 6
            }
        );
        if let Some(name) = list[1].match_atom() {
            assert_eq!(name.as_str(), "bar");
        } else {
            panic!("failed to parse identifier");
        }
        assert_eq!(
            list[1].span,
            Span {
                start_line: 1,
                start_column: 9,
                end_line: 1,
                end_column: 11
            }
        );
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].level, Level::Error);
        assert_eq!(diagnostics[0].message, "unexpected ','".to_string());
        assert_eq!(
            diagnostics[0].spans[0],
            Span {
                start_line: 1,
                start_column: 2,
                end_line: 1,
                end_column: 2
            }
        );

        let (stmts, diagnostics, success) = parse_collect_diagnostics("{  ");
        assert_eq!(success, false);
        assert_eq!(stmts.len(), 1);
        assert_eq!(
            stmts[0].span,
            Span {
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 3
            }
        );
        let list: &[PreSymbolicExpression] = match stmts[0].pre_expr {
            PreSymbolicExpressionType::Tuple(ref list) => list,
            _ => panic!("failed to parse tuple"),
        };
        assert_eq!(list.len(), 0);
        assert_eq!(diagnostics.len(), 2);
        assert_eq!(diagnostics[0].level, Level::Error);
        assert_eq!(diagnostics[0].message, "expected closing '}'".to_string());
        assert_eq!(
            diagnostics[0].spans[0],
            Span {
                start_line: 1,
                start_column: 4,
                end_line: 1,
                end_column: 4
            }
        );
        assert_eq!(diagnostics[1].level, Level::Note);
        assert_eq!(diagnostics[1].message, "to match this '{'".to_string());
        assert_eq!(
            diagnostics[1].spans[0],
            Span {
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 1
            }
        );

        let (stmts, diagnostics, success) = parse_collect_diagnostics("{foo:");
        assert_eq!(success, false);
        assert_eq!(stmts.len(), 1);
        assert_eq!(
            stmts[0].span,
            Span {
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 5
            }
        );
        let list: &[PreSymbolicExpression] = match stmts[0].pre_expr {
            PreSymbolicExpressionType::Tuple(ref list) => list,
            _ => panic!("failed to parse tuple"),
        };
        assert_eq!(list.len(), 2);
        if let Some(name) = list[0].match_atom() {
            assert_eq!(name.as_str(), "foo");
        } else {
            panic!("failed to parse identifier");
        }
        assert_eq!(
            list[0].span,
            Span {
                start_line: 1,
                start_column: 2,
                end_line: 1,
                end_column: 4
            }
        );
        if let Some(name) = list[1].match_atom() {
            assert_eq!(name.as_str(), "placeholder");
        } else {
            panic!("failed to parse identifier");
        }
        assert_eq!(
            list[1].span,
            Span {
                start_line: 1,
                start_column: 6,
                end_line: 1,
                end_column: 6
            }
        );
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].level, Level::Error);
        assert_eq!(
            diagnostics[0].message,
            "expected value expression for tuple".to_string()
        );
        assert_eq!(
            diagnostics[0].spans[0],
            Span {
                start_line: 1,
                start_column: 5,
                end_line: 1,
                end_column: 5
            }
        );

        let (stmts, diagnostics, success) = parse_collect_diagnostics("{foo:bar");
        assert_eq!(success, false);
        assert_eq!(stmts.len(), 1);
        assert_eq!(
            stmts[0].span,
            Span {
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 8
            }
        );
        let list: &[PreSymbolicExpression] = match stmts[0].pre_expr {
            PreSymbolicExpressionType::Tuple(ref list) => list,
            _ => panic!("failed to parse tuple"),
        };
        assert_eq!(list.len(), 2);
        if let Some(name) = list[0].match_atom() {
            assert_eq!(name.as_str(), "foo");
        } else {
            panic!("failed to parse identifier");
        }
        assert_eq!(
            list[0].span,
            Span {
                start_line: 1,
                start_column: 2,
                end_line: 1,
                end_column: 4
            }
        );
        if let Some(name) = list[1].match_atom() {
            assert_eq!(name.as_str(), "bar");
        } else {
            panic!("failed to parse identifier");
        }
        assert_eq!(
            list[1].span,
            Span {
                start_line: 1,
                start_column: 6,
                end_line: 1,
                end_column: 8
            }
        );
        assert_eq!(diagnostics.len(), 2);
        assert_eq!(diagnostics[0].level, Level::Error);
        assert_eq!(diagnostics[0].message, "expected closing '}'".to_string());
        assert_eq!(
            diagnostics[0].spans[0],
            Span {
                start_line: 1,
                start_column: 9,
                end_line: 1,
                end_column: 9
            }
        );
        assert_eq!(diagnostics[1].level, Level::Note);
        assert_eq!(diagnostics[1].message, "to match this '{'".to_string());
        assert_eq!(
            diagnostics[1].spans[0],
            Span {
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 1
            }
        );

        let (stmts, diagnostics, success) = parse_collect_diagnostics("{foo:bar boo:far}");
        assert_eq!(success, false);
        assert_eq!(stmts.len(), 1);
        assert_eq!(
            stmts[0].span,
            Span {
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 17
            }
        );
        let list: &[PreSymbolicExpression] = match stmts[0].pre_expr {
            PreSymbolicExpressionType::Tuple(ref list) => list,
            _ => panic!("failed to parse tuple"),
        };
        assert_eq!(list.len(), 4);
        if let Some(name) = list[2].match_atom() {
            assert_eq!(name.as_str(), "boo");
        } else {
            panic!("failed to parse identifier");
        }
        assert_eq!(
            list[2].span,
            Span {
                start_line: 1,
                start_column: 10,
                end_line: 1,
                end_column: 12
            }
        );
        if let Some(name) = list[3].match_atom() {
            assert_eq!(name.as_str(), "far");
        } else {
            panic!("failed to parse identifier");
        }
        assert_eq!(
            list[3].span,
            Span {
                start_line: 1,
                start_column: 14,
                end_line: 1,
                end_column: 16
            }
        );
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].level, Level::Error);
        assert_eq!(
            diagnostics[0].message,
            "expected ',' separating key-value pairs in tuple".to_string()
        );
        assert_eq!(
            diagnostics[0].spans[0],
            Span {
                start_line: 1,
                start_column: 10,
                end_line: 1,
                end_column: 12
            }
        );

        let (stmts, diagnostics, success) = parse_collect_diagnostics("{foo bar}");
        assert_eq!(success, false);
        assert_eq!(stmts.len(), 1);
        assert_eq!(
            stmts[0].span,
            Span {
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 9
            }
        );
        let list: &[PreSymbolicExpression] = match stmts[0].pre_expr {
            PreSymbolicExpressionType::Tuple(ref list) => list,
            _ => panic!("failed to parse tuple"),
        };
        assert_eq!(list.len(), 2);
        if let Some(name) = list[0].match_atom() {
            assert_eq!(name.as_str(), "foo");
        } else {
            panic!("failed to parse identifier");
        }
        assert_eq!(
            list[0].span,
            Span {
                start_line: 1,
                start_column: 2,
                end_line: 1,
                end_column: 4
            }
        );
        if let Some(name) = list[1].match_atom() {
            assert_eq!(name.as_str(), "bar");
        } else {
            panic!("failed to parse identifier");
        }
        assert_eq!(
            list[1].span,
            Span {
                start_line: 1,
                start_column: 6,
                end_line: 1,
                end_column: 8
            }
        );
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].level, Level::Error);
        assert_eq!(
            diagnostics[0].message,
            "expected ':' after key in tuple".to_string()
        );
        assert_eq!(
            diagnostics[0].spans[0],
            Span {
                start_line: 1,
                start_column: 6,
                end_line: 1,
                end_column: 8
            }
        );

        let (stmts, diagnostics, success) = parse_collect_diagnostics("{foo");
        assert_eq!(success, false);
        assert_eq!(stmts.len(), 1);
        assert_eq!(
            stmts[0].span,
            Span {
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 4
            }
        );
        let list: &[PreSymbolicExpression] = match stmts[0].pre_expr {
            PreSymbolicExpressionType::Tuple(ref list) => list,
            _ => panic!("failed to parse tuple"),
        };
        assert_eq!(list.len(), 2);
        if let Some(name) = list[0].match_atom() {
            assert_eq!(name.as_str(), "foo");
        } else {
            panic!("failed to parse identifier");
        }
        assert_eq!(
            list[0].span,
            Span {
                start_line: 1,
                start_column: 2,
                end_line: 1,
                end_column: 4
            }
        );
        if let Some(name) = list[1].match_atom() {
            assert_eq!(name.as_str(), "placeholder");
        } else {
            panic!("failed to parse identifier");
        }
        assert_eq!(
            list[1].span,
            Span {
                start_line: 1,
                start_column: 5,
                end_line: 1,
                end_column: 5
            }
        );
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].level, Level::Error);
        assert_eq!(
            diagnostics[0].message,
            "expected ':' after key in tuple".to_string()
        );
        assert_eq!(
            diagnostics[0].spans[0],
            Span {
                start_line: 1,
                start_column: 5,
                end_line: 1,
                end_column: 5
            }
        );
    }

    #[test]
    fn test_parse_bad() {
        let (stmts, diagnostics, success) = parse_collect_diagnostics("(1, 3)");
        assert_eq!(success, false);
        assert_eq!(stmts.len(), 1);
        assert_eq!(
            stmts[0].span,
            Span {
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 6
            }
        );
        let exprs = stmts[0].match_list().unwrap();
        assert_eq!(exprs.len(), 2);
        match exprs[0].pre_expr {
            PreSymbolicExpressionType::AtomValue(Value::Int(1)) => (),
            _ => panic!("expected Value(1)"),
        }
        match exprs[1].pre_expr {
            PreSymbolicExpressionType::AtomValue(Value::Int(3)) => (),
            _ => panic!("expected Value(3)"),
        }
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].message, "unexpected ','");
        assert_eq!(
            diagnostics[0].spans[0],
            Span {
                start_line: 1,
                start_column: 3,
                end_line: 1,
                end_column: 3
            }
        );
    }

    #[test]
    fn test_parse_principal() {
        let (stmts, diagnostics, success) =
            parse_collect_diagnostics("'ST000000000000000000002AMW42H");
        assert_eq!(success, true);
        assert_eq!(stmts.len(), 1);
        assert_eq!(
            stmts[0].span,
            Span {
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 30
            }
        );
        if let Some(Value::Principal(data)) = stmts[0].match_atom_value() {
            match data {
                PrincipalData::Standard(data) => {
                    assert_eq!(data.to_address(), "ST000000000000000000002AMW42H")
                }
                _ => panic!("failed to parse principal"),
            }
        }

        let (stmts, diagnostics, success) = parse_collect_diagnostics("' u42");
        assert_eq!(success, false);
        assert_eq!(stmts.len(), 2);
        assert_eq!(
            stmts[0].span,
            Span {
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 1
            }
        );
        let value = stmts[0].match_atom_value();
        assert!(value.is_some());
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].message, "invalid principal literal");
        assert_eq!(
            diagnostics[0].spans[0],
            Span {
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 1
            }
        );
        match stmts[1].match_atom_value() {
            Some(Value::UInt(42)) => (),
            _ => panic!("failed to parse uint after principal"),
        }

        let (stmts, diagnostics, success) =
            parse_collect_diagnostics("'ST000000000000000000002AMW42H.silly-goose");
        assert_eq!(success, true);
        assert_eq!(stmts.len(), 1);
        assert_eq!(
            stmts[0].span,
            Span {
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 42
            }
        );
        if let Some(Value::Principal(data)) = stmts[0].match_atom_value() {
            match data {
                PrincipalData::Contract(data) => {
                    assert_eq!(
                        data.to_string(),
                        "ST000000000000000000002AMW42H.silly-goose"
                    )
                }
                _ => panic!("failed to parse principal"),
            }
        }
        assert_eq!(diagnostics.len(), 0);

        let (stmts, diagnostics, success) =
            parse_collect_diagnostics("'ST000000000000000000002AMW42H.123");
        assert_eq!(success, false);
        assert_eq!(stmts.len(), 1);
        if let Some(Value::Principal(data)) = stmts[0].match_atom_value() {
            match data {
                PrincipalData::Contract(data) => {
                    assert_eq!(
                        data.to_string(),
                        "ST000000000000000000002AMW42H.placeholder"
                    )
                }
                _ => panic!("failed to parse principal"),
            }
        }
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].message, "expected contract identifier");
        assert_eq!(
            diagnostics[0].spans[0],
            Span {
                start_line: 1,
                start_column: 32,
                end_line: 1,
                end_column: 34
            }
        );

        let (stmts, diagnostics, success) =
            parse_collect_diagnostics("'ST000000000000000000002AMW42H.illegal?name ");
        assert_eq!(success, false);
        assert_eq!(stmts.len(), 1);
        if let Some(Value::Principal(data)) = stmts[0].match_atom_value() {
            match data {
                PrincipalData::Contract(data) => {
                    assert_eq!(
                        data.to_string(),
                        "ST000000000000000000002AMW42H.placeholder"
                    )
                }
                _ => panic!("failed to parse principal"),
            }
        }
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(
            diagnostics[0].message,
            "Illegal contract name: 'illegal?name'"
        );
        assert_eq!(
            diagnostics[0].spans[0],
            Span {
                start_line: 1,
                start_column: 32,
                end_line: 1,
                end_column: 43
            }
        );

        let (stmts, diagnostics, success) =
            parse_collect_diagnostics("'ST000000000000000000002AMW42H.this-name-is-way-too-many-characters-to-be-a-legal-contract-name ");
        assert_eq!(success, false);
        assert_eq!(stmts.len(), 1);
        if let Some(Value::Principal(data)) = stmts[0].match_atom_value() {
            match data {
                PrincipalData::Contract(data) => {
                    assert_eq!(
                        data.to_string(),
                        "ST000000000000000000002AMW42H.placeholder"
                    )
                }
                _ => panic!("failed to parse principal"),
            }
        }
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(
            diagnostics[0].message,
            "contract name 'this-name-is-way-too-many-characters-to-be-a-legal-contract-name' is too long"
        );
        assert_eq!(
            diagnostics[0].spans[0],
            Span {
                start_line: 1,
                start_column: 32,
                end_line: 1,
                end_column: 95
            }
        );

        let (stmts, diagnostics, success) = parse_collect_diagnostics(".fancy_pants");
        assert_eq!(success, true);
        assert_eq!(stmts.len(), 1);
        assert_eq!(
            stmts[0].span,
            Span {
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 12
            }
        );
        match &stmts[0].pre_expr {
            PreSymbolicExpressionType::SugaredContractIdentifier(name) => {
                assert_eq!(name.as_str(), "fancy_pants")
            }
            _ => panic!("failed to parse sugared contract identifier"),
        }
        assert_eq!(diagnostics.len(), 0);

        let (stmts, diagnostics, success) = parse_collect_diagnostics(".123");
        assert_eq!(success, false);
        assert_eq!(stmts.len(), 1);
        match &stmts[0].pre_expr {
            PreSymbolicExpressionType::SugaredContractIdentifier(name) => {
                assert_eq!(name.as_str(), "placeholder")
            }
            _ => panic!("failed to parse principal"),
        }
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].message, "expected contract identifier");
        assert_eq!(
            diagnostics[0].spans[0],
            Span {
                start_line: 1,
                start_column: 2,
                end_line: 1,
                end_column: 4
            }
        );

        let (stmts, diagnostics, success) = parse_collect_diagnostics(".illegal?name ");
        assert_eq!(success, false);
        assert_eq!(stmts.len(), 1);
        match &stmts[0].pre_expr {
            PreSymbolicExpressionType::SugaredContractIdentifier(name) => {
                assert_eq!(name.as_str(), "placeholder")
            }
            _ => panic!("failed to parse principal"),
        }
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(
            diagnostics[0].message,
            "Illegal contract name: 'illegal?name'"
        );
        assert_eq!(
            diagnostics[0].spans[0],
            Span {
                start_line: 1,
                start_column: 2,
                end_line: 1,
                end_column: 13
            }
        );

        let (stmts, diagnostics, success) =
            parse_collect_diagnostics("'ST000000000000000000002AMW42H.foo.bar");
        assert_eq!(success, true);
        assert_eq!(stmts.len(), 1);
        match &stmts[0].pre_expr {
            PreSymbolicExpressionType::FieldIdentifier(trait_id) => {
                assert_eq!(
                    format!("{}", trait_id),
                    "ST000000000000000000002AMW42H.foo.bar"
                );
            }
            _ => panic!("failed to parse field identifier"),
        }
        assert_eq!(
            stmts[0].span,
            Span {
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 38
            }
        );
        assert_eq!(diagnostics.len(), 0);

        let (stmts, diagnostics, success) =
            parse_collect_diagnostics("'ST000000000000000000002AMW42H.foo.123");
        assert_eq!(success, false);
        assert_eq!(stmts.len(), 1);
        match &stmts[0].pre_expr {
            PreSymbolicExpressionType::FieldIdentifier(trait_id) => {
                assert_eq!(
                    format!("{}", trait_id),
                    "ST000000000000000000002AMW42H.foo.placeholder"
                );
            }
            _ => panic!("failed to parse trait identifier"),
        }
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].message, "expected trait identifier");
        assert_eq!(
            diagnostics[0].spans[0],
            Span {
                start_line: 1,
                start_column: 36,
                end_line: 1,
                end_column: 38
            }
        );

        let (stmts, diagnostics, success) = parse_collect_diagnostics(".foo.bar");
        assert_eq!(success, true);
        assert_eq!(stmts.len(), 1);
        match &stmts[0].pre_expr {
            PreSymbolicExpressionType::SugaredFieldIdentifier(contract_name, trait_name) => {
                assert_eq!(contract_name.as_str(), "foo");
                assert_eq!(trait_name.as_str(), "bar");
            }
            _ => panic!("failed to parse sugared trait identifier"),
        }
        assert_eq!(
            stmts[0].span,
            Span {
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 8
            }
        );
        assert_eq!(diagnostics.len(), 0);

        let (stmts, diagnostics, success) = parse_collect_diagnostics(".foo.123");
        assert_eq!(success, false);
        assert_eq!(stmts.len(), 1);
        match &stmts[0].pre_expr {
            PreSymbolicExpressionType::SugaredFieldIdentifier(contract_name, trait_name) => {
                assert_eq!(contract_name.as_str(), "foo");
                assert_eq!(trait_name.as_str(), "placeholder");
            }
            _ => panic!("failed to parse sugared trait identifier"),
        }
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].message, "expected trait identifier");
        assert_eq!(
            diagnostics[0].spans[0],
            Span {
                start_line: 1,
                start_column: 6,
                end_line: 1,
                end_column: 8
            }
        );

        let (stmts, diagnostics, success) = parse_collect_diagnostics(".foo.veryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryverylong");
        assert_eq!(success, false);
        assert_eq!(stmts.len(), 1);
        match &stmts[0].pre_expr {
            PreSymbolicExpressionType::SugaredFieldIdentifier(contract_name, trait_name) => {
                assert_eq!(contract_name.as_str(), "foo");
                assert_eq!(trait_name.as_str(), "placeholder");
            }
            _ => panic!("failed to parse sugared trait identifier"),
        }
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].message, "illegal name (too long), 'veryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryverylong'");
        assert_eq!(
            diagnostics[0].spans[0],
            Span {
                start_line: 1,
                start_column: 6,
                end_line: 1,
                end_column: 137
            }
        );
    }

    #[test]
    fn test_parse_trait_reference() {
        let (stmts, diagnostics, success) = parse_collect_diagnostics("<foo-bar>");
        assert_eq!(success, true);
        assert_eq!(stmts.len(), 1);
        assert_eq!(diagnostics.len(), 0);
        if let Some(name) = stmts[0].match_trait_reference() {
            assert_eq!(name.as_str(), "foo-bar");
        } else {
            panic!("failed to parse trait reference");
        }
        assert_eq!(
            stmts[0].span,
            Span {
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 9
            }
        );

        let (stmts, diagnostics, success) = parse_collect_diagnostics("\n\t<foo-bar 1");
        assert_eq!(success, false);
        assert_eq!(stmts.len(), 2);
        if let Some(name) = stmts[0].match_trait_reference() {
            assert_eq!(name.as_str(), "foo-bar");
        } else {
            panic!("failed to parse trait reference");
        }
        assert_eq!(
            stmts[0].span,
            Span {
                start_line: 2,
                start_column: 2,
                end_line: 2,
                end_column: 10
            }
        );
        assert_eq!(diagnostics.len(), 2);
        assert_eq!(diagnostics[0].message, "expected closing '>'");
        assert_eq!(diagnostics[1].level, Level::Note);
        assert_eq!(diagnostics[1].message, "to match this '<'".to_string());
        assert_eq!(
            diagnostics[1].spans[0],
            Span {
                start_line: 2,
                start_column: 2,
                end_line: 2,
                end_column: 2
            }
        );

        let (stmts, diagnostics, success) = parse_collect_diagnostics("<123>");
        assert_eq!(success, false);
        assert_eq!(stmts.len(), 2);
        assert_eq!(diagnostics.len(), 2);
        assert_eq!(diagnostics[0].message, "expected separator");
        assert_eq!(
            diagnostics[0].spans[0],
            Span {
                start_line: 1,
                start_column: 2,
                end_line: 1,
                end_column: 2
            }
        );
        assert_eq!(
            diagnostics[1].message,
            "invalid character, '>', in int literal"
        );
        assert_eq!(
            diagnostics[1].spans[0],
            Span {
                start_line: 1,
                start_column: 5,
                end_line: 1,
                end_column: 5
            }
        );
        if let Some(name) = stmts[0].match_atom() {
            assert_eq!(name.as_str(), "<");
        } else {
            panic!("failed to parse invalid trait reference");
        }
        assert_eq!(
            stmts[0].span,
            Span {
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 1
            }
        );
        match stmts[1].match_atom_value() {
            Some(Value::Int(123)) => (),
            _ => panic!("failed to parse int with errors"),
        }
        assert_eq!(
            stmts[1].span,
            Span {
                start_line: 1,
                start_column: 2,
                end_line: 1,
                end_column: 5
            }
        );

        let (stmts, diagnostics, success) = parse_collect_diagnostics("<123 ");
        assert_eq!(success, false);
        assert_eq!(stmts.len(), 2);
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].message, "expected separator");
        assert_eq!(
            diagnostics[0].spans[0],
            Span {
                start_line: 1,
                start_column: 2,
                end_line: 1,
                end_column: 2
            }
        );
        if let Some(name) = stmts[0].match_atom() {
            assert_eq!(name.as_str(), "<");
        } else {
            panic!("failed to parse invalid trait reference");
        }
        assert_eq!(
            stmts[0].span,
            Span {
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 1
            }
        );
        match stmts[1].match_atom_value() {
            Some(Value::Int(123)) => (),
            _ => panic!("failed to parse int with errors"),
        }
        assert_eq!(
            stmts[1].span,
            Span {
                start_line: 1,
                start_column: 2,
                end_line: 1,
                end_column: 4
            }
        );

        let (stmts, diagnostics, success) = parse_collect_diagnostics("<veryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryverylong>");
        assert_eq!(success, false);
        assert_eq!(stmts.len(), 1);
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].message, "illegal name (too long), 'veryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryverylong'");
        assert_eq!(
            diagnostics[0].spans[0],
            Span {
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 134
            }
        );
    }

    #[test]
    fn test_parse_ops() {
        let (stmts, diagnostics, success) = parse_collect_diagnostics("(+ 1 2)");
        assert_eq!(success, true);
        assert_eq!(stmts.len(), 1);
        assert_eq!(diagnostics.len(), 0);
        assert_eq!(
            stmts[0].span,
            Span {
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 7
            }
        );
        let exprs = stmts[0].match_list().unwrap();
        match &exprs[0].pre_expr {
            PreSymbolicExpressionType::Atom(cname) => assert_eq!(cname.as_str(), "+"),
            _ => panic!("expected atom 'foo'"),
        }
        assert_eq!(
            exprs[0].span,
            Span {
                start_line: 1,
                start_column: 2,
                end_line: 1,
                end_column: 2
            }
        );
        match exprs[1].match_atom_value() {
            Some(Value::Int(1)) => (),
            _ => panic!("failed to parse int in list"),
        }
        match exprs[2].match_atom_value() {
            Some(Value::Int(2)) => (),
            _ => panic!("failed to parse int in list"),
        }

        let (stmts, diagnostics, success) = parse_collect_diagnostics("(- 1 2)");
        assert_eq!(success, true);
        assert_eq!(stmts.len(), 1);
        assert_eq!(diagnostics.len(), 0);
        let exprs = stmts[0].match_list().unwrap();
        match &exprs[0].pre_expr {
            PreSymbolicExpressionType::Atom(cname) => assert_eq!(cname.as_str(), "-"),
            _ => panic!("expected atom 'foo'"),
        }
        assert_eq!(
            exprs[0].span,
            Span {
                start_line: 1,
                start_column: 2,
                end_line: 1,
                end_column: 2
            }
        );

        let (stmts, diagnostics, success) = parse_collect_diagnostics("(* 1 2)");
        assert_eq!(success, true);
        assert_eq!(stmts.len(), 1);
        assert_eq!(diagnostics.len(), 0);
        let exprs = stmts[0].match_list().unwrap();
        match &exprs[0].pre_expr {
            PreSymbolicExpressionType::Atom(cname) => assert_eq!(cname.as_str(), "*"),
            _ => panic!("expected atom 'foo'"),
        }
        assert_eq!(
            exprs[0].span,
            Span {
                start_line: 1,
                start_column: 2,
                end_line: 1,
                end_column: 2
            }
        );

        let (stmts, diagnostics, success) = parse_collect_diagnostics("(/ 1 2)");
        assert_eq!(success, true);
        assert_eq!(stmts.len(), 1);
        assert_eq!(diagnostics.len(), 0);
        let exprs = stmts[0].match_list().unwrap();
        match &exprs[0].pre_expr {
            PreSymbolicExpressionType::Atom(cname) => assert_eq!(cname.as_str(), "/"),
            _ => panic!("expected atom 'foo'"),
        }
        assert_eq!(
            exprs[0].span,
            Span {
                start_line: 1,
                start_column: 2,
                end_line: 1,
                end_column: 2
            }
        );

        let (stmts, diagnostics, success) = parse_collect_diagnostics("(< 1 2)");
        assert_eq!(success, true);
        assert_eq!(stmts.len(), 1);
        assert_eq!(diagnostics.len(), 0);
        let exprs = stmts[0].match_list().unwrap();
        match &exprs[0].pre_expr {
            PreSymbolicExpressionType::Atom(cname) => assert_eq!(cname.as_str(), "<"),
            _ => panic!("expected atom 'foo'"),
        }
        assert_eq!(
            exprs[0].span,
            Span {
                start_line: 1,
                start_column: 2,
                end_line: 1,
                end_column: 2
            }
        );

        let (stmts, diagnostics, success) = parse_collect_diagnostics("(<= 1 2)");
        assert_eq!(success, true);
        assert_eq!(stmts.len(), 1);
        assert_eq!(diagnostics.len(), 0);
        let exprs = stmts[0].match_list().unwrap();
        match &exprs[0].pre_expr {
            PreSymbolicExpressionType::Atom(cname) => assert_eq!(cname.as_str(), "<="),
            _ => panic!("expected atom 'foo'"),
        }
        assert_eq!(
            exprs[0].span,
            Span {
                start_line: 1,
                start_column: 2,
                end_line: 1,
                end_column: 3
            }
        );

        let (stmts, diagnostics, success) = parse_collect_diagnostics("(> 1 2)");
        assert_eq!(success, true);
        assert_eq!(stmts.len(), 1);
        assert_eq!(diagnostics.len(), 0);
        let exprs = stmts[0].match_list().unwrap();
        match &exprs[0].pre_expr {
            PreSymbolicExpressionType::Atom(cname) => assert_eq!(cname.as_str(), ">"),
            _ => panic!("expected atom 'foo'"),
        }
        assert_eq!(
            exprs[0].span,
            Span {
                start_line: 1,
                start_column: 2,
                end_line: 1,
                end_column: 2
            }
        );

        let (stmts, diagnostics, success) = parse_collect_diagnostics("(>= 1 2)");
        assert_eq!(success, true);
        assert_eq!(stmts.len(), 1);
        assert_eq!(diagnostics.len(), 0);
        let exprs = stmts[0].match_list().unwrap();
        match &exprs[0].pre_expr {
            PreSymbolicExpressionType::Atom(cname) => assert_eq!(cname.as_str(), ">="),
            _ => panic!("expected atom 'foo'"),
        }
        assert_eq!(
            exprs[0].span,
            Span {
                start_line: 1,
                start_column: 2,
                end_line: 1,
                end_column: 3
            }
        );
    }

    #[test]
    fn test_parse_buffer() {
        let (stmts, diagnostics, success) = parse_collect_diagnostics("0x1234");
        assert_eq!(success, true);
        assert_eq!(stmts.len(), 1);
        assert_eq!(diagnostics.len(), 0);
        assert_eq!(
            stmts[0].span,
            Span {
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 6
            }
        );
        let val = stmts[0].match_atom_value().unwrap().clone();
        assert_eq!(val.expect_buff(2), vec![0x12, 0x34]);
    }

    #[test]
    fn test_parse_errors() {
        let (stmts, diagnostics, success) = parse_collect_diagnostics("123 }");
        assert_eq!(success, false);
        assert_eq!(stmts.len(), 1);
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(
            diagnostics[0].spans[0],
            Span {
                start_line: 1,
                start_column: 5,
                end_line: 1,
                end_column: 5
            }
        );
        assert_eq!(diagnostics[0].message, "unexpected '}'");

        let (stmts, diagnostics, success) = parse_collect_diagnostics("(foo))");
        assert_eq!(success, false);
        assert_eq!(stmts.len(), 1);
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(
            diagnostics[0].spans[0],
            Span {
                start_line: 1,
                start_column: 6,
                end_line: 1,
                end_column: 6
            }
        );
        assert_eq!(diagnostics[0].message, "unexpected ')'");
    }

    #[test]
    fn test_lexer_diagnostics() {
        let (stmts, diagnostics, success) =
            parse_collect_diagnostics("(print \"newline\n        in string\")");
        assert_eq!(success, false);
        assert_eq!(stmts.len(), 1);
        assert_eq!(diagnostics.len(), 3);
        assert_eq!(diagnostics[0].message, "expected closing '\"'");
        assert_eq!(diagnostics[0].level, Level::Error);
        assert_eq!(
            diagnostics[0].spans[0],
            Span {
                start_line: 1,
                start_column: 16,
                end_line: 1,
                end_column: 16
            }
        );

        assert_eq!(diagnostics[1].message, "to match this '\"'");
        assert_eq!(diagnostics[1].level, Level::Note);
        assert_eq!(
            diagnostics[1].spans[0],
            Span {
                start_line: 1,
                start_column: 8,
                end_line: 1,
                end_column: 8
            }
        );

        // This last error is because it doesn't know what to do with the next line
        assert_eq!(
            diagnostics[2].message,
            "invalid character, '\"', in identifier"
        );
    }

    #[test]
    fn test_consume_invalid_symbols() {
        let (stmts, diagnostics, success) =
            parse_collect_diagnostics(" # here is a python comment\n\n    # and another\n(foo)");
        assert_eq!(success, false);
        assert_eq!(stmts.len(), 8);
    }

    #[test]
    fn test_consume_comments_with_whitespace() {
        let (stmts, diagnostics, success) =
            parse_collect_diagnostics(" ;; here is a comment\n\n    ;; and another\n(foo)");
        assert_eq!(success, true);
        assert_eq!(stmts.len(), 1);
        assert_eq!(diagnostics.len(), 0);
    }

    #[test]
    fn test_comment_in_list() {
        let (stmts, diagnostics, success) = parse_collect_diagnostics(
            "(\n    foo ;; comment after\n    ;; comment on its own line\n    bar\n)",
        );
        assert_eq!(success, true);
        assert_eq!(stmts.len(), 1);
        assert_eq!(diagnostics.len(), 0);
    }

    #[test]
    fn test_comma_at_end() {
        let (stmts, diagnostics, success) = parse_collect_diagnostics("{this: is, a:tuple,}");
        assert_eq!(success, true);
        assert_eq!(stmts.len(), 1);
        assert_eq!(diagnostics.len(), 0);

        let (stmts, diagnostics, success) = parse_collect_diagnostics(
            r#"
{
    and: so,
    is: this,
}"#,
        );
        assert_eq!(success, true);
        assert_eq!(stmts.len(), 1);
        assert_eq!(diagnostics.len(), 0);
    }

    #[test]
    fn test_missing_whitespace() {
        let (stmts, diagnostics, success) = parse_collect_diagnostics("(foo(bar))");
        assert_eq!(success, false);
        assert_eq!(stmts.len(), 1);
        let exprs = stmts[0].match_list().unwrap();
        assert_eq!(exprs.len(), 2);
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(
            diagnostics[0].spans[0],
            Span {
                start_line: 1,
                start_column: 5,
                end_line: 1,
                end_column: 9
            }
        );
        assert_eq!(
            diagnostics[0].message,
            "expected whitespace before expression"
        );
    }

    #[test]
    fn test_parse_fail_fast() {
        match parse("42g !ok") {
            Ok(_) => panic!("fail_fast mode should have returned an error"),
            Err(e) => assert_eq!(e.err, ParseErrors::Lexer(LexerError::InvalidCharInt('g'))),
        }
    }
}
