pub mod lexer;

use std::convert::TryFrom;
use std::num::ParseIntError;

use stacks_common::util::hash::hex_bytes;

use self::lexer::error::LexerError;
use self::lexer::token::{PlacedToken, Token};
use self::lexer::Lexer;
use crate::vm::ast::errors::{ParseError, ParseErrors, ParseResult, PlacedError};
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
        let lexer = match Lexer::new(input, fail_fast) {
            Ok(lexer) => lexer,
            Err(e) => return Err(ParseErrors::Lexer(e)),
        };
        let mut p = Self {
            lexer,
            tokens: vec![],
            next_token: 0,
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
        if self.next_token >= self.tokens.len() {
            return None;
        }
        let token = self.tokens[self.next_token].clone();
        self.next_token += 1;
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
                    self.next_token += 1;
                    found = true;
                }
                _ => return found,
            }
        }
    }

    fn ignore_whitespace_and_comments(&mut self) -> Vec<PreSymbolicExpression> {
        let mut comments = Vec::new();
        loop {
            if self.next_token >= self.tokens.len() {
                return comments;
            }
            let token = &self.tokens[self.next_token];
            match &token.token {
                Token::Whitespace => {
                    self.next_token += 1;
                }
                Token::Comment(comment) => {
                    let mut comment = PreSymbolicExpression::comment(comment.to_string());
                    comment.span = token.span.clone();
                    comments.push(comment);
                    self.next_token += 1;
                }
                _ => return comments,
            }
        }
    }

    fn parse_list(&mut self, lparen: PlacedToken) -> ParseResult<PreSymbolicExpression> {
        let mut nodes = vec![];
        let mut span = lparen.span.clone();
        let mut whitespace = true;
        loop {
            if let Some(node) = self.parse_node()? {
                if !whitespace && !node.match_comment().is_some() {
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
            let mut comments = self.ignore_whitespace_and_comments();
            nodes.append(&mut comments);

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
            let mut comments = self.ignore_whitespace_and_comments();
            nodes.append(&mut comments);

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

            let mut comments = self.ignore_whitespace_and_comments();
            nodes.append(&mut comments);

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
            let mut comments = self.ignore_whitespace_and_comments();
            nodes.append(&mut comments);

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
                    let mut placeholder = PreSymbolicExpression::placeholder("".to_string());
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

            let mut comments = self.ignore_whitespace_and_comments();
            nodes.append(&mut comments);

            // Parse value
            let node = match self.parse_node_or_eof()? {
                Some(node) => node,
                None => {
                    // This indicates we have reached the end of the input.
                    // Create a placeholder value so that parsing can continue,
                    // then return.
                    let eof_span = self.tokens[self.next_token - 1].span.clone();
                    self.add_diagnostic(ParseErrors::TupleValueExpected, token.span.clone())?;
                    let mut placeholder = PreSymbolicExpression::placeholder("".to_string());
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

    fn read_principal(
        &mut self,
        addr: String,
        mut span: Span,
    ) -> ParseResult<PreSymbolicExpression> {
        let principal = match PrincipalData::parse_standard_principal(&addr) {
            Ok(principal) => principal,
            _ => {
                self.add_diagnostic(ParseErrors::InvalidPrincipalLiteral, span.clone())?;
                let mut placeholder = PreSymbolicExpression::placeholder(format!("'{}", addr));
                placeholder.span = span;
                return Ok(placeholder);
            }
        };

        // Peek ahead for a '.', indicating a contract identifier
        if self.tokens[self.next_token].token == Token::Dot {
            let dot = self.next_token().unwrap(); // skip over the dot
            let (name, contract_span) = match self.next_token() {
                Some(PlacedToken {
                    span: contract_span,
                    token: Token::Ident(ident),
                }) => {
                    span.end_line = contract_span.end_line;
                    span.end_column = contract_span.end_column;
                    (ident, contract_span)
                }
                Some(PlacedToken {
                    span: token_span,
                    token,
                }) => {
                    span.end_line = token_span.end_line;
                    span.end_column = token_span.end_column;
                    self.add_diagnostic(
                        ParseErrors::ExpectedContractIdentifier,
                        token_span.clone(),
                    )?;
                    let mut placeholder = PreSymbolicExpression::placeholder(format!(
                        "'{}.{}",
                        principal,
                        token.reproduce()
                    ));
                    placeholder.span = span;
                    return Ok(placeholder);
                }
                None => {
                    self.add_diagnostic(ParseErrors::ExpectedContractIdentifier, dot.span.clone())?;
                    let mut placeholder =
                        PreSymbolicExpression::placeholder(format!("'{}.", principal));
                    placeholder.span = span;
                    return Ok(placeholder);
                }
            };

            if name.len() > MAX_CONTRACT_NAME_LEN {
                self.add_diagnostic(
                    ParseErrors::ContractNameTooLong(name.clone()),
                    contract_span.clone(),
                )?;
                let mut placeholder =
                    PreSymbolicExpression::placeholder(format!("'{}.{}", principal, name));
                placeholder.span = span;
                return Ok(placeholder);
            }
            let contract_name = match ContractName::try_from(name.clone()) {
                Ok(id) => id,
                Err(_) => {
                    self.add_diagnostic(
                        ParseErrors::IllegalContractName(name.clone()),
                        contract_span.clone(),
                    )?;
                    let mut placeholder =
                        PreSymbolicExpression::placeholder(format!("'{}.{}", principal, name));
                    placeholder.span = span;
                    return Ok(placeholder);
                }
            };
            let contract_id = QualifiedContractIdentifier::new(principal, contract_name);

            // Peek ahead for a '.', indicating a trait identifier
            if self.tokens[self.next_token].token == Token::Dot {
                let dot = self.next_token().unwrap(); // skip over the dot
                let (name, trait_span) = match self.next_token() {
                    Some(PlacedToken {
                        span: trait_span,
                        token: Token::Ident(ident),
                    }) => {
                        span.end_line = trait_span.end_line;
                        span.end_column = trait_span.end_column;
                        (ident, trait_span)
                    }
                    Some(PlacedToken {
                        span: token_span,
                        token,
                    }) => {
                        self.add_diagnostic(
                            ParseErrors::ExpectedTraitIdentifier,
                            token_span.clone(),
                        )?;
                        let mut placeholder = PreSymbolicExpression::placeholder(format!(
                            "'{}.{}",
                            contract_id,
                            token.reproduce(),
                        ));
                        span.end_line = token_span.end_line;
                        span.end_column = token_span.end_column;
                        placeholder.span = span;
                        return Ok(placeholder);
                    }
                    None => {
                        self.add_diagnostic(
                            ParseErrors::ExpectedTraitIdentifier,
                            dot.span.clone(),
                        )?;
                        let mut placeholder =
                            PreSymbolicExpression::placeholder(format!("'{}.", contract_id));
                        span.end_line = dot.span.end_line;
                        span.end_column = dot.span.end_column;
                        placeholder.span = span;
                        return Ok(placeholder);
                    }
                };
                if name.len() > MAX_STRING_LEN {
                    self.add_diagnostic(
                        ParseErrors::NameTooLong(name.clone()),
                        trait_span.clone(),
                    )?;
                    let mut placeholder =
                        PreSymbolicExpression::placeholder(format!("'{}.{}", contract_id, name,));
                    placeholder.span = span;
                    return Ok(placeholder);
                }
                let trait_name = match ClarityName::try_from(name.clone()) {
                    Ok(id) => id,
                    Err(_) => {
                        self.add_diagnostic(
                            ParseErrors::IllegalTraitName(name.clone()),
                            trait_span.clone(),
                        )?;
                        let mut placeholder = PreSymbolicExpression::placeholder(format!(
                            "'{}.{}",
                            contract_id, name,
                        ));
                        placeholder.span = span;
                        return Ok(placeholder);
                    }
                };
                let trait_id = TraitIdentifier {
                    name: trait_name,
                    contract_identifier: contract_id,
                };
                let mut expr = PreSymbolicExpression::field_identifier(trait_id);
                expr.span = span;
                Ok(expr)
            } else {
                let contract_principal = PrincipalData::Contract(contract_id);
                let mut expr =
                    PreSymbolicExpression::atom_value(Value::Principal(contract_principal));
                expr.span = span;
                Ok(expr)
            }
        } else {
            let mut expr = PreSymbolicExpression::atom_value(Value::Principal(
                PrincipalData::Standard(principal),
            ));
            expr.span = span;
            Ok(expr)
        }
    }

    fn read_sugared_principal(&mut self, mut span: Span) -> ParseResult<PreSymbolicExpression> {
        let (name, contract_span) = match self.next_token() {
            Some(PlacedToken {
                span: contract_span,
                token: Token::Ident(ident),
            }) => {
                span.end_line = contract_span.end_line;
                span.end_column = contract_span.end_column;
                (ident, contract_span)
            }
            Some(PlacedToken {
                span: token_span,
                token,
            }) => {
                self.add_diagnostic(ParseErrors::ExpectedContractIdentifier, token_span.clone())?;
                let mut placeholder =
                    PreSymbolicExpression::placeholder(format!(".{}", token.reproduce()));
                span.end_line = token_span.end_line;
                span.end_column = token_span.end_column;
                placeholder.span = span;
                return Ok(placeholder);
            }
            None => {
                self.add_diagnostic(ParseErrors::ExpectedContractIdentifier, span.clone())?;
                let mut placeholder = PreSymbolicExpression::placeholder(".".to_string());
                placeholder.span = span;
                return Ok(placeholder);
            }
        };

        if name.len() > MAX_CONTRACT_NAME_LEN {
            self.add_diagnostic(ParseErrors::ContractNameTooLong(name.clone()), span.clone())?;
            let mut placeholder = PreSymbolicExpression::placeholder(format!(".{}", name));
            placeholder.span = span;
            return Ok(placeholder);
        }

        let contract_name = match ContractName::try_from(name.clone()) {
            Ok(id) => id,
            Err(_) => {
                self.add_diagnostic(
                    ParseErrors::IllegalContractName(name.clone()),
                    contract_span.clone(),
                )?;
                let mut placeholder = PreSymbolicExpression::placeholder(format!(".{}", name));
                placeholder.span = span;
                return Ok(placeholder);
            }
        };

        // Peek ahead for a '.', indicating a trait identifier
        if self.tokens[self.next_token].token == Token::Dot {
            let dot = self.next_token().unwrap(); // skip over the dot
            let (name, trait_span) = match self.next_token() {
                Some(PlacedToken {
                    span: trait_span,
                    token: Token::Ident(ident),
                }) => {
                    span.end_line = trait_span.end_line;
                    span.end_column = trait_span.end_column;
                    (ident, trait_span)
                }
                Some(PlacedToken {
                    span: token_span,
                    token,
                }) => {
                    self.add_diagnostic(ParseErrors::ExpectedTraitIdentifier, token_span.clone())?;
                    let mut placeholder = PreSymbolicExpression::placeholder(format!(
                        ".{}.{}",
                        contract_name,
                        token.reproduce(),
                    ));
                    span.end_line = token_span.end_line;
                    span.end_column = token_span.end_column;
                    placeholder.span = span;
                    return Ok(placeholder);
                }
                None => {
                    self.add_diagnostic(ParseErrors::ExpectedTraitIdentifier, dot.span.clone())?;
                    let mut placeholder =
                        PreSymbolicExpression::placeholder(format!(".{}.", contract_name));
                    span.end_line = dot.span.end_line;
                    span.end_column = dot.span.end_column;
                    placeholder.span = span;
                    return Ok(placeholder);
                }
            };
            if name.len() > MAX_STRING_LEN {
                self.add_diagnostic(ParseErrors::NameTooLong(name.clone()), trait_span.clone())?;
                let mut placeholder =
                    PreSymbolicExpression::placeholder(format!(".{}.{}", contract_name, name));
                placeholder.span = span;
                return Ok(placeholder);
            }
            let trait_name = match ClarityName::try_from(name.clone()) {
                Ok(id) => id,
                Err(_) => {
                    self.add_diagnostic(
                        ParseErrors::IllegalTraitName(name.clone()),
                        trait_span.clone(),
                    )?;
                    let mut placeholder =
                        PreSymbolicExpression::placeholder(format!(".{}.{}", contract_name, name));
                    placeholder.span = span;
                    return Ok(placeholder);
                }
            };
            let mut expr =
                PreSymbolicExpression::sugared_field_identifier(contract_name, trait_name);
            expr.span = span;
            Ok(expr)
        } else {
            let mut expr = PreSymbolicExpression::sugared_contract_identifier(contract_name);
            expr.span = span;
            Ok(expr)
        }
    }

    /// Returns some valid expression. When None is returned, check the current
    /// token from the caller.
    pub fn parse_node(&mut self) -> ParseResult<Option<PreSymbolicExpression>> {
        self.ignore_whitespace();
        let token = self.next_token();
        if token.is_none() {
            return Ok(None);
        }
        let token = token.unwrap();
        let node = match &token.token {
            Token::Lparen => Some(self.parse_list(token)?),
            Token::Lbrace => Some(self.parse_tuple(token)?),
            Token::Int(val_string) => {
                let mut expr = match val_string.parse::<i128>() {
                    Ok(val) => PreSymbolicExpression::atom_value(Value::Int(val)),
                    Err(_) => {
                        self.add_diagnostic(
                            ParseErrors::FailedParsingIntValue(val_string.clone()),
                            token.span.clone(),
                        )?;
                        PreSymbolicExpression::placeholder(token.token.reproduce())
                    }
                };
                expr.span = token.span;
                Some(expr)
            }
            Token::Uint(val_string) => {
                let mut expr = match val_string.parse::<u128>() {
                    Ok(val) => PreSymbolicExpression::atom_value(Value::UInt(val)),
                    Err(_) => {
                        self.add_diagnostic(
                            ParseErrors::FailedParsingUIntValue(val_string.clone()),
                            token.span.clone(),
                        )?;
                        PreSymbolicExpression::placeholder(token.token.reproduce())
                    }
                };
                expr.span = token.span;
                Some(expr)
            }
            Token::AsciiString(val) => {
                let mut expr = match Value::string_ascii_from_bytes(val.clone().into_bytes()) {
                    Ok(s) => PreSymbolicExpression::atom_value(s),
                    Err(_) => {
                        self.add_diagnostic(
                            ParseErrors::IllegalASCIIString(val.clone()),
                            token.span.clone(),
                        )?;
                        PreSymbolicExpression::placeholder(token.token.reproduce())
                    }
                };
                expr.span = token.span;
                Some(expr)
            }
            Token::Utf8String(s) => {
                let mut data: Vec<Vec<u8>> = Vec::new();
                for ch in s.chars() {
                    let mut bytes = vec![0; ch.len_utf8()];
                    ch.encode_utf8(&mut bytes);
                    data.push(bytes);
                }
                let val = Value::Sequence(SequenceData::String(CharType::UTF8(UTF8Data { data })));
                let mut expr = PreSymbolicExpression::atom_value(val);
                expr.span = token.span;
                Some(expr)
            }
            Token::Ident(name) => {
                let mut expr = if name.len() > MAX_STRING_LEN {
                    self.add_diagnostic(
                        ParseErrors::NameTooLong(name.clone()),
                        token.span.clone(),
                    )?;
                    PreSymbolicExpression::placeholder(token.token.reproduce())
                } else {
                    match ClarityName::try_from(name.clone()) {
                        Ok(name) => PreSymbolicExpression::atom(name),
                        Err(_) => {
                            self.add_diagnostic(
                                ParseErrors::IllegalClarityName(name.clone()),
                                token.span.clone(),
                            )?;
                            PreSymbolicExpression::placeholder(token.token.reproduce())
                        }
                    }
                };
                expr.span = token.span;
                Some(expr)
            }
            Token::TraitIdent(name) => {
                let mut expr = if name.len() > MAX_STRING_LEN {
                    self.add_diagnostic(
                        ParseErrors::NameTooLong(name.clone()),
                        token.span.clone(),
                    )?;
                    PreSymbolicExpression::placeholder(token.token.reproduce())
                } else {
                    match ClarityName::try_from(name.clone()) {
                        Ok(name) => PreSymbolicExpression::trait_reference(name),
                        Err(_) => {
                            self.add_diagnostic(
                                ParseErrors::IllegalTraitName(name.clone()),
                                token.span.clone(),
                            )?;
                            PreSymbolicExpression::placeholder(token.token.reproduce())
                        }
                    }
                };
                expr.span = token.span;
                Some(expr)
            }
            Token::Bytes(data) => {
                let mut expr = match hex_bytes(data) {
                    Ok(bytes) => match Value::buff_from(bytes) {
                        Ok(value) => PreSymbolicExpression::atom_value(value),
                        _ => {
                            self.add_diagnostic(ParseErrors::InvalidBuffer, token.span.clone())?;
                            PreSymbolicExpression::placeholder(token.token.reproduce())
                        }
                    },
                    Err(_) => {
                        self.add_diagnostic(ParseErrors::InvalidBuffer, token.span.clone())?;
                        PreSymbolicExpression::placeholder(token.token.reproduce())
                    }
                };
                expr.span = token.span;
                Some(expr)
            }
            Token::Principal(addr) => {
                let expr = self.read_principal(addr.clone(), token.span.clone())?;
                Some(expr)
            }
            Token::Dot => {
                let expr = self.read_sugared_principal(token.span.clone())?;
                Some(expr)
            }
            Token::Plus
            | Token::Minus
            | Token::Multiply
            | Token::Divide
            | Token::Less
            | Token::LessEqual
            | Token::Greater
            | Token::GreaterEqual => {
                let name = ClarityName::try_from(token.token.to_string()).unwrap();
                let mut e = PreSymbolicExpression::atom(name);
                e.span = token.span;
                Some(e)
            }
            Token::Placeholder(s) => {
                let mut e = PreSymbolicExpression::placeholder(s.to_string());
                e.span = token.span;
                Some(e)
            }
            Token::Comment(comment) => {
                let mut e = PreSymbolicExpression::comment(comment.to_string());
                e.span = token.span;
                Some(e)
            }
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
        if let Some("42g") = stmts[0].match_placeholder() {
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

        // Exceed the range of a 128-bit integer.
        let (stmts, diagnostics, success) =
            parse_collect_diagnostics("340282366920938463463374607431768211456 ");
        assert_eq!(success, false);
        assert_eq!(stmts.len(), 1);
        assert_eq!(
            stmts[0].match_placeholder().unwrap(),
            "340282366920938463463374607431768211456"
        );
        assert_eq!(
            stmts[0].span,
            Span {
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 39
            }
        );
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].level, Level::Error);
        assert_eq!(
            diagnostics[0].message,
            "Failed to parse int literal '340282366920938463463374607431768211456'".to_string()
        );
        assert_eq!(
            diagnostics[0].spans[0],
            Span {
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 39
            }
        );

        let (stmts, diagnostics, success) = parse_collect_diagnostics("0000000000123");
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
                start_column: 1,
                end_line: 1,
                end_column: 13
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
        if let Some("u2*3") = stmts[0].match_placeholder() {
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

        // Exceed the range of a 128-bit unsigned integer.
        let (stmts, diagnostics, success) =
            parse_collect_diagnostics("u340282366920938463463374607431768211457 ");
        assert_eq!(success, false);
        assert_eq!(stmts.len(), 1);
        assert_eq!(
            stmts[0].match_placeholder().unwrap(),
            "u340282366920938463463374607431768211457"
        );
        assert_eq!(
            stmts[0].span,
            Span {
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 40
            }
        );
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].level, Level::Error);
        assert_eq!(
            diagnostics[0].message,
            "Failed to parse uint literal 'u340282366920938463463374607431768211457'".to_string()
        );
        assert_eq!(
            diagnostics[0].spans[0],
            Span {
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 40
            }
        );

        let (stmts, diagnostics, success) = parse_collect_diagnostics("u00000000123");
        assert_eq!(success, true);
        assert_eq!(stmts.len(), 1);
        assert_eq!(diagnostics.len(), 0);
        if let Some(Value::UInt(123)) = stmts[0].match_atom_value() {
        } else {
            panic!("failed to parse int value");
        }
        assert_eq!(
            stmts[0].span,
            Span {
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 12
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
        if let Some(s) = stmts[0].match_placeholder() {
            assert_eq!(s, "\"👎 nope\"");
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
        assert_eq!(diagnostics.len(), 2);
        assert_eq!(diagnostics[0].level, Level::Error);
        assert_eq!(
            diagnostics[0].message,
            "illegal non-ASCII character, '👎'".to_string()
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
        assert_eq!(diagnostics[1].level, Level::Error);
        assert_eq!(
            diagnostics[1].message,
            "invalid character, '👎', in string literal".to_string()
        );
        assert_eq!(
            diagnostics[1].spans[0],
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
        assert_eq!(stmts[0].match_placeholder().unwrap(), "u\"\\m nope\"");
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
            ))) => assert_eq!(s, "hel\tlo".as_bytes()),
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
    fn test_parse_list_comment() {
        let (stmts, diagnostics, success) = parse_collect_diagnostics(
            "(foo ;; first comment\n  bar\n  ;; second comment\n  baz;; no space\n)",
        );
        assert_eq!(success, true);
        assert_eq!(stmts.len(), 1);
        assert_eq!(diagnostics.len(), 0);
        assert_eq!(
            stmts[0].span,
            Span {
                start_line: 1,
                start_column: 1,
                end_line: 5,
                end_column: 1
            }
        );
        let exprs = stmts[0].match_list().unwrap();
        assert_eq!(exprs.len(), 6);
        assert_eq!(exprs[0].match_atom().unwrap().as_str(), "foo");
        assert_eq!(
            exprs[0].span,
            Span {
                start_line: 1,
                start_column: 2,
                end_line: 1,
                end_column: 4
            }
        );
        assert_eq!(exprs[1].match_comment().unwrap(), "first comment");
        assert_eq!(
            exprs[1].span,
            Span {
                start_line: 1,
                start_column: 6,
                end_line: 1,
                end_column: 21
            }
        );
        assert_eq!(exprs[2].match_atom().unwrap().as_str(), "bar");
        assert_eq!(
            exprs[2].span,
            Span {
                start_line: 2,
                start_column: 3,
                end_line: 2,
                end_column: 5
            }
        );
        assert_eq!(exprs[3].match_comment().unwrap(), "second comment");
        assert_eq!(
            exprs[3].span,
            Span {
                start_line: 3,
                start_column: 3,
                end_line: 3,
                end_column: 19
            }
        );
        assert_eq!(exprs[4].match_atom().unwrap().as_str(), "baz");
        assert_eq!(
            exprs[4].span,
            Span {
                start_line: 4,
                start_column: 3,
                end_line: 4,
                end_column: 5
            }
        );
        assert_eq!(exprs[5].match_comment().unwrap(), "no space");
        assert_eq!(
            exprs[5].span,
            Span {
                start_line: 4,
                start_column: 6,
                end_line: 4,
                end_column: 16
            }
        );
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

        let (stmts, diagnostics, success) = parse_collect_diagnostics("{foo: bar,}");
        assert_eq!(success, true);
        assert_eq!(stmts.len(), 1);
        assert_eq!(diagnostics.len(), 0);
        assert_eq!(
            stmts[0].span,
            Span {
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 11
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

        let (stmts, diagnostics, success) = parse_collect_diagnostics("{foo:bar}");
        assert_eq!(success, true);
        assert_eq!(stmts.len(), 1);
        assert_eq!(diagnostics.len(), 0);
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
                end_column: 8,
            }
        );

        let (stmts, diagnostics, success) = parse_collect_diagnostics("{foo:bar,}");
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
                start_column: 6,
                end_line: 1,
                end_column: 8,
            }
        );

        let (stmts, diagnostics, success) = parse_collect_diagnostics("{foo:bar }");
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
                start_column: 6,
                end_line: 1,
                end_column: 8,
            }
        );

        let (stmts, diagnostics, success) = parse_collect_diagnostics("{foo:bar ,}");
        assert_eq!(success, true);
        assert_eq!(stmts.len(), 1);
        assert_eq!(diagnostics.len(), 0);
        assert_eq!(
            stmts[0].span,
            Span {
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 11
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
                end_column: 8,
            }
        );

        let (stmts, diagnostics, success) = parse_collect_diagnostics("{foo:bar,baz:goo}");
        assert_eq!(success, true);
        assert_eq!(stmts.len(), 1);
        assert_eq!(diagnostics.len(), 0);
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
                end_column: 8,
            }
        );
        if let Some(name) = list[2].match_atom() {
            assert_eq!(name.as_str(), "baz");
        } else {
            panic!("failed to parse identifier");
        }
        assert_eq!(
            list[2].span,
            Span {
                start_line: 1,
                start_column: 10,
                end_line: 1,
                end_column: 12,
            }
        );
        if let Some(name) = list[3].match_atom() {
            assert_eq!(name.as_str(), "goo");
        } else {
            panic!("failed to parse identifier");
        }
        assert_eq!(
            list[3].span,
            Span {
                start_line: 1,
                start_column: 14,
                end_line: 1,
                end_column: 16,
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
        assert_eq!(list[1].match_placeholder().unwrap(), "");
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
        assert_eq!(list[1].match_placeholder().unwrap(), "");
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
    fn test_parse_tuple_comments() {
        let (stmts, diagnostics, success) = parse_collect_diagnostics("{ ;; before the key\n  foo ;; before the colon\n  : ;; after the colon\n  ;; comment on newline\n  bar ;; before comma\n  ,\n  ;; after comma\n baz : qux ;; before closing\n}");
        assert_eq!(success, true);
        assert_eq!(stmts.len(), 1);
        assert_eq!(diagnostics.len(), 0);
        assert_eq!(
            stmts[0].span,
            Span {
                start_line: 1,
                start_column: 1,
                end_line: 9,
                end_column: 1
            }
        );
        let list: &[PreSymbolicExpression] = match stmts[0].pre_expr {
            PreSymbolicExpressionType::Tuple(ref list) => list,
            _ => panic!("failed to parse tuple"),
        };
        assert_eq!(list.len(), 11);
        assert_eq!(list[0].match_comment().unwrap(), "before the key");
        assert_eq!(
            list[0].span,
            Span {
                start_line: 1,
                start_column: 3,
                end_line: 1,
                end_column: 19,
            }
        );
        assert_eq!(list[1].match_atom().unwrap().as_str(), "foo");
        assert_eq!(
            list[1].span,
            Span {
                start_line: 2,
                start_column: 3,
                end_line: 2,
                end_column: 5
            }
        );
        assert_eq!(list[2].match_comment().unwrap(), "before the colon");
        assert_eq!(
            list[2].span,
            Span {
                start_line: 2,
                start_column: 7,
                end_line: 2,
                end_column: 25,
            }
        );
        assert_eq!(list[3].match_comment().unwrap(), "after the colon");
        assert_eq!(
            list[3].span,
            Span {
                start_line: 3,
                start_column: 5,
                end_line: 3,
                end_column: 22,
            }
        );
        assert_eq!(list[4].match_comment().unwrap(), "comment on newline");
        assert_eq!(
            list[4].span,
            Span {
                start_line: 4,
                start_column: 3,
                end_line: 4,
                end_column: 23,
            }
        );
        assert_eq!(list[5].match_atom().unwrap().as_str(), "bar");
        assert_eq!(
            list[5].span,
            Span {
                start_line: 5,
                start_column: 3,
                end_line: 5,
                end_column: 5
            }
        );
        assert_eq!(list[6].match_comment().unwrap(), "before comma");
        assert_eq!(
            list[6].span,
            Span {
                start_line: 5,
                start_column: 7,
                end_line: 5,
                end_column: 21,
            }
        );
        assert_eq!(list[7].match_comment().unwrap(), "after comma");
        assert_eq!(
            list[7].span,
            Span {
                start_line: 7,
                start_column: 3,
                end_line: 7,
                end_column: 16,
            }
        );
        assert_eq!(list[8].match_atom().unwrap().as_str(), "baz");
        assert_eq!(
            list[8].span,
            Span {
                start_line: 8,
                start_column: 2,
                end_line: 8,
                end_column: 4
            }
        );
        assert_eq!(list[9].match_atom().unwrap().as_str(), "qux");
        assert_eq!(
            list[9].span,
            Span {
                start_line: 8,
                start_column: 8,
                end_line: 8,
                end_column: 10
            }
        );
        assert_eq!(list[10].match_comment().unwrap(), "before closing");
        assert_eq!(
            list[10].span,
            Span {
                start_line: 8,
                start_column: 12,
                end_line: 8,
                end_column: 28,
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
        assert_eq!(stmts[0].match_placeholder().unwrap(), "'");
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
        assert_eq!(
            stmts[0].match_placeholder().unwrap(),
            "'ST000000000000000000002AMW42H.123"
        );
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
        assert_eq!(
            stmts[0].match_placeholder().unwrap(),
            "'ST000000000000000000002AMW42H.illegal?name"
        );
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
        assert_eq!(stmts[0].match_placeholder().unwrap(), "'ST000000000000000000002AMW42H.this-name-is-way-too-many-characters-to-be-a-legal-contract-name");
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
        assert_eq!(stmts[0].match_placeholder().unwrap(), ".123");
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
        assert_eq!(stmts[0].match_placeholder().unwrap(), ".illegal?name");
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
        assert_eq!(
            stmts[0].match_placeholder().unwrap(),
            "'ST000000000000000000002AMW42H.foo.123"
        );
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
        assert_eq!(stmts[0].match_placeholder().unwrap(), ".foo.123");
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

        let (stmts, diagnostics, success) = parse_collect_diagnostics(
            ".this-name-is-way-too-many-characters-to-be-a-legal-contract-name",
        );
        assert_eq!(success, false);
        assert_eq!(stmts.len(), 1);
        assert_eq!(
            stmts[0].match_placeholder().unwrap(),
            ".this-name-is-way-too-many-characters-to-be-a-legal-contract-name"
        );
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].message, "contract name 'this-name-is-way-too-many-characters-to-be-a-legal-contract-name' is too long");
        assert_eq!(
            diagnostics[0].spans[0],
            Span {
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 65
            }
        );

        let (stmts, diagnostics, success) = parse_collect_diagnostics(".foo.veryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryverylong");
        assert_eq!(success, false);
        assert_eq!(stmts.len(), 1);
        assert_eq!(stmts[0].match_placeholder().unwrap(),".foo.veryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryverylong");
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
        if let Some(s) = stmts[0].match_placeholder() {
            assert_eq!(s, "<foo-bar");
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
        if let Some(s) = stmts[1].match_placeholder() {
            assert_eq!(s, "123>");
        } else {
            panic!("failed to parse trait reference");
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
        assert_eq!(stmts.len(), 10);
    }

    #[test]
    fn test_handle_comments() {
        let (stmts, diagnostics, success) =
            parse_collect_diagnostics(" ;; here is a comment\n\n    ;; and another\n(foo)");
        assert_eq!(success, true);
        assert_eq!(stmts.len(), 3);
        assert_eq!(diagnostics.len(), 0);
        assert_eq!(stmts[0].match_comment().unwrap(), "here is a comment");
        assert_eq!(stmts[1].match_comment().unwrap(), "and another");
        stmts[2].match_list().unwrap();
    }

    #[test]
    fn test_comment_in_list() {
        let (stmts, diagnostics, success) = parse_collect_diagnostics(
            "(\n    foo ;; comment after\n    ;; comment on its own line\n    bar\n)",
        );
        assert_eq!(success, true);
        assert_eq!(stmts.len(), 1);
        assert_eq!(diagnostics.len(), 0);
        let exprs = stmts[0].match_list().unwrap();
        println!("{:?}", exprs);
        assert_eq!(exprs.len(), 4);
        assert_eq!(exprs[0].match_atom().unwrap().as_str(), "foo");
        assert_eq!(exprs[1].match_comment().unwrap(), "comment after");
        assert_eq!(exprs[2].match_comment().unwrap(), "comment on its own line");
        assert_eq!(exprs[3].match_atom().unwrap().as_str(), "bar");
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

    #[test]
    fn test_empty_contract() {
        let (stmts, diagnostics, success) = parse_collect_diagnostics("");
        assert_eq!(success, true);
        assert_eq!(stmts.len(), 0);
        assert_eq!(diagnostics.len(), 0);
    }
}
