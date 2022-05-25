use std::fmt::Display;

use super::error::LexerError;
use crate::vm::representations::Span;

#[derive(Debug, PartialEq, Clone)]
pub enum Token {
    Eof,
    Whitespace,
    Lparen,
    Rparen,
    Lbrace,
    Rbrace,
    Colon,
    Comma,
    Dot,
    Int(i128),
    Uint(u128),
    AsciiString(String),
    Utf8String(Vec<Vec<u8>>),
    Bytes(Vec<u8>),
    Principal(String),
    Ident(String),
    TraitIdent(String),
    Plus,
    Minus,
    Multiply,
    Divide,
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
    Comment(String),
    Placeholder, // used to continue parsing after errors
}

#[derive(Clone, Debug)]
pub struct PlacedToken {
    pub span: Span,
    pub token: Token,
}

impl Display for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use self::Token::*;
        match self {
            Eof => write!(f, "EOF"),
            Whitespace => write!(f, "whitespace"),
            Lparen => write!(f, "("),
            Rparen => write!(f, ")"),
            Lbrace => write!(f, "{{"),
            Rbrace => write!(f, "}}"),
            Colon => write!(f, ":"),
            Comma => write!(f, ","),
            Dot => write!(f, "."),
            Int(_) => write!(f, "int"),
            Uint(_) => write!(f, "uint"),
            AsciiString(_) => write!(f, "string-ascii"),
            Utf8String(_) => write!(f, "string-utf8"),
            Bytes(_) => write!(f, "bytes"),
            Principal(_) => write!(f, "principal"),
            Ident(_) => write!(f, "identifier"),
            TraitIdent(_) => write!(f, "trait-identifier"),
            Plus => write!(f, "+"),
            Minus => write!(f, "-"),
            Multiply => write!(f, "*"),
            Divide => write!(f, "/"),
            Less => write!(f, "<"),
            LessEqual => write!(f, "<="),
            Greater => write!(f, ">"),
            GreaterEqual => write!(f, ">="),
            Comment(_) => write!(f, "comment"),
            Placeholder => write!(f, "placeholder"),
        }
    }
}
