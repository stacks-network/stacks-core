// Copyright (C) 2025 Stacks Open Internet Foundation
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

use crate::diagnostic::{DiagnosableError, Level};
use crate::representations::Span;

#[derive(Debug, PartialEq, Clone)]
pub enum LexerError {
    InvalidCharInt(char),
    InvalidCharUint(char),
    InvalidCharBuffer(char),
    InvalidCharIdent(char),
    InvalidCharTraitIdent(char),
    InvalidCharPrincipal(char),
    InvalidBufferLength(usize),
    UnknownEscapeChar(char),
    IllegalCharString(char),
    IllegalCharUTF8Encoding(char),
    UnterminatedUTF8Encoding,
    ExpectedClosing(char),
    ExpectedSeparator,
    EmptyUTF8Encoding,
    InvalidUTF8Encoding,
    SingleSemiColon,
    UnknownSymbol(char),
    NonASCIIChar(char),
    NoteToMatchThis(char),
    UnsupportedLineEnding,
    EditorCRLFMode,
}

#[derive(Debug)]
pub struct PlacedError {
    pub e: LexerError,
    pub span: Span,
}

impl DiagnosableError for LexerError {
    fn message(&self) -> String {
        use self::LexerError::*;
        match self {
            InvalidCharInt(c) => format!("invalid character, '{c}', in int literal"),
            InvalidCharUint(c) => format!("invalid character, '{c}', in uint literal"),
            InvalidCharBuffer(c) => format!("invalid character, '{c}', in buffer"),
            InvalidCharIdent(c) => format!("invalid character, '{c}', in identifier"),
            InvalidCharTraitIdent(c) => format!("invalid character, '{c}', in trait identifier"),
            InvalidCharPrincipal(c) => format!("invalid character, '{c}', in principal literal"),
            IllegalCharString(c) => format!("invalid character, '{c}', in string literal"),
            IllegalCharUTF8Encoding(c) => format!("invalid character, '{c}', in UTF8 encoding"),
            InvalidUTF8Encoding => "invalid UTF8 encoding".to_string(),
            EmptyUTF8Encoding => "empty UTF8 encoding".to_string(),
            UnterminatedUTF8Encoding => "unterminated UTF8 encoding, missing '}'".to_string(),
            InvalidBufferLength(size) => format!("invalid buffer length, {size}"),
            UnknownEscapeChar(c) => format!("unknown escape character, '{c}'"),
            ExpectedClosing(c) => format!("expected closing '{c}'"),
            ExpectedSeparator => "expected separator".to_string(),
            SingleSemiColon => "unexpected single ';' (comments begin with \";;\"".to_string(),
            UnknownSymbol(c) => format!("unknown symbol, '{c}'"),
            NonASCIIChar(c) => format!("illegal non-ASCII character, '{c}'"),
            NoteToMatchThis(c) => format!("to match this '{c}'"),
            UnsupportedLineEnding => {
                "unsupported line-ending '\\r', only '\\n' is supported".to_string()
            }
            EditorCRLFMode => {
                "you may need to change your editor from CRLF mode to LF mode".to_string()
            }
        }
    }

    fn suggestion(&self) -> Option<String> {
        None
    }

    fn level(&self) -> Level {
        use self::LexerError::*;
        match self {
            NoteToMatchThis(_) => Level::Note,
            EditorCRLFMode => Level::Note,
            _ => Level::Error,
        }
    }
}
