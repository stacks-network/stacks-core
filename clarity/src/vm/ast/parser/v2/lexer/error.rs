// Copyright (C) 2025-2026 Stacks Open Internet Foundation
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

use std::fmt;

use clarity_types::representations::Span;

use crate::vm::diagnostic::{DiagnosableError, Level};

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
    fn write_message(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use self::LexerError::*;
        match self {
            InvalidCharInt(c) => write!(f, "invalid character, '{c}', in int literal"),
            InvalidCharUint(c) => write!(f, "invalid character, '{c}', in uint literal"),
            InvalidCharBuffer(c) => write!(f, "invalid character, '{c}', in buffer"),
            InvalidCharIdent(c) => write!(f, "invalid character, '{c}', in identifier"),
            InvalidCharTraitIdent(c) => write!(f, "invalid character, '{c}', in trait identifier"),
            InvalidCharPrincipal(c) => write!(f, "invalid character, '{c}', in principal literal"),
            IllegalCharString(c) => write!(f, "invalid character, '{c}', in string literal"),
            IllegalCharUTF8Encoding(c) => write!(f, "invalid character, '{c}', in UTF8 encoding"),
            InvalidUTF8Encoding => f.write_str("invalid UTF8 encoding"),
            EmptyUTF8Encoding => f.write_str("empty UTF8 encoding"),
            UnterminatedUTF8Encoding => f.write_str("unterminated UTF8 encoding, missing '}'"),
            InvalidBufferLength(size) => write!(f, "invalid buffer length, {size}"),
            UnknownEscapeChar(c) => write!(f, "unknown escape character, '{c}'"),
            ExpectedClosing(c) => write!(f, "expected closing '{c}'"),
            ExpectedSeparator => f.write_str("expected separator"),
            SingleSemiColon => f.write_str("unexpected single ';' (comments begin with \";;\""),
            UnknownSymbol(c) => write!(f, "unknown symbol, '{c}'"),
            NonASCIIChar(c) => write!(f, "illegal non-ASCII character, '{c}'"),
            NoteToMatchThis(c) => write!(f, "to match this '{c}'"),
            UnsupportedLineEnding => {
                f.write_str("unsupported line-ending '\\r', only '\\n' is supported")
            }
            EditorCRLFMode => {
                f.write_str("you may need to change your editor from CRLF mode to LF mode")
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
