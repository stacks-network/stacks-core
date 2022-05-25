pub mod error;
pub mod token;

use crate::vm::{
    diagnostic::{DiagnosableError, Level},
    representations::Span,
};
use std::{char, str::Chars};
use token::{PlacedToken, Token};

use crate::vm::ast::parser_v2::lexer::error::LexerError;

use self::error::PlacedError;

pub struct Lexer<'a> {
    input: Chars<'a>,
    next: char,
    offset: usize,
    pub line: usize,
    pub column: usize,
    pub last_line: usize,
    pub last_column: usize,
    // While lexing, collect diagnostics and continue on (when possible)
    pub diagnostics: Vec<PlacedError>,
    pub success: bool,
    // Used to report an error for line-endings only on the first instance
    line_endings: bool,
    // `fail_fast` mode indicates that the lexer should not report warnings
    // and should exit on the first error. This is useful for lexing in the
    // context of a stacks-node, while normal mode is useful for developers.
    fail_fast: bool,
}

fn is_separator(ch: char) -> bool {
    match ch {
        '(' | ')' | '{' | '}' | ',' | ':' | '\0' | '.' => true,
        _ => ch.is_ascii_whitespace(),
    }
}

impl<'a> Lexer<'a> {
    pub fn new(input: &'a str, fail_fast: bool) -> Self {
        let mut s = Self {
            input: input.chars(),
            next: 0 as char,
            offset: 0,
            line: 1,
            column: 0,
            last_line: 0,
            last_column: 0,
            diagnostics: vec![],
            success: true,
            line_endings: false,
            fail_fast,
        };
        s.read_char(); // Initialize with the first character
        s
    }

    fn add_diagnostic(&mut self, diagnostic: PlacedError) {
        if self.success && diagnostic.e.level() == Level::Error {
            self.success = false;
        }

        if diagnostic.e.level() == Level::Error || !self.fail_fast {
            self.diagnostics.push(diagnostic);
        }
    }

    fn read_char(&mut self) {
        self.last_line = self.line;
        self.last_column = self.column;

        match self.input.next() {
            Some(ch) => {
                if self.next == '\n' {
                    self.line = self.line + 1;
                    self.column = 0;
                }
                self.next = ch
            }
            None => self.next = '\0',
        }
        self.offset = self.offset + 1;
        self.column = self.column + 1;
    }

    fn report_line_ending(&mut self) {
        if !self.line_endings {
            self.line_endings = true;

            let span = Span {
                start_line: self.line as u32,
                start_column: self.column as u32,
                end_line: self.line as u32,
                end_column: self.column as u32,
            };

            self.add_diagnostic(PlacedError {
                span: span.clone(),
                e: LexerError::UnsupportedLineEnding,
            });
            self.add_diagnostic(PlacedError {
                span: span,
                e: LexerError::EditorCRLFMode,
            });
        }
    }

    fn skip_whitespace(&mut self) {
        while self.next != '\0' {
            match self.next {
                ' ' | '\t' | '\n' => (),
                '\r' => self.report_line_ending(),
                _ => break,
            }
            self.read_char();
        }
    }

    fn read_line(&mut self) -> String {
        let mut line = String::new();
        loop {
            match self.next {
                '\n' => {
                    break;
                }
                '\0' => break,
                '\r' => self.report_line_ending(),
                ch => line.push(ch),
            }
            self.read_char();
        }
        line
    }

    fn proceed_through_error(&mut self, err: LexerError) {
        let start_line = self.line as u32;
        let start_column = self.column as u32;
        while !is_separator(self.next) {
            self.read_char();
        }
        self.add_diagnostic(PlacedError {
            span: Span {
                start_line,
                start_column,
                end_line: self.last_line as u32,
                end_column: self.last_column as u32,
            },
            e: err,
        });
    }

    fn read_identifier(&mut self, first: Option<char>) -> String {
        let mut ident = String::new();
        if let Some(first) = first {
            ident.push(first);
        }

        loop {
            match self.next {
                'a'..='z'
                | 'A'..='Z'
                | '0'..='9'
                | '_'
                | '-'
                | '!'
                | '?'
                | '+'
                | '<'
                | '>'
                | '='
                | '/'
                | '*' => ident.push(self.next),
                _ => {
                    if is_separator(self.next) {
                        return ident;
                    } else {
                        self.proceed_through_error(LexerError::InvalidCharIdent(self.next));
                        return ident;
                    }
                }
            }
            self.read_char();
        }
    }

    fn read_trait_identifier(&mut self) -> String {
        let start_line = self.last_line as u32;
        let start_column = self.last_column as u32;
        let mut ident = String::new();

        loop {
            match self.next {
                'a'..='z' | 'A'..='Z' | '0'..='9' | '_' | '-' => ident.push(self.next),
                '>' => return ident,
                _ => {
                    if is_separator(self.next) {
                        self.add_diagnostic(PlacedError {
                            span: Span {
                                start_line: self.line as u32,
                                start_column: self.column as u32,
                                end_line: self.line as u32,
                                end_column: self.column as u32,
                            },
                            e: LexerError::ExpectedClosing('>'),
                        });
                        self.add_diagnostic(PlacedError {
                            span: Span {
                                start_line,
                                start_column,
                                end_line: start_line,
                                end_column: start_column,
                            },
                            e: LexerError::NoteToMatchThis('<'),
                        });
                        return ident;
                    } else {
                        self.proceed_through_error(LexerError::InvalidCharTraitIdent(self.next));
                        return ident;
                    }
                }
            }
            self.read_char();
        }
    }

    fn read_principal(&mut self) -> String {
        let mut principal = String::new();

        loop {
            self.read_char();
            match self.next {
                'A'..='Z' | '0'..='9' => principal.push(self.next),
                _ => {
                    if is_separator(self.next) {
                        return principal;
                    } else {
                        self.proceed_through_error(LexerError::InvalidCharPrincipal(self.next));
                        return principal;
                    }
                }
            }
        }
    }

    fn read_unsigned(&mut self) -> u128 {
        let mut num: u128 = 0;
        while self.next.is_ascii_digit() {
            let digit = self.next as u32 - '0' as u32;
            num = num * 10 + digit as u128;
            self.read_char();
        }
        if !is_separator(self.next) {
            self.proceed_through_error(LexerError::InvalidCharUint(self.next));
        }
        num
    }

    fn read_integer(&mut self) -> i128 {
        let mut num: i128 = 0;
        while self.next.is_ascii_digit() {
            let digit = self.next as u32 - '0' as u32;
            num = num * 10 + digit as i128;
            self.read_char();
        }
        if !is_separator(self.next) {
            self.proceed_through_error(LexerError::InvalidCharInt(self.next));
        }
        num
    }

    fn read_hex(&mut self) -> Vec<u8> {
        let start_line = self.line as u32;
        let start_column = (self.column - 1) as u32;
        let mut bytes = vec![];
        loop {
            self.read_char();

            let f = self.next;
            if !f.is_ascii_hexdigit() {
                if !is_separator(f) {
                    self.proceed_through_error(LexerError::InvalidCharBuffer(f));
                }
                return bytes;
            }

            self.read_char();
            let s = self.next;
            if !s.is_ascii_hexdigit() {
                if is_separator(s) {
                    self.add_diagnostic(PlacedError {
                        span: Span {
                            start_line,
                            start_column,
                            end_line: self.last_line as u32,
                            end_column: self.last_column as u32,
                        },
                        e: LexerError::InvalidBufferLength(bytes.len() * 2 + 1),
                    });
                } else {
                    self.proceed_through_error(LexerError::InvalidCharBuffer(s));
                }
                return bytes;
            }

            bytes.push((f.to_digit(16).unwrap() * 0x10 + s.to_digit(16).unwrap()) as u8);
        }
    }

    fn read_ascii_string(&mut self) -> String {
        let start_line = self.line as u32;
        let start_column = self.column as u32;
        let mut s = String::new();
        let mut escaped = false;
        self.read_char();
        loop {
            if escaped {
                let ch = match self.next {
                    '\\' => '\\',
                    '\"' => '\"',
                    'n' => '\n',
                    't' => '\t',
                    'r' => '\r',
                    '0' => '\0',
                    _ => {
                        self.add_diagnostic(PlacedError {
                            span: Span {
                                start_line: self.last_line as u32,
                                start_column: self.last_column as u32,
                                end_line: self.line as u32,
                                end_column: self.column as u32,
                            },
                            e: LexerError::UnknownEscapeChar(self.next),
                        });
                        '?'
                    }
                };
                s.push(ch);
                escaped = false;
            } else {
                match self.next {
                    '"' => {
                        self.read_char();
                        return s;
                    }
                    '\\' => escaped = !escaped,
                    '\0' | '\n' => {
                        self.add_diagnostic(PlacedError {
                            span: Span {
                                start_line: self.line as u32,
                                start_column: self.column as u32,
                                end_line: self.line as u32,
                                end_column: self.column as u32,
                            },
                            e: LexerError::ExpectedClosing('"'),
                        });
                        self.add_diagnostic(PlacedError {
                            span: Span {
                                start_line,
                                start_column,
                                end_line: start_line,
                                end_column: start_column,
                            },
                            e: LexerError::NoteToMatchThis('"'),
                        });
                        return s;
                    }
                    _ => {
                        if !self.next.is_ascii() {
                            self.add_diagnostic(PlacedError {
                                span: Span {
                                    start_line: self.line as u32,
                                    start_column: self.column as u32,
                                    end_line: self.line as u32,
                                    end_column: self.column as u32,
                                },
                                e: LexerError::IllegalCharString(self.next),
                            });
                        } else {
                            s.push(self.next);
                        }
                    }
                }
            }
            self.read_char();
        }
    }

    fn read_utf8_encoding(&mut self) -> String {
        // Red exclamation mark
        const error_string: &str = "2757";

        self.read_char();
        let start_line = self.line as u32;
        let start_column = self.column as u32;

        if self.next != '{' {
            self.add_diagnostic(PlacedError {
                span: Span {
                    start_line: self.line as u32,
                    start_column: self.column as u32,
                    end_line: self.line as u32,
                    end_column: self.column as u32,
                },
                e: LexerError::InvalidUTF8Encoding,
            });
            return error_string.to_string();
        }

        let mut code = String::new();
        loop {
            self.read_char();
            match self.next {
                '}' => {
                    if code.len() == 0 {
                        self.add_diagnostic(PlacedError {
                            span: Span {
                                start_line,
                                start_column,
                                end_line: self.line as u32,
                                end_column: self.column as u32,
                            },
                            e: LexerError::EmptyUTF8Encoding,
                        });
                        self.read_char();
                        return error_string.to_string();
                    }
                    self.read_char();
                    return code;
                }
                '\0' => {
                    self.add_diagnostic(PlacedError {
                        span: Span {
                            start_line: self.line as u32,
                            start_column: self.column as u32,
                            end_line: self.line as u32,
                            end_column: self.column as u32,
                        },
                        e: LexerError::UnterminatedUTF8Encoding,
                    });
                    return error_string.to_string();
                }
                '"' => {
                    self.add_diagnostic(PlacedError {
                        span: Span {
                            start_line: self.line as u32,
                            start_column: self.column as u32,
                            end_line: self.line as u32,
                            end_column: self.column as u32,
                        },
                        e: LexerError::UnterminatedUTF8Encoding,
                    });
                    self.add_diagnostic(PlacedError {
                        span: Span {
                            start_line,
                            start_column,
                            end_line: start_line,
                            end_column: start_column,
                        },
                        e: LexerError::NoteToMatchThis('}'),
                    });
                    return error_string.to_string();
                }
                _ => {
                    if self.next.is_ascii_hexdigit() {
                        code.push(self.next);
                    } else {
                        self.add_diagnostic(PlacedError {
                            span: Span {
                                start_line: self.line as u32,
                                start_column: self.column as u32,
                                end_line: self.line as u32,
                                end_column: self.column as u32,
                            },
                            e: LexerError::IllegalCharUTF8Encoding(self.next),
                        });
                    }
                }
            }
        }
    }

    fn read_utf8_string(&mut self) -> Vec<Vec<u8>> {
        let start_line = self.last_line as u32;
        let start_column = self.last_column as u32;
        let mut data: Vec<Vec<u8>> = vec![];
        let mut escaped = false;
        let mut advance = true;
        self.read_char();
        loop {
            if escaped {
                match self.next {
                    '\\' => data.push("\\".to_string().into_bytes()),
                    '\"' => data.push("\"".to_string().into_bytes()),
                    'n' => data.push("\n".to_string().into_bytes()),
                    't' => data.push("\t".to_string().into_bytes()),
                    'r' => data.push("\r".to_string().into_bytes()),
                    '0' => data.push("\0".to_string().into_bytes()),
                    'u' => {
                        let encode_str = self.read_utf8_encoding();
                        let unicode_char = {
                            let u = u32::from_str_radix(&encode_str, 16).unwrap();
                            let c = char::from_u32(u).unwrap();
                            let mut encoded_char: Vec<u8> = vec![0; c.len_utf8()];
                            c.encode_utf8(&mut encoded_char[..]);
                            encoded_char
                        };
                        data.push(unicode_char);
                        advance = false;
                    }
                    _ => {
                        self.add_diagnostic(PlacedError {
                            span: Span {
                                start_line: self.last_line as u32,
                                start_column: self.last_column as u32,
                                end_line: self.line as u32,
                                end_column: self.column as u32,
                            },
                            e: LexerError::UnknownEscapeChar(self.next),
                        });
                        data.push("?".to_string().into_bytes());
                    }
                };
                escaped = false;
            } else {
                match self.next {
                    '"' => {
                        self.read_char();
                        return data;
                    }
                    '\\' => escaped = !escaped,
                    '\0' | '\n' => {
                        self.add_diagnostic(PlacedError {
                            span: Span {
                                start_line: self.line as u32,
                                start_column: self.column as u32,
                                end_line: self.line as u32,
                                end_column: self.column as u32,
                            },
                            e: LexerError::ExpectedClosing('"'),
                        });
                        self.add_diagnostic(PlacedError {
                            span: Span {
                                start_line,
                                start_column,
                                end_line: start_line,
                                end_column: start_column + 1,
                            },
                            e: LexerError::NoteToMatchThis('"'),
                        });
                        return data;
                    }
                    _ => {
                        data.push(self.next.to_string().into_bytes());
                    }
                }
            }
            if advance {
                self.read_char();
            } else {
                advance = true;
            }
        }
    }

    pub fn read_token(&mut self) -> Result<PlacedToken, LexerError> {
        let start_line = self.line as u32;
        let start_column = self.column as u32;
        let mut advance = true;

        let token = match self.next {
            '\0' => Token::Eof,
            '(' => Token::Lparen,
            ')' => Token::Rparen,
            '{' => Token::Lbrace,
            '}' => Token::Rbrace,
            ':' => Token::Colon,
            '.' => Token::Dot,
            ',' => Token::Comma,
            '+' => Token::Plus,
            '*' => Token::Multiply,
            '/' => Token::Divide,
            '-' => {
                advance = false;
                self.read_char();
                if self.next.is_ascii_digit() {
                    Token::Int(-self.read_integer())
                } else {
                    Token::Minus
                }
            }
            '<' => {
                self.read_char();
                if self.next == '=' {
                    Token::LessEqual
                } else if self.next.is_ascii_alphabetic() {
                    Token::TraitIdent(self.read_trait_identifier())
                } else {
                    advance = false;
                    Token::Less
                }
            }
            '>' => {
                self.read_char();
                if self.next == '=' {
                    Token::GreaterEqual
                } else {
                    advance = false;
                    Token::Greater
                }
            }
            ';' => {
                self.read_char();
                if self.next != ';' {
                    // If there is just one ';', report an error but continue
                    //  parsing as if there were two (a comment).
                    self.add_diagnostic(PlacedError {
                        span: Span {
                            start_line: self.last_line as u32,
                            start_column: self.last_column as u32,
                            end_line: self.last_line as u32,
                            end_column: self.last_column as u32,
                        },
                        e: LexerError::SingleSemiColon,
                    });
                } else {
                    self.read_char();
                }
                advance = false;
                let comment = self.read_line();
                Token::Comment(comment.trim_start().to_string())
            }
            '\'' => {
                advance = false;
                Token::Principal(self.read_principal())
            }
            'u' => {
                advance = false;
                self.read_char();
                if self.next.is_ascii_digit() {
                    Token::Uint(self.read_unsigned())
                } else if self.next == '"' {
                    Token::Utf8String(self.read_utf8_string())
                } else {
                    Token::Ident(self.read_identifier(Some('u')))
                }
            }
            ' ' | '\t' | '\r' | '\n' => {
                self.skip_whitespace();
                advance = false;
                Token::Whitespace
            }
            '"' => {
                advance = false;
                Token::AsciiString(self.read_ascii_string())
            }
            '0' => {
                advance = false;
                self.read_char();
                if self.next == 'x' {
                    Token::Bytes(self.read_hex())
                } else if self.next.is_ascii_digit() {
                    Token::Int(self.read_integer())
                } else if is_separator(self.next) {
                    Token::Int(0)
                } else {
                    self.proceed_through_error(LexerError::InvalidCharInt(self.next));
                    Token::Int(0)
                }
            }
            _ => {
                if self.next.is_ascii_alphabetic() {
                    advance = false;
                    Token::Ident(self.read_identifier(None))
                } else if self.next.is_ascii_digit() {
                    advance = false;
                    Token::Int(self.read_integer())
                } else {
                    self.add_diagnostic(PlacedError {
                        span: Span {
                            start_line: self.line as u32,
                            start_column: self.column as u32,
                            end_line: self.line as u32,
                            end_column: self.column as u32,
                        },
                        e: LexerError::UnknownSymbol(self.next),
                    });
                    Token::Placeholder
                }
            }
        };

        if advance {
            self.read_char();
        }

        // Check for separators when required
        match token {
            Token::Plus
            | Token::Minus
            | Token::Multiply
            | Token::Divide
            | Token::Less
            | Token::LessEqual
            | Token::Greater
            | Token::GreaterEqual => {
                if !is_separator(self.next) {
                    self.add_diagnostic(PlacedError {
                        span: Span {
                            start_line: self.line as u32,
                            start_column: self.column as u32,
                            end_line: self.line as u32,
                            end_column: self.column as u32,
                        },
                        e: LexerError::ExpectedSeparator,
                    });
                }
            }
            _ => (),
        }

        if self.fail_fast && !self.success {
            return Err(self.diagnostics.remove(0).e);
        }

        Ok(PlacedToken {
            span: Span {
                start_line,
                start_column,
                end_line: self.last_line as u32,
                end_column: self.last_column as u32,
            },
            token,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::vm::types::UTF8Data;

    use super::*;

    #[test]
    fn read_tokens() {
        let mut lexer = Lexer::new("", false);
        assert_eq!(lexer.read_token().unwrap().token, Token::Eof);
        assert_eq!(lexer.diagnostics.len(), 0);

        let mut lexer = Lexer::new(" ", false);
        assert_eq!(lexer.read_token().unwrap().token, Token::Whitespace);
        assert_eq!(lexer.diagnostics.len(), 0);

        let mut lexer = Lexer::new("\t", false);
        assert_eq!(lexer.read_token().unwrap().token, Token::Whitespace);
        assert_eq!(lexer.diagnostics.len(), 0);

        let mut lexer = Lexer::new("\n", false);
        assert_eq!(lexer.read_token().unwrap().token, Token::Whitespace);
        assert_eq!(lexer.diagnostics.len(), 0);

        let mut lexer = Lexer::new("\r", false);
        assert_eq!(lexer.read_token().unwrap().token, Token::Whitespace);
        assert_eq!(lexer.diagnostics.len(), 2);
        assert_eq!(lexer.diagnostics[0].e, LexerError::UnsupportedLineEnding);
        assert_eq!(lexer.diagnostics[1].e, LexerError::EditorCRLFMode);

        lexer = Lexer::new("(", false);
        assert_eq!(lexer.read_token().unwrap().token, Token::Lparen);
        assert_eq!(lexer.diagnostics.len(), 0);

        lexer = Lexer::new(")", false);
        assert_eq!(lexer.read_token().unwrap().token, Token::Rparen);
        assert_eq!(lexer.diagnostics.len(), 0);

        lexer = Lexer::new("{", false);
        assert_eq!(lexer.read_token().unwrap().token, Token::Lbrace);
        assert_eq!(lexer.diagnostics.len(), 0);

        lexer = Lexer::new("}", false);
        assert_eq!(lexer.read_token().unwrap().token, Token::Rbrace);
        assert_eq!(lexer.diagnostics.len(), 0);

        lexer = Lexer::new(":", false);
        assert_eq!(lexer.read_token().unwrap().token, Token::Colon);
        assert_eq!(lexer.diagnostics.len(), 0);

        lexer = Lexer::new(",", false);
        assert_eq!(lexer.read_token().unwrap().token, Token::Comma);
        assert_eq!(lexer.diagnostics.len(), 0);

        lexer = Lexer::new(".", false);
        assert_eq!(lexer.read_token().unwrap().token, Token::Dot);
        assert_eq!(lexer.diagnostics.len(), 0);

        lexer = Lexer::new("123", false);
        assert_eq!(lexer.read_token().unwrap().token, Token::Int(123));
        assert_eq!(lexer.diagnostics.len(), 0);

        lexer = Lexer::new("0123", false);
        assert_eq!(lexer.read_token().unwrap().token, Token::Int(123));
        assert_eq!(lexer.diagnostics.len(), 0);

        lexer = Lexer::new("0", false);
        assert_eq!(lexer.read_token().unwrap().token, Token::Int(0));
        assert_eq!(lexer.diagnostics.len(), 0);

        lexer = Lexer::new("0a", false);
        assert_eq!(lexer.read_token().unwrap().token, Token::Int(0));
        assert_eq!(lexer.diagnostics.len(), 1);
        assert_eq!(lexer.diagnostics[0].e, LexerError::InvalidCharInt('a'));

        lexer = Lexer::new("56789*", false);
        assert_eq!(lexer.read_token().unwrap().token, Token::Int(56789));
        assert_eq!(lexer.diagnostics.len(), 1);
        assert_eq!(lexer.diagnostics[0].e, LexerError::InvalidCharInt('*'));

        lexer = Lexer::new("u123", false);
        assert_eq!(lexer.read_token().unwrap().token, Token::Uint(123));

        lexer = Lexer::new("u1a", false);
        assert_eq!(lexer.read_token().unwrap().token, Token::Uint(1));
        assert_eq!(lexer.diagnostics.len(), 1);
        assert_eq!(lexer.diagnostics[0].e, LexerError::InvalidCharUint('a'));

        lexer = Lexer::new("\"hello\"", false);
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::AsciiString("hello".to_string())
        );
        assert_eq!(lexer.diagnostics.len(), 0);

        lexer = Lexer::new("\"new\\nline\"", false);
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::AsciiString("new\nline".to_string())
        );
        assert_eq!(lexer.diagnostics.len(), 0);

        lexer = Lexer::new("\"quote \\\"this\\\"\"", false);
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::AsciiString("quote \"this\"".to_string())
        );
        assert_eq!(lexer.diagnostics.len(), 0);

        lexer = Lexer::new("\"\\r\\t\\0\\\\ ok\"", false);
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::AsciiString("\r\t\0\\ ok".to_string())
        );
        assert_eq!(lexer.diagnostics.len(), 0);

        lexer = Lexer::new("\"\\x\"", false);
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::AsciiString("?".to_string())
        );
        assert_eq!(lexer.diagnostics.len(), 1);
        assert_eq!(lexer.diagnostics[0].e, LexerError::UnknownEscapeChar('x'));

        lexer = Lexer::new("\"open", false);
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::AsciiString("open".to_string())
        );
        assert_eq!(lexer.diagnostics.len(), 2);
        assert_eq!(lexer.diagnostics[0].e, LexerError::ExpectedClosing('"'));
        assert_eq!(lexer.diagnostics[1].e, LexerError::NoteToMatchThis('"'));

        lexer = Lexer::new("\"👎\"", false);
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::AsciiString("".to_string())
        );
        assert_eq!(lexer.diagnostics.len(), 1);
        assert_eq!(lexer.diagnostics[0].e, LexerError::IllegalCharString('👎'));

        lexer = Lexer::new("\"\\u{1F600}\"", false);
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::AsciiString("?{1F600}".to_string())
        );
        assert_eq!(lexer.diagnostics.len(), 1);
        assert_eq!(lexer.diagnostics[0].e, LexerError::UnknownEscapeChar('u'));

        lexer = Lexer::new("u\"hello\"", false);
        let data = match lexer.read_token().unwrap().token {
            Token::Utf8String(data) => UTF8Data { data },
            _ => panic!("failed to parse utf8 string"),
        };
        assert_eq!(format!("{}", data), "u\"hello\"");
        assert_eq!(lexer.diagnostics.len(), 0);

        lexer = Lexer::new("u\"\\u{1F600}\"", false);
        let data = match lexer.read_token().unwrap().token {
            Token::Utf8String(data) => UTF8Data { data },
            _ => panic!("failed to parse utf8 string"),
        };
        assert_eq!(format!("{}", data), "u\"\\u{f09f9880}\"");
        assert_eq!(lexer.diagnostics.len(), 0);

        lexer = Lexer::new("u\"quote \\\"this\\\"\"", false);
        let data = match lexer.read_token().unwrap().token {
            Token::Utf8String(data) => UTF8Data { data },
            _ => panic!("failed to parse utf8 string"),
        };
        assert_eq!(format!("{}", data), "u\"quote \\\"this\\\"\"");
        assert_eq!(lexer.diagnostics.len(), 0);

        lexer = Lexer::new("u\"\\n\\r\\t\\0\\\\ ok\"", false);
        let data = match lexer.read_token().unwrap().token {
            Token::Utf8String(data) => UTF8Data { data },
            _ => panic!("failed to parse utf8 string"),
        };
        assert_eq!(format!("{}", data), "u\"\\n\\r\\t\\x00\\\\ ok\"");
        assert_eq!(lexer.diagnostics.len(), 0);

        lexer = Lexer::new("u\"\\x\"", false);
        let data = match lexer.read_token().unwrap().token {
            Token::Utf8String(data) => UTF8Data { data },
            _ => panic!("failed to parse utf8 string"),
        };
        assert_eq!(format!("{}", data), "u\"?\"");
        assert_eq!(lexer.diagnostics.len(), 1);
        assert_eq!(lexer.diagnostics[0].e, LexerError::UnknownEscapeChar('x'));

        lexer = Lexer::new("u\"open", false);
        let data = match lexer.read_token().unwrap().token {
            Token::Utf8String(data) => UTF8Data { data },
            _ => panic!("failed to parse utf8 string"),
        };
        assert_eq!(format!("{}", data), "u\"open\"");
        assert_eq!(lexer.diagnostics.len(), 2);
        assert_eq!(lexer.diagnostics[0].e, LexerError::ExpectedClosing('"'));
        assert_eq!(lexer.diagnostics[1].e, LexerError::NoteToMatchThis('"'));

        lexer = Lexer::new("u\"\\uabc\"", false);
        let data = match lexer.read_token().unwrap().token {
            Token::Utf8String(data) => UTF8Data { data },
            _ => panic!("failed to parse utf8 string"),
        };
        assert_eq!(format!("{}", data), "u\"\\u{e29d97}abc\"");
        assert_eq!(lexer.diagnostics.len(), 1);
        assert_eq!(lexer.diagnostics[0].e, LexerError::InvalidUTF8Encoding);

        lexer = Lexer::new("u\"a \\u{", false);
        let data = match lexer.read_token().unwrap().token {
            Token::Utf8String(data) => UTF8Data { data },
            _ => panic!("failed to parse utf8 string"),
        };
        assert_eq!(format!("{}", data), "u\"a \\u{e29d97}\"");
        assert_eq!(lexer.diagnostics.len(), 3);
        assert_eq!(lexer.diagnostics[0].e, LexerError::UnterminatedUTF8Encoding);
        assert_eq!(lexer.diagnostics[1].e, LexerError::ExpectedClosing('"'));
        assert_eq!(lexer.diagnostics[2].e, LexerError::NoteToMatchThis('"'));

        lexer = Lexer::new("u\"\\u{}\"", false);
        let data = match lexer.read_token().unwrap().token {
            Token::Utf8String(data) => UTF8Data { data },
            _ => panic!("failed to parse utf8 string"),
        };
        assert_eq!(format!("{}", data), "u\"\\u{e29d97}\"");
        assert_eq!(lexer.diagnostics.len(), 1);
        assert_eq!(lexer.diagnostics[0].e, LexerError::EmptyUTF8Encoding);
        assert_eq!(
            lexer.diagnostics[0].span,
            Span {
                start_line: 1,
                start_column: 5,
                end_line: 1,
                end_column: 6
            }
        );

        lexer = Lexer::new("u\"a \\u{\" foo", false);
        let data = match lexer.read_token().unwrap().token {
            Token::Utf8String(data) => UTF8Data { data },
            _ => panic!("failed to parse utf8 string"),
        };
        assert_eq!(format!("{}", data), "u\"a \\u{e29d97}\"");
        assert_eq!(lexer.diagnostics.len(), 2);
        assert_eq!(lexer.diagnostics[0].e, LexerError::UnterminatedUTF8Encoding);
        assert_eq!(lexer.diagnostics[1].e, LexerError::NoteToMatchThis('}'));

        lexer = Lexer::new("u\"\\u{24gb}\" foo", false);
        let data = match lexer.read_token().unwrap().token {
            Token::Utf8String(data) => UTF8Data { data },
            _ => panic!("failed to parse utf8 string"),
        };
        assert_eq!(format!("{}", data), "u\"\\u{c98b}\"");
        assert_eq!(lexer.diagnostics.len(), 1);
        assert_eq!(
            lexer.diagnostics[0].e,
            LexerError::IllegalCharUTF8Encoding('g')
        );
        assert_eq!(
            lexer.diagnostics[0].span,
            Span {
                start_line: 1,
                start_column: 8,
                end_line: 1,
                end_column: 8
            }
        );
        assert_eq!(lexer.read_token().unwrap().token, Token::Whitespace);
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::Ident("foo".to_string())
        );
        assert_eq!(lexer.read_token().unwrap().token, Token::Eof);

        lexer = Lexer::new("0x123abc", false);
        if let Token::Bytes(v) = lexer.read_token().unwrap().token {
            assert_eq!(v.len(), 3);
            assert_eq!(v[0], 0x12);
            assert_eq!(v[1], 0x3a);
            assert_eq!(v[2], 0xbc);
        } else {
            assert!(false);
        }
        assert_eq!(lexer.diagnostics.len(), 0);

        lexer = Lexer::new("0xdefg", false);
        if let Token::Bytes(v) = lexer.read_token().unwrap().token {
            assert_eq!(v.len(), 1);
            assert_eq!(v[0], 0xde);
        } else {
            assert!(false);
        }
        assert_eq!(lexer.diagnostics.len(), 1);
        assert_eq!(lexer.diagnostics[0].e, LexerError::InvalidCharBuffer('g'));

        lexer = Lexer::new("0xdef", false);
        if let Token::Bytes(v) = lexer.read_token().unwrap().token {
            assert_eq!(v.len(), 1);
            assert_eq!(v[0], 0xde);
        } else {
            assert!(false);
        }
        assert_eq!(lexer.diagnostics.len(), 1);
        assert_eq!(lexer.diagnostics[0].e, LexerError::InvalidBufferLength(3));

        lexer = Lexer::new("0x00p5", false);
        if let Token::Bytes(v) = lexer.read_token().unwrap().token {
            assert_eq!(v.len(), 1);
            assert_eq!(v[0], 0x0);
        } else {
            assert!(false);
        }
        assert_eq!(lexer.diagnostics.len(), 1);
        assert_eq!(lexer.diagnostics[0].e, LexerError::InvalidCharBuffer('p'));

        lexer = Lexer::new("0xdef0 ", false);
        if let Token::Bytes(v) = lexer.read_token().unwrap().token {
            assert_eq!(v.len(), 2);
            assert_eq!(v[0], 0xde);
            assert_eq!(v[1], 0xf0);
        } else {
            assert!(false);
        }
        assert_eq!(lexer.diagnostics.len(), 0);

        lexer = Lexer::new("foo", false);
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::Ident("foo".to_string())
        );
        assert_eq!(lexer.diagnostics.len(), 0);

        lexer = Lexer::new("ubar", false);
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::Ident("ubar".to_string())
        );
        assert_eq!(lexer.diagnostics.len(), 0);

        lexer = Lexer::new("baz👍buz", false);
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::Ident("baz".to_string())
        );
        assert_eq!(lexer.diagnostics.len(), 1);
        assert_eq!(lexer.diagnostics[0].e, LexerError::InvalidCharIdent('👍'));

        lexer = Lexer::new("+", false);
        assert_eq!(lexer.read_token().unwrap().token, Token::Plus);
        assert_eq!(lexer.diagnostics.len(), 0);

        lexer = Lexer::new("-", false);
        assert_eq!(lexer.read_token().unwrap().token, Token::Minus);
        assert_eq!(lexer.diagnostics.len(), 0);

        lexer = Lexer::new("*", false);
        assert_eq!(lexer.read_token().unwrap().token, Token::Multiply);
        assert_eq!(lexer.diagnostics.len(), 0);

        lexer = Lexer::new("/", false);
        assert_eq!(lexer.read_token().unwrap().token, Token::Divide);
        assert_eq!(lexer.diagnostics.len(), 0);

        lexer = Lexer::new("<", false);
        assert_eq!(lexer.read_token().unwrap().token, Token::Less);
        assert_eq!(lexer.diagnostics.len(), 0);

        lexer = Lexer::new("<=", false);
        assert_eq!(lexer.read_token().unwrap().token, Token::LessEqual);
        assert_eq!(lexer.diagnostics.len(), 0);

        lexer = Lexer::new(">", false);
        assert_eq!(lexer.read_token().unwrap().token, Token::Greater);
        assert_eq!(lexer.diagnostics.len(), 0);

        lexer = Lexer::new(">=", false);
        assert_eq!(lexer.read_token().unwrap().token, Token::GreaterEqual);
        assert_eq!(lexer.diagnostics.len(), 0);

        lexer = Lexer::new(";; this is a comment", false);
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::Comment("this is a comment".to_string())
        );
        assert_eq!(lexer.diagnostics.len(), 0);

        lexer = Lexer::new(";; this is a comment\nthis is not", false);
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::Comment("this is a comment".to_string())
        );
        assert_eq!(lexer.diagnostics.len(), 0);

        lexer = Lexer::new(";; this is a comment\r\n", false);
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::Comment("this is a comment".to_string())
        );
        assert_eq!(lexer.diagnostics.len(), 2);
        assert_eq!(lexer.diagnostics[0].e, LexerError::UnsupportedLineEnding);
        assert_eq!(lexer.diagnostics[1].e, LexerError::EditorCRLFMode);

        lexer = Lexer::new("; this is not a comment", false);
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::Comment("this is not a comment".to_string())
        );
        assert_eq!(lexer.diagnostics.len(), 1);
        assert_eq!(lexer.diagnostics[0].e, LexerError::SingleSemiColon);

        lexer = Lexer::new("'1234567890ABCDEFG", false);
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::Principal("1234567890ABCDEFG".to_string())
        );
        assert_eq!(lexer.diagnostics.len(), 0);

        lexer = Lexer::new("'1234567890aBCDEFG", false);
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::Principal("1234567890".to_string())
        );
        assert_eq!(lexer.diagnostics.len(), 1);
        assert_eq!(
            lexer.diagnostics[0].e,
            LexerError::InvalidCharPrincipal('a')
        );

        lexer = Lexer::new("~", false);
        assert_eq!(lexer.read_token().unwrap().token, Token::Placeholder);
        assert_eq!(lexer.diagnostics.len(), 1);
        assert_eq!(lexer.diagnostics[0].e, LexerError::UnknownSymbol('~'));
    }

    #[test]
    fn read_multiple_tokens() {
        let mut lexer = Lexer::new(" +321", false);
        assert_eq!(lexer.read_token().unwrap().token, Token::Whitespace);
        assert_eq!(lexer.read_token().unwrap().token, Token::Plus);
        assert_eq!(lexer.read_token().unwrap().token, Token::Int(321));
        assert_eq!(lexer.read_token().unwrap().token, Token::Eof);
        assert_eq!(lexer.read_token().unwrap().token, Token::Eof);
    }

    #[test]
    fn check_span() {
        let mut lexer = Lexer::new(
            r#"
 (foo)
    }1234{abc
        +-*/    < <=       >
>=.: ;; comment
   "hello" u"world"     0x0123456789abcdeffedcba9876543210
	

   foo-bar_
"#,
            false,
        );
        let mut token = lexer.read_token().unwrap();
        assert_eq!(token.token, Token::Whitespace);
        assert_eq!(
            token.span,
            Span {
                start_line: 1,
                start_column: 1,
                end_line: 2,
                end_column: 1
            }
        );

        token = lexer.read_token().unwrap();
        assert_eq!(token.token, Token::Lparen);
        assert_eq!(
            token.span,
            Span {
                start_line: 2,
                start_column: 2,
                end_line: 2,
                end_column: 2
            }
        );

        token = lexer.read_token().unwrap();
        assert_eq!(token.token, Token::Ident("foo".to_string()));
        assert_eq!(
            token.span,
            Span {
                start_line: 2,
                start_column: 3,
                end_line: 2,
                end_column: 5
            }
        );

        token = lexer.read_token().unwrap();
        assert_eq!(token.token, Token::Rparen);
        assert_eq!(
            token.span,
            Span {
                start_line: 2,
                start_column: 6,
                end_line: 2,
                end_column: 6
            }
        );

        token = lexer.read_token().unwrap();
        assert_eq!(token.token, Token::Whitespace);
        assert_eq!(
            token.span,
            Span {
                start_line: 2,
                start_column: 7,
                end_line: 3,
                end_column: 4
            }
        );

        token = lexer.read_token().unwrap();
        assert_eq!(token.token, Token::Rbrace);
        assert_eq!(
            token.span,
            Span {
                start_line: 3,
                start_column: 5,
                end_line: 3,
                end_column: 5
            }
        );

        token = lexer.read_token().unwrap();
        assert_eq!(token.token, Token::Int(1234));
        assert_eq!(
            token.span,
            Span {
                start_line: 3,
                start_column: 6,
                end_line: 3,
                end_column: 9
            }
        );

        token = lexer.read_token().unwrap();
        assert_eq!(token.token, Token::Lbrace);
        assert_eq!(
            token.span,
            Span {
                start_line: 3,
                start_column: 10,
                end_line: 3,
                end_column: 10
            }
        );

        token = lexer.read_token().unwrap();
        assert_eq!(token.token, Token::Ident("abc".to_string()));
        assert_eq!(
            token.span,
            Span {
                start_line: 3,
                start_column: 11,
                end_line: 3,
                end_column: 13
            }
        );

        token = lexer.read_token().unwrap();
        assert_eq!(token.token, Token::Whitespace);
        assert_eq!(
            token.span,
            Span {
                start_line: 3,
                start_column: 14,
                end_line: 4,
                end_column: 8
            }
        );

        token = lexer.read_token().unwrap();
        assert_eq!(token.token, Token::Plus);
        assert_eq!(
            token.span,
            Span {
                start_line: 4,
                start_column: 9,
                end_line: 4,
                end_column: 9
            }
        );

        token = lexer.read_token().unwrap();
        assert_eq!(token.token, Token::Minus);
        assert_eq!(
            token.span,
            Span {
                start_line: 4,
                start_column: 10,
                end_line: 4,
                end_column: 10
            }
        );

        token = lexer.read_token().unwrap();
        assert_eq!(token.token, Token::Multiply);
        assert_eq!(
            token.span,
            Span {
                start_line: 4,
                start_column: 11,
                end_line: 4,
                end_column: 11
            }
        );

        token = lexer.read_token().unwrap();
        assert_eq!(token.token, Token::Divide);
        assert_eq!(
            token.span,
            Span {
                start_line: 4,
                start_column: 12,
                end_line: 4,
                end_column: 12
            }
        );

        token = lexer.read_token().unwrap();
        assert_eq!(token.token, Token::Whitespace);
        assert_eq!(
            token.span,
            Span {
                start_line: 4,
                start_column: 13,
                end_line: 4,
                end_column: 16
            }
        );

        token = lexer.read_token().unwrap();
        assert_eq!(token.token, Token::Less);
        assert_eq!(
            token.span,
            Span {
                start_line: 4,
                start_column: 17,
                end_line: 4,
                end_column: 17
            }
        );

        token = lexer.read_token().unwrap();
        assert_eq!(token.token, Token::Whitespace);
        assert_eq!(
            token.span,
            Span {
                start_line: 4,
                start_column: 18,
                end_line: 4,
                end_column: 18
            }
        );

        token = lexer.read_token().unwrap();
        assert_eq!(token.token, Token::LessEqual);
        assert_eq!(
            token.span,
            Span {
                start_line: 4,
                start_column: 19,
                end_line: 4,
                end_column: 20
            }
        );

        token = lexer.read_token().unwrap();
        assert_eq!(token.token, Token::Whitespace);
        assert_eq!(
            token.span,
            Span {
                start_line: 4,
                start_column: 21,
                end_line: 4,
                end_column: 27
            }
        );

        token = lexer.read_token().unwrap();
        assert_eq!(token.token, Token::Greater);
        assert_eq!(
            token.span,
            Span {
                start_line: 4,
                start_column: 28,
                end_line: 4,
                end_column: 28
            }
        );

        token = lexer.read_token().unwrap();
        assert_eq!(token.token, Token::Whitespace);
        assert_eq!(
            token.span,
            Span {
                start_line: 4,
                start_column: 29,
                end_line: 4,
                end_column: 29
            }
        );

        token = lexer.read_token().unwrap();
        assert_eq!(token.token, Token::GreaterEqual);
        assert_eq!(
            token.span,
            Span {
                start_line: 5,
                start_column: 1,
                end_line: 5,
                end_column: 2
            }
        );

        token = lexer.read_token().unwrap();
        assert_eq!(token.token, Token::Dot);
        assert_eq!(
            token.span,
            Span {
                start_line: 5,
                start_column: 3,
                end_line: 5,
                end_column: 3
            }
        );

        token = lexer.read_token().unwrap();
        assert_eq!(token.token, Token::Colon);
        assert_eq!(
            token.span,
            Span {
                start_line: 5,
                start_column: 4,
                end_line: 5,
                end_column: 4
            }
        );

        token = lexer.read_token().unwrap();
        assert_eq!(token.token, Token::Whitespace);
        assert_eq!(
            token.span,
            Span {
                start_line: 5,
                start_column: 5,
                end_line: 5,
                end_column: 5
            }
        );

        token = lexer.read_token().unwrap();
        assert_eq!(token.token, Token::Comment("comment".to_string()));
        assert_eq!(
            token.span,
            Span {
                start_line: 5,
                start_column: 6,
                end_line: 5,
                end_column: 15
            }
        );

        token = lexer.read_token().unwrap();
        assert_eq!(token.token, Token::Whitespace);
        assert_eq!(
            token.span,
            Span {
                start_line: 5,
                start_column: 16,
                end_line: 6,
                end_column: 3
            }
        );

        token = lexer.read_token().unwrap();
        assert_eq!(token.token, Token::AsciiString("hello".to_string()));
        assert_eq!(
            token.span,
            Span {
                start_line: 6,
                start_column: 4,
                end_line: 6,
                end_column: 10
            }
        );

        token = lexer.read_token().unwrap();
        assert_eq!(token.token, Token::Whitespace);
        assert_eq!(
            token.span,
            Span {
                start_line: 6,
                start_column: 11,
                end_line: 6,
                end_column: 11
            }
        );

        token = lexer.read_token().unwrap();
        let data = match token.token {
            Token::Utf8String(data) => UTF8Data { data },
            _ => panic!("failed to parse utf8 string"),
        };
        assert_eq!(format!("{}", data), "u\"world\"");
        assert_eq!(
            token.span,
            Span {
                start_line: 6,
                start_column: 12,
                end_line: 6,
                end_column: 19
            }
        );

        token = lexer.read_token().unwrap();
        assert_eq!(token.token, Token::Whitespace);
        assert_eq!(
            token.span,
            Span {
                start_line: 6,
                start_column: 20,
                end_line: 6,
                end_column: 24
            }
        );

        token = lexer.read_token().unwrap();
        if let Token::Bytes(v) = token.token {
            assert_eq!(v.len(), 16);
        } else {
            assert!(false);
        }
        assert_eq!(
            token.span,
            Span {
                start_line: 6,
                start_column: 25,
                end_line: 6,
                end_column: 58
            }
        );

        token = lexer.read_token().unwrap();
        assert_eq!(token.token, Token::Whitespace);
        assert_eq!(
            token.span,
            Span {
                start_line: 6,
                start_column: 59,
                end_line: 9,
                end_column: 3
            }
        );

        token = lexer.read_token().unwrap();
        assert_eq!(token.token, Token::Ident("foo-bar_".to_string()));
        assert_eq!(
            token.span,
            Span {
                start_line: 9,
                start_column: 4,
                end_line: 9,
                end_column: 11
            }
        );

        token = lexer.read_token().unwrap();
        assert_eq!(token.token, Token::Whitespace);
        assert_eq!(
            token.span,
            Span {
                start_line: 9,
                start_column: 12,
                end_line: 9,
                end_column: 12
            }
        );

        assert_eq!(lexer.diagnostics.len(), 3);
        assert_eq!(lexer.diagnostics[0].e, LexerError::ExpectedSeparator);
        assert_eq!(
            lexer.diagnostics[0].span,
            Span {
                start_line: 4,
                start_column: 10,
                end_line: 4,
                end_column: 10
            }
        );
        assert_eq!(lexer.diagnostics[1].e, LexerError::ExpectedSeparator);
        assert_eq!(
            lexer.diagnostics[1].span,
            Span {
                start_line: 4,
                start_column: 11,
                end_line: 4,
                end_column: 11
            }
        );
        assert_eq!(lexer.diagnostics[2].e, LexerError::ExpectedSeparator);
        assert_eq!(
            lexer.diagnostics[2].span,
            Span {
                start_line: 4,
                start_column: 12,
                end_line: 4,
                end_column: 12
            }
        );
    }

    #[test]
    fn check_error_span() {
        let mut lexer = Lexer::new("0a 123", false);
        lexer.read_token().unwrap();
        assert_eq!(
            lexer.diagnostics[0].span,
            Span {
                start_line: 1,
                start_column: 2,
                end_line: 1,
                end_column: 2
            }
        );

        lexer = Lexer::new("56789* foo", false);
        lexer.read_token().unwrap();
        assert_eq!(
            lexer.diagnostics[0].span,
            Span {
                start_line: 1,
                start_column: 6,
                end_line: 1,
                end_column: 6
            }
        );

        lexer = Lexer::new("u1a *", false);
        lexer.read_token().unwrap();
        assert_eq!(
            lexer.diagnostics[0].span,
            Span {
                start_line: 1,
                start_column: 3,
                end_line: 1,
                end_column: 3
            }
        );

        lexer = Lexer::new("\"\\x\"(", false);
        lexer.read_token().unwrap();
        assert_eq!(
            lexer.diagnostics[0].span,
            Span {
                start_line: 1,
                start_column: 2,
                end_line: 1,
                end_column: 3
            }
        );

        lexer = Lexer::new("\"open", false);
        lexer.read_token().unwrap();
        assert_eq!(
            lexer.diagnostics[0].span,
            Span {
                start_line: 1,
                start_column: 6,
                end_line: 1,
                end_column: 6
            }
        );
        assert_eq!(
            lexer.diagnostics[1].span,
            Span {
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 1,
            }
        );

        lexer = Lexer::new("\" this is 👎!\"", false);
        lexer.read_token().unwrap();
        assert_eq!(
            lexer.diagnostics[0].span,
            Span {
                start_line: 1,
                start_column: 11,
                end_line: 1,
                end_column: 11
            }
        );

        lexer = Lexer::new("\"\\u{1F600}\"", false);
        lexer.read_token().unwrap();
        assert_eq!(
            lexer.diagnostics[0].span,
            Span {
                start_line: 1,
                start_column: 2,
                end_line: 1,
                end_column: 3
            }
        );

        lexer = Lexer::new("u\"\\x ok\"", false);
        lexer.read_token().unwrap();
        assert_eq!(
            lexer.diagnostics[0].span,
            Span {
                start_line: 1,
                start_column: 3,
                end_line: 1,
                end_column: 4
            }
        );

        lexer = Lexer::new("u\"open", false);
        lexer.read_token().unwrap();
        assert_eq!(
            lexer.diagnostics[0].span,
            Span {
                start_line: 1,
                start_column: 7,
                end_line: 1,
                end_column: 7
            }
        );
        assert_eq!(
            lexer.diagnostics[1].span,
            Span {
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 2,
            }
        );

        lexer = Lexer::new("0xdefg", false);
        lexer.read_token().unwrap();
        assert_eq!(
            lexer.diagnostics[0].span,
            Span {
                start_line: 1,
                start_column: 6,
                end_line: 1,
                end_column: 6
            }
        );

        lexer = Lexer::new("0xdef", false);
        lexer.read_token().unwrap();
        assert_eq!(
            lexer.diagnostics[0].span,
            Span {
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 5
            }
        );

        lexer = Lexer::new("0x00p5", false);
        lexer.read_token().unwrap();
        assert_eq!(
            lexer.diagnostics[0].span,
            Span {
                start_line: 1,
                start_column: 5,
                end_line: 1,
                end_column: 6
            }
        );

        lexer = Lexer::new("baz👍buz", false);
        lexer.read_token().unwrap();
        assert_eq!(
            lexer.diagnostics[0].span,
            Span {
                start_line: 1,
                start_column: 4,
                end_line: 1,
                end_column: 7
            }
        );

        lexer = Lexer::new("; this is not a comment", false);
        lexer.read_token().unwrap();
        assert_eq!(
            lexer.diagnostics[0].span,
            Span {
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 1
            }
        );

        lexer = Lexer::new("123 ~ abc", false);
        lexer.read_token().unwrap();
        lexer.read_token().unwrap();
        lexer.read_token().unwrap();
        assert_eq!(
            lexer.diagnostics[0].span,
            Span {
                start_line: 1,
                start_column: 5,
                end_line: 1,
                end_column: 5
            }
        );

        lexer = Lexer::new("  \"newline\n  \"", false);
        lexer.read_token().unwrap(); // whitespace
        lexer.read_token().unwrap(); // string
        assert_eq!(
            lexer.diagnostics[0].span,
            Span {
                start_line: 1,
                start_column: 11,
                end_line: 1,
                end_column: 11,
            }
        );
        assert_eq!(
            lexer.diagnostics[1].span,
            Span {
                start_line: 1,
                start_column: 3,
                end_line: 1,
                end_column: 3,
            }
        );
    }

    #[test]
    fn read_contract_identifier() {
        let mut lexer = Lexer::new("'ST000000000000000000002AMW42H.silly-goose", false);
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::Principal("ST000000000000000000002AMW42H".to_string())
        );
        assert_eq!(lexer.read_token().unwrap().token, Token::Dot);
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::Ident("silly-goose".to_string())
        );
        assert_eq!(lexer.diagnostics.len(), 0);
    }

    #[test]
    fn read_trait_reference() {
        let mut lexer = Lexer::new("<fancy-dolphin>", false);
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::TraitIdent("fancy-dolphin".to_string())
        );
        assert_eq!(lexer.read_token().unwrap().token, Token::Eof);
        assert_eq!(lexer.diagnostics.len(), 0);

        lexer = Lexer::new("<illegal*name>", false);
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::TraitIdent("illegal".to_string())
        );
        assert_eq!(lexer.diagnostics.len(), 1);
        assert_eq!(
            lexer.diagnostics[0].e,
            LexerError::InvalidCharTraitIdent('*')
        );
        assert_eq!(
            lexer.diagnostics[0].span,
            Span {
                start_line: 1,
                start_column: 9,
                end_line: 1,
                end_column: 14,
            }
        );

        lexer = Lexer::new("<not-closed ", false);
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::TraitIdent("not-closed".to_string())
        );
        assert_eq!(lexer.diagnostics.len(), 2);
        assert_eq!(lexer.diagnostics[0].e, LexerError::ExpectedClosing('>'));
        assert_eq!(
            lexer.diagnostics[0].span,
            Span {
                start_line: 1,
                start_column: 12,
                end_line: 1,
                end_column: 12,
            }
        );
        assert_eq!(lexer.diagnostics[1].e, LexerError::NoteToMatchThis('<'));
        assert_eq!(
            lexer.diagnostics[1].span,
            Span {
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 1,
            }
        );
    }
}
