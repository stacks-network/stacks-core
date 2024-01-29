pub mod error;
pub mod token;

use std::char;
use std::str::Chars;

use token::{PlacedToken, Token};

use self::error::{LexerError, PlacedError};
use crate::vm::diagnostic::{DiagnosableError, Level};
use crate::vm::representations::Span;

pub type LexResult<T> = Result<T, LexerError>;

const EOF: char = std::char::REPLACEMENT_CHARACTER;

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
        '(' | ')' | '{' | '}' | ',' | ':' | '.' | ';' | EOF => true,
        _ => ch.is_ascii_whitespace(),
    }
}

fn is_string_terminator(ch: char) -> bool {
    matches!(ch, '"' | '\n' | EOF)
}

impl<'a> Lexer<'a> {
    pub fn new(input: &'a str, fail_fast: bool) -> LexResult<Self> {
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
        s.read_char()?; // Initialize with the first character
        Ok(s)
    }

    fn add_diagnostic(&mut self, e: LexerError, span: Span) -> LexResult<()> {
        if self.fail_fast {
            Err(e)
        } else {
            if e.level() == Level::Error {
                self.success = false;
            }
            self.diagnostics.push(PlacedError { e, span });
            Ok(())
        }
    }

    fn read_char(&mut self) -> LexResult<()> {
        self.last_line = self.line;
        self.last_column = self.column;

        match self.input.next() {
            Some(ch) => {
                if self.next == '\n' {
                    self.line += 1;
                    self.column = 0;
                }

                if !ch.is_ascii() {
                    self.add_diagnostic(
                        LexerError::NonASCIIChar(ch),
                        Span {
                            start_line: self.line as u32,
                            start_column: (self.column + 1) as u32,
                            end_line: self.line as u32,
                            end_column: (self.column + 1) as u32,
                        },
                    )?;
                }

                self.next = ch
            }
            None => self.next = EOF,
        }
        self.offset += 1;
        self.column += 1;

        Ok(())
    }

    fn report_line_ending(&mut self) -> LexResult<()> {
        if !self.line_endings {
            self.line_endings = true;

            let span = Span {
                start_line: self.line as u32,
                start_column: self.column as u32,
                end_line: self.line as u32,
                end_column: self.column as u32,
            };

            self.add_diagnostic(LexerError::UnsupportedLineEnding, span.clone())?;
            self.add_diagnostic(LexerError::EditorCRLFMode, span)?;
        }
        Ok(())
    }

    fn skip_whitespace(&mut self) -> LexResult<()> {
        while self.next != EOF {
            match self.next {
                ' ' | '\t' | '\n' => (),
                '\r' => self.report_line_ending()?,
                _ => break,
            }
            self.read_char()?;
        }
        Ok(())
    }

    fn read_line(&mut self) -> LexResult<String> {
        let mut line = String::new();
        loop {
            match self.next {
                '\n' => {
                    break;
                }
                EOF => break,
                '\r' => self.report_line_ending()?,
                ch => line.push(ch),
            }
            self.read_char()?;
        }
        Ok(line)
    }

    fn proceed_through_error(
        &mut self,
        mut skipped: String,
        err: Option<LexerError>,
    ) -> LexResult<String> {
        let start_line = self.line as u32;
        let start_column = self.column as u32;
        while !is_separator(self.next) {
            skipped.push(self.next);
            self.read_char()?;
        }
        if let Some(err) = err {
            self.add_diagnostic(
                err,
                Span {
                    start_line,
                    start_column,
                    end_line: self.last_line as u32,
                    end_column: self.last_column as u32,
                },
            )?;
        }
        Ok(skipped)
    }

    fn proceed_through_error_string(
        &mut self,
        mut skipped: String,
        err: Option<LexerError>,
    ) -> LexResult<String> {
        let start_line = self.line as u32;
        let start_column = self.column as u32;
        while !is_string_terminator(self.next) {
            skipped.push(self.next);
            self.read_char()?;
        }
        while !is_separator(self.next) {
            skipped.push(self.next);
            self.read_char()?;
        }
        if let Some(err) = err {
            self.add_diagnostic(
                err,
                Span {
                    start_line,
                    start_column,
                    end_line: self.last_line as u32,
                    end_column: self.last_column as u32,
                },
            )?;
        }
        Ok(skipped)
    }

    fn read_identifier(&mut self, first: Option<char>) -> LexResult<Token> {
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
                    if !is_separator(self.next) {
                        return Ok(Token::Placeholder(self.proceed_through_error(
                            ident,
                            Some(LexerError::InvalidCharIdent(self.next)),
                        )?));
                    }

                    return Ok(Token::Ident(ident));
                }
            }
            self.read_char()?;
        }
    }

    fn read_trait_identifier(&mut self) -> LexResult<Token> {
        let start_line = self.last_line as u32;
        let start_column = self.last_column as u32;
        let mut ident = String::new();

        loop {
            match self.next {
                'a'..='z' | 'A'..='Z' | '0'..='9' | '_' | '-' => ident.push(self.next),
                '>' => return Ok(Token::TraitIdent(ident)),
                _ => {
                    if !is_separator(self.next) {
                        return Ok(Token::Placeholder(self.proceed_through_error(
                            format!("<{}", ident),
                            Some(LexerError::InvalidCharTraitIdent(self.next)),
                        )?));
                    }

                    self.add_diagnostic(
                        LexerError::ExpectedClosing('>'),
                        Span {
                            start_line: self.line as u32,
                            start_column: self.column as u32,
                            end_line: self.line as u32,
                            end_column: self.column as u32,
                        },
                    )?;
                    self.add_diagnostic(
                        LexerError::NoteToMatchThis('<'),
                        Span {
                            start_line,
                            start_column,
                            end_line: start_line,
                            end_column: start_column,
                        },
                    )?;
                    return Ok(Token::Placeholder(format!("<{}", ident)));
                }
            }
            self.read_char()?;
        }
    }

    fn read_principal(&mut self) -> LexResult<Token> {
        let mut principal = String::new();

        loop {
            self.read_char()?;
            match self.next {
                // Crockford alphabet characters only
                '0'..='9' | 'A'..='H' | 'J' | 'K' | 'M' | 'N' | 'P'..='T' | 'V'..='Z' => {
                    principal.push(self.next)
                }
                _ => {
                    if !is_separator(self.next) {
                        return Ok(Token::Placeholder(self.proceed_through_error(
                            format!("'{}", principal),
                            Some(LexerError::InvalidCharPrincipal(self.next)),
                        )?));
                    }
                    return Ok(Token::Principal(principal));
                }
            }
        }
    }

    fn read_unsigned(&mut self) -> LexResult<Token> {
        let mut num = String::new();
        while self.next.is_ascii_digit() {
            num.push(self.next);
            self.read_char()?;
        }
        if !is_separator(self.next) {
            return Ok(Token::Placeholder(self.proceed_through_error(
                format!("u{}", num),
                Some(LexerError::InvalidCharUint(self.next)),
            )?));
        }
        Ok(Token::Uint(num))
    }

    fn read_integer(&mut self, prefix: Option<char>) -> LexResult<Token> {
        let mut num = String::new();
        if let Some(ch) = prefix {
            num.push(ch);
        }

        while self.next.is_ascii_digit() {
            num.push(self.next);
            self.read_char()?;
        }
        if !is_separator(self.next) {
            return Ok(Token::Placeholder(self.proceed_through_error(
                num,
                Some(LexerError::InvalidCharInt(self.next)),
            )?));
        }
        Ok(Token::Int(num))
    }

    fn read_hex(&mut self) -> LexResult<Token> {
        let start_line = self.line as u32;
        let start_column = (self.column - 1) as u32;
        let mut bytes = String::new();
        loop {
            self.read_char()?;

            let f = self.next;
            if !f.is_ascii_hexdigit() {
                if !is_separator(f) {
                    return Ok(Token::Placeholder(self.proceed_through_error(
                        format!("0x{}", bytes),
                        Some(LexerError::InvalidCharBuffer(f)),
                    )?));
                }
                return Ok(Token::Bytes(bytes));
            }
            bytes.push(f);

            self.read_char()?;
            let s = self.next;
            if !s.is_ascii_hexdigit() {
                if is_separator(s) {
                    self.add_diagnostic(
                        LexerError::InvalidBufferLength(bytes.len()),
                        Span {
                            start_line,
                            start_column,
                            end_line: self.last_line as u32,
                            end_column: self.last_column as u32,
                        },
                    )?;
                    return Ok(Token::Placeholder(format!("0x{}", bytes)));
                } else {
                    return Ok(Token::Placeholder(self.proceed_through_error(
                        format!("0x{}", bytes),
                        Some(LexerError::InvalidCharBuffer(s)),
                    )?));
                }
            }
            bytes.push(s);
        }
    }

    fn read_ascii_string(&mut self) -> LexResult<Token> {
        let start_line = self.line as u32;
        let start_column = self.column as u32;
        let mut s = String::new();
        let mut escaped = false;
        self.read_char()?;
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
                        self.add_diagnostic(
                            LexerError::UnknownEscapeChar(self.next),
                            Span {
                                start_line: self.last_line as u32,
                                start_column: self.last_column as u32,
                                end_line: self.line as u32,
                                end_column: self.column as u32,
                            },
                        )?;
                        return Ok(Token::Placeholder(
                            self.proceed_through_error_string(format!("\"{}\\", s), None)?,
                        ));
                    }
                };
                s.push(ch);
                escaped = false;
            } else {
                match self.next {
                    '"' => {
                        self.read_char()?;
                        return Ok(Token::AsciiString(s));
                    }
                    '\\' => escaped = true,
                    EOF | '\n' => {
                        self.add_diagnostic(
                            LexerError::ExpectedClosing('"'),
                            Span {
                                start_line: self.line as u32,
                                start_column: self.column as u32,
                                end_line: self.line as u32,
                                end_column: self.column as u32,
                            },
                        )?;
                        self.add_diagnostic(
                            LexerError::NoteToMatchThis('"'),
                            Span {
                                start_line,
                                start_column,
                                end_line: start_line,
                                end_column: start_column,
                            },
                        )?;
                        return Ok(Token::Placeholder(format!("\"{}", s)));
                    }
                    _ => {
                        if !self.next.is_ascii() {
                            self.add_diagnostic(
                                LexerError::IllegalCharString(self.next),
                                Span {
                                    start_line: self.line as u32,
                                    start_column: self.column as u32,
                                    end_line: self.line as u32,
                                    end_column: self.column as u32,
                                },
                            )?;
                            return Ok(Token::Placeholder(
                                self.proceed_through_error_string(format!("\"{}", s), None)?,
                            ));
                        } else {
                            s.push(self.next);
                        }
                    }
                }
            }
            self.read_char()?;
        }
    }

    /// Read `X` in `\u{X}` in a UTF8 string
    fn read_utf8_encoding(&mut self) -> LexResult<Result<String, String>> {
        self.read_char()?;
        let start_line = self.line as u32;
        let start_column = self.column as u32;
        let mut code = String::new();

        if self.next != '{' {
            self.add_diagnostic(
                LexerError::InvalidUTF8Encoding,
                Span {
                    start_line: self.line as u32,
                    start_column: self.column as u32,
                    end_line: self.line as u32,
                    end_column: self.column as u32,
                },
            )?;
            return Ok(Err(code));
        }

        loop {
            self.read_char()?;
            match self.next {
                '}' => {
                    if code.is_empty() {
                        self.add_diagnostic(
                            LexerError::EmptyUTF8Encoding,
                            Span {
                                start_line,
                                start_column,
                                end_line: self.line as u32,
                                end_column: self.column as u32,
                            },
                        )?;
                        self.read_char()?;
                        return Ok(Err("{}".to_string()));
                    }
                    self.read_char()?;
                    return Ok(Ok(code));
                }
                '"' => {
                    self.add_diagnostic(
                        LexerError::UnterminatedUTF8Encoding,
                        Span {
                            start_line: self.line as u32,
                            start_column: self.column as u32,
                            end_line: self.line as u32,
                            end_column: self.column as u32,
                        },
                    )?;
                    self.add_diagnostic(
                        LexerError::NoteToMatchThis('}'),
                        Span {
                            start_line,
                            start_column,
                            end_line: start_line,
                            end_column: start_column,
                        },
                    )?;
                    return Ok(Err(format!("{{{}", code)));
                }
                EOF => {
                    self.add_diagnostic(
                        LexerError::UnterminatedUTF8Encoding,
                        Span {
                            start_line: self.line as u32,
                            start_column: self.column as u32,
                            end_line: self.line as u32,
                            end_column: self.column as u32,
                        },
                    )?;
                    self.add_diagnostic(
                        LexerError::NoteToMatchThis('}'),
                        Span {
                            start_line,
                            start_column,
                            end_line: start_line,
                            end_column: start_column,
                        },
                    )?;
                    return Ok(Err(format!("{{{}", code)));
                }
                _ => {
                    if self.next.is_ascii_hexdigit() {
                        code.push(self.next);
                    } else {
                        self.add_diagnostic(
                            LexerError::IllegalCharUTF8Encoding(self.next),
                            Span {
                                start_line: self.line as u32,
                                start_column: self.column as u32,
                                end_line: self.line as u32,
                                end_column: self.column as u32,
                            },
                        )?;
                        return Ok(Err(format!("{{{}", code)));
                    }
                }
            }
        }
    }

    fn read_utf8_string(&mut self) -> LexResult<Token> {
        let start_line = self.last_line as u32;
        let start_column = self.last_column as u32;
        let mut s = String::new();
        let mut escaped = false;
        let mut advance = true;
        self.read_char()?;
        loop {
            if escaped {
                let ch = match self.next {
                    '\\' => '\\',
                    '\"' => '\"',
                    'n' => '\n',
                    't' => '\t',
                    'r' => '\r',
                    '0' => '\0',
                    'u' => {
                        let code_start_line = self.line as u32;
                        let code_start_column = self.column as u32;
                        let encode_str = match self.read_utf8_encoding()? {
                            Ok(code) => code,
                            Err(bad) => {
                                return Ok(Token::Placeholder(self.proceed_through_error_string(
                                    format!("u\"{}\\u{}", s, bad),
                                    None,
                                )?));
                            }
                        };
                        let unicode_char = {
                            let u = match u32::from_str_radix(&encode_str, 16) {
                                Ok(u) => u,
                                Err(_) => {
                                    self.add_diagnostic(
                                        LexerError::InvalidUTF8Encoding,
                                        Span {
                                            start_line: code_start_line,
                                            start_column: code_start_column,
                                            end_line: self.line as u32,
                                            end_column: self.column as u32,
                                        },
                                    )?;
                                    return Ok(Token::Placeholder(
                                        self.proceed_through_error_string(
                                            format!("u\"{}\\u{{{}}}", s, encode_str),
                                            None,
                                        )?,
                                    ));
                                }
                            };
                            match char::from_u32(u) {
                                Some(c) => c,
                                None => {
                                    self.add_diagnostic(
                                        LexerError::InvalidUTF8Encoding,
                                        Span {
                                            start_line: code_start_line,
                                            start_column: code_start_column,
                                            end_line: self.line as u32,
                                            end_column: self.column as u32,
                                        },
                                    )?;
                                    return Ok(Token::Placeholder(
                                        self.proceed_through_error_string(
                                            format!("u\"{}\\u{{{}}}", s, encode_str),
                                            None,
                                        )?,
                                    ));
                                }
                            }
                        };
                        advance = false;
                        unicode_char
                    }
                    _ => {
                        self.add_diagnostic(
                            LexerError::UnknownEscapeChar(self.next),
                            Span {
                                start_line: self.last_line as u32,
                                start_column: self.last_column as u32,
                                end_line: self.line as u32,
                                end_column: self.column as u32,
                            },
                        )?;
                        return Ok(Token::Placeholder(
                            self.proceed_through_error_string(format!("u\"{}\\", s), None)?,
                        ));
                    }
                };
                s.push(ch);
                escaped = false;
            } else {
                match self.next {
                    '"' => {
                        self.read_char()?;
                        return Ok(Token::Utf8String(s));
                    }
                    '\\' => escaped = true,
                    EOF | '\n' => {
                        self.add_diagnostic(
                            LexerError::ExpectedClosing('"'),
                            Span {
                                start_line: self.line as u32,
                                start_column: self.column as u32,
                                end_line: self.line as u32,
                                end_column: self.column as u32,
                            },
                        )?;
                        self.add_diagnostic(
                            LexerError::NoteToMatchThis('"'),
                            Span {
                                start_line,
                                start_column,
                                end_line: start_line,
                                end_column: start_column + 1,
                            },
                        )?;
                        return Ok(Token::Placeholder(format!("u\"{}", s)));
                    }
                    _ => {
                        s.push(self.next);
                    }
                }
            }
            if advance {
                self.read_char()?;
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
            EOF => Token::Eof,
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
                self.read_char()?;
                if self.next.is_ascii_digit() {
                    self.read_integer(Some('-'))?
                } else {
                    Token::Minus
                }
            }
            '<' => {
                self.read_char()?;
                if self.next == '=' {
                    Token::LessEqual
                } else if self.next.is_ascii_alphabetic() {
                    self.read_trait_identifier()?
                } else {
                    advance = false;
                    Token::Less
                }
            }
            '>' => {
                self.read_char()?;
                if self.next == '=' {
                    Token::GreaterEqual
                } else {
                    advance = false;
                    Token::Greater
                }
            }
            ';' => {
                self.read_char()?;
                if self.next != ';' {
                    // If there is just one ';', report an error but continue
                    //  parsing as if there were two (a comment).
                    self.add_diagnostic(
                        LexerError::SingleSemiColon,
                        Span {
                            start_line: self.last_line as u32,
                            start_column: self.last_column as u32,
                            end_line: self.last_line as u32,
                            end_column: self.last_column as u32,
                        },
                    )?;
                } else {
                    self.read_char()?;
                }
                advance = false;
                let comment = self.read_line()?;
                Token::Comment(comment.trim_start().to_string())
            }
            '\'' => {
                advance = false;
                self.read_principal()?
            }
            'u' => {
                advance = false;
                self.read_char()?;
                if self.next.is_ascii_digit() {
                    self.read_unsigned()?
                } else if self.next == '"' {
                    self.read_utf8_string()?
                } else {
                    self.read_identifier(Some('u'))?
                }
            }
            ' ' | '\t' | '\r' | '\n' => {
                self.skip_whitespace()?;
                advance = false;
                Token::Whitespace
            }
            '"' => {
                advance = false;
                self.read_ascii_string()?
            }
            '0' => {
                advance = false;
                self.read_char()?;
                if self.next == 'x' {
                    self.read_hex()?
                } else if self.next.is_ascii_digit() {
                    self.read_integer(Some('0'))?
                } else if is_separator(self.next) {
                    Token::Int("0".to_string())
                } else {
                    Token::Placeholder(self.proceed_through_error(
                        "0".to_string(),
                        Some(LexerError::InvalidCharInt(self.next)),
                    )?)
                }
            }
            _ => {
                if self.next.is_ascii_alphabetic() {
                    advance = false;
                    self.read_identifier(None)?
                } else if self.next.is_ascii_digit() {
                    advance = false;
                    self.read_integer(None)?
                } else {
                    self.add_diagnostic(
                        LexerError::UnknownSymbol(self.next),
                        Span {
                            start_line: self.line as u32,
                            start_column: self.column as u32,
                            end_line: self.line as u32,
                            end_column: self.column as u32,
                        },
                    )?;
                    Token::Placeholder(self.next.to_string())
                }
            }
        };

        if advance {
            self.read_char()?;
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
                    self.add_diagnostic(
                        LexerError::ExpectedSeparator,
                        Span {
                            start_line: self.line as u32,
                            start_column: self.column as u32,
                            end_line: self.line as u32,
                            end_column: self.column as u32,
                        },
                    )?;
                }
            }
            _ => (),
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
    use super::*;

    #[test]
    fn read_tokens() {
        let mut lexer = Lexer::new("", false).unwrap();
        assert_eq!(lexer.read_token().unwrap().token, Token::Eof);
        assert!(lexer.diagnostics.is_empty());

        let mut lexer = Lexer::new(" ", false).unwrap();
        assert_eq!(lexer.read_token().unwrap().token, Token::Whitespace);
        assert!(lexer.diagnostics.is_empty());

        let mut lexer = Lexer::new("\t", false).unwrap();
        assert_eq!(lexer.read_token().unwrap().token, Token::Whitespace);
        assert!(lexer.diagnostics.is_empty());

        let mut lexer = Lexer::new("\n", false).unwrap();
        assert_eq!(lexer.read_token().unwrap().token, Token::Whitespace);
        assert!(lexer.diagnostics.is_empty());

        let mut lexer = Lexer::new("\r", false).unwrap();
        assert_eq!(lexer.read_token().unwrap().token, Token::Whitespace);
        assert_eq!(lexer.diagnostics.len(), 2);
        assert_eq!(lexer.diagnostics[0].e, LexerError::UnsupportedLineEnding);
        assert_eq!(lexer.diagnostics[1].e, LexerError::EditorCRLFMode);

        lexer = Lexer::new("(", false).unwrap();
        assert_eq!(lexer.read_token().unwrap().token, Token::Lparen);
        assert!(lexer.diagnostics.is_empty());

        lexer = Lexer::new(").unwrap()", false).unwrap();
        assert_eq!(lexer.read_token().unwrap().token, Token::Rparen);
        assert!(lexer.diagnostics.is_empty());

        lexer = Lexer::new("{", false).unwrap();
        assert_eq!(lexer.read_token().unwrap().token, Token::Lbrace);
        assert!(lexer.diagnostics.is_empty());

        lexer = Lexer::new("}", false).unwrap();
        assert_eq!(lexer.read_token().unwrap().token, Token::Rbrace);
        assert!(lexer.diagnostics.is_empty());

        lexer = Lexer::new(":", false).unwrap();
        assert_eq!(lexer.read_token().unwrap().token, Token::Colon);
        assert!(lexer.diagnostics.is_empty());

        lexer = Lexer::new(",", false).unwrap();
        assert_eq!(lexer.read_token().unwrap().token, Token::Comma);
        assert!(lexer.diagnostics.is_empty());

        lexer = Lexer::new(".", false).unwrap();
        assert_eq!(lexer.read_token().unwrap().token, Token::Dot);
        assert!(lexer.diagnostics.is_empty());

        lexer = Lexer::new("123", false).unwrap();
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::Int("123".to_string())
        );
        assert!(lexer.diagnostics.is_empty());

        lexer = Lexer::new("0123", false).unwrap();
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::Int("0123".to_string())
        );
        assert!(lexer.diagnostics.is_empty());

        lexer = Lexer::new("0", false).unwrap();
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::Int("0".to_string())
        );
        assert!(lexer.diagnostics.is_empty());

        lexer = Lexer::new("okay", false).unwrap();
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::Ident("okay".to_string())
        );
        assert!(lexer.diagnostics.is_empty());

        lexer = Lexer::new("0a", false).unwrap();
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::Placeholder("0a".to_string())
        );
        assert_eq!(lexer.diagnostics.len(), 1);
        assert_eq!(lexer.diagnostics[0].e, LexerError::InvalidCharInt('a'));

        lexer = Lexer::new("test\0", false).unwrap();
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::Placeholder("test\u{0}".to_string())
        );
        assert_eq!(lexer.diagnostics.len(), 1);
        assert_eq!(lexer.diagnostics[0].e, LexerError::InvalidCharIdent('\0'));

        let mut lexer = Lexer::new("👎", false).unwrap();
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::Placeholder("👎".to_string())
        );
        assert_eq!(lexer.diagnostics.len(), 2);
        assert_eq!(lexer.diagnostics[0].e, LexerError::NonASCIIChar('👎'));
        assert_eq!(lexer.diagnostics[1].e, LexerError::UnknownSymbol('👎'));

        lexer = Lexer::new("56789*", false).unwrap();
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::Placeholder("56789*".to_string())
        );
        assert_eq!(lexer.diagnostics.len(), 1);
        assert_eq!(lexer.diagnostics[0].e, LexerError::InvalidCharInt('*'));

        lexer = Lexer::new("-89+", false).unwrap();
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::Placeholder("-89+".to_string())
        );
        assert_eq!(lexer.diagnostics.len(), 1);
        assert_eq!(lexer.diagnostics[0].e, LexerError::InvalidCharInt('+'));

        lexer = Lexer::new("u123", false).unwrap();
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::Uint("123".to_string())
        );

        lexer = Lexer::new("u1a", false).unwrap();
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::Placeholder("u1a".to_string())
        );
        assert_eq!(lexer.diagnostics.len(), 1);
        assert_eq!(lexer.diagnostics[0].e, LexerError::InvalidCharUint('a'));

        lexer = Lexer::new("\"hello\"", false).unwrap();
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::AsciiString("hello".to_string())
        );
        assert!(lexer.diagnostics.is_empty());

        lexer = Lexer::new("\"new\\nline\"", false).unwrap();
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::AsciiString("new\nline".to_string())
        );
        assert!(lexer.diagnostics.is_empty());

        lexer = Lexer::new("\"quote \\\"this\\\"\"", false).unwrap();
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::AsciiString("quote \"this\"".to_string())
        );
        assert!(lexer.diagnostics.is_empty());

        lexer = Lexer::new("\"\\r\\t\\0\\\\ ok\"", false).unwrap();
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::AsciiString("\r\t\0\\ ok".to_string())
        );
        assert!(lexer.diagnostics.is_empty());

        lexer = Lexer::new("\"\\x\"", false).unwrap();
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::Placeholder("\"\\x\"".to_string())
        );
        assert_eq!(lexer.diagnostics.len(), 1);
        assert_eq!(lexer.diagnostics[0].e, LexerError::UnknownEscapeChar('x'));

        lexer = Lexer::new("\"\\z\"a", false).unwrap();
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::Placeholder("\"\\z\"a".to_string())
        );
        assert_eq!(lexer.diagnostics.len(), 1);
        assert_eq!(lexer.diagnostics[0].e, LexerError::UnknownEscapeChar('z'));

        lexer = Lexer::new("\"open", false).unwrap();
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::Placeholder("\"open".to_string())
        );
        assert_eq!(lexer.diagnostics.len(), 2);
        assert_eq!(lexer.diagnostics[0].e, LexerError::ExpectedClosing('"'));
        assert_eq!(lexer.diagnostics[1].e, LexerError::NoteToMatchThis('"'));

        lexer = Lexer::new("\"👎\"", false).unwrap();
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::Placeholder("\"👎\"".to_string())
        );
        assert_eq!(lexer.diagnostics.len(), 2);
        assert_eq!(lexer.diagnostics[0].e, LexerError::NonASCIIChar('👎'));
        assert_eq!(lexer.diagnostics[1].e, LexerError::IllegalCharString('👎'));

        lexer = Lexer::new("\"\\u{1F600}\"", false).unwrap();
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::Placeholder("\"\\u{1F600}\"".to_string())
        );
        assert_eq!(lexer.diagnostics.len(), 1);
        assert_eq!(lexer.diagnostics[0].e, LexerError::UnknownEscapeChar('u'));

        lexer = Lexer::new("u\"hello\"", false).unwrap();
        let data = match lexer.read_token().unwrap().token {
            Token::Utf8String(s) => s,
            _ => panic!("failed to parse utf8 string"),
        };
        assert_eq!(data, "hello");
        assert!(lexer.diagnostics.is_empty());

        lexer = Lexer::new("u\"\\u{1F600}\"", false).unwrap();
        let data = match lexer.read_token().unwrap().token {
            Token::Utf8String(s) => s,
            _ => panic!("failed to parse utf8 string"),
        };
        assert_eq!(data, "😀");
        assert!(lexer.diagnostics.is_empty());

        lexer = Lexer::new("u\"quote \\\"this\\\"\"", false).unwrap();
        let data = match lexer.read_token().unwrap().token {
            Token::Utf8String(s) => s,
            _ => panic!("failed to parse utf8 string"),
        };
        assert_eq!(data, "quote \"this\"");
        assert!(lexer.diagnostics.is_empty());

        lexer = Lexer::new("u\"\\n\\r\\t\\0\\\\ ok\"", false).unwrap();
        let data = match lexer.read_token().unwrap().token {
            Token::Utf8String(s) => s,
            _ => panic!("failed to parse utf8 string"),
        };
        assert_eq!(data, "\n\r\t\u{0}\\ ok");
        assert!(lexer.diagnostics.is_empty());

        lexer = Lexer::new("u\"\\x\"", false).unwrap();
        let data = match lexer.read_token().unwrap().token {
            Token::Placeholder(s) => s,
            _ => panic!("failed to parse utf8 string"),
        };
        assert_eq!(data, "u\"\\x\"");
        assert_eq!(lexer.diagnostics.len(), 1);
        assert_eq!(lexer.diagnostics[0].e, LexerError::UnknownEscapeChar('x'));

        lexer = Lexer::new("u\"open", false).unwrap();
        let data = match lexer.read_token().unwrap().token {
            Token::Placeholder(s) => s,
            _ => panic!("failed to parse utf8 string"),
        };
        assert_eq!(data, "u\"open");
        assert_eq!(lexer.diagnostics.len(), 2);
        assert_eq!(lexer.diagnostics[0].e, LexerError::ExpectedClosing('"'));
        assert_eq!(lexer.diagnostics[1].e, LexerError::NoteToMatchThis('"'));

        lexer = Lexer::new("u\"\\uabc\"", false).unwrap();
        let data = match lexer.read_token().unwrap().token {
            Token::Placeholder(s) => s,
            _ => panic!("failed to parse utf8 string"),
        };
        assert_eq!(data, "u\"\\uabc\"");
        assert_eq!(lexer.diagnostics.len(), 1);
        assert_eq!(lexer.diagnostics[0].e, LexerError::InvalidUTF8Encoding);

        lexer = Lexer::new("u\"\\u{1234567}\"", false).unwrap();
        let data = match lexer.read_token().unwrap().token {
            Token::Placeholder(s) => s,
            _ => panic!("failed to parse utf8 string"),
        };
        assert_eq!(data, "u\"\\u{1234567}\"");
        assert_eq!(lexer.diagnostics.len(), 1);
        assert_eq!(lexer.diagnostics[0].e, LexerError::InvalidUTF8Encoding);

        lexer = Lexer::new("u\"\\u{123456789}\"", false).unwrap();
        let data = match lexer.read_token().unwrap().token {
            Token::Placeholder(s) => s,
            _ => panic!("failed to parse utf8 string"),
        };
        assert_eq!(data, "u\"\\u{123456789}\"");
        assert_eq!(lexer.diagnostics.len(), 1);
        assert_eq!(lexer.diagnostics[0].e, LexerError::InvalidUTF8Encoding);

        lexer = Lexer::new("u\"a \\u{", false).unwrap();
        let data = match lexer.read_token().unwrap().token {
            Token::Placeholder(s) => s,
            _ => panic!("failed to parse utf8 string"),
        };
        assert_eq!(data, "u\"a \\u{");
        assert_eq!(lexer.diagnostics.len(), 2);
        assert_eq!(lexer.diagnostics[0].e, LexerError::UnterminatedUTF8Encoding);
        assert_eq!(lexer.diagnostics[1].e, LexerError::NoteToMatchThis('}'));

        lexer = Lexer::new("u\"\\u{}\"", false).unwrap();
        let data = match lexer.read_token().unwrap().token {
            Token::Placeholder(s) => s,
            _ => panic!("failed to parse utf8 string"),
        };
        assert_eq!(data, "u\"\\u{}\"");
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

        lexer = Lexer::new("u\"a \\u{\" foo", false).unwrap();
        let data = match lexer.read_token().unwrap().token {
            Token::Placeholder(s) => s,
            _ => panic!("failed to parse utf8 string"),
        };
        assert_eq!(data, "u\"a \\u{\"");
        assert_eq!(lexer.diagnostics.len(), 2);
        assert_eq!(lexer.diagnostics[0].e, LexerError::UnterminatedUTF8Encoding);
        assert_eq!(lexer.diagnostics[1].e, LexerError::NoteToMatchThis('}'));

        lexer = Lexer::new("u\"\\u{24gb}\" foo", false).unwrap();
        let data = match lexer.read_token().unwrap().token {
            Token::Placeholder(s) => s,
            _ => panic!("failed to parse utf8 string"),
        };
        assert_eq!(data, "u\"\\u{24gb}\"");
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

        lexer = Lexer::new("0x123abc", false).unwrap();
        if let Token::Bytes(s) = lexer.read_token().unwrap().token {
            assert_eq!(s, "123abc");
        } else {
            panic!("failed to parse hex literal");
        }
        assert!(lexer.diagnostics.is_empty());

        lexer = Lexer::new("0xdefg", false).unwrap();
        if let Token::Placeholder(s) = lexer.read_token().unwrap().token {
            assert_eq!(s, "0xdefg");
        } else {
            panic!("failed to parse hex literal");
        }
        assert_eq!(lexer.diagnostics.len(), 1);
        assert_eq!(lexer.diagnostics[0].e, LexerError::InvalidCharBuffer('g'));

        lexer = Lexer::new("0xdef", false).unwrap();
        if let Token::Placeholder(s) = lexer.read_token().unwrap().token {
            assert_eq!(s, "0xdef");
        } else {
            panic!("failed to parse hex literal");
        }
        assert_eq!(lexer.diagnostics.len(), 1);
        assert_eq!(lexer.diagnostics[0].e, LexerError::InvalidBufferLength(3));

        lexer = Lexer::new("0x00p5", false).unwrap();
        if let Token::Placeholder(s) = lexer.read_token().unwrap().token {
            assert_eq!(s, "0x00p5");
        } else {
            panic!("failed to parse hex literal")
        }
        assert_eq!(lexer.diagnostics.len(), 1);
        assert_eq!(lexer.diagnostics[0].e, LexerError::InvalidCharBuffer('p'));

        lexer = Lexer::new("0xdef0 ", false).unwrap();
        if let Token::Bytes(s) = lexer.read_token().unwrap().token {
            assert_eq!(s, "def0");
        } else {
            panic!("failed to parse hex literal");
        }
        assert!(lexer.diagnostics.is_empty());

        lexer = Lexer::new("foo", false).unwrap();
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::Ident("foo".to_string())
        );
        assert!(lexer.diagnostics.is_empty());

        lexer = Lexer::new("ubar", false).unwrap();
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::Ident("ubar".to_string())
        );
        assert!(lexer.diagnostics.is_empty());

        lexer = Lexer::new("baz👍buz", false).unwrap();
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::Placeholder("baz👍buz".to_string())
        );
        assert_eq!(lexer.diagnostics.len(), 2);
        assert_eq!(lexer.diagnostics[0].e, LexerError::NonASCIIChar('👍'));
        assert_eq!(lexer.diagnostics[1].e, LexerError::InvalidCharIdent('👍'));

        lexer = Lexer::new("+", false).unwrap();
        assert_eq!(lexer.read_token().unwrap().token, Token::Plus);
        assert!(lexer.diagnostics.is_empty());

        lexer = Lexer::new("-", false).unwrap();
        assert_eq!(lexer.read_token().unwrap().token, Token::Minus);
        assert!(lexer.diagnostics.is_empty());

        lexer = Lexer::new("*", false).unwrap();
        assert_eq!(lexer.read_token().unwrap().token, Token::Multiply);
        assert!(lexer.diagnostics.is_empty());

        lexer = Lexer::new("/", false).unwrap();
        assert_eq!(lexer.read_token().unwrap().token, Token::Divide);
        assert!(lexer.diagnostics.is_empty());

        lexer = Lexer::new("<", false).unwrap();
        assert_eq!(lexer.read_token().unwrap().token, Token::Less);
        assert!(lexer.diagnostics.is_empty());

        lexer = Lexer::new("<=", false).unwrap();
        assert_eq!(lexer.read_token().unwrap().token, Token::LessEqual);
        assert!(lexer.diagnostics.is_empty());

        lexer = Lexer::new(">", false).unwrap();
        assert_eq!(lexer.read_token().unwrap().token, Token::Greater);
        assert!(lexer.diagnostics.is_empty());

        lexer = Lexer::new(">=", false).unwrap();
        assert_eq!(lexer.read_token().unwrap().token, Token::GreaterEqual);
        assert!(lexer.diagnostics.is_empty());

        lexer = Lexer::new(";; this is a comment", false).unwrap();
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::Comment("this is a comment".to_string())
        );
        assert!(lexer.diagnostics.is_empty());

        lexer = Lexer::new(";; this is a comment\nthis is not", false).unwrap();
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::Comment("this is a comment".to_string())
        );
        assert!(lexer.diagnostics.is_empty());

        lexer = Lexer::new(";; this is a comment\r\n", false).unwrap();
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::Comment("this is a comment".to_string())
        );
        assert_eq!(lexer.diagnostics.len(), 2);
        assert_eq!(lexer.diagnostics[0].e, LexerError::UnsupportedLineEnding);
        assert_eq!(lexer.diagnostics[1].e, LexerError::EditorCRLFMode);

        lexer = Lexer::new("; this is not a comment", false).unwrap();
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::Comment("this is not a comment".to_string())
        );
        assert_eq!(lexer.diagnostics.len(), 1);
        assert_eq!(lexer.diagnostics[0].e, LexerError::SingleSemiColon);

        lexer = Lexer::new("'1234567890ABCDEFG", false).unwrap();
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::Principal("1234567890ABCDEFG".to_string())
        );
        assert!(lexer.diagnostics.is_empty());

        lexer = Lexer::new("'1234567890aBCDEFG", false).unwrap();
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::Placeholder("'1234567890aBCDEFG".to_string())
        );
        assert_eq!(lexer.diagnostics.len(), 1);
        assert_eq!(
            lexer.diagnostics[0].e,
            LexerError::InvalidCharPrincipal('a')
        );

        lexer = Lexer::new("'123456789OABCDEFG", false).unwrap();
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::Placeholder("'123456789OABCDEFG".to_string())
        );
        assert_eq!(lexer.diagnostics.len(), 1);
        assert_eq!(
            lexer.diagnostics[0].e,
            LexerError::InvalidCharPrincipal('O')
        );

        lexer = Lexer::new("@", false).unwrap();
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::Placeholder("@".to_string())
        );
        assert_eq!(lexer.diagnostics.len(), 1);
        assert_eq!(lexer.diagnostics[0].e, LexerError::UnknownSymbol('@'));

        lexer = Lexer::new("okay;; comment", false).unwrap();
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::Ident("okay".to_string())
        );
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::Comment("comment".to_string())
        );
        assert!(lexer.diagnostics.is_empty());
    }

    #[test]
    fn read_multiple_tokens() {
        let mut lexer = Lexer::new(" +321", false).unwrap();
        assert_eq!(lexer.read_token().unwrap().token, Token::Whitespace);
        assert_eq!(lexer.read_token().unwrap().token, Token::Plus);
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::Int("321".to_string())
        );
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
        )
        .unwrap();
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
        assert_eq!(token.token, Token::Int("1234".to_string()));
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
            Token::Utf8String(s) => s,
            _ => panic!("failed to parse utf8 string"),
        };
        assert_eq!(data, "world");
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
        if let Token::Bytes(s) = token.token {
            assert_eq!(s, "0123456789abcdeffedcba9876543210");
        } else {
            panic!("failed to parse hex literal");
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
        let mut lexer = Lexer::new("0a 123", false).unwrap();
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

        lexer = Lexer::new("56789* foo", false).unwrap();
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

        lexer = Lexer::new("u1a *", false).unwrap();
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

        lexer = Lexer::new("\"\\x\"(", false).unwrap();
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

        lexer = Lexer::new("\"open", false).unwrap();
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

        lexer = Lexer::new("\" this is 👎!\"", false).unwrap();
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

        lexer = Lexer::new("\"\\u{1F600}\"", false).unwrap();
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

        lexer = Lexer::new("u\"\\x ok\"", false).unwrap();
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

        lexer = Lexer::new("u\"open", false).unwrap();
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

        lexer = Lexer::new("0xdefg", false).unwrap();
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

        lexer = Lexer::new("0xdef", false).unwrap();
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

        lexer = Lexer::new("0x00p5", false).unwrap();
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

        lexer = Lexer::new("baz👍buz", false).unwrap();
        lexer.read_token().unwrap();
        assert_eq!(
            lexer.diagnostics[0].span,
            Span {
                start_line: 1,
                start_column: 4,
                end_line: 1,
                end_column: 4
            }
        );
        assert_eq!(
            lexer.diagnostics[1].span,
            Span {
                start_line: 1,
                start_column: 4,
                end_line: 1,
                end_column: 7
            }
        );

        lexer = Lexer::new("; this is not a comment", false).unwrap();
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

        lexer = Lexer::new("123 @ abc", false).unwrap();
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

        lexer = Lexer::new("  \"newline\n  \"", false).unwrap();
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
        let mut lexer = Lexer::new("'ST000000000000000000002AMW42H.silly-goose", false).unwrap();
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::Principal("ST000000000000000000002AMW42H".to_string())
        );
        assert_eq!(lexer.read_token().unwrap().token, Token::Dot);
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::Ident("silly-goose".to_string())
        );
        assert!(lexer.diagnostics.is_empty());
    }

    #[test]
    fn read_trait_reference() {
        let mut lexer = Lexer::new("<fancy-dolphin>", false).unwrap();
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::TraitIdent("fancy-dolphin".to_string())
        );
        assert_eq!(lexer.read_token().unwrap().token, Token::Eof);
        assert!(lexer.diagnostics.is_empty());

        lexer = Lexer::new("<illegal*name>", false).unwrap();
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::Placeholder("<illegal*name>".to_string())
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

        lexer = Lexer::new("<not-closed ", false).unwrap();
        assert_eq!(
            lexer.read_token().unwrap().token,
            Token::Placeholder("<not-closed".to_string())
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
