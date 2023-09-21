// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
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

use std::error;
use std::fmt;

use crate::vm::ast::parser::v2::lexer::error::LexerError;
use crate::vm::ast::parser::v2::lexer::token::Token;
use crate::vm::costs::{CostErrors, ExecutionCost};
use crate::vm::diagnostic::{DiagnosableError, Diagnostic, Level};
use crate::vm::representations::{PreSymbolicExpression, Span};
use crate::vm::types::{TupleTypeSignature, TypeSignature};
use crate::vm::MAX_CALL_STACK_DEPTH;

pub type ParseResult<T> = Result<T, ParseError>;

#[derive(Debug, PartialEq)]
pub enum ParseErrors {
    CostOverflow,
    CostBalanceExceeded(ExecutionCost, ExecutionCost),
    MemoryBalanceExceeded(u64, u64),
    TooManyExpressions,
    ExpressionStackDepthTooDeep,
    VaryExpressionStackDepthTooDeep,
    FailedCapturingInput,
    SeparatorExpected(String),
    SeparatorExpectedAfterColon(String),
    ProgramTooLarge,
    IllegalVariableName(String),
    IllegalContractName(String),
    UnknownQuotedValue(String),
    FailedParsingIntValue(String),
    FailedParsingUIntValue(String),
    FailedParsingBuffer(String),
    FailedParsingHexValue(String, String),
    FailedParsingPrincipal(String),
    FailedParsingField(String),
    FailedParsingRemainder(String),
    ClosingParenthesisUnexpected,
    ClosingParenthesisExpected,
    ClosingTupleLiteralUnexpected,
    ClosingTupleLiteralExpected,
    CircularReference(Vec<String>),
    TupleColonExpected(usize),
    TupleCommaExpected(usize),
    TupleItemExpected(usize),
    NameAlreadyUsed(String),
    TraitReferenceNotAllowed,
    ImportTraitBadSignature,
    DefineTraitBadSignature,
    ImplTraitBadSignature,
    TraitReferenceUnknown(String),
    CommaSeparatorUnexpected,
    ColonSeparatorUnexpected,
    InvalidCharactersDetected,
    InvalidEscaping,
    CostComputationFailed(String),

    // V2 Errors
    Lexer(LexerError),
    ContractNameTooLong(String),
    ExpectedContractIdentifier,
    ExpectedTraitIdentifier,
    IllegalTraitName(String),
    InvalidPrincipalLiteral,
    InvalidBuffer,
    NameTooLong(String),
    UnexpectedToken(Token),
    ExpectedClosing(Token),
    TupleColonExpectedv2,
    TupleCommaExpectedv2,
    TupleValueExpected,
    IllegalClarityName(String),
    IllegalASCIIString(String),
    IllegalUtf8String(String),
    ExpectedWhitespace,
    // Notes
    NoteToMatchThis(Token),

    /// Should be an unreachable error
    UnexpectedParserFailure,
}

#[derive(Debug, PartialEq)]
pub struct ParseError {
    pub err: ParseErrors,
    pub pre_expressions: Option<Vec<PreSymbolicExpression>>,
    pub diagnostic: Diagnostic,
}

impl ParseError {
    pub fn new(err: ParseErrors) -> ParseError {
        let diagnostic = Diagnostic::err(&err);
        ParseError {
            err,
            pre_expressions: None,
            diagnostic,
        }
    }

    pub fn has_pre_expression(&self) -> bool {
        self.pre_expressions.is_some()
    }

    pub fn set_pre_expression(&mut self, expr: &PreSymbolicExpression) {
        self.diagnostic.spans = vec![expr.span().clone()];
        self.pre_expressions.replace(vec![expr.clone()]);
    }

    pub fn set_pre_expressions(&mut self, exprs: Vec<PreSymbolicExpression>) {
        self.diagnostic.spans = exprs.iter().map(|e| e.span().clone()).collect();
        self.pre_expressions.replace(exprs.to_vec());
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.err {
            _ => write!(f, "{:?}", self.err),
        }?;

        if let Some(ref e) = self.pre_expressions {
            write!(f, "\nNear:\n{:?}", e)?;
        }

        Ok(())
    }
}

impl error::Error for ParseError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self.err {
            _ => None,
        }
    }
}

impl From<ParseErrors> for ParseError {
    fn from(err: ParseErrors) -> Self {
        ParseError::new(err)
    }
}

impl From<CostErrors> for ParseError {
    fn from(err: CostErrors) -> Self {
        match err {
            CostErrors::CostOverflow => ParseError::new(ParseErrors::CostOverflow),
            CostErrors::CostBalanceExceeded(a, b) => {
                ParseError::new(ParseErrors::CostBalanceExceeded(a, b))
            }
            CostErrors::MemoryBalanceExceeded(a, b) => {
                ParseError::new(ParseErrors::MemoryBalanceExceeded(a, b))
            }
            CostErrors::CostComputationFailed(s) => {
                ParseError::new(ParseErrors::CostComputationFailed(s))
            }
            CostErrors::CostContractLoadFailure => ParseError::new(
                ParseErrors::CostComputationFailed("Failed to load cost contract".into()),
            ),
        }
    }
}

impl DiagnosableError for ParseErrors {
    fn message(&self) -> String {
        match &self {
            ParseErrors::CostOverflow => format!("Used up cost budget during the parse"),
            ParseErrors::CostBalanceExceeded(bal, used) => format!(
                "Used up cost budget during the parse: {} balance, {} used",
                bal, used
            ),
            ParseErrors::MemoryBalanceExceeded(bal, used) => format!(
                "Used up memory budget during the parse: {} balance, {} used",
                bal, used
            ),
            ParseErrors::TooManyExpressions => format!("Too many expressions"),
            ParseErrors::FailedCapturingInput => format!("Failed to capture value from input"),
            ParseErrors::SeparatorExpected(found) => {
                format!("Expected whitespace or a close parens. Found: '{}'", found)
            }
            ParseErrors::SeparatorExpectedAfterColon(found) => {
                format!("Whitespace expected after colon (:), Found: '{}'", found)
            }
            ParseErrors::ProgramTooLarge => format!("Program too large to parse"),
            ParseErrors::IllegalContractName(contract_name) => {
                format!("Illegal contract name: '{}'", contract_name)
            }
            ParseErrors::IllegalVariableName(var_name) => {
                format!("Illegal variable name: '{}'", var_name)
            }
            ParseErrors::UnknownQuotedValue(value) => format!("Unknown 'quoted value '{}'", value),
            ParseErrors::FailedParsingIntValue(value) => {
                format!("Failed to parse int literal '{}'", value)
            }
            ParseErrors::FailedParsingUIntValue(value) => {
                format!("Failed to parse uint literal 'u{}'", value)
            }
            ParseErrors::FailedParsingHexValue(value, x) => {
                format!("Invalid hex-string literal {}: {}", value, x)
            }
            ParseErrors::FailedParsingPrincipal(value) => {
                format!("Invalid principal literal: {}", value)
            }
            ParseErrors::FailedParsingBuffer(value) => format!("Invalid buffer literal: {}", value),
            ParseErrors::FailedParsingField(value) => format!("Invalid field literal: {}", value),
            ParseErrors::FailedParsingRemainder(remainder) => {
                format!("Failed to lex input remainder: '{}'", remainder)
            }
            ParseErrors::ClosingParenthesisUnexpected => {
                format!("Tried to close list which isn't open.")
            }
            ParseErrors::ClosingParenthesisExpected => {
                format!("List expressions (..) left opened.")
            }
            ParseErrors::ClosingTupleLiteralUnexpected => {
                format!("Tried to close tuple literal which isn't open.")
            }
            ParseErrors::ClosingTupleLiteralExpected => {
                format!("Tuple literal {{..}} left opened.")
            }
            ParseErrors::ColonSeparatorUnexpected => format!("Misplaced colon."),
            ParseErrors::CommaSeparatorUnexpected => format!("Misplaced comma."),
            ParseErrors::TupleColonExpected(i) => {
                format!("Tuple literal construction expects a colon at index {}", i)
            }
            ParseErrors::TupleCommaExpected(i) => {
                format!("Tuple literal construction expects a comma at index {}", i)
            }
            ParseErrors::TupleItemExpected(i) => format!(
                "Tuple literal construction expects a key or value at index {}",
                i
            ),
            ParseErrors::CircularReference(function_names) => format!(
                "detected interdependent functions ({})",
                function_names.join(", ")
            ),
            ParseErrors::NameAlreadyUsed(name) => {
                format!("defining '{}' conflicts with previous value", name)
            }
            ParseErrors::ImportTraitBadSignature => {
                format!("(use-trait ...) expects a trait name and a trait identifier")
            }
            ParseErrors::DefineTraitBadSignature => {
                format!("(define-trait ...) expects a trait name and a trait definition")
            }
            ParseErrors::ImplTraitBadSignature => {
                format!("(impl-trait ...) expects a trait identifier")
            }
            ParseErrors::TraitReferenceNotAllowed => format!("trait references can not be stored"),
            ParseErrors::TraitReferenceUnknown(trait_name) => {
                format!("use of undeclared trait <{}>", trait_name)
            }
            ParseErrors::ExpressionStackDepthTooDeep => format!(
                "AST has too deep of an expression nesting. The maximum stack depth is {}",
                MAX_CALL_STACK_DEPTH
            ),
            ParseErrors::VaryExpressionStackDepthTooDeep => format!(
                "AST has too deep of an expression nesting. The maximum stack depth is {}",
                MAX_CALL_STACK_DEPTH
            ),
            ParseErrors::InvalidCharactersDetected => format!("invalid characters detected"),
            ParseErrors::InvalidEscaping => format!("invalid escaping detected in string"),
            ParseErrors::CostComputationFailed(s) => format!("Cost computation failed: {}", s),

            // Parser v2 errors
            ParseErrors::Lexer(le) => le.message(),
            ParseErrors::ContractNameTooLong(name) => {
                format!("contract name '{}' is too long", name)
            }
            ParseErrors::ExpectedContractIdentifier => "expected contract identifier".to_string(),
            ParseErrors::ExpectedTraitIdentifier => "expected trait identifier".to_string(),
            ParseErrors::IllegalTraitName(name) => format!("illegal trait name, '{}'", name),
            ParseErrors::InvalidPrincipalLiteral => "invalid principal literal".to_string(),
            ParseErrors::InvalidBuffer => "invalid hex-string literal".to_string(),
            ParseErrors::NameTooLong(name) => format!("illegal name (too long), '{}'", name),
            ParseErrors::UnexpectedToken(token) => format!("unexpected '{}'", token),
            ParseErrors::ExpectedClosing(token) => format!("expected closing '{}'", token),
            ParseErrors::TupleColonExpectedv2 => "expected ':' after key in tuple".to_string(),
            ParseErrors::TupleCommaExpectedv2 => {
                "expected ',' separating key-value pairs in tuple".to_string()
            }
            ParseErrors::TupleValueExpected => "expected value expression for tuple".to_string(),
            ParseErrors::IllegalClarityName(name) => format!("illegal clarity name, '{}'", name),
            ParseErrors::IllegalASCIIString(s) => format!("illegal ascii string \"{}\"", s),
            ParseErrors::IllegalUtf8String(s) => format!("illegal UTF8 string \"{}\"", s),
            ParseErrors::ExpectedWhitespace => "expected whitespace before expression".to_string(),
            ParseErrors::NoteToMatchThis(token) => format!("to match this '{}'", token),
            ParseErrors::UnexpectedParserFailure => "unexpected failure while parsing".to_string(),
        }
    }

    fn suggestion(&self) -> Option<String> {
        match &self {
            _ => None,
        }
    }

    fn level(&self) -> crate::vm::diagnostic::Level {
        use self::ParseErrors::*;
        match self {
            ParseErrors::NoteToMatchThis(_) => Level::Note,
            ParseErrors::Lexer(lexerError) => lexerError.level(),
            _ => Level::Error,
        }
    }
}

pub struct PlacedError {
    pub e: ParseErrors,
    pub span: Span,
}
