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

use std::{error, fmt};

use crate::MAX_CALL_STACK_DEPTH;
use crate::diagnostic::{DiagnosableError, Diagnostic, Level};
use crate::errors::{CostErrors, LexerError};
use crate::execution_cost::ExecutionCost;
use crate::representations::{PreSymbolicExpression, Span};
use crate::token::Token;

pub type ParseResult<T> = Result<T, ParseError>;

#[derive(Debug, PartialEq)]
pub enum ParseErrorKind {
    // Cost errors
    CostOverflow,
    CostBalanceExceeded(ExecutionCost, ExecutionCost),
    MemoryBalanceExceeded(u64, u64),
    CostComputationFailed(String),
    ExecutionTimeExpired,

    TooManyExpressions,
    ExpressionStackDepthTooDeep,
    VaryExpressionStackDepthTooDeep,
    FailedParsingIntValue(String),
    CircularReference(Vec<String>),
    NameAlreadyUsed(String),
    TraitReferenceNotAllowed,
    ImportTraitBadSignature,
    DefineTraitBadSignature,
    ImplTraitBadSignature,
    TraitReferenceUnknown(String),

    // V1 errors
    FailedCapturingInput,
    SeparatorExpected(String),
    SeparatorExpectedAfterColon(String),
    ProgramTooLarge,
    IllegalVariableName(String),
    FailedParsingBuffer(String),
    FailedParsingHexValue(String, String),
    FailedParsingPrincipal(String),
    FailedParsingField(String),
    FailedParsingRemainder(String),
    ClosingParenthesisUnexpected,
    ClosingParenthesisExpected,
    ClosingTupleLiteralUnexpected,
    ClosingTupleLiteralExpected,
    TupleColonExpected(usize),
    TupleCommaExpected(usize),
    TupleItemExpected(usize),
    CommaSeparatorUnexpected,
    ColonSeparatorUnexpected,
    InvalidCharactersDetected,
    InvalidEscaping,

    // V2 Errors
    Lexer(LexerError),
    ContractNameTooLong(String),
    ExpectedClosing(Token),
    ExpectedContractIdentifier,
    ExpectedTraitIdentifier,
    ExpectedWhitespace,
    FailedParsingUIntValue(String),
    IllegalTraitName(String),
    InvalidPrincipalLiteral,
    InvalidBuffer,
    NameTooLong(String),
    UnexpectedToken(Token),
    TupleColonExpectedv2,
    TupleCommaExpectedv2,
    TupleValueExpected,
    IllegalClarityName(String),
    IllegalASCIIString(String),
    IllegalContractName(String),
    // Notes
    NoteToMatchThis(Token),
    /// Should be an unreachable error
    UnexpectedParserFailure,

    /// Should be an unreachable failure which invalidates the transaction
    InterpreterFailure,
}

#[derive(Debug, PartialEq)]
pub struct ParseError {
    pub err: Box<ParseErrorKind>,
    pub pre_expressions: Option<Vec<PreSymbolicExpression>>,
    pub diagnostic: Diagnostic,
}

impl ParseError {
    pub fn new(err: ParseErrorKind) -> ParseError {
        let diagnostic = Diagnostic::err(&err);
        ParseError {
            err: Box::new(err),
            pre_expressions: None,
            diagnostic,
        }
    }

    pub fn rejectable(&self) -> bool {
        matches!(*self.err, ParseErrorKind::InterpreterFailure)
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
        write!(f, "{:?}", self.err)?;

        if let Some(ref e) = self.pre_expressions {
            write!(f, "\nNear:\n{e:?}")?;
        }

        Ok(())
    }
}

impl error::Error for ParseError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

impl From<ParseErrorKind> for ParseError {
    fn from(err: ParseErrorKind) -> Self {
        ParseError::new(err)
    }
}

impl From<CostErrors> for ParseError {
    fn from(err: CostErrors) -> Self {
        match err {
            CostErrors::CostOverflow => ParseError::new(ParseErrorKind::CostOverflow),
            CostErrors::CostBalanceExceeded(a, b) => {
                ParseError::new(ParseErrorKind::CostBalanceExceeded(a, b))
            }
            CostErrors::MemoryBalanceExceeded(a, b) => {
                ParseError::new(ParseErrorKind::MemoryBalanceExceeded(a, b))
            }
            CostErrors::CostComputationFailed(s) => {
                ParseError::new(ParseErrorKind::CostComputationFailed(s))
            }
            CostErrors::CostContractLoadFailure => ParseError::new(
                ParseErrorKind::CostComputationFailed("Failed to load cost contract".into()),
            ),
            CostErrors::InterpreterFailure | CostErrors::Expect(_) => {
                ParseError::new(ParseErrorKind::InterpreterFailure)
            }
            CostErrors::ExecutionTimeExpired => {
                ParseError::new(ParseErrorKind::ExecutionTimeExpired)
            }
        }
    }
}

impl DiagnosableError for ParseErrorKind {
    fn message(&self) -> String {
        match &self {
            ParseErrorKind::CostOverflow => "Used up cost budget during the parse".into(),
            ParseErrorKind::CostBalanceExceeded(bal, used) => {
                format!("Used up cost budget during the parse: {bal} balance, {used} used")
            }
            ParseErrorKind::MemoryBalanceExceeded(bal, used) => {
                format!("Used up memory budget during the parse: {bal} balance, {used} used")
            }
            ParseErrorKind::TooManyExpressions => "Too many expressions".into(),
            ParseErrorKind::FailedCapturingInput => "Failed to capture value from input".into(),
            ParseErrorKind::SeparatorExpected(found) => {
                format!("Expected whitespace or a close parens. Found: '{found}'")
            }
            ParseErrorKind::SeparatorExpectedAfterColon(found) => {
                format!("Whitespace expected after colon (:), Found: '{found}'")
            }
            ParseErrorKind::ProgramTooLarge => "Program too large to parse".into(),
            ParseErrorKind::IllegalContractName(contract_name) => {
                format!("Illegal contract name: '{contract_name}'")
            }
            ParseErrorKind::IllegalVariableName(var_name) => {
                format!("Illegal variable name: '{var_name}'")
            }
            ParseErrorKind::FailedParsingIntValue(value) => {
                format!("Failed to parse int literal '{value}'")
            }
            ParseErrorKind::FailedParsingUIntValue(value) => {
                format!("Failed to parse uint literal 'u{value}'")
            }
            ParseErrorKind::FailedParsingHexValue(value, x) => {
                format!("Invalid hex-string literal {value}: {x}")
            }
            ParseErrorKind::FailedParsingPrincipal(value) => {
                format!("Invalid principal literal: {value}")
            }
            ParseErrorKind::FailedParsingBuffer(value) => {
                format!("Invalid buffer literal: {value}")
            }
            ParseErrorKind::FailedParsingField(value) => format!("Invalid field literal: {value}"),
            ParseErrorKind::FailedParsingRemainder(remainder) => {
                format!("Failed to lex input remainder: '{remainder}'")
            }
            ParseErrorKind::ClosingParenthesisUnexpected => {
                "Tried to close list which isn't open.".into()
            }
            ParseErrorKind::ClosingParenthesisExpected => {
                "List expressions (..) left opened.".into()
            }
            ParseErrorKind::ClosingTupleLiteralUnexpected => {
                "Tried to close tuple literal which isn't open.".into()
            }
            ParseErrorKind::ClosingTupleLiteralExpected => {
                "Tuple literal {{..}} left opened.".into()
            }
            ParseErrorKind::ColonSeparatorUnexpected => "Misplaced colon.".into(),
            ParseErrorKind::CommaSeparatorUnexpected => "Misplaced comma.".into(),
            ParseErrorKind::TupleColonExpected(i) => {
                format!("Tuple literal construction expects a colon at index {i}")
            }
            ParseErrorKind::TupleCommaExpected(i) => {
                format!("Tuple literal construction expects a comma at index {i}")
            }
            ParseErrorKind::TupleItemExpected(i) => {
                format!("Tuple literal construction expects a key or value at index {i}")
            }
            ParseErrorKind::CircularReference(function_names) => format!(
                "detected interdependent functions ({})",
                function_names.join(", ")
            ),
            ParseErrorKind::NameAlreadyUsed(name) => {
                format!("defining '{name}' conflicts with previous value")
            }
            ParseErrorKind::ImportTraitBadSignature => {
                "(use-trait ...) expects a trait name and a trait identifier".into()
            }
            ParseErrorKind::DefineTraitBadSignature => {
                "(define-trait ...) expects a trait name and a trait definition".into()
            }
            ParseErrorKind::ImplTraitBadSignature => {
                "(impl-trait ...) expects a trait identifier".into()
            }
            ParseErrorKind::TraitReferenceNotAllowed => "trait references can not be stored".into(),
            ParseErrorKind::TraitReferenceUnknown(trait_name) => {
                format!("use of undeclared trait <{trait_name}>")
            }
            ParseErrorKind::ExpressionStackDepthTooDeep => format!(
                "AST has too deep of an expression nesting. The maximum stack depth is {MAX_CALL_STACK_DEPTH}"
            ),
            ParseErrorKind::VaryExpressionStackDepthTooDeep => format!(
                "AST has too deep of an expression nesting. The maximum stack depth is {MAX_CALL_STACK_DEPTH}"
            ),
            ParseErrorKind::InvalidCharactersDetected => "invalid characters detected".into(),
            ParseErrorKind::InvalidEscaping => "invalid escaping detected in string".into(),
            ParseErrorKind::CostComputationFailed(s) => format!("Cost computation failed: {s}"),

            // Parser v2 errors
            ParseErrorKind::Lexer(le) => le.message(),
            ParseErrorKind::ContractNameTooLong(name) => {
                format!("contract name '{name}' is too long")
            }
            ParseErrorKind::ExpectedContractIdentifier => "expected contract identifier".into(),
            ParseErrorKind::ExpectedTraitIdentifier => "expected trait identifier".into(),
            ParseErrorKind::IllegalTraitName(name) => format!("illegal trait name, '{name}'"),
            ParseErrorKind::InvalidPrincipalLiteral => "invalid principal literal".into(),
            ParseErrorKind::InvalidBuffer => "invalid hex-string literal".into(),
            ParseErrorKind::NameTooLong(name) => format!("illegal name (too long), '{name}'"),
            ParseErrorKind::UnexpectedToken(token) => format!("unexpected '{token}'"),
            ParseErrorKind::ExpectedClosing(token) => format!("expected closing '{token}'"),
            ParseErrorKind::TupleColonExpectedv2 => "expected ':' after key in tuple".into(),
            ParseErrorKind::TupleCommaExpectedv2 => {
                "expected ',' separating key-value pairs in tuple".into()
            }
            ParseErrorKind::TupleValueExpected => "expected value expression for tuple".into(),
            ParseErrorKind::IllegalClarityName(name) => format!("illegal clarity name, '{name}'"),
            ParseErrorKind::IllegalASCIIString(s) => format!("illegal ascii string \"{s}\""),
            ParseErrorKind::ExpectedWhitespace => "expected whitespace before expression".into(),
            ParseErrorKind::NoteToMatchThis(token) => format!("to match this '{token}'"),
            ParseErrorKind::UnexpectedParserFailure => {
                "unexpected failure while parsing".to_string()
            }
            ParseErrorKind::InterpreterFailure => "unexpected failure while parsing".to_string(),
            ParseErrorKind::ExecutionTimeExpired => "max execution time expired".to_string(),
        }
    }

    fn suggestion(&self) -> Option<String> {
        None
    }

    fn level(&self) -> Level {
        match self {
            ParseErrorKind::NoteToMatchThis(_) => Level::Note,
            ParseErrorKind::Lexer(lexer_error) => lexer_error.level(),
            _ => Level::Error,
        }
    }
}

pub struct PlacedError {
    pub e: ParseErrorKind,
    pub span: Span,
}
