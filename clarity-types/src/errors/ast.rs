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
pub enum ParseErrors {
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
    pub err: Box<ParseErrors>,
    pub pre_expressions: Option<Vec<PreSymbolicExpression>>,
    pub diagnostic: Diagnostic,
}

impl ParseError {
    pub fn new(err: ParseErrors) -> ParseError {
        let diagnostic = Diagnostic::err(&err);
        ParseError {
            err: Box::new(err),
            pre_expressions: None,
            diagnostic,
        }
    }

    pub fn rejectable(&self) -> bool {
        matches!(*self.err, ParseErrors::InterpreterFailure)
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
            CostErrors::InterpreterFailure | CostErrors::Expect(_) => {
                ParseError::new(ParseErrors::InterpreterFailure)
            }
            CostErrors::ExecutionTimeExpired => ParseError::new(ParseErrors::ExecutionTimeExpired),
        }
    }
}

impl DiagnosableError for ParseErrors {
    fn message(&self) -> String {
        match &self {
            ParseErrors::CostOverflow => "Used up cost budget during the parse".into(),
            ParseErrors::CostBalanceExceeded(bal, used) => {
                format!("Used up cost budget during the parse: {bal} balance, {used} used")
            }
            ParseErrors::MemoryBalanceExceeded(bal, used) => {
                format!("Used up memory budget during the parse: {bal} balance, {used} used")
            }
            ParseErrors::TooManyExpressions => "Too many expressions".into(),
            ParseErrors::FailedCapturingInput => "Failed to capture value from input".into(),
            ParseErrors::SeparatorExpected(found) => {
                format!("Expected whitespace or a close parens. Found: '{found}'")
            }
            ParseErrors::SeparatorExpectedAfterColon(found) => {
                format!("Whitespace expected after colon (:), Found: '{found}'")
            }
            ParseErrors::ProgramTooLarge => "Program too large to parse".into(),
            ParseErrors::IllegalContractName(contract_name) => {
                format!("Illegal contract name: '{contract_name}'")
            }
            ParseErrors::IllegalVariableName(var_name) => {
                format!("Illegal variable name: '{var_name}'")
            }
            ParseErrors::FailedParsingIntValue(value) => {
                format!("Failed to parse int literal '{value}'")
            }
            ParseErrors::FailedParsingUIntValue(value) => {
                format!("Failed to parse uint literal 'u{value}'")
            }
            ParseErrors::FailedParsingHexValue(value, x) => {
                format!("Invalid hex-string literal {value}: {x}")
            }
            ParseErrors::FailedParsingPrincipal(value) => {
                format!("Invalid principal literal: {value}")
            }
            ParseErrors::FailedParsingBuffer(value) => format!("Invalid buffer literal: {value}"),
            ParseErrors::FailedParsingField(value) => format!("Invalid field literal: {value}"),
            ParseErrors::FailedParsingRemainder(remainder) => {
                format!("Failed to lex input remainder: '{remainder}'")
            }
            ParseErrors::ClosingParenthesisUnexpected => {
                "Tried to close list which isn't open.".into()
            }
            ParseErrors::ClosingParenthesisExpected => "List expressions (..) left opened.".into(),
            ParseErrors::ClosingTupleLiteralUnexpected => {
                "Tried to close tuple literal which isn't open.".into()
            }
            ParseErrors::ClosingTupleLiteralExpected => "Tuple literal {{..}} left opened.".into(),
            ParseErrors::ColonSeparatorUnexpected => "Misplaced colon.".into(),
            ParseErrors::CommaSeparatorUnexpected => "Misplaced comma.".into(),
            ParseErrors::TupleColonExpected(i) => {
                format!("Tuple literal construction expects a colon at index {i}")
            }
            ParseErrors::TupleCommaExpected(i) => {
                format!("Tuple literal construction expects a comma at index {i}")
            }
            ParseErrors::TupleItemExpected(i) => {
                format!("Tuple literal construction expects a key or value at index {i}")
            }
            ParseErrors::CircularReference(function_names) => format!(
                "detected interdependent functions ({})",
                function_names.join(", ")
            ),
            ParseErrors::NameAlreadyUsed(name) => {
                format!("defining '{name}' conflicts with previous value")
            }
            ParseErrors::ImportTraitBadSignature => {
                "(use-trait ...) expects a trait name and a trait identifier".into()
            }
            ParseErrors::DefineTraitBadSignature => {
                "(define-trait ...) expects a trait name and a trait definition".into()
            }
            ParseErrors::ImplTraitBadSignature => {
                "(impl-trait ...) expects a trait identifier".into()
            }
            ParseErrors::TraitReferenceNotAllowed => "trait references can not be stored".into(),
            ParseErrors::TraitReferenceUnknown(trait_name) => {
                format!("use of undeclared trait <{trait_name}>")
            }
            ParseErrors::ExpressionStackDepthTooDeep => format!(
                "AST has too deep of an expression nesting. The maximum stack depth is {MAX_CALL_STACK_DEPTH}"
            ),
            ParseErrors::VaryExpressionStackDepthTooDeep => format!(
                "AST has too deep of an expression nesting. The maximum stack depth is {MAX_CALL_STACK_DEPTH}"
            ),
            ParseErrors::InvalidCharactersDetected => "invalid characters detected".into(),
            ParseErrors::InvalidEscaping => "invalid escaping detected in string".into(),
            ParseErrors::CostComputationFailed(s) => format!("Cost computation failed: {s}"),

            // Parser v2 errors
            ParseErrors::Lexer(le) => le.message(),
            ParseErrors::ContractNameTooLong(name) => {
                format!("contract name '{name}' is too long")
            }
            ParseErrors::ExpectedContractIdentifier => "expected contract identifier".into(),
            ParseErrors::ExpectedTraitIdentifier => "expected trait identifier".into(),
            ParseErrors::IllegalTraitName(name) => format!("illegal trait name, '{name}'"),
            ParseErrors::InvalidPrincipalLiteral => "invalid principal literal".into(),
            ParseErrors::InvalidBuffer => "invalid hex-string literal".into(),
            ParseErrors::NameTooLong(name) => format!("illegal name (too long), '{name}'"),
            ParseErrors::UnexpectedToken(token) => format!("unexpected '{token}'"),
            ParseErrors::ExpectedClosing(token) => format!("expected closing '{token}'"),
            ParseErrors::TupleColonExpectedv2 => "expected ':' after key in tuple".into(),
            ParseErrors::TupleCommaExpectedv2 => {
                "expected ',' separating key-value pairs in tuple".into()
            }
            ParseErrors::TupleValueExpected => "expected value expression for tuple".into(),
            ParseErrors::IllegalClarityName(name) => format!("illegal clarity name, '{name}'"),
            ParseErrors::IllegalASCIIString(s) => format!("illegal ascii string \"{s}\""),
            ParseErrors::ExpectedWhitespace => "expected whitespace before expression".into(),
            ParseErrors::NoteToMatchThis(token) => format!("to match this '{token}'"),
            ParseErrors::UnexpectedParserFailure => "unexpected failure while parsing".to_string(),
            ParseErrors::InterpreterFailure => "unexpected failure while parsing".to_string(),
            ParseErrors::ExecutionTimeExpired => "max execution time expired".to_string(),
        }
    }

    fn suggestion(&self) -> Option<String> {
        None
    }

    fn level(&self) -> Level {
        match self {
            ParseErrors::NoteToMatchThis(_) => Level::Note,
            ParseErrors::Lexer(lexer_error) => lexer_error.level(),
            _ => Level::Error,
        }
    }
}

pub struct PlacedError {
    pub e: ParseErrors,
    pub span: Span,
}
