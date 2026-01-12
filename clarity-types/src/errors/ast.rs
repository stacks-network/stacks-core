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

use std::{error, fmt};

use crate::MAX_CALL_STACK_DEPTH;
use crate::diagnostic::{DiagnosableError, Diagnostic, Level};
use crate::errors::{CostErrors, LexerError};
use crate::execution_cost::ExecutionCost;
use crate::representations::{PreSymbolicExpression, Span};
use crate::token::Token;

pub type ParseResult<T> = Result<T, ParseError>;
/// Errors encountered during the lexical and syntactic analysis of Clarity source code
/// when constructing the abstract syntax tree (AST).
#[derive(Debug, PartialEq)]
pub enum ParseErrorKind {
    // Cost-related errors
    /// Arithmetic overflow in cost computation during AST construction, exceeding the maximum threshold.
    CostOverflow,
    /// Cumulative parsing cost exceeds the allocated budget.
    /// The first `ExecutionCost` represents the total consumed cost, and the second represents the budget limit.
    CostBalanceExceeded(ExecutionCost, ExecutionCost),
    /// Memory usage during AST construction exceeds the allocated budget.
    /// The first `u64` represents the total consumed memory, and the second represents the memory limit.
    MemoryBalanceExceeded(u64, u64),
    /// Failure in cost-tracking due to an unexpected condition or invalid state.
    /// The `String` represents the specific reason for the failure.
    CostComputationFailed(String),
    /// Parsing time exceeds the allowed budget, halting AST construction to ensure responsiveness.
    ExecutionTimeExpired,

    // Structural errors
    /// Number of expressions exceeds the maximum allowed limit.
    TooManyExpressions,
    /// Nesting depth of expressions exceeds the maximum allowed stack depth.
    ExpressionStackDepthTooDeep,
    /// Nesting depth of expressions exceeds the maximum allowed stack depth.
    VaryExpressionStackDepthTooDeep,

    // Semantic errors
    /// Failed to parse a string into an integer literal.
    /// The `String` represents the invalid input string.
    FailedParsingIntValue(String),
    /// Circular reference detected in interdependent function definitions.
    /// The `Vec<String>` represents the list of function names forming the cycle.
    CircularReference(Vec<String>),
    /// Variable name is already in use within the same scope.
    /// The `String` represents the conflicting variable name.
    NameAlreadyUsed(String),
    /// Attempt to store a trait reference, which is prohibited to ensure type safety.
    TraitReferenceNotAllowed,
    /// Invalid or malformed signature in a `(use-trait ...)` expression.
    ImportTraitBadSignature,
    /// Invalid or malformed signature in a `(define-trait ...)` expression.
    DefineTraitBadSignature,
    /// Invalid or malformed signature in a `(impl-trait ...)` expression.
    ImplTraitBadSignature,
    /// Referenced trait does not exist or cannot be found.
    /// The `String` represents the non-existent trait name.
    TraitReferenceUnknown(String),

    // V1 Errors
    /// Failed to capture an expected substring or value during pattern matching in lexical analysis.
    FailedCapturingInput,
    /// Expected a whitespace or closing parenthesis but found an unexpected token or character.
    /// The `String` represents the unexpected token or character found.
    SeparatorExpected(String),
    /// Expected a whitespace after a colon but found an unexpected token.
    /// The `String` represents the unexpected token found.
    SeparatorExpectedAfterColon(String),
    /// Input program exceeds the maximum allowed number of lines.
    ProgramTooLarge,
    /// Variable name contains invalid characters or violates naming rules.
    /// The `String` represents the invalid variable name.
    IllegalVariableName(String),
    /// Failed to parse a string into a buffer literal.
    /// The `String` represents the invalid buffer string.
    FailedParsingBuffer(String),
    /// Failed to parse a string into a hexadecimal value.
    /// The first `String` represents the invalid input string, and the second represents the error details.
    FailedParsingHexValue(String, String),
    /// Failed to parse a string into a principal literal (e.g., invalid principal format).
    /// The `String` represents the invalid principal string.
    FailedParsingPrincipal(String),
    /// Failed to parse a string into a valid field literal.
    /// The `String` represents the invalid field string.
    FailedParsingField(String),
    /// Failed to parse the remaining input after processing a construct, leaving invalid tokens.
    /// The `String` represents the unparsed remainder of the input.
    FailedParsingRemainder(String),
    /// Unexpected closing parenthesis encountered in the input.
    ClosingParenthesisUnexpected,
    /// Expected a closing parenthesis but found another token or end of input.
    ClosingParenthesisExpected,
    /// Unexpected closing brace for a tuple literal encountered in the input.
    ClosingTupleLiteralUnexpected,
    /// Expected a closing brace for a tuple literal but it was missing.
    ClosingTupleLiteralExpected,
    /// Expected a colon in a tuple literal at the specified position, but it was missing.
    /// The `usize` represents the index where the colon was expected.
    TupleColonExpected(usize),
    /// Expected a comma in a tuple literal at the specified position, but it was missing.
    /// The `usize` represents the index where the comma was expected.
    TupleCommaExpected(usize),
    /// Expected a tuple item (e.g., key-value pair) at the specified position, but it was missing or invalid.
    /// The `usize` represents the index where the item was expected.
    TupleItemExpected(usize),
    /// Unexpected comma separator encountered outside a valid list or tuple context.
    CommaSeparatorUnexpected,
    /// Unexpected colon separator encountered.
    ColonSeparatorUnexpected,
    /// Input contains invalid or disallowed characters.
    InvalidCharactersDetected,
    /// Invalid escape sequence in a string literal (e.g., incorrect use of `\`).
    InvalidEscaping,

    // V2 Errors
    /// Lexical analysis failed due to an underlying lexer error.
    /// The `LexerError` represents the specific lexer error encountered.
    Lexer(LexerError),
    /// Contract name exceeds the maximum allowed length.
    /// The `String` represents the overly long contract name.
    ContractNameTooLong(String),
    /// Expected a specific closing token (e.g., parenthesis or brace) but found another token.
    /// The `Token` represents the expected closing token.
    ExpectedClosing(Token),
    /// Expected a contract identifier (e.g., `.contract-name`) but found an invalid or missing token.
    ExpectedContractIdentifier,
    /// Expected a trait identifier (e.g., `.trait-name`) but found an invalid or missing token.
    ExpectedTraitIdentifier,
    /// Expected whitespace to separate tokens but found an unexpected token or character.
    ExpectedWhitespace,
    /// Failed to parse a string into an unsigned integer literal.
    /// The `String` represents the invalid unsigned integer string.
    FailedParsingUIntValue(String),
    /// Trait name contains invalid characters or violates naming rules.
    /// The `String` represents the invalid trait name.
    IllegalTraitName(String),
    /// Invalid principal literal format, preventing parsing into a valid principal.
    InvalidPrincipalLiteral,
    /// Invalid buffer literal format, preventing parsing into a valid buffer.
    InvalidBuffer,
    /// Name (e.g., variable or function) exceeds the maximum allowed length.
    /// The `String` represents the overly long name.
    NameTooLong(String),
    /// Encountered an unexpected token during parsing.
    /// The `Token` represents the unexpected token found.
    UnexpectedToken(Token),
    /// Expected a colon in a tuple literal (version 2 syntax) but it was missing.
    TupleColonExpectedv2,
    /// Expected a comma in a tuple literal (version 2 syntax) but it was missing.
    TupleCommaExpectedv2,
    /// Expected a value in a tuple literal but it was missing or invalid.
    TupleValueExpected,
    /// Clarity name (e.g., variable, function, or trait) contains invalid characters or violates naming rules.
    /// The `String` represents the invalid Clarity name.
    IllegalClarityName(String),
    /// ASCII string literal contains invalid characters or violates format rules.
    /// The `String` represents the invalid ASCII string.
    IllegalASCIIString(String),
    /// Contract name contains invalid characters or violates naming rules.
    /// The `String` represents the invalid contract name.
    IllegalContractName(String),

    // Notes
    /// Indicates a token mismatch for internal parser diagnostics.
    /// The `Token` represents the expected token to match.
    NoteToMatchThis(Token),
    /// Unreachable error indicating an unexpected parser failure; should never occur in valid execution.
    UnexpectedParserFailure,
    /// Unreachable failure indicating an invalid transaction due to an unexpected interpreter error.
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
        matches!(
            *self.err,
            ParseErrorKind::InterpreterFailure
                | ParseErrorKind::ExpressionStackDepthTooDeep
                | ParseErrorKind::VaryExpressionStackDepthTooDeep
        )
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
