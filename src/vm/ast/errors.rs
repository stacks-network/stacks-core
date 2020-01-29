use vm::representations::SymbolicExpression;
use vm::diagnostic::{Diagnostic, DiagnosableError};
use vm::types::{TypeSignature, TupleTypeSignature};
use std::error;
use std::fmt;

pub type ParseResult <T> = Result<T, ParseError>;

#[derive(Debug, PartialEq)]
pub enum ParseErrors {
    TooManyExpressions,
    FailedCapturingInput,
    SeparatorExpected(String),
    ProgramTooLarge,
    IllegalVariableName(String),
    IllegalContractName(String),
    UnknownQuotedValue(String),
    FailedParsingIntValue(String),
    FailedParsingBuffer(String),
    FailedParsingHexValue(String, String),
    FailedParsingPrincipal(String),
    FailedParsingField(String),
    FailedParsingRemainder(String),
    ClosingParenthesisUnexpected,
    ClosingParenthesisExpected
}

#[derive(Debug, PartialEq)]
pub struct ParseError {
    pub err: ParseErrors,
    pub expressions: Option<Vec<SymbolicExpression>>,
    pub diagnostic: Diagnostic,
}

impl ParseError {
    pub fn new(err: ParseErrors) -> ParseError {
        let diagnostic = Diagnostic::err(&err);
        ParseError {
            err,
            expressions: None,
            diagnostic
        }
    }

    pub fn has_expression(&self) -> bool {
        self.expressions.is_some()
    }

    pub fn set_expression(&mut self, expr: &SymbolicExpression) {
        self.diagnostic.spans = vec![expr.span.clone()];
        self.expressions.replace(vec![expr.clone()]);
    }

    pub fn set_expressions(&mut self, exprs: Vec<SymbolicExpression>) {
        self.diagnostic.spans = exprs.iter().map(|e| e.span.clone()).collect();
        self.expressions.replace(exprs.clone().to_vec());
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.err {
            _ =>  write!(f, "{:?}", self.err)
        }?;

        if let Some(ref e) = self.expressions {
            write!(f, "\nNear:\n{:?}", e)?;
        }

        Ok(())
    }
}

impl error::Error for ParseError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self.err {
            _ => None
        }
    }
}

impl From<ParseErrors> for ParseError {
    fn from(err: ParseErrors) -> Self {
        ParseError::new(err)
    }
}

impl DiagnosableError for ParseErrors {

    fn message(&self) -> String {
        match &self {
            ParseErrors::TooManyExpressions => format!("Too many expressions"),
            ParseErrors::FailedCapturingInput => format!("Failed to capture value from input"),
            ParseErrors::SeparatorExpected(found) => format!("Expected whitespace or a close parens. Found: '{}'", found),
            ParseErrors::ProgramTooLarge => format!("Program too large to parse"),
            ParseErrors::IllegalContractName(contract_name) => format!("Illegal contract name: '{}'", contract_name),
            ParseErrors::IllegalVariableName(var_name) => format!("Illegal variable name: '{}'", var_name),
            ParseErrors::UnknownQuotedValue(value) => format!("Unknown 'quoted value '{}'", value),
            ParseErrors::FailedParsingIntValue(value) => format!("Failed to parse int literal '{}'", value),
            ParseErrors::FailedParsingHexValue(value, x) => format!("Invalid hex-string literal {}: {}", value, x),
            ParseErrors::FailedParsingPrincipal(value) => format!("Invalid principal literal: {}", value),
            ParseErrors::FailedParsingBuffer(value) => format!("Invalid buffer literal: {}", value),
            ParseErrors::FailedParsingField(value) => format!("Invalid field literal: {}", value),
            ParseErrors::FailedParsingRemainder(remainder) => format!("Failed to lex input remainder: {}", remainder),
            ParseErrors::ClosingParenthesisUnexpected => format!("Tried to close list which isn't open."),
            ParseErrors::ClosingParenthesisExpected => format!("List expressions (..) left opened."),
        }
    }

    fn suggestion(&self) -> Option<String> {
        match &self {
            _ => None
        }
    }
}
