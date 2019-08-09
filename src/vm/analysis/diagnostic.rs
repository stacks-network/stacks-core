use vm::representations::{Span};
use std::fmt;
use vm::analysis::{CheckErrors};

/// In a near future, we can go further in our static analysis and provide different levels 
/// of diagnostics, such as warnings, hints, best practices, etc.
#[derive(Debug)]
#[derive(Serialize, Deserialize)]
#[derive(PartialEq)]
pub enum Level {
    Error,
}

pub trait DiagnosableError {
    fn message(&self) -> String;
    fn suggestion(&self) -> Option<String>;
}

#[derive(Debug)]
#[derive(Serialize, Deserialize)]
#[derive(PartialEq)]
pub struct Diagnostic {
    pub level: Level,
    pub message: String,
    pub span: Option<Span>,
    pub suggestion: Option<String>,
}

impl Diagnostic {

    pub fn err(error: &DiagnosableError, span: Option<Span>) -> Diagnostic {
        Diagnostic {
            span,
            level: Level::Error,
            message: error.message(),
            suggestion: error.suggestion(),
        }
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.level)?;
        if let Some(span) = &self.span {
            write!(f, " (line {}, column {})", span.start_line, span.start_column)?;
        }
        write!(f, ": {}.", &self.message)?;
        if let Some(suggestion) = &self.suggestion {
            write!(f, "\n{}", suggestion)?;
        }
        write!(f, "\n")
    }
}
