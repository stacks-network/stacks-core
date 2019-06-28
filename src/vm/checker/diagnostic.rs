use vm::representations::{Span};
use std::fmt;
use vm::checker::{CheckErrors};

#[derive(Debug)]
#[derive(Serialize, Deserialize)]
#[derive(PartialEq)]
pub enum Level {
    Error,
    Warning,
    Hint,
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub trait DiagnosableError {
    fn context(&self) -> Option<String>;
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

    pub fn to_json(&self) -> String {
        format!("{}", serde_json::to_string_pretty(&self).unwrap())
    }

    pub fn to_text(&self) -> String {
        format!("{}", self)
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.level)?;
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
