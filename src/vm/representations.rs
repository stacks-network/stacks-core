use std::fmt;
use std::borrow::Borrow;
use std::ops::Deref;
use std::convert::TryFrom;
use regex::{Regex};
use vm::types::{Value};
use vm::errors::{RuntimeErrorType};


#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub enum SymbolicExpressionType {
    AtomValue(Value),
    Atom(ClarityName),
    List(Box<[SymbolicExpression]>),
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct SymbolicExpression {
    pub expr: SymbolicExpressionType,
    // this id field is used by compiler passes to store information in
    //  maps.
    // first pass       -> fill out unique ids
    // ...typing passes -> store information in hashmap according to id.
    // 
    // this is a fairly standard technique in compiler passes
    pub id: u64,

    #[cfg(feature = "developer-mode")]
    pub span: Span,
}

macro_rules! guarded_string {
    ($Name:ident, $Label:literal, $Regex:expr) => {
        #[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $Name (String);
        impl TryFrom<String> for $Name {
            type Error = RuntimeErrorType;
            fn try_from(value: String) -> Result<Self, Self::Error> {
                // TODO: use lazy static ?
                let regex_check = $Regex
                    .expect("FAIL: Bad static regex.");
                if regex_check.is_match(&value) {
                    Ok(Self(value))
                } else {
                    Err(RuntimeErrorType::ParseError(format!("Attempted to construct bad {}", $Label)).into())
                }
            }
        }
        
        impl Deref for $Name {
            type Target = str;
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl Borrow<str> for $Name {
            fn borrow(&self) -> &str {
                &self.0
            }
        }

        impl Into<String> for $Name {
            fn into(self) -> String {
                self.0
            }
        }

        #[cfg(test)]
        impl From<&'_ str> for $Name {
            fn from(value: &str) -> Self {
                Self::try_from(value.to_string()).unwrap()
            }
        }
    }
}

guarded_string!(ClarityName, "ClarityName", Regex::new("^([a-zA-z0-9]|[-!?+<>=/*])*$"));
guarded_string!(ContractName, "ContractName", Regex::new("^([a-zA-z0-9]|[-!?+<>=/*])*$"));

impl SymbolicExpression {
    #[cfg(feature = "developer-mode")]
    fn cons() -> Self {
        Self {
            id: 0,
            span: Span::zero(),
            expr: SymbolicExpressionType::AtomValue(Value::Bool(false))
        }
    }
    #[cfg(not(feature = "developer-mode"))]
    fn cons() -> Self {
        Self {
            id: 0,
            expr: SymbolicExpressionType::AtomValue(Value::Bool(false))
        }
    }

    #[cfg(feature = "developer-mode")]
    pub fn set_span(&mut self, start_line: u32, start_column: u32, end_line: u32, end_column: u32) {
        self.span = Span {
            start_line,
            start_column,
            end_line,
            end_column
        }
    }

    #[cfg(not(feature = "developer-mode"))]
    pub fn set_span(&mut self, _start_line: u32, _start_column: u32, _end_line: u32, _end_column: u32) {
    }
    
    pub fn atom_value(val: Value) -> SymbolicExpression {
        SymbolicExpression {
            expr: SymbolicExpressionType::AtomValue(val),
            .. SymbolicExpression::cons()
        }
    }

    pub fn atom(val: ClarityName) -> SymbolicExpression {
        SymbolicExpression {
            expr: SymbolicExpressionType::Atom(val),
            .. SymbolicExpression::cons()
        }
    }

    pub fn list(val: Box<[SymbolicExpression]>) -> SymbolicExpression {
        SymbolicExpression {
            expr: SymbolicExpressionType::List(val),
            .. SymbolicExpression::cons()
        }
    }

    // These match functions are used to simplify calling code
    //   areas a lot. There is a frequent code pattern where
    //   a block _expects_ specific symbolic expressions, leading
    //   to a lot of very verbose `if let x = {` expressions. 

    pub fn match_list(&self) -> Option<&[SymbolicExpression]> {
        if let SymbolicExpressionType::List(ref list) = self.expr {
            Some(list)
        } else {
            None
        }
    }

    pub fn match_atom(&self) -> Option<&ClarityName> {
        if let SymbolicExpressionType::Atom(ref value) = self.expr {
            Some(value)
        } else {
            None
        }
    }

    pub fn match_atom_value(&self) -> Option<&Value> {
        if let SymbolicExpressionType::AtomValue(ref value) = self.expr {
            Some(value)
        } else {
            None
        }
    }
}

impl fmt::Display for SymbolicExpression {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.expr {
            SymbolicExpressionType::List(ref list) => {
                write!(f, "(")?;
                for item in list.iter() {
                    write!(f, " {}", item)?;
                }
                write!(f, " )")?;
            },
            SymbolicExpressionType::Atom(ref value) => {
                write!(f, "{}", &**value)?;
            },
            SymbolicExpressionType::AtomValue(ref value) => {
                write!(f, "{}", value)?;
            }
        };
        
        Ok(())
    }
}

#[derive(Debug)]
#[derive(Serialize, Deserialize)]
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Span {
    pub start_line: u32,
    pub start_column: u32,
    pub end_line: u32,
    pub end_column: u32
}

impl Span {
    pub fn zero() -> Span {
        Span {
            start_line: 0,
            start_column: 0,
            end_line: 0,
            end_column: 0
        }
    }
}
