// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2026 Stacks Open Internet Foundation
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

use std::fmt;

// The shared VM error vocabulary lives in `clarity-kernel`; it is re-exported
// here so all pre-existing `crate::vm::errors::...` paths keep working.
pub use clarity_kernel::errors::*;

use crate::vm::ast::errors::ParseError;

/// An error that occurs during Clarity evaluation, either a VM execution error or a parse error.
#[derive(Debug, PartialEq)]
pub enum ClarityEvalError {
    Vm(VmExecutionError),
    Parse(ParseError),
}

impl From<VmExecutionError> for ClarityEvalError {
    fn from(err: VmExecutionError) -> Self {
        Self::Vm(err)
    }
}

impl From<ParseError> for ClarityEvalError {
    fn from(err: ParseError) -> Self {
        Self::Parse(err)
    }
}

impl From<RuntimeCheckErrorKind> for ClarityEvalError {
    fn from(err: RuntimeCheckErrorKind) -> Self {
        Self::Vm(err.into())
    }
}

impl From<RuntimeError> for ClarityEvalError {
    fn from(err: RuntimeError) -> Self {
        Self::Vm(err.into())
    }
}

impl fmt::Display for ClarityEvalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClarityEvalError::Vm(err) => write!(f, "{err}"),
            ClarityEvalError::Parse(err) => write!(f, "{err}"),
        }
    }
}

#[cfg(test)]
mod test {
    #[test]
    #[cfg(feature = "developer-mode")]
    fn error_formats() {
        let t = "(/ 10 0)";
        let expected = "DivisionByZero
 Stack Trace:
_native_:native_div
";

        assert_eq!(format!("{}", crate::vm::execute(t).unwrap_err()), expected);
    }
}
