pub mod parser;

use vm::analysis::errors::{CheckResult, CheckError, CheckErrors};
use vm::representations::{SymbolicExpression};
use vm::types::QualifiedContractIdentifier;

/// Legacy function
pub fn parse(src: &str) -> CheckResult<[SymbolicExpression]> {
    build_ast(src)
}
