mod typecheck;
mod errors;
mod identity_pass;

use vm::representations::{SymbolicExpression};

pub use self::errors::{CheckResult, CheckError, CheckErrors};

pub fn type_check(contract: &mut [SymbolicExpression]) -> CheckResult<()> {
    identity_pass::identity_pass(contract)?;
    typecheck::type_check_contract(contract)
}
