use vm::representations::{SymbolicExpression, SymbolicExpressionType};
use vm::analysis::errors::{CheckResult, CheckErrors, CheckError};

fn inner_relabel(args: &mut [SymbolicExpression], index: u64) -> CheckResult<u64> {
    let mut current = index.checked_add(1)
        .ok_or(CheckError::new(CheckErrors::TooManyExpressions))?;
    for expression in &mut args[..] {
        expression.id = current;
        current = match expression.expr {
            SymbolicExpressionType::AtomValue(_) => {
                current.checked_add(1)
                    .ok_or(CheckError::new(CheckErrors::TooManyExpressions))
            },
            SymbolicExpressionType::Atom(_) => {
                current.checked_add(1)
                    .ok_or(CheckError::new(CheckErrors::TooManyExpressions))
            },
            SymbolicExpressionType::List(ref mut exprs) => {
                inner_relabel(exprs, current)
            }
        }?;
    }
    Ok(current)
}

pub fn identity_pass(args: &mut [SymbolicExpression]) -> CheckResult<()> {
    inner_relabel(args, 0)?;
    Ok(())
}
