use vm::representations::{SymbolicExpression, SymbolicExpressionType};
use vm::analysis::types::{ContractAnalysis, AnalysisPass};
use vm::analysis::errors::{CheckResult, CheckErrors, CheckError};
use vm::analysis::check_db::{AnalysisDatabase};

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

pub fn update_expression_id(exprs: &mut [SymbolicExpression]) -> CheckResult<()> {
    inner_relabel(exprs, 0)?;
    Ok(())
}

pub struct UpdateExpressionId;

impl AnalysisPass for UpdateExpressionId {

    fn run_pass(contract_analysis: &mut ContractAnalysis, _analysis_db: &mut AnalysisDatabase) -> CheckResult<()> {
        update_expression_id(& mut contract_analysis.expressions)?;
        Ok(())
    }
}