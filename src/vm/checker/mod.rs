pub mod typecheck;
mod errors;
mod identity_pass;
mod check_db;

use vm::checker::typecheck::contexts::ContractAnalysis;
use vm::representations::{SymbolicExpression};

pub use self::errors::{CheckResult, CheckError, CheckErrors};
pub use self::check_db::{AnalysisDatabase, AnalysisDatabaseConnection};

pub fn type_check(contract_name: &str, contract: &mut [SymbolicExpression],
                  analysis_db: &mut AnalysisDatabase, insert_contract: bool) -> CheckResult<ContractAnalysis> {
    identity_pass::identity_pass(contract)?;
    let contract_analysis = typecheck::TypeChecker::type_check_contract(contract, analysis_db)?;
    if insert_contract {
        analysis_db.insert_contract(contract_name, &contract_analysis)?;
    }
    Ok(contract_analysis)
}
