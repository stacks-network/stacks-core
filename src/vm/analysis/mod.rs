pub mod diagnostic;
pub mod types;
pub mod errors;
pub mod update_expressions_id;
pub mod update_expressions_sorting;
pub mod check_typing;
pub mod check_readonly_definitions;
pub mod check_db;
pub mod build_contract_interface;

use self::types::{ContractAnalysis, AnalysisPass};
use vm::representations::{SymbolicExpression};

pub use self::errors::{CheckResult, CheckError, CheckErrors};
pub use self::check_db::{AnalysisDatabase, AnalysisDatabaseConnection};

use self::update_expressions_id::UpdateExpressionId;
use self::update_expressions_sorting::UpdateExpressionsSorting;
use self::check_readonly_definitions::CheckReadOnlyDefinitions;
use self::check_typing::CheckTyping;

// Legacy function
// The analysis is not just checking type.
pub fn type_check(contract_name: &str, 
                      expressions: &mut [SymbolicExpression],
                      analysis_db: &mut AnalysisDatabase, 
                      insert_contract: bool) -> CheckResult<ContractAnalysis> {
    run_analysis(contract_name, expressions, analysis_db, insert_contract)
}

pub fn run_analysis(contract_name: &str, 
                    expressions: &mut [SymbolicExpression],
                    analysis_db: &mut AnalysisDatabase, 
                    save_contract: bool) -> CheckResult<ContractAnalysis> {

    let mut contract_analysis = ContractAnalysis::new(expressions.to_vec());
    UpdateExpressionId::run_pass(&mut contract_analysis, analysis_db)?;
    UpdateExpressionsSorting::run_pass(&mut contract_analysis, analysis_db)?;
    CheckReadOnlyDefinitions::run_pass(&mut contract_analysis, analysis_db)?;
    CheckTyping::run_pass(&mut contract_analysis, analysis_db)?;
    if save_contract {
        analysis_db.insert_contract(contract_name, &contract_analysis)?;
    }
    Ok(contract_analysis)
}

#[cfg(test)]
mod tests;


