pub mod diagnostic;
pub mod types;
pub mod errors;
pub mod update_expressions_id;
pub mod update_expressions_sorting;
pub mod check_typing;
pub mod check_readonly_definitions;
pub mod check_db;
pub mod build_contract_interface;

use self::types::ContractAnalysis;
use vm::representations::{SymbolicExpression};

pub use self::errors::{CheckResult, CheckError, CheckErrors};
pub use self::check_db::{AnalysisDatabase, AnalysisDatabaseConnection};

pub fn type_check(contract_name: &str, contract: &mut [SymbolicExpression],
                  analysis_db: &mut AnalysisDatabase, insert_contract: bool) -> CheckResult<ContractAnalysis> {
    update_expressions_id::identity_pass(contract)?;
    update_expressions_sorting::TopLevelExpressionSorter::check_contract(contract, analysis_db)?;
    check_readonly_definitions::ReadOnlyChecker::check_contract(contract, analysis_db)?;
    let contract_analysis = check_typing::TypeChecker::type_check_contract(contract, analysis_db)?;
    if insert_contract {
        analysis_db.insert_contract(contract_name, &contract_analysis)?;
    }
    Ok(contract_analysis)
}

// struct Pass;

// impl Pass {
//     fn run(contract_analysis: &mut ContractAnalysis, analysis_db: &mut AnalysisDatabase) -> CheckResult<ContractAnalysis>
// }

// pub fn run_analysis(contract_name: &str, 
//                     expressions: &mut [SymbolicExpression],
//                     analysis_db: &mut AnalysisDatabase, 
//                     save_contract: bool) -> CheckResult<ContractAnalysis> {
//     let mut contract_analysis = ContractAnalysis::new(expressions);
//     UpdateExpressionIdPass::run(contract_analysis, analysis_db)?;
//     UpdateExpressionSortingPass::run(contract_analysis, analysis_db)?;
//     CheckReadOnlyDefinitionsPass::run(contract_analysis, analysis_db)?;
//     CheckTypingPass:run(contract_analysis, analysis_db)?;
//     if save_contract {
//         analysis_db.insert_contract(contract_name, contract_analysis)?;
//     }
//     Ok(contract_analysis);
// }

#[cfg(test)]
mod tests;
