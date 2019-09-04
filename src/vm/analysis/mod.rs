pub mod diagnostic;
pub mod types;
pub mod errors;
pub mod expression_identifier;
pub mod definition_sorter;
pub mod type_checker;
pub mod sugar_expander;
pub mod read_only_checker;
pub mod analysis_db;
pub mod build_contract_interface;

use self::types::{ContractAnalysis, AnalysisPass};
use vm::representations::{SymbolicExpression};
use vm::types::QualifiedContractIdentifier;

pub use self::errors::{CheckResult, CheckError, CheckErrors};
pub use self::analysis_db::{AnalysisDatabase};

use self::expression_identifier::ExpressionIdentifier;
use self::definition_sorter::DefinitionSorter;
use self::read_only_checker::ReadOnlyChecker;
use self::type_checker::TypeChecker;
use self::sugar_expander::SugarExpander;

#[cfg(test)]
pub fn mem_type_check(snippet: &str) -> CheckResult<ContractAnalysis> {
    use vm::parser::parse;
    let mut contract = parse(snippet).unwrap();
    let mut analysis_db = AnalysisDatabase::memory();
    type_check(&QualifiedContractIdentifier::transient(), &mut contract, &mut analysis_db, false)
}

// Legacy function
// The analysis is not just checking type.
pub fn type_check(contract_identifier: &QualifiedContractIdentifier, 
                  expressions: &mut [SymbolicExpression],
                  analysis_db: &mut AnalysisDatabase, 
                  insert_contract: bool) -> CheckResult<ContractAnalysis> {
    run_analysis(&contract_identifier, expressions, analysis_db, insert_contract)
}

pub fn run_analysis(contract_identifier: &QualifiedContractIdentifier, 
                    expressions: &mut [SymbolicExpression],
                    analysis_db: &mut AnalysisDatabase, 
                    save_contract: bool) -> CheckResult<ContractAnalysis> {

    analysis_db.execute(|db| {
        let mut contract_analysis = ContractAnalysis::new(contract_identifier.clone(), expressions.to_vec());
        ExpressionIdentifier::run_pass(&mut contract_analysis, db)?;
        DefinitionSorter::run_pass(&mut contract_analysis, db)?;
        SugarExpander::run_pass(&mut contract_analysis, db)?;
        ReadOnlyChecker::run_pass(&mut contract_analysis, db)?;
        TypeChecker::run_pass(&mut contract_analysis, db)?;
        if save_contract {
            db.insert_contract(&contract_identifier, &contract_analysis)?;
        }
        Ok(contract_analysis)
    })
}

#[cfg(test)]
mod tests;


