// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
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

pub mod analysis_db;
pub mod arithmetic_checker;
pub mod contract_interface_builder;
pub mod errors;
pub mod read_only_checker;
pub mod trait_checker;
pub mod type_checker;
pub mod types;

use crate::types::StacksEpochId;

pub use self::types::{AnalysisPass, ContractAnalysis};

use crate::vm::costs::LimitedCostTracker;
use crate::vm::database::STORE_CONTRACT_SRC_INTERFACE;
use crate::vm::representations::SymbolicExpression;
use crate::vm::types::{QualifiedContractIdentifier, TypeSignature};
use crate::vm::ClarityVersion;

pub use self::analysis_db::AnalysisDatabase;
pub use self::errors::{CheckError, CheckErrors, CheckResult};

use self::arithmetic_checker::ArithmeticOnlyChecker;
use self::contract_interface_builder::build_contract_interface;
use self::read_only_checker::ReadOnlyChecker;
use self::trait_checker::TraitChecker;
use self::type_checker::TypeChecker;

// Legacy function
// The analysis is not just checking type.
#[cfg(test)]
pub fn type_check(
    contract_identifier: &QualifiedContractIdentifier,
    expressions: &mut [SymbolicExpression],
    analysis_db: &mut AnalysisDatabase,
    insert_contract: bool,
    version: &ClarityVersion,
) -> CheckResult<ContractAnalysis> {
    run_analysis(
        &contract_identifier,
        expressions,
        analysis_db,
        insert_contract,
        // for the type check tests, the cost tracker's epoch doesn't
        //  matter: the costs in those tests are all free anyways.
        LimitedCostTracker::new_free(),
        version.clone(),
    )
    .map_err(|(e, _cost_tracker)| e)
}

pub fn run_analysis(
    contract_identifier: &QualifiedContractIdentifier,
    expressions: &mut [SymbolicExpression],
    analysis_db: &mut AnalysisDatabase,
    save_contract: bool,
    cost_tracker: LimitedCostTracker,
    version: ClarityVersion,
) -> Result<ContractAnalysis, (CheckError, LimitedCostTracker)> {
    let mut contract_analysis = ContractAnalysis::new(
        contract_identifier.clone(),
        expressions.to_vec(),
        cost_tracker,
        version,
    );
    let result = analysis_db.execute(|db| {
        ReadOnlyChecker::run_pass(&mut contract_analysis, db)?;
        TypeChecker::run_pass(&mut contract_analysis, db)?;
        TraitChecker::run_pass(&mut contract_analysis, db)?;
        ArithmeticOnlyChecker::check_contract_cost_eligible(&mut contract_analysis);

        if STORE_CONTRACT_SRC_INTERFACE {
            let interface = build_contract_interface(&contract_analysis);
            contract_analysis.contract_interface = Some(interface);
        }
        if save_contract {
            db.insert_contract(&contract_identifier, &contract_analysis)?;
        }
        Ok(())
    });
    match result {
        Ok(_) => Ok(contract_analysis),
        Err(e) => Err((e, contract_analysis.take_contract_cost_tracker())),
    }
}

#[cfg(test)]
mod tests;
