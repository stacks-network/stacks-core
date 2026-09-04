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

pub mod analysis_db;
pub mod contract_interface_builder;
pub mod errors;
pub mod read_only_checker;
pub mod trait_checker;
pub mod type_checker;
pub mod types;

#[cfg(feature = "rusqlite")]
use stacks_common::bounded_format;
use stacks_common::types::StacksEpochId;

pub use self::analysis_db::AnalysisDatabase;
use self::contract_interface_builder::build_contract_interface;
pub use self::errors::{
    CommonCheckErrorKind, RuntimeCheckErrorKind, StaticCheckError, StaticCheckErrorKind,
};
use self::read_only_checker::ReadOnlyChecker;
use self::trait_checker::TraitChecker;
use self::type_checker::v2_1::TypeChecker as TypeChecker2_1;
use self::type_checker::v2_05::TypeChecker as TypeChecker2_05;
pub use self::types::{AnalysisPass, ContractAnalysis};
use crate::vm::ClarityVersion;
#[cfg(feature = "rusqlite")]
use crate::vm::ast::build_ast;
use crate::vm::costs::LimitedCostTracker;
#[cfg(feature = "rusqlite")]
use crate::vm::database::MemoryBackingStore;
use crate::vm::database::STORE_CONTRACT_SRC_INTERFACE;
use crate::vm::representations::SymbolicExpression;
use crate::vm::resource_limiter::{ResourceLimitExceeded, ResourceLimiter};
use crate::vm::types::QualifiedContractIdentifier;
#[cfg(feature = "rusqlite")]
use crate::vm::types::TypeSignature;

/// Cooperative analysis resource limit check shared by analysis passes
///
/// This is the single place the analysis resource error is constructed. The budget is
/// limited only on the non-consensus voting paths (mining / block-proposal
/// validation); on the deterministic replay/commit path it is unlimited,
/// so this never fires during consensus and the surfaced `AnalysisResourceBudgetExceeded`
/// cannot affect block validity.
pub(crate) fn check_analysis_resource_limits(
    resource_limiter: &ResourceLimiter,
) -> Result<(), StaticCheckError> {
    resource_limiter
        .check_not_exceeded()
        .map_err(|err| match err {
            ResourceLimitExceeded::MaxDurationExceeded(s) => {
                StaticCheckErrorKind::AnalysisResourceBudgetExceeded(format!(
                    "Analysis took too much time: {s}"
                ))
                .into()
            }
            ResourceLimitExceeded::MaxAllocationExceeded(s) => {
                StaticCheckErrorKind::AnalysisResourceBudgetExceeded(format!(
                    "Analysis used too much memory: {s}"
                ))
                .into()
            }
        })
}

/// Used by CLI tools like the docs generator. Not used in production
#[cfg(feature = "rusqlite")]
pub fn mem_type_check(
    snippet: &str,
    version: ClarityVersion,
    epoch: StacksEpochId,
) -> Result<(Option<TypeSignature>, ContractAnalysis), StaticCheckError> {
    let contract_identifier = QualifiedContractIdentifier::transient();
    let contract = build_ast(&contract_identifier, snippet, &mut (), version, epoch)
        .map_err(|e| {
            StaticCheckErrorKind::Unreachable(bounded_format!("Failed to build AST: {e}"))
        })?
        .expressions;

    let mut marf = MemoryBackingStore::new();
    let mut analysis_db = marf.as_analysis_db();
    let cost_tracker = LimitedCostTracker::new_free();
    match run_analysis(
        &QualifiedContractIdentifier::transient(),
        &contract,
        &mut analysis_db,
        false,
        cost_tracker,
        epoch,
        version,
        true,
        ResourceLimiter::unlimited(),
    ) {
        Ok(analysis) => Ok((analysis.type_of_final_expression()?, analysis)),
        Err(e) => Err(e.0),
    }
}

// Legacy function
// The analysis is not just checking type.
#[cfg(test)]
pub fn type_check(
    contract_identifier: &QualifiedContractIdentifier,
    expressions: &mut [SymbolicExpression],
    analysis_db: &mut AnalysisDatabase,
    insert_contract: bool,
    epoch: &StacksEpochId,
    version: &ClarityVersion,
) -> Result<ContractAnalysis, StaticCheckError> {
    run_analysis(
        contract_identifier,
        expressions,
        analysis_db,
        insert_contract,
        // for the type check tests, the cost tracker's epoch doesn't
        //  matter: the costs in those tests are all free anyways.
        LimitedCostTracker::new_free(),
        *epoch,
        *version,
        true,
        ResourceLimiter::unlimited(),
    )
    .map_err(|e| e.0)
}

/// Run the full static-analysis pipeline (read-only, type, and trait passes)
/// over a parsed contract, optionally persisting the result.
///
/// # Arguments
///
/// * `contract_identifier` - Identity of the contract being analyzed.
/// * `expressions` - The parsed top-level expressions (AST) to analyze.
/// * `analysis_db` - Database used to read referenced contracts and (optionally) write
///   the resulting analysis.
/// * `save_contract` - When `true`, the completed analysis is persisted to
///   `analysis_db`; when `false`, it is only returned to the caller.
/// * `cost_tracker` - Cost meter bounding the work performed by the analysis. It is
///   threaded through the passes and handed back to the caller (on both success and
///   failure) so the consumed budget is preserved.
/// * `epoch` - Stacks epoch, which selects the type-checker implementation
///   (2.05 vs 2.1+) and epoch-specific analysis rules.
/// * `version` - Clarity language version of the contract.
/// * `build_type_map` - When `true`, the type checker records a full expression →
///   type map on the resulting analysis (needed by tooling/tests); when `false`, the
///   map is skipped to save work.
/// * `resource_limiter` - Wall-clock deadline and heap allocation limit enforced across
///   the analysis passes. The budget may already have been exceeded from AST building
///   by the time it reaches here. Limits are used only on the non-consensus voting
///   paths (mining / block-proposal validation); it is unlimited on the deterministic
///   replay/commit path so consensus stays deterministic, meaning the limiter never
///   fires there.
///
/// # Returns
///
/// On success, the completed [`ContractAnalysis`]. On failure, a boxed pair of the
/// [`StaticCheckError`] and the [`LimitedCostTracker`] recovered from the analysis, so
/// the caller can continue accounting for the cost already consumed.
#[allow(clippy::too_many_arguments)]
pub fn run_analysis(
    contract_identifier: &QualifiedContractIdentifier,
    expressions: &[SymbolicExpression],
    analysis_db: &mut AnalysisDatabase,
    save_contract: bool,
    cost_tracker: LimitedCostTracker,
    epoch: StacksEpochId,
    version: ClarityVersion,
    build_type_map: bool,
    resource_limiter: ResourceLimiter,
) -> Result<ContractAnalysis, Box<(StaticCheckError, LimitedCostTracker)>> {
    let mut contract_analysis = ContractAnalysis::new(
        contract_identifier.clone(),
        expressions.to_vec(),
        cost_tracker,
        epoch,
        version,
    );
    let result = analysis_db.execute(|db| {
        let read_only_before_types = epoch.performs_read_only_checks_before_type_checks();
        let read_only_after_types = !read_only_before_types;

        if read_only_before_types {
            ReadOnlyChecker::run_pass(&epoch, &mut contract_analysis, db, resource_limiter)?;
        }
        if epoch >= StacksEpochId::Epoch21 {
            TypeChecker2_1::run_pass(
                &epoch,
                &mut contract_analysis,
                db,
                build_type_map,
                resource_limiter,
            )?;
        } else {
            TypeChecker2_05::run_pass(&epoch, &mut contract_analysis, db, build_type_map)?;
        }
        if read_only_after_types {
            ReadOnlyChecker::run_pass(&epoch, &mut contract_analysis, db, resource_limiter)?;
        }
        TraitChecker::run_pass(&epoch, &mut contract_analysis, db, resource_limiter)?;

        // Final boundary check on the analysis passes
        check_analysis_resource_limits(&resource_limiter)?;

        if STORE_CONTRACT_SRC_INTERFACE {
            let interface = build_contract_interface(&contract_analysis)?;
            contract_analysis.contract_interface = Some(interface);
        }
        if save_contract {
            db.insert_contract(contract_identifier, &contract_analysis)?;
        }
        Ok(())
    });
    match result {
        Ok(_) => Ok(contract_analysis),
        Err(e) => Err(Box::new((
            e,
            contract_analysis.take_contract_cost_tracker(),
        ))),
    }
}

#[cfg(test)]
mod tests;
