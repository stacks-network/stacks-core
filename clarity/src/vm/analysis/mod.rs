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
pub mod arithmetic_checker;
pub mod contract_interface_builder;
pub mod errors;
pub mod read_only_checker;
pub mod trait_checker;
pub mod type_checker;
pub mod types;

use stacks_common::types::StacksEpochId;

pub use self::analysis_db::AnalysisDatabase;
use self::arithmetic_checker::ArithmeticOnlyChecker;
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
use crate::vm::time_tracker::TimeTracker;
use crate::vm::types::QualifiedContractIdentifier;
#[cfg(feature = "rusqlite")]
use crate::vm::types::TypeSignature;

/// Cooperative analysis-deadline check shared by analysis passes
///
/// This is the single place the analysis-timeout error is constructed. The deadline is
/// `TimeTracker::MaxTime` only on the non-consensus voting paths (mining / block-proposal
/// validation); on the deterministic replay/commit path it is `TimeTracker::NoTracking`,
/// so this never fires during consensus and the surfaced `AnalysisTimeExpired` cannot
/// affect block validity.
pub(crate) fn check_analysis_timeout(time_tracker: &TimeTracker) -> Result<(), StaticCheckError> {
    if time_tracker.is_expired() {
        return Err(StaticCheckErrorKind::AnalysisTimeExpired.into());
    }
    Ok(())
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
        .map_err(|e| StaticCheckErrorKind::Unreachable(format!("Failed to build AST: {e}")))?
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
        TimeTracker::unlimited(),
    ) {
        Ok(x) => {
            // return the first type result of the type checker

            let first_type = x
                .type_map
                .as_ref()
                .ok_or_else(|| StaticCheckErrorKind::Unreachable("Should be non-empty".into()))?
                .get_type_expected(x.expressions.last().ok_or_else(|| {
                    StaticCheckErrorKind::Unreachable("Should be non-empty".into())
                })?)
                .cloned();
            Ok((first_type, x))
        }
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
        TimeTracker::unlimited(),
    )
    .map_err(|e| e.0)
}

/// Run the full static-analysis pipeline (read-only, type, trait and arithmetic
/// passes) over a parsed contract, optionally persisting the result.
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
/// * `time_tracker` - Wall-clock deadline enforced across the analysis passes. The
///   clock may already have elapsed time on it from AST building by the time it
///   reaches here. `TimeTracker::MaxTime` is used only on the non-consensus voting
///   paths (mining / block-proposal validation); `TimeTracker::NoTracking` is used on
///   the deterministic replay/commit path so consensus stays deterministic, meaning
///   the deadline never fires there.
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
    time_tracker: TimeTracker,
) -> Result<ContractAnalysis, Box<(StaticCheckError, LimitedCostTracker)>> {
    let mut contract_analysis = ContractAnalysis::new(
        contract_identifier.clone(),
        expressions.to_vec(),
        cost_tracker,
        epoch,
        version,
    );
    let result = analysis_db.execute(|db| {
        ReadOnlyChecker::run_pass(&epoch, &mut contract_analysis, db, time_tracker)?;
        match epoch {
            StacksEpochId::Epoch20 | StacksEpochId::Epoch2_05 => {
                TypeChecker2_05::run_pass(&epoch, &mut contract_analysis, db, build_type_map)
            }
            StacksEpochId::Epoch21
            | StacksEpochId::Epoch22
            | StacksEpochId::Epoch23
            | StacksEpochId::Epoch24
            | StacksEpochId::Epoch25
            | StacksEpochId::Epoch30
            | StacksEpochId::Epoch31
            | StacksEpochId::Epoch32
            | StacksEpochId::Epoch33
            | StacksEpochId::Epoch34 => TypeChecker2_1::run_pass(
                &epoch,
                &mut contract_analysis,
                db,
                build_type_map,
                time_tracker,
            ),
            StacksEpochId::Epoch10 => {
                return Err(StaticCheckErrorKind::Unreachable(
                    "Epoch 1.0 is not a valid epoch for analysis".into(),
                )
                .into());
            }
        }?;
        TraitChecker::run_pass(&epoch, &mut contract_analysis, db, time_tracker)?;
        ArithmeticOnlyChecker::check_contract_cost_eligible(&mut contract_analysis);

        // Final boundary check on the analysis passes
        check_analysis_timeout(&time_tracker)?;

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
