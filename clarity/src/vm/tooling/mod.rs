// Copyright (C) 2026 Stacks Open Internet Foundation
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
use stacks_common::types::StacksEpochId;

use super::ClarityVersion;
use super::analysis::ContractAnalysis;
use super::types::TypeSignature;
use crate::vm::analysis::{StaticCheckError, run_analysis};
use crate::vm::ast::build_ast;
use crate::vm::costs::LimitedCostTracker;
use crate::vm::database::MemoryBackingStore;
use crate::vm::types::QualifiedContractIdentifier;

/// Used by CLI tools like the docs generator. Not used in production
pub fn mem_type_check(
    snippet: &str,
    version: ClarityVersion,
    epoch: StacksEpochId,
) -> Result<(Option<TypeSignature>, ContractAnalysis), StaticCheckError> {
    let contract_identifier = QualifiedContractIdentifier::transient();
    let contract = build_ast(&contract_identifier, snippet, &mut (), version, epoch)
        .unwrap()
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
    ) {
        Ok(x) => {
            // return the first type result of the type checker
            let first_type = x
                .type_map
                .as_ref()
                .unwrap()
                .get_type_expected(x.expressions.last().unwrap())
                .cloned();
            Ok((first_type, x))
        }
        Err(e) => Err(e.0),
    }
}
