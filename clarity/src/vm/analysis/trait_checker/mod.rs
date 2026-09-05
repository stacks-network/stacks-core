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
use std::collections::BTreeSet;

use stacks_common::types::StacksEpochId;

use crate::vm::analysis::errors::{StaticCheckError, StaticCheckErrorKind};
use crate::vm::analysis::types::{AnalysisPass, ContractAnalysis};
use crate::vm::analysis::{AnalysisDatabase, check_analysis_resource_limits};
use crate::vm::resource_limiter::ResourceLimiter;
use crate::vm::{ClarityName, ClarityVersion, is_reserved, is_shadowable_reserved};

pub struct TraitChecker {
    epoch: StacksEpochId,
    resource_limiter: ResourceLimiter,
}

impl AnalysisPass for TraitChecker {
    fn run_pass(
        epoch: &StacksEpochId,
        contract_analysis: &mut ContractAnalysis,
        analysis_db: &mut AnalysisDatabase,
        resource_limiter: ResourceLimiter,
    ) -> Result<(), StaticCheckError> {
        let mut command = TraitChecker::new(epoch, resource_limiter);
        command.run(contract_analysis, analysis_db)?;
        Ok(())
    }
}

impl TraitChecker {
    fn new(epoch: &StacksEpochId, resource_limiter: ResourceLimiter) -> Self {
        Self {
            epoch: *epoch,
            resource_limiter,
        }
    }

    pub fn run(
        &mut self,
        contract_analysis: &ContractAnalysis,
        analysis_db: &mut AnalysisDatabase,
    ) -> Result<(), StaticCheckError> {
        let mut unmatched_shadowable = Self::shadowable_function_names(contract_analysis)?;

        for trait_identifier in &contract_analysis.implemented_traits {
            // per-trait analysis deadline check
            check_analysis_resource_limits(&self.resource_limiter)?;

            let trait_name = trait_identifier.name.to_string();
            let contract_defining_trait = analysis_db
                .load_contract(&trait_identifier.contract_identifier, &self.epoch)?
                .ok_or(StaticCheckErrorKind::TraitReferenceUnknown(
                    trait_identifier.name.to_string(),
                ))?;

            let trait_definition = contract_defining_trait
                .get_defined_trait(&trait_name)
                .ok_or(StaticCheckErrorKind::TraitReferenceUnknown(
                    trait_identifier.name.to_string(),
                ))?;

            contract_analysis.check_trait_compliance(
                &self.epoch,
                trait_identifier,
                trait_definition,
            )?;

            // A method still free at the defining contract's version unlocks
            // the same-named function. (Empty set below Clarity 7.)
            if !unmatched_shadowable.is_empty() {
                let trait_version = &contract_defining_trait.clarity_version;
                for method_name in trait_definition.keys() {
                    if !is_reserved(method_name, trait_version) {
                        unmatched_shadowable.remove(method_name);
                    }
                }
            }
        }

        if let Some(name) = unmatched_shadowable.first() {
            return Err(StaticCheckErrorKind::NameAlreadyUsed(name.to_string()).into());
        }
        Ok(())
    }

    /// Shadowable-named public/read-only functions (see
    /// [`is_shadowable_reserved`]) that [`Self::run`] must match to a legacy
    /// trait method. Private ones are rejected outright: trait methods are
    /// never private.
    fn shadowable_function_names(
        contract_analysis: &ContractAnalysis,
    ) -> Result<BTreeSet<ClarityName>, StaticCheckError> {
        let version = &contract_analysis.clarity_version;
        if *version < ClarityVersion::Clarity7 {
            return Ok(BTreeSet::new());
        }
        if let Some(name) = contract_analysis
            .private_function_types
            .keys()
            .find(|name| is_shadowable_reserved(name, version))
        {
            return Err(StaticCheckErrorKind::NameAlreadyUsed(name.to_string()).into());
        }
        Ok(contract_analysis
            .public_function_types
            .keys()
            .chain(contract_analysis.read_only_function_types.keys())
            .filter(|name| is_shadowable_reserved(name, version))
            .cloned()
            .collect())
    }
}

#[cfg(test)]
mod tests;
