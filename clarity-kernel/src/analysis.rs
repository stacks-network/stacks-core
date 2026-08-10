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

//! The stored contract-interface format: how a deployed contract's analyzed
//! interface (function types, trait definitions, ABI) is persisted in the
//! metadata store.
//!
//! This is the format through which engines see each other's contracts —
//! when engine A type-checks a `contract-call?` into a contract deployed by
//! engine B, it reads this record, never engine B's internal analysis
//! representation. Its serde output is consensus-adjacent stored data:
//! **field names, field order, and field types must never change.**
//!
//! Engines keep their own richer *working* analysis (the legacy engine's
//! `ContractAnalysis` carries its type map and cost tracker) and convert to
//! and from this stored form at the storage boundary.

use std::collections::{BTreeMap, BTreeSet};

use clarity_types::ClarityVersion;
use clarity_types::representations::ClarityName;
use clarity_types::types::{QualifiedContractIdentifier, TraitIdentifier, TypeSignature};
use stacks_common::types::StacksEpochId;

use crate::contract_interface::ContractInterface;
use crate::database::structures::deserialize_json;
use crate::database::{ClarityDatabase, ClarityDeserializable, ClaritySerializable};
use crate::errors::{RuntimeCheckErrorKind, VmExecutionError};
use crate::signatures::{FunctionSignature, FunctionType};

/// The metadata key under which the stored analysis is persisted.
pub const ANALYSIS_METADATA_KEY: &str = "analysis";

/// A deployed contract's stored interface record.
///
/// This struct is a serde-exact mirror of the serialized subset of the
/// legacy engine's `ContractAnalysis` — same fields, same order, same
/// types — so the stored JSON is byte-identical to what has always been
/// written. (Enforced by `stored_format_is_byte_identical` in the legacy
/// engine's tests.)
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct StoredContractAnalysis {
    pub contract_identifier: QualifiedContractIdentifier,
    pub private_function_types: BTreeMap<ClarityName, FunctionType>,
    pub variable_types: BTreeMap<ClarityName, TypeSignature>,
    pub public_function_types: BTreeMap<ClarityName, FunctionType>,
    pub read_only_function_types: BTreeMap<ClarityName, FunctionType>,
    pub map_types: BTreeMap<ClarityName, (TypeSignature, TypeSignature)>,
    pub persisted_variable_types: BTreeMap<ClarityName, TypeSignature>,
    pub fungible_tokens: BTreeSet<ClarityName>,
    pub non_fungible_tokens: BTreeMap<ClarityName, TypeSignature>,
    pub defined_traits: BTreeMap<ClarityName, BTreeMap<ClarityName, FunctionSignature>>,
    pub implemented_traits: BTreeSet<TraitIdentifier>,
    pub contract_interface: Option<ContractInterface>,
    pub is_cost_contract_eligible: bool,
    pub epoch: StacksEpochId,
    pub clarity_version: ClarityVersion,
}

impl ClaritySerializable for StoredContractAnalysis {
    fn serialize(&self) -> String {
        serde_json::to_string(self).expect("Failed to serialize stored contract analysis")
    }
}

impl ClarityDeserializable<StoredContractAnalysis> for StoredContractAnalysis {
    fn deserialize(json: &str) -> Result<Self, VmExecutionError> {
        deserialize_json(json)
    }
}

impl StoredContractAnalysis {
    /// Load a deployed contract's stored interface record, engine-agnostically.
    ///
    /// Returns `Ok(None)` if the contract does not exist or was deployed
    /// without a persisted analysis (e.g. by unit-test tooling).
    pub fn load(
        db: &mut ClarityDatabase,
        contract_identifier: &QualifiedContractIdentifier,
    ) -> Result<Option<StoredContractAnalysis>, VmExecutionError> {
        db.store
            .get_metadata(contract_identifier, ANALYSIS_METADATA_KEY)
            .or_else(|error| match error {
                // Absence is not an error here, but storage and corruption
                // failures must remain visible to callers.
                VmExecutionError::RuntimeCheck(RuntimeCheckErrorKind::NoSuchContract(_)) => {
                    Ok(None)
                }
                other => Err(other),
            })?
            .map(|x| StoredContractAnalysis::deserialize(&x))
            .transpose()
    }
}
