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

//! Consensus behavior shared by every engine in one transaction.
//!
//! A host maps its protocol epochs onto these cumulative rulesets. Engines
//! receive the ruleset directly, so neither the kernel nor a gate-free engine
//! needs to understand the host's epoch numbering.

use clarity_types::types::SerializationRules;
use stacks_common::types::StacksEpochId;

/// A cumulative, kernel-owned consensus ruleset identifier.
///
/// Variants are append-only. Existing variants must never change behavior
/// after publication because historical replay selects them directly.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KernelRuleset {
    /// Pre-value-sanitization behavior; `at-block` remains available.
    V1 = 1,
    /// Value sanitization is active; `at-block` remains available.
    V2 = 2,
    /// Value sanitization is active and `at-block` is unavailable.
    V3 = 3,
    /// V3 plus exact typed-tuple field enforcement during deserialization.
    V4 = 4,
}

impl KernelRuleset {
    pub const fn supports_at_block(self) -> bool {
        matches!(self, Self::V1 | Self::V2)
    }

    pub const fn serialization(self) -> SerializationRules {
        match self {
            Self::V1 => SerializationRules::PRE_SANITIZATION,
            Self::V2 | Self::V3 => SerializationRules::SANITIZED,
            Self::V4 => SerializationRules::STRICT_TYPED_TUPLES,
        }
    }

    /// The ruleset a Stacks protocol epoch selects.
    ///
    /// This is the single definition of that mapping. It lives here because
    /// every crate that needs it — the legacy engine's compatibility entry
    /// points, gate-free engines constructing a context from a bare epoch, the
    /// conformance harness — depends on this crate and on nothing else in
    /// common. `StacksEpochId` already appears throughout the kernel's public
    /// API, so naming it here costs no new coupling.
    ///
    /// The Stacks host keeps its own authoritative copy in its engine manifest,
    /// because protocol policy is the host's to decide and its exhaustive match
    /// forces a deliberate choice for each new epoch. That copy and this one
    /// must agree; `stackslib` has a test that asserts they do for every epoch.
    ///
    /// Kept exhaustive for the same reason: adding an epoch must not silently
    /// inherit a ruleset.
    pub const fn for_stacks_epoch(epoch: StacksEpochId) -> Self {
        match epoch {
            StacksEpochId::Epoch10
            | StacksEpochId::Epoch20
            | StacksEpochId::Epoch2_05
            | StacksEpochId::Epoch21
            | StacksEpochId::Epoch22
            | StacksEpochId::Epoch23 => Self::V1,
            StacksEpochId::Epoch24
            | StacksEpochId::Epoch25
            | StacksEpochId::Epoch30
            | StacksEpochId::Epoch31
            | StacksEpochId::Epoch32
            | StacksEpochId::Epoch33 => Self::V2,
            StacksEpochId::Epoch34 | StacksEpochId::Epoch40 => Self::V3,
            StacksEpochId::Epoch41 => Self::V4,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rulesets_are_cumulative_at_known_boundaries() {
        assert!(KernelRuleset::V1.supports_at_block());
        assert!(KernelRuleset::V2.supports_at_block());
        assert!(!KernelRuleset::V3.supports_at_block());
        assert!(!KernelRuleset::V4.supports_at_block());

        assert!(!KernelRuleset::V1.serialization().sanitizes_values());
        assert!(KernelRuleset::V2.serialization().sanitizes_values());
        assert!(KernelRuleset::V3.serialization().sanitizes_values());
        assert!(KernelRuleset::V4.serialization().sanitizes_values());
    }
}
