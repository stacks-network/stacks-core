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

//! Host-owned selection of Clarity engine revisions.
//!
//! A contract stores its [`ClarityVersion`], not the concrete engine build
//! that executes it. For each block, the current protocol epoch selects a
//! manifest, and that manifest maps every supported language version to an
//! engine revision:
//!
//! ```text
//! (current epoch, contract Clarity version) -> engine revision
//! ```
//!
//! Selecting by the current epoch is consensus-critical. An old contract can
//! acquire epoch-gated behavior changes when called later (`at-block` is the
//! historical example), while replay of its earlier calls must retain the old
//! behavior. Engine revisions are reused across epochs that do not change
//! their semantics; this is not one engine crate per epoch/version cell. The
//! transitional legacy engine remains one revision because it intentionally
//! carries all historical epoch gates internally. Gate-free engines use new
//! linked revisions when an epoch changes their existing contracts.

use std::fmt;

use clarity::vm::engine::{Engine, LegacyEngine};
use clarity::vm::ClarityVersion;
use stacks_common::types::StacksEpochId;

static LEGACY_V1: LegacyEngine = LegacyEngine;

/// A concrete, linkable consensus revision of a Clarity engine.
///
/// Future variants will distinguish side-by-side major releases such as
/// `Clarity7V1` and `Clarity7V2`. Multiple epochs may select the same variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineRevision {
    LegacyV1,
}

/// One engine selected from the manifest for an interaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectedEngine {
    revision: EngineRevision,
}

impl SelectedEngine {
    pub fn revision(self) -> EngineRevision {
        self.revision
    }

    pub fn engine(self) -> &'static dyn Engine {
        match self.revision {
            EngineRevision::LegacyV1 => &LEGACY_V1,
        }
    }
}

/// The engine set active in one Stacks protocol epoch.
#[derive(Debug, Clone, Copy)]
pub struct ClarityEngineManifest {
    epoch: StacksEpochId,
}

impl ClarityEngineManifest {
    pub fn for_epoch(epoch: StacksEpochId) -> Self {
        Self { epoch }
    }

    pub fn epoch(self) -> StacksEpochId {
        self.epoch
    }

    /// The newest contract language version deployable in this epoch.
    pub fn default_version(self) -> Option<ClarityVersion> {
        if self.epoch == StacksEpochId::Epoch10 {
            None
        } else {
            Some(ClarityVersion::default_for_epoch(self.epoch))
        }
    }

    /// Select the engine revision for a contract language version at this
    /// manifest's current execution epoch.
    pub fn select(self, version: ClarityVersion) -> Result<SelectedEngine, EngineSelectionError> {
        let Some(maximum) = self.default_version() else {
            return Err(EngineSelectionError::ClarityUnavailable { epoch: self.epoch });
        };
        if version > maximum {
            return Err(EngineSelectionError::UnsupportedVersion {
                epoch: self.epoch,
                requested: version,
                maximum,
            });
        }

        Ok(SelectedEngine {
            revision: EngineRevision::LegacyV1,
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub enum EngineSelectionError {
    ClarityUnavailable {
        epoch: StacksEpochId,
    },
    UnsupportedVersion {
        epoch: StacksEpochId,
        requested: ClarityVersion,
        maximum: ClarityVersion,
    },
}

impl fmt::Display for EngineSelectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClarityUnavailable { epoch } => {
                write!(f, "Clarity is unavailable in epoch {epoch}")
            }
            Self::UnsupportedVersion {
                epoch,
                requested,
                maximum,
            } => write!(
                f,
                "{requested} is unavailable in epoch {epoch}; maximum is {maximum}"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_selects_every_historically_available_version() {
        for &epoch in StacksEpochId::ALL {
            let manifest = ClarityEngineManifest::for_epoch(epoch);
            let Some(maximum) = manifest.default_version() else {
                assert_eq!(epoch, StacksEpochId::Epoch10);
                for &version in ClarityVersion::ALL {
                    assert!(manifest.select(version).is_err());
                }
                continue;
            };

            for &version in ClarityVersion::ALL {
                let selected = manifest.select(version);
                if version <= maximum {
                    let selected = selected.unwrap();
                    assert_eq!(selected.revision(), EngineRevision::LegacyV1);
                    assert!(selected.engine().supported_versions().contains(&version));
                } else {
                    assert!(selected.is_err());
                }
            }
        }
    }

    #[test]
    fn legacy_revision_carries_historical_epoch_gates() {
        let epoch_40 = ClarityEngineManifest::for_epoch(StacksEpochId::Epoch40)
            .select(ClarityVersion::Clarity6)
            .unwrap();
        let epoch_41 = ClarityEngineManifest::for_epoch(StacksEpochId::Epoch41)
            .select(ClarityVersion::Clarity6)
            .unwrap();

        assert_eq!(epoch_40.revision(), epoch_41.revision());
    }
}
