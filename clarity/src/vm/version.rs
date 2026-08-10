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

// `ClarityVersion` lives in `clarity-types` so that lower-level crates (e.g.
// `stacks-codec`) can name it without taking on the full `clarity` dependency.
// Existing callers that imported `clarity::vm::ClarityVersion` continue to work
// via this re-export.
pub use clarity_types::version::ClarityVersion;
use stacks_common::types::StacksEpochId;

/// Historical epoch-to-language mapping retained by the frozen legacy
/// interpreter's compatibility APIs. Production protocol policy lives in
/// stackslib's Clarity engine manifest.
///
/// Public so the host can assert its manifest agrees with this mapping for
/// every epoch; call the manifest, not this, from consensus code.
pub fn legacy_default_clarity_version_for_epoch(epoch: StacksEpochId) -> ClarityVersion {
    match epoch {
        StacksEpochId::Epoch10 => {
            warn!(
                "Attempted to get default Clarity version for Epoch 1.0 where Clarity does not exist"
            );
            ClarityVersion::Clarity1
        }
        StacksEpochId::Epoch20 | StacksEpochId::Epoch2_05 => ClarityVersion::Clarity1,
        StacksEpochId::Epoch21
        | StacksEpochId::Epoch22
        | StacksEpochId::Epoch23
        | StacksEpochId::Epoch24
        | StacksEpochId::Epoch25 => ClarityVersion::Clarity2,
        StacksEpochId::Epoch30 | StacksEpochId::Epoch31 | StacksEpochId::Epoch32 => {
            ClarityVersion::Clarity3
        }
        StacksEpochId::Epoch33 => ClarityVersion::Clarity4,
        StacksEpochId::Epoch34 => ClarityVersion::Clarity5,
        StacksEpochId::Epoch40 | StacksEpochId::Epoch41 => ClarityVersion::Clarity6,
    }
}
