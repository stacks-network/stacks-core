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

use crate::vm::ClarityVersion;

/// `default_for_epoch` must be monotonically non-decreasing: later epochs
/// never downgrade the default ClarityVersion.
#[test]
fn test_default_for_epoch_is_monotonic() {
    // No Clarity in Epoch10.
    let clarity_epochs = &StacksEpochId::ALL[1..];
    for window in clarity_epochs.windows(2) {
        let earlier = ClarityVersion::default_for_epoch(window[0]);
        let later = ClarityVersion::default_for_epoch(window[1]);
        assert!(
            later >= earlier,
            "default_for_epoch not monotonic: \
             {} -> {:?}, {} -> {:?}",
            window[0],
            earlier,
            window[1],
            later
        );
    }
}

/// All Epoch34 feature-gate predicates must agree with each other for every
/// epoch. Uses `default_for_epoch` to bridge epoch-level and version-level
/// predicates.
#[test]
fn test_epoch34_feature_gates_are_consistent() {
    for &epoch in StacksEpochId::ALL {
        let is_34_plus = epoch >= StacksEpochId::Epoch34;
        let version = ClarityVersion::default_for_epoch(epoch);

        assert_eq!(
            is_34_plus,
            !version.uses_secp256r1_double_hashing(),
            "secp256r1 hashing inconsistent at epoch {epoch}"
        );
        assert_eq!(
            is_34_plus,
            version.protects_logn_cost_fn(),
            "logn cost protection inconsistent at epoch \
             {epoch}"
        );
        assert_eq!(
            is_34_plus,
            epoch.treats_unexpected_serialization_as_none(),
            "unexpected serialization handling inconsistent \
             at epoch {epoch}"
        );
        assert_eq!(
            is_34_plus,
            !epoch.rejects_parse_depth_errors(),
            "parse depth rejection inconsistent at epoch \
             {epoch}"
        );
        assert_eq!(
            is_34_plus,
            !epoch.rejects_supertype_too_large(),
            "supertype rejection inconsistent at epoch \
             {epoch}"
        );
    }
}
