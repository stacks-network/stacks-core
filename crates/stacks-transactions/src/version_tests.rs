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

//! Unit tests for the epoch gate on versioned smart-contract deploys. The
//! block-pipeline tests that exercise it through the node stay in `stackslib`.

use clarity_types::ClarityVersion;
use stacks_common::types::StacksEpochId;

use crate::{UnsupportedVersionedDeploy, check_versioned_deploy_supported_in_epoch};

#[test]
fn test_check_versioned_deploy_supported_in_epoch() {
    use ClarityVersion::*;
    use StacksEpochId::*;

    let too_new = |requested, epoch_id, max| {
        Err(UnsupportedVersionedDeploy::VersionTooNew {
            requested,
            epoch_id,
            max,
        })
    };
    let not_accepted = |requested, epoch_default| {
        Err(UnsupportedVersionedDeploy::NotAccepted {
            requested,
            epoch_default,
        })
    };

    // (expected, pinned version, epoch)
    let tests = vec![
        // Before Epoch 2.1 static block validation rejects the payload; here
        // only an unknown version is reported.
        (Ok(()), Clarity1, Epoch2_05),
        (too_new(Clarity2, Epoch2_05, Clarity1), Clarity2, Epoch2_05),
        // Epochs 2.1 through 4.0 accept any version up to the epoch default.
        (too_new(Clarity5, Epoch33, Clarity4), Clarity5, Epoch33),
        (Ok(()), Clarity5, Epoch34),
        (Ok(()), Clarity1, Epoch40),
        (Ok(()), Clarity6, Epoch40),
        // From Epoch 4.1 no pin is accepted, not even the epoch default.
        (not_accepted(Clarity1, Clarity7), Clarity1, Epoch41),
        (not_accepted(Clarity6, Clarity7), Clarity6, Epoch41),
        (not_accepted(Clarity7, Clarity7), Clarity7, Epoch41),
    ];

    for (expected, version, epoch) in tests {
        assert_eq!(
            check_versioned_deploy_supported_in_epoch(version, epoch),
            expected,
            "test failed:\nscenario: version={version:?} epoch={epoch:?}"
        );
    }
}

/// `stackslib` tests and node logs match on these phrases.
#[test]
fn test_unsupported_versioned_deploy_display() {
    let too_new = check_versioned_deploy_supported_in_epoch(
        ClarityVersion::Clarity2,
        StacksEpochId::Epoch2_05,
    )
    .unwrap_err();
    assert_eq!(
        too_new.to_string(),
        "asks for Clarity 2, but current epoch 2.05 only supports up to Clarity 1"
    );

    let not_accepted =
        check_versioned_deploy_supported_in_epoch(ClarityVersion::Clarity6, StacksEpochId::Epoch41)
            .unwrap_err();
    assert_eq!(
        not_accepted.to_string(),
        "pins Clarity 6, but versioned smart-contract deploys are not accepted since Stacks 4.1; an unversioned deploy gets Clarity 7"
    );
}
