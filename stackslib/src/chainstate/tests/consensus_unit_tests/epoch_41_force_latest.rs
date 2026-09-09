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

//! Consensus unit tests for the Epoch 4.1 rule that new contracts must use the
//! epoch's default (latest) Clarity version.

use std::collections::HashMap;

use clarity::types::StacksEpochId;
use clarity::vm::ClarityVersion;

use crate::chainstate::tests::consensus::{
    ConsensusTest, ConsensusUtils, ExpectedResult, TestBlock,
};

/// Full-pipeline enforcement: a deploy pinning Clarity 6 at Epoch 4.1 makes
/// the whole block invalid at `process_transaction_precheck`.
#[test]
fn test_epoch41_rejects_older_version_deploy_block() {
    let mut epoch_blocks = HashMap::new();
    epoch_blocks.insert(
        StacksEpochId::Epoch41,
        vec![TestBlock {
            transactions: vec![ConsensusUtils::new_deploy_tx(
                0,
                "c6-pinned",
                "(define-public (ping) (ok true))",
                Some(ClarityVersion::Clarity6),
            )],
        }],
    );
    let results = ConsensusTest::new(function_name!(), vec![], epoch_blocks).run();

    assert_eq!(results.len(), 1);
    match &results[0] {
        ExpectedResult::Failure(failure) => {
            assert_eq!(StacksEpochId::Epoch41, failure.evaluated_epoch);
            assert!(
                failure.error.contains("requires contracts to use"),
                "unexpected error: {}",
                failure.error
            );
        }
        r => panic!("expected block rejection, got {r:?}"),
    }
}
