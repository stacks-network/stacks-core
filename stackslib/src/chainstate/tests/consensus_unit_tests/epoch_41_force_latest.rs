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

//! Consensus unit tests for the Epoch 4.1 rule that smart-contract deploys
//! cannot pin a Clarity version: new contracts always use the epoch default,
//! while contracts deployed earlier keep their pinned version.

use std::collections::HashMap;

use clarity::types::StacksEpochId;
use clarity::vm::ClarityVersion;

use crate::chainstate::tests::consensus::{
    ConsensusTest, ConsensusUtils, ExpectedBlockOutput, ExpectedResult, TestBlock,
};

const CODE: &str = "(define-public (ping) (ok true))";

fn deploy_block(nonce: u64, name: &str, version: Option<ClarityVersion>) -> TestBlock {
    TestBlock {
        transactions: vec![ConsensusUtils::new_deploy_tx(nonce, name, CODE, version)],
    }
}

fn expect_accepted(result: &ExpectedResult, epoch: StacksEpochId) -> &ExpectedBlockOutput {
    let ExpectedResult::Success(output) = result else {
        panic!("expected block acceptance, got {result:?}");
    };
    assert_eq!(epoch, output.evaluated_epoch);
    assert!(
        output.transactions[0].vm_error.is_none(),
        "unexpected vm error: {:?}",
        output.transactions[0].vm_error
    );
    output
}

fn expect_rejected_at_static_checks(result: &ExpectedResult) {
    let ExpectedResult::Failure(failure) = result else {
        panic!("expected block rejection, got {result:?}");
    };
    assert_eq!(StacksEpochId::Epoch41, failure.evaluated_epoch);
    assert!(
        failure.error.contains("failed static checks"),
        "unexpected error: {}",
        failure.error
    );
}

/// Full-pipeline enforcement. At Epoch 4.1 a versioned deploy makes the whole
/// block fail static validation, so it is rejected before staging; pinning the
/// epoch default is rejected like any other version. An unversioned deploy and
/// a call into a contract pinned before 4.1 still succeed, which also proves
/// the harness builds valid 4.1 blocks rather than failing them all.
#[test]
fn test_epoch41_rejects_versioned_deploy_blocks() {
    let mut epoch_blocks = HashMap::new();
    // Pinned before 4.1: accepted, and keeps working after the boundary.
    epoch_blocks.insert(
        StacksEpochId::Epoch40,
        vec![deploy_block(0, "pinned-c6", Some(ClarityVersion::Clarity6))],
    );
    // Rejected blocks leave the faucet nonce untouched.
    epoch_blocks.insert(
        StacksEpochId::Epoch41,
        vec![
            deploy_block(1, "pinned", Some(ClarityVersion::Clarity6)),
            deploy_block(1, "pinned", Some(ClarityVersion::Clarity7)),
            deploy_block(1, "unpinned", None),
            TestBlock {
                transactions: vec![ConsensusUtils::new_call_tx(2, "pinned-c6", "ping")],
            },
        ],
    );
    let results = ConsensusTest::new(function_name!(), vec![], epoch_blocks).run();

    let [c6_deploy, pinned_c6, pinned_c7, unpinned, call] = results.as_slice() else {
        panic!("expected 5 block results, got {results:?}");
    };
    expect_accepted(c6_deploy, StacksEpochId::Epoch40);
    expect_rejected_at_static_checks(pinned_c6);
    expect_rejected_at_static_checks(pinned_c7);
    expect_accepted(unpinned, StacksEpochId::Epoch41);
    let call = expect_accepted(call, StacksEpochId::Epoch41);
    assert_eq!("(ok true)", call.transactions[0].return_type.to_string());
}
