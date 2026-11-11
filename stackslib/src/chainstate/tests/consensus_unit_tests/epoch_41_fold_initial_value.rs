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

//! Epoch 4.1 types a `fold` result to admit its initial value, which an empty
//! sequence returns unchanged. Before, the result took the callback's return
//! type alone, so a value of another type could leave `fold` under a wrong
//! static type. Stored contracts keep executing as deployed.

use clarity::types::StacksEpochId;
use clarity::vm::{ClarityVersion, Value};

use crate::chainstate::tests::consensus::{
    contract_call_consensus_unit_test, contract_deploy_consensus_unit_test,
};

/// `fetch` is typed `(response uint ...)` before 4.1, but the empty `fold`
/// returns its initial value, so it returns a string.
const FOLD_PROVIDER: &str = "
    (define-private (keep-none (x (buff 1)) (acc (optional (string-ascii 5)))) none)
    (define-public (fetch)
      (ok (default-to u1 (fold keep-none 0x (some \"hello\")))))";

const BOTH_SIDES: &[StacksEpochId] = &[StacksEpochId::Epoch40, StacksEpochId::Epoch41];
const VERSIONS: &[ClarityVersion] = &[ClarityVersion::Clarity2, ClarityVersion::Clarity7];

/// The provider deploys at 4.0 and fails analysis at 4.1, where `default-to`
/// sees the widened `fold` type.
#[test]
fn test_epoch41_rejects_fold_result_narrower_than_initial_value() {
    let report = contract_deploy_consensus_unit_test!(
        contract_name: "fold-provider",
        contract_code: FOLD_PROVIDER,
        deploy_epochs: BOTH_SIDES,
        clarity_versions: VERSIONS,
    );
    assert!(report.all_blocks_accepted());
    let deploys = report.contract_deploys();
    assert_eq!(deploys.len(), 2);
    for deploy in deploys {
        match deploy.contract_epoch() {
            StacksEpochId::Epoch40 => assert!(deploy.executed(), "{deploy:?}"),
            StacksEpochId::Epoch41 => {
                assert_eq!(deploy.return_value(), &Value::error(Value::none()).unwrap());
                assert!(
                    deploy
                        .vm_error()
                        .unwrap()
                        .contains("expression types passed in 'default-to' must match"),
                    "{deploy:?}"
                );
            }
            other => panic!("unexpected deploy epoch {other}"),
        }
    }
}

/// A provider stored at 4.0 returns the same string, under its `uint` type, on
/// both sides of the boundary.
#[test]
fn test_epoch41_stored_fold_executes_unchanged() {
    let report = contract_call_consensus_unit_test!(
        contract_name: "fold-provider",
        contract_code: FOLD_PROVIDER,
        function_name: "fetch",
        function_args: &[],
        deploy_epochs: &[StacksEpochId::Epoch40],
        call_epochs: BOTH_SIDES,
        clarity_versions: VERSIONS,
    );
    assert!(report.all_blocks_accepted());
    for deploy in report.contract_deploys() {
        assert!(deploy.executed(), "{deploy:?}");
    }
    let calls = report.contract_calls();
    // One deploy at 4.0, with the single version valid there, called at 4.0 and 4.1.
    assert_eq!(calls.len(), 2);
    for call in calls {
        assert!(call.executed(), "{call:?}");
        assert_eq!(
            call.return_value().to_string(),
            "(ok \"hello\")",
            "{call:?}"
        );
    }
}
