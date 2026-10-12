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

//! Epoch 4.1 analysis requires calls to user-defined functions, and to fixed-arity
//! natives that used to ignore extra arguments, to pass exactly the expected
//! number of arguments. Before, analysis never checked extra arguments to a user
//! function, and the runtime evaluates them before checking the count. Stored
//! contracts keep executing as deployed.

use clarity::types::StacksEpochId;
use clarity::vm::{ClarityVersion, Value};
use rstest::rstest;

use crate::chainstate::tests::consensus::{
    contract_call_consensus_unit_test, contract_deploy_consensus_unit_test,
};

/// `escape` passes `one` an extra argument that writes a data var and returns it
/// early, so the call never reaches the runtime count check.
const ESCAPE: &str = "
    (define-data-var touched bool false)
    (define-private (one (x uint)) x)
    (define-public (escape)
      (begin
        (one u1 (begin (var-set touched true) (asserts! false (ok (var-get touched)))))
        (ok false)))";

/// `missing` calls `one` with no argument, which analysis accepted and only the
/// runtime rejected.
const MISSING: &str = "
    (define-private (one (x uint)) x)
    (define-public (missing)
      (ok (one)))";

/// `map-set` takes three arguments; the fourth was accepted and ignored.
const MAP_SET: &str = "
    (define-map m uint uint)
    (define-public (set)
      (ok (map-set m u1 u2 u3)))";

const BOTH_SIDES: &[StacksEpochId] = &[StacksEpochId::Epoch40, StacksEpochId::Epoch41];
const VERSIONS: &[ClarityVersion] = &[ClarityVersion::Clarity2, ClarityVersion::Clarity7];

/// Deploys at 4.0 and fails analysis at 4.1 with `expected_error`.
#[rstest]
#[case::user_function_extra_argument("escape", ESCAPE, "expecting 1 arguments, got 2")]
#[case::user_function_missing_argument("missing", MISSING, "expecting 1 arguments, got 0")]
#[case::map_set_extra_argument("map-set-extra", MAP_SET, "expecting 3 arguments, got 4")]
fn test_epoch41_rejects_wrong_argument_count(
    #[case] contract_name: &str,
    #[case] contract_code: &str,
    #[case] expected_error: &str,
) {
    let report = contract_deploy_consensus_unit_test!(
        contract_name: contract_name,
        contract_code: contract_code,
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
                    deploy.vm_error().unwrap().contains(expected_error),
                    "{deploy:?}"
                );
            }
            other => panic!("unexpected deploy epoch {other}"),
        }
    }
}

/// `escape` stored at 4.0 commits the extra argument's write through the early
/// return on both sides of the boundary.
#[test]
fn test_epoch41_stored_extra_argument_executes_unchanged() {
    let report = contract_call_consensus_unit_test!(
        contract_name: "escape",
        contract_code: ESCAPE,
        function_name: "escape",
        function_args: &[],
        deploy_epochs: &[StacksEpochId::Epoch40],
        call_epochs: BOTH_SIDES,
        clarity_versions: VERSIONS,
    );
    assert!(report.all_blocks_accepted());
    let calls = report.contract_calls();
    // One deploy at 4.0, with the single version valid there, called at 4.0 and 4.1.
    assert_eq!(calls.len(), 2);
    for call in calls {
        assert!(call.committed(), "{call:?}");
        assert_eq!(
            call.return_value(),
            &Value::okay(Value::Bool(true)).unwrap(),
            "{call:?}"
        );
    }
}
