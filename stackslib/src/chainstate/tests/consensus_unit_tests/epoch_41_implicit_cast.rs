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

//! A stored contract can pass a filtered list whose cached bound, times its
//! parameter's item size, overflows even though the list fits.

use clarity::types::StacksEpochId;
use clarity::vm::{ClarityVersion, Value};

use crate::chainstate::tests::consensus::contract_call_consensus_unit_test;

const CALL_EPOCHS: &[StacksEpochId] = &[StacksEpochId::Epoch40, StacksEpochId::Epoch41];

// The empty fold hides the filtered list's two-element type from pre-4.1 analysis.
const FILTERED_LIST_CALL: &str = "
    (define-private (is-one (x {n: (buff 1)})) (is-eq (get n x) 0x01))
    (define-private (keep-none
        (x (buff 1)) (acc (optional (list 2 {n: (buff 1)})))) none)
    (define-private (callee (xs (list 1 {n: (buff 600000)}))) u1)
    (define-public (trigger)
        (ok (callee (default-to (list {n: 0x})
            (fold keep-none 0x
                (some (filter is-one (list {n: 0x01} {n: 0x02}))))))))
";

/// The one remaining element fits the parameter even though filter keeps a bound of two.
#[test]
fn test_epoch41_stored_contract_accepts_filtered_list() {
    let report = contract_call_consensus_unit_test!(
        contract_name: "implicit-size",
        contract_code: FILTERED_LIST_CALL,
        function_name: "trigger",
        function_args: &[],
        deploy_epochs: &[StacksEpochId::Epoch34],
        call_epochs: CALL_EPOCHS,
        clarity_versions: &[ClarityVersion::Clarity2],
    );
    assert!(report.all_blocks_accepted());
    for deploy in report.contract_deploys() {
        assert!(deploy.executed(), "{deploy:?}: {:?}", deploy.vm_error());
    }
    let calls = report.contract_calls();
    assert_eq!(calls.len(), CALL_EPOCHS.len());
    for call in calls {
        match call.block_epoch() {
            StacksEpochId::Epoch40 => {
                assert!(call.failed(), "{call:?}");
                assert_eq!(call.vm_error(), Some("ValueTooLarge"));
            }
            StacksEpochId::Epoch41 => {
                assert!(call.committed(), "{call:?}: {:?}", call.vm_error());
                assert_eq!(call.return_value(), &Value::okay(Value::UInt(1)).unwrap());
            }
            epoch => panic!("unexpected call epoch: {epoch:?}"),
        }
    }
}
