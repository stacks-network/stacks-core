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

use clarity::types::StacksEpochId;
use clarity::vm::{ClarityVersion, Value};

use crate::chainstate::tests::consensus::{
    contract_call_consensus_unit_test, contract_deploy_consensus_unit_test,
};

#[test]
fn test_example_1_cdeploy() {
    let report = contract_deploy_consensus_unit_test!(
        contract_name: "map_empty",
        contract_code: "(map + (list) (list 10 20))",
        deploy_epochs: StacksEpochId::since(StacksEpochId::Epoch20),
        clarity_versions: ClarityVersion::ALL,
    );

    assert!(report.all_blocks_accepted());

    let txs = report.contract_deploys();

    for each in txs {
        let expected = Value::error(Value::none()).unwrap();
        assert_eq!(&expected, each.return_value(), "wrong return for {each:?}");

        assert_eq!(
            ":0:0: expecting expression of type 'int' or 'uint', found 'UnknownType'",
            each.vm_error().unwrap(),
            "wrong error for {each:?}"
        );
    }
}

#[test]
fn test_example_2_ccall() {
    let report = contract_call_consensus_unit_test!(
        contract_name: "map_empty",
        contract_code: "
            (define-data-var xs (list 10 int) (list))
            (define-data-var ys (list 10 int) (list 10 20))
            (define-public (trigger)
                (ok (map + (var-get xs) (var-get ys))))
        ",
        function_name: "trigger",
        function_args: &[],
        deploy_epochs: StacksEpochId::since(StacksEpochId::Epoch20),
        clarity_versions: ClarityVersion::ALL,
    );

    assert!(report.all_blocks_accepted());

    let txs = report.contract_calls();

    for each in txs {
        let expected = if each.block_epoch() <= &StacksEpochId::Epoch34 {
            Value::okay(Value::list_from(vec![Value::Int(10)]).unwrap()).unwrap()
        } else {
            Value::okay(Value::list_from(vec![]).unwrap()).unwrap()
        };

        assert_eq!(&expected, each.return_value(), "wrong return for {each:?}");
    }
}
