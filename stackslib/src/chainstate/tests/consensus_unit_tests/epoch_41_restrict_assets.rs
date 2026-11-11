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

//! From Epoch 4.1, `restrict-assets?` fails at runtime on `with-all-assets-unsafe`.
//! Earlier epochs keep their outcomes.

use std::collections::HashMap;

use clarity::types::chainstate::StacksPrivateKey;
use clarity::types::StacksEpochId;
use clarity::vm::types::StacksAddressExtensions;
use clarity::vm::{ClarityVersion, Value};

use crate::chainstate::stacks::StacksTransaction;
use crate::chainstate::tests::consensus::{
    contract_call_consensus_unit_test, ConsensusMacroUnitReport, ConsensusTest, ConsensusUtils,
    ContractTxReport, TestBlock, SK_1,
};
use crate::core::test_util::to_addr;

/// For a 4.0 deploy, the body runs and divides by zero at 4.0; at 4.1 the call
/// fails before the body runs. Both failures are includable. A 4.1 deploy of
/// the same contract fails analysis.
#[test]
fn test_epoch41_restrict_assets_in_unchecked_argument() {
    let contract_code = "
        (define-private (ignore) true)
        (define-public (run)
          (begin
            (ignore (unwrap-panic
              (restrict-assets? tx-sender ((with-all-assets-unsafe)) (/ u1 u0))))
            (ok true)))";
    let report = contract_call_consensus_unit_test!(
        contract_name: "unchecked-allowance",
        contract_code: contract_code,
        function_name: "run",
        function_args: &[],
        deploy_epochs: &[StacksEpochId::Epoch40, StacksEpochId::Epoch41],
        call_epochs: &[StacksEpochId::Epoch40, StacksEpochId::Epoch41],
        clarity_versions: &[
            ClarityVersion::Clarity4,
            ClarityVersion::Clarity6,
            ClarityVersion::Clarity7,
        ],
    );
    assert!(report.all_blocks_accepted());

    // Clarity 4 and 6 at 4.0; 4.1 deploys always use Clarity 7.
    let deploys = report.contract_deploys();
    assert_eq!(deploys.len(), 3);
    for deploy in deploys {
        match deploy.contract_epoch() {
            StacksEpochId::Epoch40 => assert!(deploy.executed(), "{deploy:?}"),
            StacksEpochId::Epoch41 => assert!(
                deploy
                    .vm_error()
                    .unwrap()
                    .contains("expecting 0 arguments, got 1"),
                "{deploy:?}"
            ),
            other => panic!("unexpected deploy epoch {other}"),
        }
    }

    // The 4.1 deploy stored no contract, so only calls to the 4.0 deploys matter.
    let calls = report.contract_calls();
    let calls: Vec<_> = calls
        .iter()
        .filter(|call| *call.contract_epoch() == StacksEpochId::Epoch40)
        .collect();
    assert_eq!(calls.len(), 4);
    for call in calls {
        let expected_error = match call.block_epoch() {
            StacksEpochId::Epoch40 => "DivisionByZero",
            StacksEpochId::Epoch41 => "WithAllAllowanceNotAllowed",
            other => panic!("unexpected call epoch {other}"),
        };
        assert!(call.failed(), "{call:?}");
        assert_eq!(call.return_value(), &Value::error(Value::none()).unwrap());
        assert!(
            call.vm_error().unwrap().contains(expected_error),
            "{call:?}"
        );
    }
}

/// Before 4.1 the call commits and the transfer lands. From 4.1 the call fails:
/// it is included and pays its fee, and the transfer does not land.
#[test]
fn test_epoch41_restrict_assets_unchecked_argument_early_return() {
    const AMOUNT: u128 = 1_000_000;

    // The faucet signs every tx, so it is `tx-sender`. The boot plan does not
    // fund the recipient.
    let recipient = to_addr(&StacksPrivateKey::from_hex(SK_1).unwrap()).to_account_principal();
    let recipient = Value::Principal(recipient);

    // The report parses the deploy epoch and Clarity version from the suffix.
    let contract_name = "early-return-Epoch4_0-Clarity4";
    let contract_code = "
        (define-private (ignore) true)
        (define-public (transfer (amount uint) (recipient principal))
          (begin
            (ignore (begin
              (unwrap-panic (restrict-assets? tx-sender ((with-all-assets-unsafe))
                (stx-transfer? amount tx-sender recipient)))
              (asserts! false (ok true))))
            (ok false)))
        (define-public (balances (recipient principal))
          (ok {sender: (stx-get-balance tx-sender),
               recipient: (stx-get-balance recipient)}))";

    let call_tx = |nonce, function_name, args: &[Value]| {
        ConsensusUtils::new_call_tx_with_args(nonce, contract_name, function_name, args)
    };
    let block = |tx: &StacksTransaction| TestBlock {
        transactions: vec![tx.clone()],
    };
    let transfer_args = [Value::UInt(AMOUNT), recipient.clone()];
    let balances_args = [recipient];
    let transfer_41_tx = call_tx(3, "transfer", &transfer_args);
    let balances_41_tx = call_tx(4, "balances", &balances_args);
    let epoch_blocks = HashMap::from([
        (
            StacksEpochId::Epoch40,
            vec![
                TestBlock {
                    transactions: vec![ConsensusUtils::new_deploy_tx(
                        0,
                        contract_name,
                        contract_code,
                        Some(ClarityVersion::Clarity4),
                    )],
                },
                block(&call_tx(1, "transfer", &transfer_args)),
                block(&call_tx(2, "balances", &balances_args)),
            ],
        ),
        (
            StacksEpochId::Epoch41,
            vec![block(&transfer_41_tx), block(&balances_41_tx)],
        ),
    ]);
    let results = ConsensusTest::new(function_name!(), vec![], epoch_blocks).run();
    let report = ConsensusMacroUnitReport::new(results);
    assert!(report.all_blocks_accepted());

    let deploys = report.contract_deploys();
    assert_eq!(deploys.len(), 1);
    assert!(deploys[0].executed(), "{:?}", deploys[0]);

    let calls = report.contract_calls();
    let [transfer_40, balances_40, transfer_41, balances_41] = calls.as_slice() else {
        panic!("expected 4 contract calls");
    };
    let balance = |call: &ContractTxReport, field: &str| {
        call.return_value()
            .clone()
            .expect_result_ok()
            .unwrap()
            .expect_tuple()
            .unwrap()
            .get_owned(field)
            .unwrap()
            .expect_u128()
            .unwrap()
    };

    assert!(transfer_40.committed(), "{transfer_40:?}");
    assert_eq!(transfer_40.return_value(), &Value::okay_true());
    assert_eq!(balance(balances_40, "recipient"), AMOUNT);

    assert!(transfer_41.failed(), "{transfer_41:?}");
    assert!(
        transfer_41
            .vm_error()
            .unwrap()
            .contains("WithAllAllowanceNotAllowed"),
        "{transfer_41:?}",
    );
    assert_eq!(balance(balances_41, "recipient"), AMOUNT);
    // Fees are paid before the payload runs, so between the two reads the
    // sender pays the failed transfer's fee and the second read's.
    let fees = transfer_41_tx.get_tx_fee() + balances_41_tx.get_tx_fee();
    assert_eq!(
        balance(balances_40, "sender") - balance(balances_41, "sender"),
        u128::from(fees),
    );
}
