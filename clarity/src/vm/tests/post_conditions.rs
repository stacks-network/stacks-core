// Copyright (C) 2025 Stacks Open Internet Foundation
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

use clarity_types::errors::InterpreterResult;
use clarity_types::types::{PrincipalData, QualifiedContractIdentifier, StandardPrincipalData};
use clarity_types::Value;
use stacks_common::types::StacksEpochId;

use crate::vm::database::STXBalance;
use crate::vm::{execute_with_parameters_and_call_in_global_context, ClarityVersion};

fn execute(snippet: &str) -> InterpreterResult<Option<Value>> {
    execute_with_parameters_and_call_in_global_context(
        snippet,
        ClarityVersion::Clarity4,
        StacksEpochId::Epoch33,
        false,
        |g| {
            // Setup initial balances for the sender and the contract
            let sender_principal = PrincipalData::Standard(StandardPrincipalData::transient());
            let contract_id = QualifiedContractIdentifier::transient();
            let contract_principal = PrincipalData::Contract(contract_id);
            let balance = STXBalance::initial(1000);
            let mut snapshot = g
                .database
                .get_stx_balance_snapshot_genesis(&sender_principal)
                .unwrap();
            snapshot.set_balance(balance.clone());
            snapshot.save().unwrap();
            let mut snapshot = g
                .database
                .get_stx_balance_snapshot_genesis(&contract_principal)
                .unwrap();
            snapshot.set_balance(balance);
            snapshot.save().unwrap();
            g.database.increment_ustx_liquid_supply(2000).unwrap();
            Ok(())
        },
    )
}

// ---------- Tests for as-contract? ----------

#[test]
fn test_as_contract_with_stx_ok() {
    let snippet = r#"
(let ((recipient tx-sender))
  (as-contract? ((with-stx u100))
    (try! (stx-transfer? u50 tx-sender recipient))
  )
)"#;
    let expected = Value::okay_true();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_as_contract_with_stx_exceeds() {
    let snippet = r#"
(let ((recipient tx-sender))
  (as-contract? ((with-stx u10))
    (try! (stx-transfer? u50 tx-sender recipient))
  )
)"#;
    let expected = Value::error(Value::Int(0)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_as_contract_with_stx_no_allowance() {
    let snippet = r#"
(let ((recipient tx-sender))
  (as-contract? ()
    (try! (stx-transfer? u50 tx-sender recipient))
  )
)"#;
    let expected = Value::error(Value::Int(-1)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_as_contract_stx_all() {
    let snippet = r#"
(let ((recipient tx-sender))
  (as-contract? ((with-all-assets-unsafe))
    (try! (stx-transfer? u50 tx-sender recipient))
  )
)"#;
    let expected = Value::okay_true();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_as_contract_stx_other_allowances() {
    let snippet = r#"
(let ((recipient tx-sender))
  (as-contract? ((with-ft .token "stackaroo" u100) (with-nft .token "stackaroo" 123))
    (try! (stx-transfer? u50 tx-sender recipient))
  )
)"#;
    let expected = Value::error(Value::Int(-1)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_as_contract_with_stx_burn_ok() {
    let snippet = r#"
(as-contract? ((with-stx u100))
  (try! (stx-burn? u50 tx-sender))
)"#;
    let expected = Value::okay_true();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_as_contract_with_stx_burn_exceeds() {
    let snippet = r#"
(as-contract? ((with-stx u10))
  (try! (stx-burn? u50 tx-sender))
)"#;
    let expected = Value::error(Value::Int(0)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_as_contract_with_stx_burn_no_allowance() {
    let snippet = r#"
(as-contract? ()
  (try! (stx-burn? u50 tx-sender))
)"#;
    let expected = Value::error(Value::Int(-1)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_as_contract_stx_burn_all() {
    let snippet = r#"
(as-contract? ((with-all-assets-unsafe))
  (try! (stx-burn? u50 tx-sender))
)"#;
    let expected = Value::okay_true();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_as_contract_stx_burn_other_allowances() {
    let snippet = r#"
(as-contract? ((with-ft .token "stackaroo" u100) (with-nft .token "stackaroo" 123))
  (try! (stx-burn? u50 tx-sender))
)"#;
    let expected = Value::error(Value::Int(-1)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_as_contract_multiple_allowances_both_low() {
    let snippet = r#"
(let ((recipient tx-sender))
  (as-contract? ((with-stx u30) (with-stx u20))
    (try! (stx-transfer? u40 tx-sender recipient))
  )
)"#;
    let expected = Value::error(Value::Int(0)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_as_contract_multiple_allowances_both_ok() {
    let snippet = r#"
(let ((recipient tx-sender))
  (as-contract? ((with-stx u300) (with-stx u200))
    (try! (stx-transfer? u40 tx-sender recipient))
  )
)"#;
    let expected = Value::okay_true();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_as_contract_multiple_allowances_one_low() {
    let snippet = r#"
(let ((recipient tx-sender))
  (as-contract? ((with-stx u100) (with-stx u20))
    (try! (stx-transfer? u40 tx-sender recipient))
  )
)"#;
    let expected = Value::error(Value::Int(1)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

// #[test]
// fn test_as_contract_with_stacking_delegate_ok() {
//     let snippet = r#"
// (as-contract? ((with-stacking u2000))
//   (try! (contract-call? 'SP000000000000000000002Q6VF78.pox-4 delegate-stx
//     u1000 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM none none
//   ))
// )"#;
//     let expected = Value::okay_true();
//     assert_eq!(expected, execute(snippet).unwrap().unwrap());
// }

// #[test]
// fn test_as_contract_with_stacking_stack_ok() {
//     let snippet = r#"
// (as-contract? ((with-stacking u100))
//   (try! (contract-call? 'SP000000000000000000002Q6VF78.pox-4 stack-stx
//     u1100000000000 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM none none
//   ))
// )"#;
//     let expected = Value::okay_true();
//     assert_eq!(expected, execute(snippet).unwrap().unwrap());
// }

// #[test]
// fn test_as_contract_with_stacking_exceeds() {
//     let snippet = r#"
// (as-contract? ((with-stacking u10))
//   (try! (contract-call? 'SP000000000000000000002Q6VF78.pox-4 delegate-stx
//     u1000 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM none none
//   ))
// )"#;
//     let expected = Value::error(Value::Int(0)).unwrap();
//     assert_eq!(expected, execute(snippet).unwrap().unwrap());
// }

// ---------- Tests for restrict-assets? ----------

#[test]
fn test_restrict_assets_with_stx_ok() {
    let snippet = r#"
(restrict-assets? tx-sender ((with-stx u100))
  (try! (stx-transfer? u50 tx-sender 'SP000000000000000000002Q6VF78))
)"#;
    let expected = Value::okay_true();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_with_stx_exceeds() {
    let snippet = r#"
(restrict-assets? tx-sender ((with-stx u10))
  (try! (stx-transfer? u50 tx-sender 'SP000000000000000000002Q6VF78))
)"#;
    let expected = Value::error(Value::Int(0)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_with_stx_no_allowance() {
    let snippet = r#"
(restrict-assets? tx-sender ()
  (try! (stx-transfer? u50 tx-sender 'SP000000000000000000002Q6VF78))
)"#;
    let expected = Value::error(Value::Int(-1)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_stx_all() {
    let snippet = r#"
(restrict-assets? tx-sender ((with-all-assets-unsafe))
  (try! (stx-transfer? u50 tx-sender 'SP000000000000000000002Q6VF78))
)"#;
    let expected = Value::okay_true();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_stx_other_allowances() {
    let snippet = r#"
(restrict-assets? tx-sender ((with-ft .token "stackaroo" u100) (with-nft .token "stackaroo" 123))
  (try! (stx-transfer? u50 tx-sender 'SP000000000000000000002Q6VF78))
)"#;
    let expected = Value::error(Value::Int(-1)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_with_stx_burn_ok() {
    let snippet = r#"
(restrict-assets? tx-sender ((with-stx u100))
  (try! (stx-burn? u50 tx-sender))
)"#;
    let expected = Value::okay_true();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_with_stx_burn_exceeds() {
    let snippet = r#"
(restrict-assets? tx-sender ((with-stx u10))
  (try! (stx-burn? u50 tx-sender))
)"#;
    let expected = Value::error(Value::Int(0)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_with_stx_burn_no_allowance() {
    let snippet = r#"
(restrict-assets? tx-sender ()
  (try! (stx-burn? u50 tx-sender))
)"#;
    let expected = Value::error(Value::Int(-1)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_stx_burn_all() {
    let snippet = r#"
(restrict-assets? tx-sender ((with-all-assets-unsafe))
  (try! (stx-burn? u50 tx-sender))
)"#;
    let expected = Value::okay_true();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_stx_burn_other_allowances() {
    let snippet = r#"
(restrict-assets? tx-sender ((with-ft .token "stackaroo" u100) (with-nft .token "stackaroo" 123))
  (try! (stx-burn? u50 tx-sender))
)"#;
    let expected = Value::error(Value::Int(-1)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_multiple_allowances_both_low() {
    let snippet = r#"
(restrict-assets? tx-sender ((with-stx u30) (with-stx u20))
  (try! (stx-transfer? u40 tx-sender 'SP000000000000000000002Q6VF78))
)"#;
    let expected = Value::error(Value::Int(0)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_multiple_allowances_both_ok() {
    let snippet = r#"
(restrict-assets? tx-sender ((with-stx u300) (with-stx u200))
  (try! (stx-transfer? u40 tx-sender 'SP000000000000000000002Q6VF78))
)"#;
    let expected = Value::okay_true();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

#[test]
fn test_restrict_assets_multiple_allowances_one_low() {
    let snippet = r#"
(restrict-assets? tx-sender ((with-stx u100) (with-stx u20))
  (try! (stx-transfer? u40 tx-sender 'SP000000000000000000002Q6VF78))
)"#;
    let expected = Value::error(Value::Int(1)).unwrap();
    assert_eq!(expected, execute(snippet).unwrap().unwrap());
}

// #[test]
// fn test_restrict_assets_with_stacking_delegate_ok() {
//     let snippet = r#"
// (restrict-assets? tx-sender ((with-stacking u2000))
//   (try! (contract-call? 'SP000000000000000000002Q6VF78.pox-4 delegate-stx
//     u1000 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM none none
//   ))
// )"#;
//     let expected = Value::okay_true();
//     assert_eq!(expected, execute(snippet).unwrap().unwrap());
// }

// #[test]
// fn test_restrict_assets_with_stacking_stack_ok() {
//     let snippet = r#"
// (restrict-assets? tx-sender ((with-stacking u100))
//   (try! (contract-call? 'SP000000000000000000002Q6VF78.pox-4 stack-stx
//     u1100000000000 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM none none
//   ))
// )"#;
//     let expected = Value::okay_true();
//     assert_eq!(expected, execute(snippet).unwrap().unwrap());
// }

// #[test]
// fn test_restrict_assets_with_stacking_exceeds() {
//     let snippet = r#"
// (restrict-assets? tx-sender ((with-stacking u10))
//   (try! (contract-call? 'SP000000000000000000002Q6VF78.pox-4 delegate-stx
//     u1000 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM none none
//   ))
// )"#;
//     let expected = Value::error(Value::Int(0)).unwrap();
//     assert_eq!(expected, execute(snippet).unwrap().unwrap());
// }
