// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
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

use crate::vm::contexts::OwnedEnvironment;
use crate::vm::costs::ExecutionCost;
use crate::vm::events::*;
use crate::vm::tests::execute;
use crate::vm::types::{AssetIdentifier, BuffData, QualifiedContractIdentifier, Value};

use stacks_common::types::StacksEpochId;

use crate::vm::ast::ASTRules;
use crate::vm::database::MemoryBackingStore;
use crate::vm::tests::{TEST_BURN_STATE_DB, TEST_HEADER_DB};

fn helper_execute(contract: &str, method: &str) -> (Value, Vec<StacksTransactionEvent>) {
    let contract_id = QualifiedContractIdentifier::local("contract").unwrap();
    let address = "'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR";
    let sender = execute(address).expect_principal();

    let mut marf_kv = MemoryBackingStore::new();
    let mut owned_env = OwnedEnvironment::new(marf_kv.as_clarity_db());

    {
        let mut env = owned_env.get_exec_environment(None);
        env.initialize_contract(contract_id.clone(), contract, ASTRules::PrecheckSize)
            .unwrap();
    }

    owned_env.stx_faucet(&sender, 10);

    let (value, _, events) = owned_env
        .execute_transaction(sender, contract_id, method, &vec![])
        .unwrap();
    (value, events)
}

#[test]
fn test_emit_print_ok() {
    let contract = "(define-public (emit-event-ok)
            (begin
                (print \"Hello world\")
                (ok u1)))";

    let (value, mut events) = helper_execute(contract, "emit-event-ok");
    assert_eq!(value, Value::okay(Value::UInt(1)).unwrap());
    assert_eq!(events.len(), 1);
    match events.pop() {
        Some(StacksTransactionEvent::SmartContractEvent(data)) => {
            let contract_id = QualifiedContractIdentifier::local("contract").unwrap();
            assert_eq!(data.key, (contract_id, "print".to_string()));
            assert_eq!(data.value, execute("\"Hello world\""));
        }
        _ => panic!("assertion failed"),
    };
}

#[test]
fn test_emit_print_nok() {
    let contract = "(define-public (emit-event-nok)
            (begin
                (print \"Hello world\")
                (err u1)))";

    let (value, events) = helper_execute(contract, "emit-event-nok");
    assert_eq!(value, Value::error(Value::UInt(1)).unwrap());
    assert_eq!(events.len(), 0);
}

#[test]
fn test_emit_stx_transfer_ok() {
    let contract = "(define-constant sender 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)
        (define-constant recipient 'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G)
        (define-fungible-token token)
        (define-public (emit-event-ok)
            (begin
                (unwrap-panic (stx-transfer? u10 sender recipient))
                (ok u1)))";

    let (value, mut events) = helper_execute(contract, "emit-event-ok");
    assert_eq!(value, Value::okay(Value::UInt(1)).unwrap());
    assert_eq!(events.len(), 1);
    match events.pop() {
        Some(StacksTransactionEvent::STXEvent(STXEventType::STXTransferEvent(data))) => {
            assert_eq!(data.amount, 10u128);
            assert_eq!(
                Value::Principal(data.sender),
                execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR")
            );
            assert_eq!(
                Value::Principal(data.recipient),
                execute("'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G")
            );
        }
        _ => panic!("assertion failed"),
    };
}

#[test]
fn test_emit_stx_transfer_nok() {
    let contract = "(define-constant sender 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)
        (define-constant recipient 'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G)
        (define-fungible-token token)
        (define-public (emit-event-nok)
            (begin
                (unwrap-panic (stx-transfer? u10 sender recipient))
                (err u1)))";

    let (value, events) = helper_execute(contract, "emit-event-nok");
    assert_eq!(value, Value::error(Value::UInt(1)).unwrap());
    assert_eq!(events.len(), 0);
}

#[test]
fn test_emit_stx_burn_ok() {
    let contract = "(define-constant sender 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)
        (define-fungible-token token)
        (define-public (emit-event-ok)
            (begin
                (unwrap-panic (stx-burn? u10 sender))
                (ok u1)))";

    let (value, mut events) = helper_execute(contract, "emit-event-ok");
    assert_eq!(value, Value::okay(Value::UInt(1)).unwrap());
    assert_eq!(events.len(), 1);
    match events.pop() {
        Some(StacksTransactionEvent::STXEvent(STXEventType::STXBurnEvent(data))) => {
            assert_eq!(data.amount, 10u128);
            assert_eq!(
                Value::Principal(data.sender),
                execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR")
            );
        }
        _ => panic!("assertion failed"),
    };
}

#[test]
fn test_emit_stx_burn_nok() {
    let contract = "(define-constant sender 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)
        (define-fungible-token token)
        (define-public (emit-event-nok)
            (begin
                (unwrap-panic (stx-burn? u10 sender))
                (err u1)))";

    let (value, events) = helper_execute(contract, "emit-event-nok");
    assert_eq!(value, Value::error(Value::UInt(1)).unwrap());
    assert_eq!(events.len(), 0);
}

#[test]
fn test_emit_nested_print_nok() {
    let contract = "(define-public (emit-event-nok)
            (begin
                (print \"bar\")
                (err u1)))
        (define-public (emit-event-ok)
            (begin
                (emit-event-nok)
                (print \"foo\")
                (ok u1)))";

    let (value, events) = helper_execute(contract, "emit-event-ok");
    assert_eq!(value, Value::okay(Value::UInt(1)).unwrap());
    assert_eq!(events.len(), 1);
}

#[test]
fn test_emit_ft_transfer_ok() {
    let contract = "(define-constant sender 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)
        (define-constant recipient 'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G)
        (define-fungible-token token)
        (define-public (emit-event-ok)
            (begin
                (unwrap-panic (ft-transfer? token u10 sender recipient))
                (ok u1)))
        (begin (ft-mint? token u10 sender))";

    let (value, mut events) = helper_execute(contract, "emit-event-ok");
    assert_eq!(value, Value::okay(Value::UInt(1)).unwrap());
    assert_eq!(events.len(), 1);
    match events.pop() {
        Some(StacksTransactionEvent::FTEvent(FTEventType::FTTransferEvent(data))) => {
            let contract_identifier = QualifiedContractIdentifier::local("contract").unwrap();
            let asset_identifier = AssetIdentifier {
                contract_identifier,
                asset_name: "token".into(),
            };
            assert_eq!(data.asset_identifier, asset_identifier);
            assert_eq!(data.amount, 10u128);
            assert_eq!(
                Value::Principal(data.sender),
                execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR")
            );
            assert_eq!(
                Value::Principal(data.recipient),
                execute("'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G")
            );
        }
        _ => panic!("assertion failed"),
    };
}

#[test]
fn test_emit_ft_transfer_nok() {
    let contract = "(define-constant sender 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)
        (define-constant recipient 'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G)
        (define-fungible-token token)
        (define-public (emit-event-nok)
            (begin
                (unwrap-panic (ft-transfer? token u10 sender recipient))
                (err u1)))
        (begin (ft-mint? token u10 sender))";

    let (value, events) = helper_execute(contract, "emit-event-nok");
    assert_eq!(value, Value::error(Value::UInt(1)).unwrap());
    assert_eq!(events.len(), 0);
}

#[test]
fn test_emit_ft_mint_ok() {
    let contract = "(define-constant recipient 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)
        (define-fungible-token token)
        (define-public (emit-event-ok)
            (begin
                (unwrap-panic (ft-mint? token u10 recipient))
                (ok u1)))";

    let (value, mut events) = helper_execute(contract, "emit-event-ok");
    assert_eq!(value, Value::okay(Value::UInt(1)).unwrap());
    assert_eq!(events.len(), 1);
    match events.pop() {
        Some(StacksTransactionEvent::FTEvent(FTEventType::FTMintEvent(data))) => {
            let contract_identifier = QualifiedContractIdentifier::local("contract").unwrap();
            let asset_identifier = AssetIdentifier {
                contract_identifier,
                asset_name: "token".into(),
            };
            assert_eq!(data.asset_identifier, asset_identifier);
            assert_eq!(data.amount, 10u128);
            assert_eq!(
                Value::Principal(data.recipient),
                execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR")
            );
        }
        _ => panic!("assertion failed"),
    };
}

#[test]
fn test_emit_ft_mint_nok() {
    let contract = "(define-constant recipient 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)
        (define-fungible-token token)
        (define-public (emit-event-nok)
            (begin
                (unwrap-panic (ft-mint? token u10 recipient))
                (err u1)))";

    let (value, events) = helper_execute(contract, "emit-event-nok");
    assert_eq!(value, Value::error(Value::UInt(1)).unwrap());
    assert_eq!(events.len(), 0);
}

#[test]
fn test_emit_nft_transfer_ok() {
    let contract = "(define-constant sender 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)
        (define-constant recipient 'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G)
        (define-non-fungible-token token uint)
        (define-public (emit-event-ok)
            (begin
                (unwrap-panic (nft-transfer? token u1 sender recipient))
                (ok u1)))
        (begin (nft-mint? token u1 sender))";

    let (value, mut events) = helper_execute(contract, "emit-event-ok");
    assert_eq!(value, Value::okay(Value::UInt(1)).unwrap());
    assert_eq!(events.len(), 1);
    match events.pop() {
        Some(StacksTransactionEvent::NFTEvent(NFTEventType::NFTTransferEvent(data))) => {
            let contract_identifier = QualifiedContractIdentifier::local("contract").unwrap();
            let asset_identifier = AssetIdentifier {
                contract_identifier,
                asset_name: "token".into(),
            };
            assert_eq!(data.asset_identifier, asset_identifier);
            assert_eq!(data.value, execute("u1"));
            assert_eq!(
                Value::Principal(data.sender),
                execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR")
            );
            assert_eq!(
                Value::Principal(data.recipient),
                execute("'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G")
            );
        }
        _ => panic!("assertion failed"),
    };
}

#[test]
fn test_emit_nft_transfer_nok() {
    let contract = "(define-constant sender 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)
        (define-constant recipient 'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G)
        (define-non-fungible-token token uint)
        (define-public (emit-event-nok)
            (begin
                (unwrap-panic (nft-transfer? token u1 sender recipient))
                (err u1)))
        (begin (nft-mint? token u1 sender))";

    let (value, events) = helper_execute(contract, "emit-event-nok");
    assert_eq!(value, Value::error(Value::UInt(1)).unwrap());
    assert_eq!(events.len(), 0);
}

#[test]
fn test_emit_nft_mint_ok() {
    let contract = "(define-constant recipient 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)
        (define-non-fungible-token token uint)
        (define-public (emit-event-ok)
            (begin
                (unwrap-panic (nft-mint? token u1 recipient))
                (ok u1)))";

    let (value, mut events) = helper_execute(contract, "emit-event-ok");
    assert_eq!(value, Value::okay(Value::UInt(1)).unwrap());
    assert_eq!(events.len(), 1);
    match events.pop() {
        Some(StacksTransactionEvent::NFTEvent(NFTEventType::NFTMintEvent(data))) => {
            let contract_identifier = QualifiedContractIdentifier::local("contract").unwrap();
            let asset_identifier = AssetIdentifier {
                contract_identifier,
                asset_name: "token".into(),
            };
            assert_eq!(data.asset_identifier, asset_identifier);
            assert_eq!(data.value, execute("u1"));
            assert_eq!(
                Value::Principal(data.recipient),
                execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR")
            );
        }
        _ => panic!("assertion failed"),
    };
}

#[test]
fn test_emit_nft_mint_nok() {
    let contract = "(define-constant recipient 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)
        (define-non-fungible-token token uint)
        (define-public (emit-event-nok)
            (begin
                (unwrap-panic (nft-mint? token u1 recipient))
                (err u1)))";

    let (value, events) = helper_execute(contract, "emit-event-nok");
    assert_eq!(value, Value::error(Value::UInt(1)).unwrap());
    assert_eq!(events.len(), 0);
}
