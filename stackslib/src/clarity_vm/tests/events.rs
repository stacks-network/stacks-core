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

use clarity::vm::clarity::TransactionConnection;
use clarity::vm::contexts::OwnedEnvironment;
use clarity::vm::costs::ExecutionCost;
use clarity::vm::events::*;
use clarity::vm::resource_limiter::ResourceBudget;
use clarity::vm::tests::{
    execute, is_committed, test_only_mainnet_to_chain_id, TEST_BURN_STATE_DB, TEST_HEADER_DB,
};
use clarity::vm::types::{
    AssetIdentifier, BuffData, PrincipalData, QualifiedContractIdentifier, Value,
};
use clarity::vm::{ClarityName, ClarityVersion, ContractContext};
use stacks_common::types::chainstate::{BurnchainHeaderHash, StacksAddress, StacksBlockId};
use stacks_common::types::{Address, StacksEpochId};

use crate::burnchains::Txid;
use crate::chainstate::burn::operations::DelegateStxOp;
use crate::chainstate::stacks::boot::POX_2_NAME;
use crate::chainstate::stacks::db::{ClarityTx, StacksChainState};
use crate::chainstate::stacks::events::StacksTransactionReceipt;
use crate::chainstate::stacks::index::ClarityMarfTrieId;
use crate::chainstate::stacks::StacksBlockHeader;
use crate::clarity_vm::clarity::{
    ClarityBlockConnection, ClarityError, ClarityInstance, ClarityMarfStore,
};
use crate::clarity_vm::database::marf::MarfedKV;
use crate::core::{FIRST_BURNCHAIN_CONSENSUS_HASH, FIRST_STACKS_BLOCK_HASH};

fn helper_execute(contract: &str, method: &str) -> (Value, Vec<StacksTransactionEvent>) {
    let (value, events, _, _) =
        helper_execute_epoch(contract, method, None, StacksEpochId::Epoch21, false, false);
    (value, events)
}

fn helper_execute_epoch(
    contract: &str,
    method: &str,
    set_epoch: Option<StacksEpochId>,
    epoch: StacksEpochId,
    use_mainnet: bool,
    emit_vm_trace: bool,
) -> (Value, Vec<StacksTransactionEvent>, ExecutionCost, usize) {
    let contract_id = QualifiedContractIdentifier::local("contract").unwrap();
    let address = "'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR";
    let sender = execute(address).expect_principal().unwrap();

    let marf_kv = MarfedKV::temporary();
    let chain_id = test_only_mainnet_to_chain_id(use_mainnet);
    let mut clarity_instance = ClarityInstance::new(use_mainnet, chain_id, marf_kv);
    let mut genesis = clarity_instance.begin_test_genesis_block(
        &StacksBlockId::sentinel(),
        &StacksBlockHeader::make_index_block_hash(
            &FIRST_BURNCHAIN_CONSENSUS_HASH,
            &FIRST_STACKS_BLOCK_HASH,
        ),
        &TEST_HEADER_DB,
        &TEST_BURN_STATE_DB,
    );
    if epoch > StacksEpochId::Epoch20 {
        genesis.initialize_epoch_2_05().unwrap();
    }
    if epoch > StacksEpochId::Epoch2_05 {
        genesis.initialize_epoch_2_1().unwrap();
    }

    if let Some(epoch) = set_epoch {
        genesis.as_transaction(|tx_conn| {
            // bump the epoch in the Clarity DB
            tx_conn
                .with_clarity_db(|db| {
                    db.set_clarity_epoch_version(epoch).unwrap();
                    Ok(())
                })
                .unwrap();
        });
    }

    genesis.commit_block();

    let mut marf_kv = clarity_instance.destroy();

    let mut store = marf_kv.begin(
        &StacksBlockHeader::make_index_block_hash(
            &FIRST_BURNCHAIN_CONSENSUS_HASH,
            &FIRST_STACKS_BLOCK_HASH,
        ),
        &StacksBlockId([1; 32]),
    );

    let mut owned_env = OwnedEnvironment::new_max_limit(
        store.as_clarity_db(&TEST_HEADER_DB, &TEST_BURN_STATE_DB),
        epoch,
        use_mainnet,
    );
    let placeholder_context = ContractContext::new(
        QualifiedContractIdentifier::transient(),
        ClarityVersion::default_for_epoch(epoch),
    );

    {
        let (mut exec_state, invoke_ctx) =
            owned_env.get_exec_environment(None, None, &placeholder_context);
        exec_state
            .initialize_contract(&invoke_ctx, contract_id.clone(), contract)
            .unwrap();
    }

    owned_env.stx_faucet(&sender, 10);
    owned_env.set_emit_vm_trace(emit_vm_trace);

    let (value, _, events) = owned_env
        .execute_transaction(sender, None, contract_id, method, &[])
        .unwrap();
    let cost = owned_env.get_cost_total();
    let vm_n = owned_env.vm_trace_events().len();
    (value, events, cost, vm_n)
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
    assert!(events.is_empty());
}

#[test]
fn test_emit_stx_transfer_ok() {
    let contract = r#"(define-constant sender 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)
        (define-constant recipient 'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G)
        (define-fungible-token token)
        (define-public (emit-event-ok)
            (begin
                (unwrap-panic (stx-transfer? u10 sender recipient))
                (ok u1)))"#;

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
            assert_eq!(data.memo, BuffData { data: vec![] });
        }
        _ => panic!("assertion failed"),
    };
}

#[test]
fn test_emit_stx_transfer_memo_ok() {
    let contract = r#"(define-constant sender 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)
        (define-constant recipient 'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G)
        (define-fungible-token token)
        (define-public (emit-event-ok)
            (begin
                (unwrap-panic (stx-transfer-memo? u10 sender recipient 0x010203))
                (ok u1)))"#;

    let (value, mut events, _, _) = helper_execute_epoch(
        contract,
        "emit-event-ok",
        Some(StacksEpochId::Epoch21),
        StacksEpochId::Epoch21,
        false,
        false,
    );
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
            assert_eq!(
                data.memo,
                BuffData {
                    data: vec![1, 2, 3]
                }
            );
        }
        _ => panic!("assertion failed"),
    };
}

#[test]
fn test_emit_stx_transfer_nok() {
    let contract = r#"(define-constant sender 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)
        (define-constant recipient 'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G)
        (define-fungible-token token)
        (define-public (emit-event-nok)
            (begin
                (unwrap-panic (stx-transfer? u10 sender recipient))
                (err u1)))"#;

    let (value, events) = helper_execute(contract, "emit-event-nok");
    assert_eq!(value, Value::error(Value::UInt(1)).unwrap());
    assert!(events.is_empty());
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
    assert!(events.is_empty());
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
                asset_name: ClarityName::from_literal("token"),
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
    assert!(events.is_empty());
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
                asset_name: ClarityName::from_literal("token"),
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
    assert!(events.is_empty());
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
                asset_name: ClarityName::from_literal("token"),
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
    assert!(events.is_empty());
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
                asset_name: ClarityName::from_literal("token"),
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
    assert!(events.is_empty());
}

/// Flag on vs off must not change metered execution cost. The free-tracker
/// twin in `clarity::vm::tests::vm_trace` cannot prove this (both costs ZERO).
#[test]
fn vm_trace_limited_tracker_cost_identity() {
    let contract = r#"
        (define-data-var n uint u0)
        (define-public (set-n)
          (begin
            (print u1)
            (ok (var-set n u8))))
    "#;
    let (off_val, off_events, off_cost, off_vm) = helper_execute_epoch(
        contract,
        "set-n",
        None,
        StacksEpochId::Epoch21,
        false,
        false,
    );
    let (on_val, on_events, on_cost, on_vm) =
        helper_execute_epoch(contract, "set-n", None, StacksEpochId::Epoch21, false, true);
    assert_eq!(off_val, on_val);
    assert_eq!(off_events, on_events);
    assert!(
        !off_cost.is_zero(),
        "Limited tracker must meter this tx, got {off_cost:?}"
    );
    assert_eq!(
        off_cost, on_cost,
        "emit_vm_trace must not change ExecutionCost"
    );
    assert_eq!(off_vm, 0);
    assert_eq!(on_vm, 1);
}

fn process_delegate_with_trace(emit_vm_trace: bool) -> Vec<StacksTransactionReceipt> {
    let marf_kv = MarfedKV::temporary();
    let chain_id = test_only_mainnet_to_chain_id(false);
    let mut clarity_instance = ClarityInstance::new(false, chain_id, marf_kv);
    clarity_instance.set_emit_vm_trace(emit_vm_trace);

    let genesis_id = StacksBlockHeader::make_index_block_hash(
        &FIRST_BURNCHAIN_CONSENSUS_HASH,
        &FIRST_STACKS_BLOCK_HASH,
    );
    let genesis = clarity_instance.begin_test_genesis_block_2_1(
        &StacksBlockId::sentinel(),
        &genesis_id,
        &TEST_HEADER_DB,
        &TEST_BURN_STATE_DB,
    );
    let mut clarity_tx = ClarityTx::from_block_connection(genesis);

    let sender = StacksAddress::from_string("ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM").unwrap();
    let delegate_to =
        StacksAddress::from_string("ST1SJ3DTE5DN7X54YDH5D64R3BCB6A2AG2ZQ8YPD5").unwrap();

    StacksChainState::process_delegate_ops(
        &mut clarity_tx,
        vec![DelegateStxOp {
            sender,
            delegate_to,
            reward_addr: None,
            delegated_ustx: 1,
            until_burn_height: None,
            txid: Txid([1; 32]),
            vtxindex: 0,
            block_height: 1,
            burn_header_hash: BurnchainHeaderHash([0; 32]),
        }],
        POX_2_NAME,
    )
}

/// Bitcoin-origin `delegate-stx` must keep traces taken inside `as_transaction`.
#[test]
fn burn_op_delegate_carries_vm_events() {
    let on = process_delegate_with_trace(true);
    assert_eq!(on.len(), 1);
    assert_eq!(on[0].result, Value::okay_true());
    assert!(
        on[0].vm_events.iter().any(|e| matches!(
            e,
            VmTraceEvent::Storage(StorageEvent::MapSet(d)) if d.map_name == "delegation-state"
        )),
        "committed delegate-stx must emit map_set_event: {:?}",
        on[0].vm_events
    );

    let off = process_delegate_with_trace(false);
    assert_eq!(off.len(), 1);
    assert_eq!(off[0].result, Value::okay_true());
    assert!(
        off[0].vm_events.is_empty(),
        "flag off must not collect traces"
    );
}

const STORE_CONTRACT: &str = r#"
(define-data-var n uint u0)
(define-public (set-n (x uint))
  (ok (var-set n x)))
"#;

fn publish_store(
    conn: &mut ClarityBlockConnection,
) -> (QualifiedContractIdentifier, PrincipalData) {
    let contract_id = QualifiedContractIdentifier::local("store").unwrap();
    let sender = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR")
        .expect_principal()
        .unwrap();
    conn.as_transaction(|tx| {
        let (ast, analysis) = tx
            .analyze_smart_contract(
                &contract_id,
                ClarityVersion::Clarity2,
                STORE_CONTRACT,
                &ResourceBudget::unlimited(),
            )
            .unwrap();
        tx.initialize_smart_contract(
            &contract_id,
            ClarityVersion::Clarity2,
            &ast,
            STORE_CONTRACT,
            None,
            |_, _| None,
            &ResourceBudget::unlimited(),
        )
        .unwrap();
        tx.save_analysis(&contract_id, &analysis).unwrap();
    });
    (contract_id, sender)
}

/// Production hop: `as_transaction` → `run_contract_call` → `take_vm_trace_events`.
fn call_set_n(
    conn: &mut ClarityBlockConnection,
    sender: &PrincipalData,
    contract: &QualifiedContractIdentifier,
    x: u128,
    abort: bool,
) -> (Result<Value, ClarityError>, Vec<VmTraceEvent>) {
    conn.as_transaction(|tx| {
        let result = tx
            .run_contract_call(
                sender,
                None,
                contract,
                "set-n",
                &[Value::UInt(x)],
                |_, _| {
                    if abort {
                        Some("aborted".into())
                    } else {
                        None
                    }
                },
                &ResourceBudget::unlimited(),
            )
            .map(|(v, _, _)| v);
        let events = tx.take_vm_trace_events();
        (result, events)
    })
}

/// Block ↔ transaction hop: later receipts still collect; abort drops traces.
#[test]
fn vm_trace_block_connection_collects_across_receipts() {
    let marf_kv = MarfedKV::temporary();
    let chain_id = test_only_mainnet_to_chain_id(false);
    let mut clarity_instance = ClarityInstance::new(false, chain_id, marf_kv);
    clarity_instance.set_emit_vm_trace(true);

    let genesis_id = StacksBlockHeader::make_index_block_hash(
        &FIRST_BURNCHAIN_CONSENSUS_HASH,
        &FIRST_STACKS_BLOCK_HASH,
    );
    let mut conn = clarity_instance.begin_test_genesis_block_2_1(
        &StacksBlockId::sentinel(),
        &genesis_id,
        &TEST_HEADER_DB,
        &TEST_BURN_STATE_DB,
    );
    let (contract_id, sender) = publish_store(&mut conn);

    let (r1, e1) = call_set_n(&mut conn, &sender, &contract_id, 1, false);
    assert!(is_committed(&r1.unwrap()));
    assert_eq!(e1.len(), 1);
    assert!(matches!(
        e1[0],
        VmTraceEvent::Storage(StorageEvent::VarSet(_))
    ));

    let (r2, e2) = call_set_n(&mut conn, &sender, &contract_id, 2, false);
    assert!(is_committed(&r2.unwrap()));
    assert_eq!(e2.len(), 1);

    let (aborted, abort_events) = call_set_n(&mut conn, &sender, &contract_id, 3, true);
    assert!(
        matches!(aborted, Err(ClarityError::AbortedByCallback { .. })),
        "expected abort, got {aborted:?}"
    );
    assert!(
        abort_events.is_empty(),
        "aborted tx must drop traces: {abort_events:?}"
    );

    let (r3, e3) = call_set_n(&mut conn, &sender, &contract_id, 4, false);
    assert!(is_committed(&r3.unwrap()));
    assert_eq!(e3.len(), 1);
}
