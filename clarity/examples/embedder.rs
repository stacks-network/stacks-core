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

//! A minimal Clarity embedder: deploys and calls contracts purely through
//! the kernel's `Engine` ABI — no stacks-core, no chainstate, no MARF.
//!
//! This is the proof artifact for the kernel/engine split: everything below
//! interacts with the VM through `dyn Engine` and kernel types only.
//!
//! Run with: `cargo run -p clarity --example embedder`

use clarity::vm::database::MemoryBackingStore;
use clarity::vm::engine::{Engine, LegacyEngine, TransactionContext};
use clarity_kernel::clarity_types::types::{
    PrincipalData, QualifiedContractIdentifier, StandardPrincipalData,
};
use clarity_kernel::clarity_types::{ClarityName, ClarityVersion, ContractName, Value};
use stacks_common::consts::CHAIN_ID_TESTNET;
use stacks_common::types::StacksEpochId;

const COUNTER_CONTRACT: &str = r#"
(define-data-var count uint u0)

(define-read-only (get-count)
  (var-get count))

(define-public (increment)
  (begin
    (var-set count (+ (var-get count) u1))
    (print { event: "incremented", new-count: (var-get count) })
    (ok (var-get count))))
"#;

fn main() {
    // The host provides storage; here, an in-memory sqlite store.
    let mut store = MemoryBackingStore::new();

    // The engine is just a trait object — any implementation of the kernel
    // ABI (interpreter, Wasm backend, a future clarity-vNEXT) slots in here.
    let engine: &dyn Engine = &LegacyEngine;
    println!(
        "engine: {} (supports {} language versions)",
        engine.name(),
        engine.supported_versions().len()
    );

    let deployer = StandardPrincipalData::transient();
    let contract_id =
        QualifiedContractIdentifier::new(deployer.clone(), ContractName::from_literal("counter"));
    let sender: PrincipalData = deployer.into();

    let mut ctx = TransactionContext::new(
        store.as_clarity_db(),
        false,
        CHAIN_ID_TESTNET,
        StacksEpochId::latest(),
    );

    // Deploy.
    let deploy = engine
        .deploy_contract(
            &mut ctx,
            &contract_id,
            COUNTER_CONTRACT,
            ClarityVersion::latest(),
            None,
        )
        .expect("deploy failed");
    println!("deployed {contract_id} ({} events)", deploy.events.len());

    // Call `increment` twice.
    for _ in 0..2 {
        let outcome = engine
            .execute_call(
                &mut ctx,
                sender.clone(),
                None,
                &contract_id,
                &ClarityName::from_literal("increment"),
                &[],
            )
            .expect("call failed");
        println!(
            "increment -> {} ({} events)",
            outcome.value,
            outcome.events.len()
        );
        for event in &outcome.events {
            println!(
                "  event: {}",
                event
                    .json_serialize(0, &"txid", true)
                    .expect("serialize event")
            );
        }
    }

    // Read back the counter through a read-only eval.
    let count = engine
        .eval_read_only(&mut ctx, &contract_id, "(get-count)")
        .expect("read-only eval failed");
    println!("final count: {count}");

    assert_eq!(count, Value::UInt(2));
    println!("ok: embedded Clarity ran end-to-end through the Engine ABI");
}
