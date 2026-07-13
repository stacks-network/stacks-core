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

//! Tests for the per-transaction memory-limit abort callback
//! (`make_mem_abort_callback`). These live in the stacks-node crate because
//! it sets a `TrackingAllocator` as the `#[global_allocator]`, which is
//! required for the thread-local counters to reflect actual allocations.

use clarity::vm::contexts::{AbortCallback, GlobalContext};
use clarity::vm::costs::LimitedCostTracker;
use clarity::vm::database::MemoryBackingStore;
use clarity::vm::types::QualifiedContractIdentifier;
use clarity::vm::{ast, eval_all, ClarityVersion, ContractContext};
use stacks::chainstate::nakamoto::miner::make_mem_abort_callback;
use stacks_common::consts::CHAIN_ID_TESTNET;
use stacks_common::types::StacksEpochId;

/// A Clarity program that allocates a non-trivial amount of memory
/// by building a large list of string literals.
fn big_alloc_program() -> String {
    let mut lines = Vec::new();
    for i in 0u8..100 {
        let ch = (b'a' + (i % 26)) as char;
        let s: String = std::iter::repeat(ch).take(100).collect();
        lines.push(format!("    \"{s}\""));
    }
    format!("(list\n{}\n)", lines.join("\n"))
}

/// Helper: run a Clarity program with an abort callback (use
/// `AbortCallback::None` for "no callback").
fn run_with_abort_callback(
    program: &str,
    abort_cb: AbortCallback,
) -> Result<Option<clarity::vm::Value>, clarity::vm::errors::VmExecutionError> {
    let contract_id = QualifiedContractIdentifier::transient();
    let mut marf = MemoryBackingStore::new();
    let conn = marf.as_clarity_db();
    let epoch = StacksEpochId::Epoch30;

    let mut global_context = GlobalContext::new(
        false,
        CHAIN_ID_TESTNET,
        conn,
        LimitedCostTracker::new_free(),
        epoch,
    );
    global_context.abort_callback = abort_cb;

    let mut contract_context = ContractContext::new(contract_id.clone(), ClarityVersion::Clarity2);
    let parsed = ast::build_ast(
        &contract_id,
        program,
        &mut global_context.cost_track,
        ClarityVersion::Clarity2,
        epoch,
    )
    .expect("Failed to parse program")
    .expressions;

    global_context.execute(|g| eval_all(&parsed, &mut contract_context, g, None))
}

#[test]
fn test_mem_abort_callback_aborts_on_exceeded_limit() {
    let program = big_alloc_program();

    // 1 byte limit => any real execution will exceed this.
    let abort_cb = make_mem_abort_callback(1);

    let result = run_with_abort_callback(&program, abort_cb);

    assert!(
        result.is_err(),
        "Expected execution to be aborted, but it succeeded"
    );
    let err_string = format!("{:?}", result.unwrap_err());
    assert!(
        err_string.contains("exceeded limit"),
        "Expected 'exceeded limit' in error, got: {err_string}"
    );
}

#[test]
fn test_mem_abort_callback_allows_execution_under_limit() {
    let program = big_alloc_program();

    // 100 MB limit => the large list program should not exceed this.
    let abort_cb = make_mem_abort_callback(100 * 1024 * 1024);

    let result = run_with_abort_callback(&program, abort_cb);

    assert!(
        result.is_ok(),
        "Expected execution to succeed, but got: {result:?}"
    );
}

#[test]
fn test_mem_abort_callback_disabled_when_zero() {
    // Limit of 0 means disabled => should return AbortCallback::None.
    assert!(
        matches!(make_mem_abort_callback(0), AbortCallback::None),
        "Expected AbortCallback::None for limit_bytes=0"
    );
}

#[test]
fn test_no_abort_callback_allows_large_allocation() {
    let program = big_alloc_program();

    // No abort callback at all => should succeed regardless of allocations.
    let result = run_with_abort_callback(&program, AbortCallback::None);

    assert!(
        result.is_ok(),
        "Expected execution to succeed without abort callback, but got: {result:?}"
    );
}

/// The read-only RPC memory limit must be threaded from `ConnectionOptions`
/// into the HTTP server state so the handlers can install the abort callback.
#[test]
fn test_read_only_call_max_mem_bytes_threaded_into_http() {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use stacks::net::connection::ConnectionOptions;
    use stacks::net::httpcore::StacksHttp;

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
    let mut conn_opts = ConnectionOptions::default();
    conn_opts.read_only_call_max_mem_bytes = 12345;

    let http = StacksHttp::new(addr, &conn_opts);
    assert_eq!(http.read_only_call_max_mem_bytes, 12345);
}
