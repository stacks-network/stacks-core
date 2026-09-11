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

//! Tests for the per-transaction memory-limit ResourceBudgets. These live
//! in the stacks-node crate because it sets a `TrackingAllocator` as the
//! `#[global_allocator]`, which is required for the thread-local counters
//! to reflect actual allocations.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use clarity::vm::analysis::run_analysis;
use clarity::vm::clarity::ClarityError;
use clarity::vm::contexts::GlobalContext;
use clarity::vm::costs::LimitedCostTracker;
use clarity::vm::database::MemoryBackingStore;
use clarity::vm::resource_limiter::{ResourceBudget, ResourceLimitExceeded};
use clarity::vm::types::{QualifiedContractIdentifier, StacksAddressExtensions};
use clarity::vm::{ast, eval_all, ClarityVersion, ContractContext, Value};
use stacks::core::BLOCK_LIMIT_MAINNET_21;
use stacks::net::api::callreadonly;
use stacks::net::connection::ConnectionOptions;
use stacks::net::http::{HttpRequest, HttpRequestContents};
use stacks::net::httpcore::{StacksHttp, StacksHttpPreamble, StacksHttpRequest};
use stacks::net::ProtocolFamily;
use stacks_common::consts::CHAIN_ID_TESTNET;
use stacks_common::types::chainstate::StacksAddress;
use stacks_common::types::{Address, StacksEpochId};

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

fn big_type_signature_program() -> String {
    let scream = "a".repeat(100);
    let mut s = "(define-private (f (tup {".to_string();
    for i in 0..100 {
        s.push_str(format!("{scream}{i}: int").as_str());
        if i < 99 {
            s.push_str(", ");
        }
    }
    s.push_str("})) 0)\n42");
    s
}

/// Helper: analyze and run a Clarity program with memory resource budgets
/// for both phases (use `None` for no limit).
fn run_with_memory_limits(
    program: &str,
    analysis_mem_limit: Option<u64>,
    eval_mem_limit: Option<u64>,
) -> Result<Option<clarity::vm::Value>, ClarityError> {
    let analysis_budget = ResourceBudget::new().with_max_memory_use(analysis_mem_limit);
    let eval_budget = ResourceBudget::new().with_max_memory_use(eval_mem_limit);

    let contract_id = QualifiedContractIdentifier::transient();
    let mut marf = MemoryBackingStore::new();
    let conn = marf.as_clarity_db();
    let version = ClarityVersion::latest();
    let epoch = StacksEpochId::latest();

    let mut global_context = GlobalContext::new(
        false,
        CHAIN_ID_TESTNET,
        conn,
        LimitedCostTracker::new_free(),
        epoch,
    );

    let mut contract_context = ContractContext::new(contract_id.clone(), ClarityVersion::Clarity2);
    let analysis_limiter = analysis_budget.start_tracking();

    let parsed = ast::build_ast(
        &contract_id,
        program,
        &mut global_context.cost_track,
        version,
        epoch,
    )
    .expect("Failed to parse program")
    .expressions;

    let mut marf = MemoryBackingStore::new();
    let mut analysis_db = marf.as_analysis_db();
    let cost_tracker = LimitedCostTracker::new_free();
    let _ = run_analysis(
        &QualifiedContractIdentifier::transient(),
        &parsed,
        &mut analysis_db,
        false,
        cost_tracker,
        epoch,
        version,
        true,
        analysis_limiter,
    )
    .map_err(|e| ClarityError::from(e.0))?;

    global_context
        .execute(|g| {
            g.set_execution_resource_limiter(eval_budget.start_tracking());

            eval_all(&parsed, &mut contract_context, g, None)
        })
        .map_err(|e| e.into())
}

#[test]
fn test_mem_budget_aborts_on_exceeded_execution_limit() {
    let program = big_alloc_program();

    // 1 byte limit => any real execution will exceed this.
    let result = run_with_memory_limits(&program, None, Some(1));

    assert!(
        result.is_err(),
        "Expected execution to be aborted, but it succeeded"
    );
    let err_string = format!("{:?}", result.unwrap_err());
    assert!(
        err_string.contains("Evaluation used too much memory"),
        "Expected 'Evaluation used too much memory' in error, got: {err_string}"
    );
}

#[test]
fn test_mem_budget_allows_execution_under_limit() {
    let program = big_alloc_program();

    // 100 MB limit => the large list program should not exceed this.
    let result = run_with_memory_limits(&program, None, Some(100 * 1024 * 1024));

    assert!(
        result.is_ok(),
        "Expected execution to succeed, but got: {result:?}"
    );
}

#[test]
fn test_no_mem_budget_allows_large_allocation() {
    let program = big_alloc_program();

    // No abort callback at all => should succeed regardless of allocations.
    let result = run_with_memory_limits(&program, None, None);

    assert!(
        result.is_ok(),
        "Expected execution to succeed with unlimited memory, but got: {result:?}"
    );
}

#[test]
fn test_mem_budget_aborts_on_exceeded_analysis_limit() {
    let program = big_type_signature_program();

    // the type signature of the tuple is 100 keys with 100+ chars each, so 10k is
    // an absolute lower bound
    let result = run_with_memory_limits(&program, Some(10_000), None);

    assert!(
        result.is_err(),
        "Expected execution to be aborted, but it succeeded"
    );
    let err_string = format!("{:?}", result.unwrap_err());
    assert!(
        err_string.contains("Analysis used too much memory"),
        "Expected 'Analysis used too much memory' in error, got: {err_string}"
    );
}

#[test]
fn test_high_enough_analysis_limit_is_fine() {
    let program = big_type_signature_program();

    // 10 MiB should be more than plenty
    let result = run_with_memory_limits(&program, Some(10 * 1024 * 1024), None);

    assert!(
        result.is_ok(),
        "Expected analysis to succeed with enough memory, but got: {result:?}"
    );
}

#[test]
fn test_analysis_and_execution_limits_high_enough() {
    let program = big_type_signature_program();

    let result = run_with_memory_limits(&program, Some(10 * 1024 * 1024), Some(10 * 1024 * 1024));

    assert!(
        result.is_ok(),
        "Expected analysis and execution to succeed with enough memory, but got: {result:?}"
    );
}

#[test]
fn test_analysis_limit_fine_but_execution_limit_too_low() {
    let program = big_type_signature_program();

    let result = run_with_memory_limits(&program, Some(10 * 1024 * 1024), Some(1));
    // analysis should succeed, but execution shouldn't
    assert!(
        result.is_err(),
        "Expected execution to be aborted, but it succeeded"
    );
    let err_string = format!("{:?}", result.unwrap_err());
    assert!(
        err_string.contains("Evaluation used too much memory"),
        "Expected 'Evaluation used too much memory' in error, got: {err_string}"
    );
}

/// The read-only RPC memory limit must be threaded from `ConnectionOptions`
/// into the HTTP server state so the handlers can set the correct budget.
#[test]
fn test_read_only_call_max_mem_bytes_threaded_into_http() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
    let mut conn_opts = ConnectionOptions::default();
    conn_opts.read_only_call_max_mem_bytes = 12345;

    let http = StacksHttp::new(addr, &conn_opts);
    assert_eq!(http.read_only_call_max_mem_bytes, 12345);
}

fn new_call_read_request(addr: SocketAddr, arguments: Vec<String>) -> StacksHttpRequest {
    let contract_addr =
        StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R").unwrap();
    StacksHttpRequest::new_for_peer(
        addr.into(),
        "POST".into(),
        format!("/v2/contracts/call-read/{contract_addr}/flood/f"),
        HttpRequestContents::new().payload_json(
            serde_json::to_value(callreadonly::CallReadOnlyRequestBody {
                sender: contract_addr.to_account_principal().to_string(),
                sponsor: None,
                arguments,
            })
            .unwrap(),
        ),
    )
    .unwrap()
}

/// Parse a call-read request with the real allocation counter live.
fn try_parse_call_read(
    arguments: Vec<String>,
    read_only_call_max_mem_bytes: u64,
) -> Result<(), String> {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);
    let mut conn_opts = ConnectionOptions::default();
    conn_opts.read_only_call_max_mem_bytes = read_only_call_max_mem_bytes;
    let mut http = StacksHttp::new(addr, &conn_opts);
    let request = new_call_read_request(addr, arguments);
    let mut bytes = vec![];
    request.send(&mut bytes).unwrap();

    let (StacksHttpPreamble::Request(parsed_preamble), offset) =
        http.read_preamble(&bytes).unwrap()
    else {
        panic!("expected request preamble");
    };

    http.try_parse_request(&parsed_preamble, &bytes[offset..])
        .map(|_| ())
        .map_err(|e| format!("{e:?}"))
}

/// Execution is budgeted from the same total, so parsing must record what it
/// retained.
#[test]
fn test_read_only_parse_records_retained_mem() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);
    let conn_opts = ConnectionOptions::default();
    let mut http = StacksHttp::new(addr, &conn_opts);
    let request = new_call_read_request(addr, vec!["03".into(); 8]);
    let mut bytes = vec![];
    request.send(&mut bytes).unwrap();

    let (StacksHttpPreamble::Request(parsed_preamble), offset) =
        http.read_preamble(&bytes).unwrap()
    else {
        panic!("expected request preamble");
    };

    let mut handler = callreadonly::RPCCallReadOnlyRequestHandler::new(
        conn_opts.maximum_call_argument_size,
        BLOCK_LIMIT_MAINNET_21,
        Duration::from_secs(conn_opts.read_only_max_execution_time_secs),
        conn_opts.read_only_call_max_mem_bytes,
    );
    let path = format!(
        "/v2/contracts/call-read/{}/flood/f",
        StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R").unwrap()
    );
    let path_regex = handler.path_regex();
    let captures = path_regex.captures(&path).unwrap();
    handler
        .try_parse_request(&parsed_preamble, &captures, None, &bytes[offset..])
        .unwrap();

    assert!(handler.parse_retained_mem_bytes > 0);

    // with the limit disabled, retention is not measured.
    let mut handler = callreadonly::RPCCallReadOnlyRequestHandler::new(
        conn_opts.maximum_call_argument_size,
        BLOCK_LIMIT_MAINNET_21,
        Duration::from_secs(conn_opts.read_only_max_execution_time_secs),
        0,
    );
    handler
        .try_parse_request(&parsed_preamble, &captures, None, &bytes[offset..])
        .unwrap();

    assert_eq!(handler.parse_retained_mem_bytes, 0);
}

#[test]
fn test_read_only_parse_mem_limit_rejects_json_argument_allocation() {
    let error = try_parse_call_read(vec!["03".into(); 512], 4 * 1024).unwrap_err();
    assert!(
        error.contains("Read-only argument parsing exceeded memory limit"),
        "expected parse allocation limit error, got: {error}"
    );
}

/// Guards against over-rejection: a small request must parse.
#[test]
fn test_read_only_parse_mem_limit_accepts_request_under_limit() {
    try_parse_call_read(vec!["03".into(); 8], 1024 * 1024).unwrap();
}

/// `0` disables the byte budget (the argument-count cap remains).
#[test]
fn test_read_only_parse_mem_limit_zero_disables_budget() {
    try_parse_call_read(vec!["03".into(); 512], 0).unwrap();
}

/// The post-deserialization checkpoint rejects an argument whose deserialized
/// size exceeds the limit.
#[test]
fn test_read_only_parse_mem_limit_rejects_large_deserialized_value() {
    let big_list = Value::cons_list_unsanitized(vec![Value::Bool(true); 100_000]).unwrap();
    let hex = big_list.serialize_to_hex().unwrap();
    let error = try_parse_call_read(vec![hex], 4 * 1024 * 1024).unwrap_err();
    assert!(
        error.contains("Read-only argument parsing exceeded memory limit"),
        "expected parse allocation limit error, got: {error}"
    );
}

/// Execution's limiter gets what the total has left after parsing.
#[test]
fn test_execution_limiter_budgets_remaining_total() {
    let conn_opts = ConnectionOptions::default();
    let mut handler = callreadonly::RPCCallReadOnlyRequestHandler::new(
        conn_opts.maximum_call_argument_size,
        BLOCK_LIMIT_MAINNET_21,
        Duration::from_secs(conn_opts.read_only_max_execution_time_secs),
        1024,
    );
    handler.parse_retained_mem_bytes = 1000;

    // 24 bytes of budget left: this allocation must trip the limiter.
    let limiter = handler.execution_resource_limiter();
    let data = vec![0u8; 4096];
    assert!(matches!(
        limiter.check_not_exceeded(),
        Err(ResourceLimitExceeded::MaxAllocationExceeded(_))
    ));
    drop(data);

    // A total of `0` leaves execution unlimited regardless of retention.
    let mut handler = callreadonly::RPCCallReadOnlyRequestHandler::new(
        conn_opts.maximum_call_argument_size,
        BLOCK_LIMIT_MAINNET_21,
        Duration::from_secs(conn_opts.read_only_max_execution_time_secs),
        0,
    );
    handler.parse_retained_mem_bytes = 1000;
    let limiter = handler.execution_resource_limiter();
    let data = vec![0u8; 4096];
    assert!(limiter.check_not_exceeded().is_ok());
    drop(data);
}
