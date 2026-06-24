//! Generator and drift-guard for the checked-in wire-contract JSON Schema
//! (`schema/v1.json`).
//!
//! The document pins the versioned [`CommandResult`](crate::wire::CommandResult)
//! envelope plus every result payload, keyed by surface (`cli` / `mcp`) and
//! `result_type`. Each payload entry records its `result_version` so a consumer
//! can match the runtime envelope header to the right schema.
//!
//! Regenerate after any wire change with:
//!
//! ```text
//! UPDATE_SCHEMA=1 cargo test -p stacks-bench --bin stacks-bench schema_v1
//! ```
//!
//! The whole module is `#[cfg(test)]`: it exists only to produce and verify the
//! checked-in artifact, not to ship in the binary.
#![cfg(test)]

use serde_json::{Value, json};

/// Path to the checked-in schema artifact, relative to the crate manifest.
const SCHEMA_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/schema/v1.json");

/// Convert a generated `schemars::Schema` into a `serde_json::Value`.
fn schema_to_value(schema: schemars::Schema) -> Value {
    serde_json::to_value(schema).expect("schemars Schema serializes to JSON")
}

/// One `(result_type, { result_version, schema })` registry entry. The
/// discriminator key and version are read from the type's
/// [`WirePayloadMeta`](crate::wire::WirePayloadMeta) impl, so they cannot drift
/// from the runtime wire contract declared by `wire_payload!`.
macro_rules! entry {
    ($ty:ty) => {
        (
            <$ty as crate::wire::WirePayloadMeta>::RESULT_TYPE.to_string(),
            json!({
                "result_version": <$ty as crate::wire::WirePayloadMeta>::RESULT_VERSION,
                "schema": schema_to_value(schemars::schema_for!($ty)),
            }),
        )
    };
}

/// Assemble a `result_type -> { result_version, schema }` object from entries.
///
/// Panics on a duplicate discriminator: since the keys are now derived from
/// each type's [`WirePayloadMeta`](crate::wire::WirePayloadMeta) rather than
/// written at the call site, a collision would otherwise silently overwrite an
/// entry. Each `result_type` must be unique within a surface.
fn payload_map<const N: usize>(entries: [(String, Value); N]) -> Value {
    let mut map = serde_json::Map::with_capacity(N);
    for (key, value) in entries {
        assert!(
            map.insert(key.clone(), value).is_none(),
            "duplicate wire discriminator `{key}` in schema registry"
        );
    }
    Value::Object(map)
}

/// Assemble the full schema document for wire schema v1.
fn build_schema_document() -> Value {
    json!({
        "schema_version": crate::wire::ENVELOPE_SCHEMA_VERSION,
        "$comment": "Frozen wire-contract envelope plus per-payload schemas. The \
            envelope header (everything except `result`) is a stable contract; \
            payloads evolve additively within a result_version. See src/wire.rs.",
        "envelope": schema_to_value(schemars::schema_for!(crate::wire::CommandResult)),
        "cli_events": {
            "progress": {
                "schema_version": crate::wire::CLI_EVENT_SCHEMA_VERSION,
                "event_version": crate::wire::CLI_PROGRESS_EVENT_VERSION,
                "schema": schema_to_value(schemars::schema_for!(crate::wire::CliProgressEvent)),
            }
        },
        // CLI `--json` payloads (the `result` body for each command).
        "cli_payloads": payload_map([
            entry!(crate::commands::bench::run::RunResult),
            entry!(crate::commands::bench::baseline::BaselineCalibrationResult),
            entry!(crate::commands::bench::show::ShowResult),
            entry!(Vec<crate::commands::bench::list::RunJson>),
            entry!(crate::commands::bench::remove::RemoveResult),
            entry!(Vec<crate::commands::chainstate::list::ChainstateJson>),
            entry!(crate::commands::chainstate::remove::RemoveResult),
            entry!(crate::commands::chainstate::index::IndexResult),
        ]),
        // MCP tool payloads. `run` / `chainstate_index` reuse the CLI types;
        // the list shapes differ from CLI and are documented per surface.
        "mcp_payloads": payload_map([
            entry!(crate::commands::bench::run::RunResult),
            entry!(crate::commands::chainstate::index::IndexResult),
            entry!(crate::mcp::tools::compare_runs::ComparisonJson),
            entry!(crate::mcp::tools::delete_run::DeleteRunResult),
            entry!(crate::mcp::tools::delete_chainstate::DeleteChainstateResult),
            entry!(Vec<crate::mcp::tools::get_block_stats::BlockStatsJson>),
            entry!(Vec<crate::mcp::tools::get_tx_stats::TxStatsJson>),
            entry!(crate::mcp::tools::get_chainstate::ChainstateDetailJson),
            entry!(Vec<crate::mcp::tools::get_hotspots::HotSpanJson>),
            entry!(Vec<crate::mcp::tools::list_chainstates::ChainstateJson>),
            entry!(crate::mcp::tools::get_run_details::RunDetailsJson),
            entry!(Vec<crate::mcp::tools::list_runs::RunJson>),
        ]),
    })
}

/// Serialize the schema document the same way it is written to disk
/// (pretty-printed, trailing newline).
fn rendered_document() -> String {
    let doc = build_schema_document();
    let mut out = serde_json::to_string_pretty(&doc).expect("schema document serializes");
    out.push('\n');
    out
}

/// Verify the checked-in `schema/v1.json` matches the types. Set
/// `UPDATE_SCHEMA=1` to (re)write it instead of asserting.
#[test]
fn schema_v1_is_current() {
    let rendered = rendered_document();

    if std::env::var_os("UPDATE_SCHEMA").is_some() {
        if let Some(parent) = std::path::Path::new(SCHEMA_PATH).parent() {
            std::fs::create_dir_all(parent).expect("create schema dir");
        }
        std::fs::write(SCHEMA_PATH, &rendered).expect("write schema/v1.json");
        return;
    }

    let existing = std::fs::read_to_string(SCHEMA_PATH).unwrap_or_else(|e| {
        panic!(
            "schema/v1.json could not be read ({e}); regenerate with \
             `UPDATE_SCHEMA=1 cargo test -p stacks-bench --bin stacks-bench schema_v1`"
        )
    });

    assert_eq!(
        existing, rendered,
        "schema/v1.json is out of date with the wire types; regenerate with \
         `UPDATE_SCHEMA=1 cargo test -p stacks-bench --bin stacks-bench schema_v1`"
    );
}
