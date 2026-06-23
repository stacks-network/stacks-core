//! Versioned wire contracts for `stacks-bench` structured output.
//!
//! Every successful `--json` and MCP command result is serialized inside a
//! stable [`CommandResult`] envelope. The envelope *header* — every field
//! except `result` — is a **frozen contract**: a consumer can always parse it
//! to learn the command's status and, via (`result_type`, `result_version`),
//! exactly how to interpret the `result` payload — regardless of which
//! `stacks-bench` binary version produced it.
//!
//! Errors use each surface's native structured channel: the CLI `--json` path
//! emits an error *envelope* ([`CommandResult::err`], `success: false`), while
//! MCP application failures surface as MCP protocol/tool errors rather than an
//! envelope. Only successful MCP tool results are enveloped.
//!
//! # Evolution policy
//!
//! - **The header is frozen.** Never rename, remove, or repurpose a header
//!   field. [`ENVELOPE_SCHEMA_VERSION`] bumps only if the header structure
//!   itself ever changes (it is not expected to).
//! - **Payloads evolve additively within a `result_version`.** Adding an
//!   optional field does *not* bump the version. Renaming, removing, or
//!   changing the *meaning* of a field *does* bump that payload's
//!   [`WirePayload::result_version`].
//! - **Consumers should be tolerant readers:** parse the header strictly,
//!   parse the payload leniently (ignore unknown fields, treat missing
//!   fields as absent). Then additive producer changes never break a
//!   consumer — only a `result_version` bump requires consumer work.

use serde::Serialize;

/// Version of the [`CommandResult`] envelope structure itself. This is the
/// stable header contract; bump only if a header field is added, removed, or
/// renamed (not expected to happen).
pub const ENVELOPE_SCHEMA_VERSION: u32 = 1;

/// Sentinel `result_type` used on the error envelope, which carries no
/// payload.
pub const ERROR_RESULT_TYPE: &str = "error";

/// Version of the CLI stderr event envelope structure.
pub const CLI_EVENT_SCHEMA_VERSION: u32 = 1;
/// Event discriminator for CLI progress JSONL records.
pub const CLI_PROGRESS_EVENT_TYPE: &str = "progress";
/// Version of the current CLI progress event payload.
pub const CLI_PROGRESS_EVENT_VERSION: u32 = 1;

/// Implemented by every type that can appear as a command `result` payload.
///
/// Uses methods rather than associated consts so that type-erased carriers
/// (the CLI's [`crate::cli::common::BoxedOutput`]) can return the
/// discriminator/version captured from the concrete leaf type at
/// construction time, after the type itself has been erased.
pub trait WirePayload {
    /// Stable discriminator for this payload kind, surfaced as
    /// [`CommandResult::result_type`] (e.g. `"run"`, `"compare"`,
    /// `"run_list"`). Lets a consumer dispatch on the header alone.
    fn result_type(&self) -> &'static str;

    /// Schema version of this payload's contract, surfaced as
    /// [`CommandResult::result_version`]. Bump on any non-additive change.
    fn result_version(&self) -> u32;
}

/// Generate a one-line [`WirePayload`] implementation for a concrete payload
/// type, pinning its stable discriminator and current schema version.
macro_rules! wire_payload {
    ($ty:ty, $result_type:literal, $result_version:literal) => {
        impl $crate::wire::WirePayload for $ty {
            fn result_type(&self) -> &'static str {
                $result_type
            }
            fn result_version(&self) -> u32 {
                $result_version
            }
        }
    };
}
pub(crate) use wire_payload;

/// Opaque passthrough payload for ad hoc JSON values that are not stable data
/// contracts. These are tagged `"opaque"` / version `0` and are not covered by
/// the wire-evolution policy.
impl WirePayload for serde_json::Value {
    fn result_type(&self) -> &'static str {
        "opaque"
    }
    fn result_version(&self) -> u32 {
        0
    }
}

/// Stable JSON envelope wrapping every structured command result.
///
/// Every field except `result` is part of the frozen header contract (see
/// the [module docs](self)). `result` carries the version-specific payload,
/// whose shape is fully described by (`result_type`, `result_version`).
#[derive(Serialize, schemars::JsonSchema)]
pub struct CommandResult {
    /// Version of this envelope structure. See [`ENVELOPE_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Whether the command succeeded.
    pub success: bool,
    /// Discriminator for the `result` payload (`"error"` on failure).
    pub result_type: String,
    /// Schema version of the `result` payload contract (`0` on failure).
    pub result_version: u32,
    /// Wall-clock duration of the command, in seconds.
    pub duration_secs: f64,
    /// Error message; present iff `success` is `false`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// The version-specific result payload; present iff `success` is `true`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
}

impl CommandResult {
    /// Build a success envelope around an already-serialized payload value,
    /// tagged with its `result_type` / `result_version`.
    pub fn ok(
        result_type: &str,
        result_version: u32,
        result: serde_json::Value,
        duration_secs: f64,
    ) -> Self {
        Self {
            schema_version: ENVELOPE_SCHEMA_VERSION,
            success: true,
            result_type: result_type.to_string(),
            result_version,
            duration_secs,
            error: None,
            result: Some(result),
        }
    }

    /// Build a success envelope directly from a typed [`WirePayload`],
    /// reading its discriminator/version and serializing it to JSON.
    pub fn from_payload<T: WirePayload + Serialize>(
        data: &T,
        duration_secs: f64,
    ) -> anyhow::Result<Self> {
        Ok(Self::ok(
            data.result_type(),
            data.result_version(),
            serde_json::to_value(data)?,
            duration_secs,
        ))
    }

    /// Build an error envelope. Carries no payload; `result_type` is
    /// [`ERROR_RESULT_TYPE`] and `result_version` is `0`. Used by the CLI
    /// `--json` path; MCP failures surface as MCP protocol errors instead.
    pub fn err(error: &anyhow::Error, duration_secs: f64) -> Self {
        Self {
            schema_version: ENVELOPE_SCHEMA_VERSION,
            success: false,
            result_type: ERROR_RESULT_TYPE.to_string(),
            result_version: 0,
            duration_secs,
            error: Some(format!("{error:#}")),
            result: None,
        }
    }

    /// Serialize this envelope to a pretty JSON string.
    pub fn to_json_string(&self) -> anyhow::Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Serialize and print this envelope to stdout.
    pub fn print(&self) -> anyhow::Result<()> {
        println!("{}", self.to_json_string()?);
        Ok(())
    }
}

/// Versioned progress event emitted to stderr while `--json` commands are running.
///
/// This uses the generic CLI event envelope header. The `event_type` /
/// `event_version` pair identifies the typed payload field (`progress` here).
#[derive(Serialize, schemars::JsonSchema)]
pub struct CliProgressEvent {
    /// Version of this CLI event envelope structure.
    pub schema_version: u32,
    /// Event discriminator, such as `"progress"`.
    pub event_type: String,
    /// Schema version of this event type's payload.
    pub event_version: u32,
    /// Progress payload. Present when `event_type` is `"progress"`.
    pub progress: CliProgressPayload,
}

/// Payload for `event_type: "progress"` CLI stderr events.
#[derive(Serialize, schemars::JsonSchema)]
pub struct CliProgressPayload {
    /// Stable phase label, such as `"indexing"`, `"baseline"`, or `"replay"`.
    pub phase: String,
    /// Phase-relative current progress value.
    pub current: f64,
    /// Optional phase-relative total.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<f64>,
    /// Optional human-readable status text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl CliProgressEvent {
    pub fn progress(
        phase: impl Into<String>,
        current: f64,
        total: Option<f64>,
        message: Option<String>,
    ) -> Self {
        Self {
            schema_version: CLI_EVENT_SCHEMA_VERSION,
            event_type: CLI_PROGRESS_EVENT_TYPE.to_string(),
            event_version: CLI_PROGRESS_EVENT_VERSION,
            progress: CliProgressPayload {
                phase: phase.into(),
                current,
                total,
                message,
            },
        }
    }
}
