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

//! Request-body parsing shared by the read-only RPC endpoints, run under a
//! [`ParseLimiter`] against `read_only_call_max_mem_bytes`.
//! Preflights charge sizes known before allocating and hold even without the
//! `TrackingAllocator`; checkpoints compare the thread's net retained
//! allocations to the limit and measure nothing without it. What parsing
//! retains is deducted from the same limit before execution.

use std::fmt;

use clarity::vm::resource_limiter::{ResourceBudget, ResourceLimitExceeded, ResourceLimiter};
use clarity::vm::types::PrincipalData;
use clarity::vm::Value;
use serde::de::{self, DeserializeOwned, IgnoredAny, SeqAccess, Visitor};
use serde::Deserializer;
use stacks_common::util::hash::hex_bytes;

use crate::chainstate::stacks::MAX_TRANSACTION_LEN;
use crate::net::http::Error;

/// Shortest Clarity parameter declaration, `(a int)`, plus a separating space.
const MIN_FUNCTION_PARAMETER_SRC_BYTES: usize = 8;
/// No deployable function can take more parameters: pre-epoch-3.3 contracts
/// must fit in one transaction (epoch 3.3+ caps parameters at 256). This cap
/// bounds per-element overhead during JSON parsing, where the allocation
/// checkpoints cannot run yet; it applies even when the byte budget is `0`.
pub const MAX_READ_ONLY_CALL_ARGUMENTS: usize =
    MAX_TRANSACTION_LEN as usize / MIN_FUNCTION_PARAMETER_SRC_BYTES;

/// JSON body of a read-only call request.
#[derive(Clone, Serialize, Deserialize)]
pub struct CallReadOnlyRequestBody {
    /// Principal used as the read-only call sender.
    pub sender: String,
    /// Optional principal used as the sponsored call sponsor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sponsor: Option<String>,
    /// Hex-encoded Clarity arguments passed to the target function.
    #[serde(deserialize_with = "bounded_arguments")]
    pub arguments: Vec<String>,
}

struct BoundedArgumentsVisitor;

impl<'de> Visitor<'de> for BoundedArgumentsVisitor {
    type Value = Vec<String>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a bounded list of read-only call arguments")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut arguments = Vec::new();

        while arguments.len() < MAX_READ_ONLY_CALL_ARGUMENTS {
            let Some(argument) = seq.next_element::<String>()? else {
                return Ok(arguments);
            };
            arguments.push(argument);
        }

        // `IgnoredAny` avoids materializing the over-the-cap element.
        if seq.next_element::<IgnoredAny>()?.is_some() {
            return Err(de::Error::custom(format!(
                "Too many argument values: {} > {MAX_READ_ONLY_CALL_ARGUMENTS}",
                arguments.len() + 1
            )));
        }

        Ok(arguments)
    }
}

/// Deserialize the `arguments` array while bounding its element count.
fn bounded_arguments<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_seq(BoundedArgumentsVisitor)
}

/// Enforces the parse share of the request's memory budget: a memory-only
/// [`ResourceLimiter`] plus prospective checks and typed 400s.
struct ParseLimiter {
    limiter: ResourceLimiter,
}

/// 400 for a limit overrun already measured by the limiter.
fn exceeded_mem_limit(e: ResourceLimitExceeded) -> Error {
    let msg = match e {
        ResourceLimitExceeded::MaxAllocationExceeded(msg)
        | ResourceLimitExceeded::MaxDurationExceeded(msg) => msg,
    };
    Error::DecodeError(format!(
        "Read-only argument parsing exceeded memory limit: {msg}"
    ))
}

impl ParseLimiter {
    /// Starts measuring now; a `limit_bytes` of `0` disables all checks.
    fn new(limit_bytes: u64) -> Self {
        Self {
            limiter: ResourceBudget::new()
                .with_max_memory_use((limit_bytes > 0).then_some(limit_bytes))
                .start_tracking(),
        }
    }

    /// Reject an upcoming allocation of `bytes`. Retention is checked first so
    /// an over-budget parse and an oversized value report different errors.
    fn preflight(&self, bytes: u64) -> Result<(), Error> {
        self.limiter
            .check_can_allocate(0)
            .map_err(exceeded_mem_limit)?;
        self.limiter.check_can_allocate(bytes).map_err(|_e| {
            Error::DecodeError("Read-only argument value exceeds parse memory limit".into())
        })
    }

    /// Reject if net retention since the baseline exceeds the limit.
    fn checkpoint(&self) -> Result<(), Error> {
        self.preflight(0)
    }

    /// Net bytes retained since the baseline (`0` when untracked), to deduct
    /// from the execution budget.
    fn finish(&self) -> Result<u64, Error> {
        self.checkpoint()?;
        Ok(self.limiter.net_allocated_bytes().unwrap_or(0))
    }
}

/// Execution's share of the per-request memory total: whatever parsing did
/// not retain. `None` (a total of `0`) leaves execution unlimited.
pub fn remaining_execution_mem_budget(
    total_mem_bytes: u64,
    parse_retained_mem_bytes: u64,
) -> Option<u64> {
    if total_mem_bytes == 0 {
        return None;
    }
    Some(total_mem_bytes.saturating_sub(parse_retained_mem_bytes))
}

/// Parse a JSON body, preflighting its wire size: it approximates what parsing
/// retains, so oversized bodies are rejected before allocating. The body buffer
/// is allocated before the baseline, so the HTTP length check bounds it instead.
fn parse_json_body<T: DeserializeOwned>(body: &[u8], limiter: &ParseLimiter) -> Result<T, Error> {
    limiter.preflight(body.len() as u64)?;
    let parsed: T = serde_json::from_slice(body)
        .map_err(|e| Error::DecodeError(format!("Failed to parse JSON body: {e}")))?;
    limiter.checkpoint()?;
    Ok(parsed)
}

/// Decode one hex-encoded Clarity value under the limiter. `error_msg` keeps
/// each endpoint's pre-existing error string.
fn deserialize_value(
    hex: &str,
    limiter: &ParseLimiter,
    error_msg: &'static str,
) -> Result<Value, Error> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    // The decoded size is known before allocating; reject early.
    limiter.preflight((hex.len() as u64).div_ceil(2))?;
    let value = {
        let data = hex_bytes(hex).map_err(|_e| Error::DecodeError(error_msg.into()))?;
        Value::deserialize_read(&mut data.as_slice(), None, false)
            .map_err(|_e| Error::DecodeError(error_msg.into()))?
    };
    limiter.checkpoint()?;
    Ok(value)
}

/// Decode a full read-only argument vector under the limiter.
fn deserialize_arguments(
    arguments: Vec<String>,
    limiter: &ParseLimiter,
) -> Result<Vec<Value>, Error> {
    debug_assert!(arguments.len() <= MAX_READ_ONLY_CALL_ARGUMENTS);
    // The reservation below is the one allocation not covered by a checkpoint.
    limiter
        .preflight((arguments.len() as u64).saturating_mul(std::mem::size_of::<Value>() as u64))?;
    let mut values = Vec::with_capacity(arguments.len());
    for hex in arguments {
        values.push(deserialize_value(
            &hex,
            limiter,
            "Failed to deserialize argument value",
        )?);
    }

    Ok(values)
}

/// A parsed call body and the net bytes parsing retained.
pub struct ParsedReadOnlyCall {
    pub sender: PrincipalData,
    pub sponsor: Option<PrincipalData>,
    pub arguments: Vec<Value>,
    pub retained_mem_bytes: u64,
}

/// Parse and deserialize the JSON body shared by the read-only call endpoints.
pub fn parse_read_only_call_body(
    body: &[u8],
    max_parse_mem_bytes: u64,
) -> Result<ParsedReadOnlyCall, Error> {
    let limiter = ParseLimiter::new(max_parse_mem_bytes);
    let body: CallReadOnlyRequestBody = parse_json_body(body, &limiter)?;

    let sender = PrincipalData::parse(&body.sender)
        .map_err(|_e| Error::DecodeError("Failed to parse sender principal".into()))?;

    let sponsor = body
        .sponsor
        .map(|sponsor| {
            PrincipalData::parse(&sponsor)
                .map_err(|_e| Error::DecodeError("Failed to parse sponsor principal".into()))
        })
        .transpose()?;

    let arguments = deserialize_arguments(body.arguments, &limiter)?;

    Ok(ParsedReadOnlyCall {
        sender,
        sponsor,
        arguments,
        retained_mem_bytes: limiter.finish()?,
    })
}

/// Parse the `getmapentry` body: one JSON string holding a hex-encoded map key.
pub fn parse_map_key_body(body: &[u8], max_parse_mem_bytes: u64) -> Result<Value, Error> {
    let limiter = ParseLimiter::new(max_parse_mem_bytes);
    let key_hex: String = parse_json_body(body, &limiter)?;
    let value = deserialize_value(&key_hex, &limiter, "Failed to deserialize key value")?;
    limiter.finish()?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::remaining_execution_mem_budget;

    #[test]
    fn test_remaining_execution_mem_budget() {
        // 0 total keeps the execution limit disabled.
        assert_eq!(remaining_execution_mem_budget(0, 500), None);
        assert_eq!(remaining_execution_mem_budget(1000, 300), Some(700));
        assert_eq!(remaining_execution_mem_budget(1000, 1000), Some(0));
        assert_eq!(remaining_execution_mem_budget(1000, 2000), Some(0));
    }
}
