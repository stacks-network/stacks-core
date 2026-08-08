// Copyright (C) 2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Serialized, engine-agnostic conformance vectors for Clarity engines.
//!
//! The format contains only kernel ABI inputs and normalized observations.
//! A new engine can therefore run an existing suite without linking the
//! engine that originally recorded the golden results.

use clarity_kernel::assets::AssetMap;
use clarity_kernel::costs::ExecutionCost;
use clarity_kernel::database::{ClarityDatabase, MemoryBackingStore};
use clarity_kernel::engine::{CostBudget, Engine, EngineError, TransactionContext};
use clarity_kernel::events::StacksTransactionEvent;
use clarity_kernel::resource_limiter::ResourceBudget;
use clarity_kernel::rules::KernelRuleset;
use clarity_types::ClarityVersion;
use clarity_types::types::{
    PrincipalData, QualifiedContractIdentifier, StandardPrincipalData, Value,
};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use stacks_common::codec::StacksMessageCodec;
use stacks_common::consts::CHAIN_ID_TESTNET;
use stacks_common::types::StacksEpochId;
use stacks_common::util::hash::{Sha256Sum, hex_bytes, to_hex};

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VectorSuite {
    pub schema_version: u32,
    pub target: String,
    pub cases: Vec<VectorCase>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VectorCase {
    pub name: String,
    pub epoch: StacksEpochId,
    pub language_version: ClarityVersion,
    pub contract_name: String,
    pub source: String,
    pub steps: Vec<VectorStep>,
    #[serde(default)]
    pub expected: Vec<Observation>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum VectorStep {
    Analyze,
    Initialize,
    SaveAnalysis,
    Call {
        function: String,
        #[serde(default)]
        /// Clarity values encoded with their consensus codec, as lowercase
        /// hexadecimal. This preserves the full `u128` range and every
        /// compound value without coupling the schema to Rust serde details.
        args: Vec<String>,
        #[serde(default)]
        sender: Option<PrincipalData>,
        #[serde(default)]
        sponsor: Option<PrincipalData>,
        #[serde(default)]
        abort_reason: Option<String>,
    },
    ReadOnly {
        expression: String,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub result: ObservationResult,
    pub cumulative_cost: ExecutionCost,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObservationResult {
    Analysis {
        interface_sha256: String,
    },
    Deployment {
        assets: JsonValue,
        events: Vec<JsonValue>,
    },
    AnalysisSaved,
    Execution {
        value: String,
        assets: JsonValue,
        events: Vec<JsonValue>,
    },
    ReadOnly {
        value: String,
    },
    Error {
        error: ErrorObservation,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ErrorObservation {
    Parse {
        rejectable: bool,
        messages: Vec<String>,
    },
    Static {
        message: String,
    },
    Cost {
        total: ExecutionCost,
        limit: ExecutionCost,
    },
    Execution {
        message: String,
    },
    Aborted {
        output: Option<String>,
        assets: JsonValue,
        events: Vec<JsonValue>,
        reason: String,
    },
    Internal {
        message: String,
    },
}

pub fn parse_suite(json: &str) -> Result<VectorSuite, String> {
    let suite: VectorSuite = serde_json::from_str(json)
        .map_err(|error| format!("Invalid conformance vector JSON: {error}"))?;
    if suite.schema_version != SCHEMA_VERSION {
        return Err(format!(
            "Unsupported conformance schema version {}; expected {SCHEMA_VERSION}",
            suite.schema_version
        ));
    }
    Ok(suite)
}

pub fn record_suite(engine: &dyn Engine, suite: &VectorSuite) -> Result<VectorSuite, String> {
    if suite.schema_version != SCHEMA_VERSION {
        return Err(format!(
            "Unsupported conformance schema version {}; expected {SCHEMA_VERSION}",
            suite.schema_version
        ));
    }
    let mut recorded = suite.clone();
    for case in &mut recorded.cases {
        case.expected = run_case(engine, case)?;
    }
    Ok(recorded)
}

pub fn verify_suite(engine: &dyn Engine, suite: &VectorSuite) -> Result<(), String> {
    for case in &suite.cases {
        let actual = run_case(engine, case)?;
        if actual != case.expected {
            let expected = serde_json::to_string_pretty(&case.expected)
                .map_err(|error| format!("Failed to format expected observations: {error}"))?;
            let actual = serde_json::to_string_pretty(&actual)
                .map_err(|error| format!("Failed to format actual observations: {error}"))?;
            return Err(format!(
                "Conformance case {:?} diverged\nexpected:\n{expected}\nactual:\n{actual}",
                case.name
            ));
        }
    }
    Ok(())
}

pub fn run_case(engine: &dyn Engine, case: &VectorCase) -> Result<Vec<Observation>, String> {
    let mut store = MemoryBackingStore::new();
    {
        let mut db = store.as_clarity_db();
        db.begin();
        db.set_clarity_epoch_version(case.epoch)
            .map_err(|error| format!("Failed to set test epoch: {error}"))?;
        db.commit()
            .map_err(|error| format!("Failed to commit test epoch: {error}"))?;
    }
    let ruleset = match case.epoch {
        StacksEpochId::Epoch41 => KernelRuleset::V4,
        StacksEpochId::Epoch40 | StacksEpochId::Epoch34 => KernelRuleset::V3,
        StacksEpochId::Epoch24
        | StacksEpochId::Epoch25
        | StacksEpochId::Epoch30
        | StacksEpochId::Epoch31
        | StacksEpochId::Epoch32
        | StacksEpochId::Epoch33 => KernelRuleset::V2,
        _ => KernelRuleset::V1,
    };
    let mut context = TransactionContext::new(
        store.as_clarity_db(),
        false,
        CHAIN_ID_TESTNET,
        case.epoch,
        ruleset,
    )
    .with_budget(CostBudget::Limited(ExecutionCost::max_value()));
    let contract = contract_id(&case.contract_name)?;
    let mut analyzed = None;
    let mut observations = Vec::with_capacity(case.steps.len());

    for step in &case.steps {
        let result = match step {
            VectorStep::Analyze => match engine.analyze_contract(
                &mut context,
                &contract,
                &case.source,
                case.language_version,
                &ResourceBudget::unlimited(),
            ) {
                Ok(value) => {
                    let interface = serde_json::to_value(value.interface()).map_err(|error| {
                        format!("Failed to serialize stored contract analysis: {error}")
                    })?;
                    // `serde_json::Value` canonicalizes object keys in its
                    // ordered map before hashing; directly serializing the
                    // source HashMaps would make fingerprints process-random.
                    let canonical = serde_json::to_vec(&interface).map_err(|error| {
                        format!("Failed to canonicalize stored contract analysis: {error}")
                    })?;
                    let interface_sha256 = Sha256Sum::from_data(&canonical).to_string();
                    analyzed = Some(value);
                    ObservationResult::Analysis { interface_sha256 }
                }
                Err(error) => ObservationResult::Error {
                    error: observe_error(error)?,
                },
            },
            VectorStep::Initialize => {
                let analyzed = analyzed.as_ref().ok_or_else(|| {
                    format!(
                        "Case {:?} initializes before successful analysis; prior observations: {observations:?}",
                        case.name
                    )
                })?;
                match engine.initialize_contract(
                    &mut context,
                    analyzed,
                    None,
                    None,
                    &ResourceBudget::unlimited(),
                ) {
                    Ok(outcome) => ObservationResult::Deployment {
                        assets: outcome.assets.to_json(),
                        events: observe_events(&outcome.events)?,
                    },
                    Err(error) => ObservationResult::Error {
                        error: observe_error(error)?,
                    },
                }
            }
            VectorStep::SaveAnalysis => {
                let analyzed = analyzed.as_ref().ok_or_else(|| {
                    format!("Case {:?} saves before successful analysis", case.name)
                })?;
                match engine.save_analysis(&mut context, analyzed) {
                    Ok(()) => ObservationResult::AnalysisSaved,
                    Err(error) => ObservationResult::Error {
                        error: observe_error(error)?,
                    },
                }
            }
            VectorStep::Call {
                function,
                args,
                sender,
                sponsor,
                abort_reason,
            } => {
                let args = args
                    .iter()
                    .map(|argument| decode_value(argument))
                    .collect::<Result<Vec<_>, _>>()?;
                let sender = sender
                    .clone()
                    .unwrap_or_else(|| StandardPrincipalData::transient().into());
                let abort_reason_for_callback = abort_reason.clone();
                let mut abort = move |_assets: &AssetMap, _db: &mut ClarityDatabase<'_>| {
                    abort_reason_for_callback.clone()
                };
                let abort = abort_reason.as_ref().map(|_| {
                    &mut abort
                        as &mut dyn FnMut(&AssetMap, &mut ClarityDatabase<'_>) -> Option<String>
                });
                match engine.execute_call(
                    &mut context,
                    sender,
                    sponsor.clone(),
                    &contract,
                    function,
                    &args,
                    abort,
                    &ResourceBudget::unlimited(),
                ) {
                    Ok(outcome) => ObservationResult::Execution {
                        value: outcome.value.to_string(),
                        assets: outcome.assets.to_json(),
                        events: observe_events(&outcome.events)?,
                    },
                    Err(error) => ObservationResult::Error {
                        error: observe_error(error)?,
                    },
                }
            }
            VectorStep::ReadOnly { expression } => {
                match engine.eval_read_only(&mut context, &contract, expression) {
                    Ok(value) => ObservationResult::ReadOnly {
                        value: value.to_string(),
                    },
                    Err(error) => ObservationResult::Error {
                        error: observe_error(error)?,
                    },
                }
            }
        };
        observations.push(Observation {
            result,
            cumulative_cost: cumulative_cost(&mut context)?,
        });
    }
    Ok(observations)
}

pub fn encode_value(value: &Value) -> String {
    to_hex(&<Value as StacksMessageCodec>::serialize_to_vec(value))
}

pub fn decode_value(encoded: &str) -> Result<Value, String> {
    let bytes = hex_bytes(encoded)
        .map_err(|error| format!("Invalid consensus-value hexadecimal: {error}"))?;
    let mut cursor = std::io::Cursor::new(bytes.as_slice());
    let value = Value::consensus_deserialize(&mut cursor)
        .map_err(|error| format!("Invalid consensus-serialized Clarity value: {error}"))?;
    if cursor.position() != bytes.len() as u64 {
        return Err("Consensus-serialized Clarity value has trailing bytes".into());
    }
    Ok(value)
}

fn contract_id(name: &str) -> Result<QualifiedContractIdentifier, String> {
    Ok(QualifiedContractIdentifier::new(
        StandardPrincipalData::transient(),
        name.to_string()
            .try_into()
            .map_err(|error| format!("Invalid vector contract name {name:?}: {error}"))?,
    ))
}

fn cumulative_cost(context: &mut TransactionContext<'_>) -> Result<ExecutionCost, String> {
    let tracker = context
        .take_cost_tracker()
        .ok_or_else(|| "Engine did not restore the cumulative cost tracker".to_string())?;
    let total = tracker.get_total();
    context.restore_cost_tracker(tracker);
    Ok(total)
}

fn observe_events(events: &[StacksTransactionEvent]) -> Result<Vec<JsonValue>, String> {
    events
        .iter()
        .enumerate()
        .map(|(index, event)| {
            let mut value = event
                .json_serialize(index, &"conformance-vector", true)
                .map_err(|error| format!("Failed to serialize event: {error}"))?;
            let object = value
                .as_object_mut()
                .ok_or_else(|| "Event JSON was not an object".to_string())?;
            // The vector order already captures the event index. Transaction
            // id and receipt commitment are host envelope fields, not engine
            // output, so exclude all three from the normalized observation.
            object.remove("txid");
            object.remove("event_index");
            object.remove("committed");
            Ok(value)
        })
        .collect()
}

fn observe_error(error: EngineError) -> Result<ErrorObservation, String> {
    Ok(match error {
        EngineError::Parse {
            diagnostics,
            rejectable,
        } => ErrorObservation::Parse {
            rejectable,
            messages: diagnostics
                .into_iter()
                .map(|diagnostic| diagnostic.message.to_string())
                .collect(),
        },
        EngineError::Static(error) => ErrorObservation::Static {
            message: error.diagnostic.message.to_string(),
        },
        EngineError::Cost(total, limit) => ErrorObservation::Cost { total, limit },
        EngineError::Execution(error) => ErrorObservation::Execution {
            message: error.to_string(),
        },
        EngineError::AbortedByCallback {
            output,
            assets,
            events,
            reason,
        } => ErrorObservation::Aborted {
            output: output.map(|value| value.to_string()),
            assets: assets.to_json(),
            events: observe_events(&events)?,
            reason,
        },
        EngineError::Internal(message) => ErrorObservation::Internal { message },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consensus_value_arguments_round_trip_the_full_uint_range() {
        let value = Value::okay(Value::UInt(u128::MAX)).unwrap();
        let encoded = encode_value(&value);
        assert_eq!(decode_value(&encoded).unwrap(), value);
        assert!(decode_value(&format!("{encoded}00")).is_err());
    }

    #[test]
    fn parser_rejects_unknown_schema_versions() {
        let error =
            parse_suite(r#"{"schema_version":2,"target":"future","cases":[]}"#).unwrap_err();
        assert!(error.contains("Unsupported conformance schema version 2"));
    }
}
