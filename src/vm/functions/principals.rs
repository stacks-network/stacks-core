use std::convert::TryFrom;
use util::hash::hex_bytes;
use vm::costs::cost_functions::ClarityCostFunction;
use vm::costs::{cost_functions, runtime_cost, CostTracker};
use vm::errors::{
    check_argument_count, CheckErrors, Error, InterpreterError, InterpreterResult as Result,
    RuntimeErrorType,
};
use vm::representations::ClarityName;
use vm::representations::SymbolicExpression;
use vm::types::{
    BuffData, BufferLength, PrincipalData, QualifiedContractIdentifier, ResponseData, SequenceData,
    SequenceSubtype, StandardPrincipalData, TupleData, TypeSignature, Value,
};
use vm::{eval, Environment, LocalContext};

use vm::database::ClarityDatabase;
use vm::database::STXBalance;

use chainstate::stacks::{
    C32_ADDRESS_VERSION_MAINNET_MULTISIG, C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
    C32_ADDRESS_VERSION_TESTNET_MULTISIG, C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
};

/// Returns true if `version` indicates a mainnet address.
fn version_matches_mainnet(version: u8) -> bool {
    version == C32_ADDRESS_VERSION_MAINNET_MULTISIG
        || version == C32_ADDRESS_VERSION_MAINNET_SINGLESIG
}

/// Returns true if `version` indicates a testnet address.
fn version_matches_testnet(version: u8) -> bool {
    version == C32_ADDRESS_VERSION_TESTNET_MULTISIG
        || version == C32_ADDRESS_VERSION_TESTNET_SINGLESIG
}

pub fn special_is_standard(
    args: &[SymbolicExpression],
    env: &mut Environment,
    context: &LocalContext,
) -> Result<Value> {
    check_argument_count(1, args)?;
    runtime_cost(ClarityCostFunction::Unimplemented, env, 0)?;
    let owner = eval(&args[0], env, context)?;

    let version = match owner {
        Value::Principal(PrincipalData::Standard(StandardPrincipalData(version, _bytes))) => {
            version
        }
        Value::Principal(PrincipalData::Contract(QualifiedContractIdentifier {
            issuer,
            name: _,
        })) => issuer.0,
        _ => return Err(CheckErrors::TypeValueError(TypeSignature::PrincipalType, owner).into()),
    };

    let address_is_mainnet = version_matches_mainnet(version);
    let address_is_testnet = version_matches_testnet(version);
    let context_is_mainnet = env.global_context.mainnet;

    Ok(Value::Bool(
        (address_is_mainnet && context_is_mainnet) || (address_is_testnet && !context_is_mainnet),
    ))
}

/// Creates a Tuple which is the result of parsing a Principal tuple into a Tuple of its `version`
/// and `hash-bytes`.
fn create_principal_parse_tuple(version: u8, hash_bytes: &[u8; 20]) -> Value {
    Value::Tuple(
        TupleData::from_data(vec![
            (
                "version".into(),
                Value::Sequence(SequenceData::Buffer(BuffData {
                    data: vec![version],
                })),
            ),
            (
                "hash-bytes".into(),
                Value::Sequence(SequenceData::Buffer(BuffData {
                    data: hash_bytes.to_vec(),
                })),
            ),
        ])
        .expect("FAIL: Failed to initialize tuple."),
    )
}

/// Creates Response return type, to wrap an *actual error* result of a `principal-construct` or
/// `principal-parse`.
///
/// The response is an error Response, where the `err` value is a tuple `{error_int,parse_tuple}`.
/// `error_int` is of type `UInt`, `parse_tuple` is None.
fn create_principal_true_error_response(error_int: u32) -> Value {
    Value::Response(ResponseData {
        committed: false,
        data: Box::new(Value::Tuple(
            TupleData::from_data(vec![
                ("error_int".into(), Value::UInt(error_int.into())),
                ("value".into(), Value::none()),
            ])
            .expect("FAIL: Failed to initialize tuple."),
        )),
    })
}

/// Creates Response return type, to wrap a *return value returned as an error* result of a
/// `principal-construct` or `principal-parse`.
///
/// The response is an error Response, where the `err` value is a tuple `{error_int,value}`.
/// `error_int` is of type `UInt`, `value` is of type `Some(Value)`.
fn create_principal_value_error_response(error_int: u32, value: Value) -> Value {
    Value::Response(ResponseData {
        committed: false,
        data: Box::new(Value::Tuple(
            TupleData::from_data(vec![
                ("error_int".into(), Value::UInt(error_int.into())),
                (
                    "value".into(),
                    Value::some(value).expect("Unexpected problem creating Value."),
                ),
            ])
            .expect("FAIL: Failed to initialize tuple."),
        )),
    })
}

pub fn native_principal_parse(principal: Value) -> Result<Value> {
    let (version_byte, hash_bytes) = match principal {
        Value::Principal(PrincipalData::Standard(StandardPrincipalData(version, bytes))) => {
            (version, bytes)
        }
        Value::Principal(PrincipalData::Contract(QualifiedContractIdentifier { issuer, name })) => {
            (issuer.0, issuer.1)
        }
        _ => {
            return Err(CheckErrors::TypeValueError(TypeSignature::PrincipalType, principal).into())
        }
    };

    // `version_byte_is_valid` determines whether the returned `Response` is through the success
    // channel or the error channel.
    // DO NOT SUBMIT: Should this be "version byte matches network"?
    let version_byte_is_valid =
        version_matches_mainnet(version_byte) || version_matches_testnet(version_byte);

    let tuple = create_principal_parse_tuple(version_byte, &hash_bytes);
    if version_byte_is_valid {
        Ok(tuple)
    } else {
        Ok(create_principal_value_error_response(2, tuple))
    }
}

pub fn native_principal_construct(version: Value, hash_bytes: Value) -> Result<Value> {
    // Check the version byte.
    let verified_version = match version {
        Value::Sequence(SequenceData::Buffer(BuffData { ref data })) => data,
        _ => {
            return {
                // This is an aborting error because this should have been caught in analysis pass.
                Err(CheckErrors::TypeValueError(
                    TypeSignature::SequenceType(SequenceSubtype::BufferType(BufferLength(1))),
                    version,
                )
                .into())
            };
        }
    };

    // This is an aborting error because this should have been caught in analysis pass.
    if verified_version.len() > 1 {
        return Err(CheckErrors::TypeValueError(
            TypeSignature::SequenceType(SequenceSubtype::BufferType(BufferLength(1))),
            version,
        )
        .into());
    }

    // If the version byte buffer has 0 bytes, this is a recoverable error, because it wasn't the
    // job of the type system.
    if verified_version.len() < 1 {
        // do some kind of error
        return Ok(create_principal_true_error_response(1));
    }

    // Assume: verified_version.len() == 1
    let version_byte = (*verified_version)[0];

    // If the version byte is >= 32, this is a recoverable error, because it wasn't the job of the
    // type system.
    if version_byte >= 32 {
        return Ok(create_principal_true_error_response(1));
    }

    // `version_byte_is_valid` determines whether the returned `Response` is through the success
    // channel or the error channel.
    let version_byte_is_valid =
        version_matches_mainnet(version_byte) || version_matches_testnet(version_byte);

    // Check the hash bytes.
    // This is an aborting error because this should have been caught in analysis pass.
    let verified_hash_bytes = match hash_bytes {
        Value::Sequence(SequenceData::Buffer(BuffData { ref data })) => data,
        _ => {
            return Err(CheckErrors::TypeValueError(
                TypeSignature::SequenceType(SequenceSubtype::BufferType(BufferLength(20))),
                hash_bytes,
            )
            .into())
        }
    };

    // This is an aborting error because this should have been caught in analysis pass.
    if verified_hash_bytes.len() > 20 {
        return Err(CheckErrors::TypeValueError(
            TypeSignature::SequenceType(SequenceSubtype::BufferType(BufferLength(20))),
            hash_bytes,
        )
        .into());
    }

    // If the hash-bytes buffer has less than 20 bytes, this is a recoverable error, because it
    // wasn't the job of the type system.
    if verified_hash_bytes.len() < 20 {
        return Ok(create_principal_true_error_response(1));
    }

    // Construct the principal.
    let mut transfer_buffer = [0u8; 20];
    transfer_buffer.copy_from_slice(&verified_hash_bytes);
    let principal_data = StandardPrincipalData(version_byte, transfer_buffer);

    let principal = Value::Principal(PrincipalData::Standard(principal_data));
    if version_byte_is_valid {
        Ok(principal)
    } else {
        Ok(create_principal_value_error_response(2, principal))
    }
}
