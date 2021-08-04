use std::convert::TryFrom;
use vm::costs::cost_functions::ClarityCostFunction;
use vm::costs::{cost_functions, runtime_cost, CostTracker};
use vm::errors::{
    check_argument_count, CheckErrors, Error, InterpreterError, InterpreterResult as Result,
    RuntimeErrorType,
};
use vm::representations::ClarityName;
use vm::representations::SymbolicExpression;
use vm::types::{
    BuffData, BufferLength, PrincipalData, QualifiedContractIdentifier, SequenceData,
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

    if !version_matches_mainnet(version_byte) && !version_matches_testnet(version_byte) {
        return Err(CheckErrors::InvalidVersionByte.into());
    }

    let buffer_data = match Value::buff_from(hash_bytes.to_vec()) {
        Ok(data) => data,
        Err(err) => return Err(err),
    };

    let tuple_data = TupleData::from_data(vec![
        (
            ClarityName::try_from("version".to_owned()).unwrap(),
            Value::buff_from_byte(version_byte),
        ),
        (
            ClarityName::try_from("hash-bytes".to_owned()).unwrap(),
            buffer_data,
        ),
    ])?;

    Ok(Value::Tuple(tuple_data))
}

pub fn native_principal_construct(version: Value, hash_bytes: Value) -> Result<Value> {
    // Check the version byte.
    let verified_version = match version {
        Value::Sequence(SequenceData::Buffer(BuffData { ref data })) => data,
        _ => return Err(CheckErrors::TypeValueError(TypeSignature::UIntType, version).into()),
    };

    if verified_version.len() != 1 {
        return Err(CheckErrors::TypeValueError(
            TypeSignature::SequenceType(SequenceSubtype::BufferType(BufferLength(1))),
            version,
        )
        .into());
    }

    // Assume: verified_version.len() == 1
    let version_byte = (*verified_version)[0];
    if !version_matches_mainnet(version_byte) && !version_matches_testnet(version_byte) {
        return Err(CheckErrors::InvalidVersionByte.into());
    }

    // Check the hask bytes.
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

    if verified_hash_bytes.len() != 20 {
        return Err(CheckErrors::TypeValueError(
            TypeSignature::SequenceType(SequenceSubtype::BufferType(BufferLength(20))),
            hash_bytes,
        )
        .into());
    }

    // Construct the principal.
    let mut transfer_buffer = [0u8; 20];
    for i in 0..verified_hash_bytes.len() {
        transfer_buffer[i] = verified_hash_bytes[i];
    }
    let principal_data = StandardPrincipalData(version_byte, transfer_buffer);
    Ok(Value::Principal(PrincipalData::Standard(principal_data)))
}
