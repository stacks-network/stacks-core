use vm::costs::cost_functions::ClarityCostFunction;
use vm::costs::{cost_functions, runtime_cost, CostTracker};
use vm::errors::{
    check_argument_count, CheckErrors, Error, InterpreterError, InterpreterResult as Result,
    RuntimeErrorType,
};
use vm::representations::ClarityName;
use std::convert::TryFrom;
use vm::representations::SymbolicExpression;
use vm::types::{
    BuffData, BufferLength, PrincipalData, QualifiedContractIdentifier, SequenceData,
    SequenceSubtype, StandardPrincipalData, TupleData, TypeSignature, Value,
};
use vm::{eval, Environment, LocalContext};

use vm::database::ClarityDatabase;
use vm::database::STXBalance;

use burnchains::bitcoin::address::to_c32_version_byte;

use vm::types::PrincipalProperty;

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
        Value::Principal(PrincipalData::Standard(StandardPrincipalData(version, bytes))) => version,
        Value::Principal(PrincipalData::Contract(QualifiedContractIdentifier { issuer, name })) => {
            issuer.0
        }
        _ => return Err(CheckErrors::TypeValueError(TypeSignature::PrincipalType, owner).into()),
    };

    let address_is_mainnet = version_matches_mainnet(version);
    let address_is_testnet = version_matches_testnet(version);
    let context_is_mainnet = env.global_context.mainnet;

    Ok(Value::Bool(
        (address_is_mainnet && context_is_mainnet) || (address_is_testnet && !context_is_mainnet),
    ))
}

pub fn special_parse_principal(
    args: &[SymbolicExpression],
    env: &mut Environment,
    context: &LocalContext,
) -> Result<Value> {
    check_argument_count(1, args)?;
    runtime_cost(ClarityCostFunction::Unimplemented, env, 0)?;
    let principal = eval(&args[0], env, context)?;

    let (version_byte, pub_key_hash) = match principal {
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

    let buffer_data = match Value::buff_from(pub_key_hash.to_vec()) {
        Ok(data) => data,
        Err(err) => return Err(err),
    };

    let tuple_data = TupleData::from_data(vec![
        (
            ClarityName::try_from("version".to_owned()).unwrap(),
            Value::buff_from_byte(version_byte),
        ),
        (
            ClarityName::try_from("version".to_owned()).unwrap(),
            buffer_data,
        ),
    ]);

    match tuple_data {
        Ok(data) => Ok(Value::Tuple(data)),
        Err(err) => Err(err),
    }
    // let result = Value::Tuple(tuple_data);
    // Ok(result)
    // let result = match principal_property {
    //     PrincipalProperty::Version => Value::UInt(version as u128),
    //     PrincipalProperty::PubKeyHash => Value::Sequence(SequenceData::Buffer(BuffData {
    //         data: pub_key_hash.into(),
    //     })),
    // };
    // Ok(result)
}

pub fn native_principal_construct(version: Value, pub_key_hash: Value) -> Result<Value> {
    // Check the version byte.
    let verified_version = match version {
        Value::Sequence(SequenceData::Buffer(BuffData { ref data })) => data,
        _ => return Err(CheckErrors::TypeValueError(TypeSignature::UIntType, version).into()),
    };

    warn!("verified_version {:?}", verified_version);
    if verified_version.len() != 1 {
        return Err(CheckErrors::TypeValueError(
            TypeSignature::SequenceType(SequenceSubtype::BufferType(BufferLength(1))),
            version,
        )
        .into());
    }

    // Assume: verified_version.len() == 1
    let version_byte = (*verified_version)[0];
    warn!("version_byte {:?}", version_byte);
    let checked_byte = to_c32_version_byte(version_byte);
    warn!("checked_byte {:?}", checked_byte);
    if !version_matches_mainnet(version_byte) && !version_matches_testnet(version_byte) {
        return Err(CheckErrors::InvalidVersionByte.into());
    }

    // Check the hask bytes.
    let verified_pub_key_hash = match pub_key_hash {
        Value::Sequence(SequenceData::Buffer(BuffData { ref data })) => data,
        _ => {
            return Err(CheckErrors::TypeValueError(
                TypeSignature::SequenceType(SequenceSubtype::BufferType(BufferLength(20))),
                pub_key_hash,
            )
            .into())
        }
    };

    if verified_pub_key_hash.len() != 20 {
        return Err(CheckErrors::TypeValueError(
            TypeSignature::SequenceType(SequenceSubtype::BufferType(BufferLength(20))),
            pub_key_hash,
        )
        .into());
    }

    // Construct the principal.
    let mut transfer_buffer = [0u8; 20];
    for i in 0..verified_pub_key_hash.len() {
        transfer_buffer[i] = verified_pub_key_hash[i];
    }
    let principal_data = StandardPrincipalData(version_byte, transfer_buffer);
    Ok(Value::Principal(PrincipalData::Standard(principal_data)))
}
