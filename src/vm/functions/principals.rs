use vm::costs::cost_functions::ClarityCostFunction;
use vm::costs::{cost_functions, runtime_cost, CostTracker};
use vm::errors::{
    check_argument_count, CheckErrors, Error, InterpreterError, InterpreterResult as Result,
    RuntimeErrorType,
};
use vm::representations::SymbolicExpression;
use vm::types::{
    BuffData, PrincipalData, QualifiedContractIdentifier, SequenceData, StandardPrincipalData,
    TypeSignature, Value,
};
use vm::{eval, Environment, LocalContext};

use vm::database::ClarityDatabase;
use vm::database::STXBalance;

use vm::types::PrincipalProperty;

use chainstate::stacks::{
    C32_ADDRESS_VERSION_MAINNET_MULTISIG, C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
    C32_ADDRESS_VERSION_TESTNET_MULTISIG, C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
};

pub fn special_is_standard(
    args: &[SymbolicExpression],
    env: &mut Environment,
    context: &LocalContext,
) -> Result<Value> {
    check_argument_count(1, args)?;
    runtime_cost(ClarityCostFunction::StxTransfer, env, 0)?;
    let owner = eval(&args[0], env, context)?;

    let version = match owner {
        Value::Principal(PrincipalData::Standard(StandardPrincipalData(version, bytes))) => version,
        Value::Principal(PrincipalData::Contract(QualifiedContractIdentifier { issuer, name })) => {
            issuer.0
        }
        _ => return Err(CheckErrors::TypeValueError(TypeSignature::PrincipalType, owner).into()),
    };

    let address_is_mainnet = version == C32_ADDRESS_VERSION_MAINNET_MULTISIG
        || version == C32_ADDRESS_VERSION_MAINNET_SINGLESIG;
    let address_is_testnet = version == C32_ADDRESS_VERSION_TESTNET_MULTISIG
        || version == C32_ADDRESS_VERSION_TESTNET_SINGLESIG;
    let context_is_mainnet = env.global_context.mainnet;

    if address_is_mainnet || address_is_testnet {
        // We can only return true if the address is mainnet or testnet.
        Ok(Value::Bool(address_is_mainnet == context_is_mainnet))
    } else {
        // If the address is not mainnet or testnet, then return false.
        Ok(Value::Bool(false))
    }
}

pub fn special_parse_principal(
    args: &[SymbolicExpression],
    env: &mut Environment,
    context: &LocalContext,
) -> Result<Value> {
    check_argument_count(1, args)?;
    runtime_cost(ClarityCostFunction::StxTransfer, env, 0)?;

    // Handle the block property name input arg.
    let property_name = args[0]
        .match_atom()
        .ok_or(CheckErrors::ParsePrincipalExpectPropertyName)?;

    let principal_property = PrincipalProperty::lookup_by_name(property_name)
        .ok_or(CheckErrors::ParsePrincipalExpectPropertyName)?;

    let principal = eval(&args[1], env, context)?;

    let (version, pub_key_hash) = match principal {
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

    let result = match principal_property {
        PrincipalProperty::Version => Value::UInt(version as u128),
        PrincipalProperty::PubKeyHash => Value::Sequence(SequenceData::Buffer(BuffData {
            data: pub_key_hash.into(),
        })),
    };
    Ok(result)
}
