use vm::costs::cost_functions::ClarityCostFunction;
use vm::costs::{cost_functions, runtime_cost, CostTracker};
use vm::errors::{
    check_argument_count, CheckErrors, Error, InterpreterError, InterpreterResult as Result,
    RuntimeErrorType,
};
use vm::representations::SymbolicExpression;
use vm::types::{
    PrincipalData, QualifiedContractIdentifier, StandardPrincipalData, TypeSignature, Value,
};
use vm::{eval, Environment, LocalContext};

use vm::database::ClarityDatabase;
use vm::database::STXBalance;

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

    let address_is_mainnet = version == C32_ADDRESS_VERSION_MAINNET_MULTISIG
        || version == C32_ADDRESS_VERSION_MAINNET_SINGLESIG;
    let address_is_testnet = version == C32_ADDRESS_VERSION_TESTNET_MULTISIG
        || version == C32_ADDRESS_VERSION_TESTNET_SINGLESIG;
    let context_is_mainnet = env.global_context.mainnet;

    Ok(Value::Bool(
        (address_is_mainnet && context_is_mainnet) || (address_is_testnet && !context_is_mainnet),
    ))
}
