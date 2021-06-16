use vm::costs::cost_functions::ClarityCostFunction;
use vm::costs::{cost_functions, runtime_cost, CostTracker};
use vm::errors::{
    check_argument_count, CheckErrors, Error, InterpreterError, InterpreterResult as Result,
    RuntimeErrorType,
};
use vm::representations::SymbolicExpression;
use vm::types::{TypeSignature, Value, PrincipalData, StandardPrincipalData};
use vm::{eval, Environment, LocalContext};

use vm::database::ClarityDatabase;
use vm::database::STXBalance;

pub fn special_principal_matches(
    args: &[SymbolicExpression],
    env: &mut Environment,
    context: &LocalContext,
) -> Result<Value> {
    check_argument_count(1, args)?;
    runtime_cost(ClarityCostFunction::StxTransfer, env, 0)?;
    let owner = eval(&args[0], env, context)?;

    match owner {
        Value::Principal(PrincipalData::Contract(ref identifier)) => Ok(Value::UInt(0)),
        Value::Principal(PrincipalData::Standard(StandardPrincipalData(version, bytes))) => {
        println!("identifier {:?} {:?}", version, bytes);
        Ok(Value::UInt(1))

        }
        _ => Err(CheckErrors::TypeValueError(TypeSignature::PrincipalType, owner).into()),
    }
}
