use std::convert::TryFrom;
use vm::contexts::{Environment, LocalContext};
use vm::errors::{InterpreterResult as Result, RuntimeErrorType};
use vm::types::BuffData;
use vm::types::Value;

define_named_enum!(NativeVariables {
    ContractCaller("contract-caller"), TxSender("tx-sender"), BlockHeight("block-height"),
    BurnBlockHeight("burn-block-height"), NativeNone("none"),
    NativeTrue("true"), NativeFalse("false"),
    TotalLiquidMicroSTX("stx-liquid-supply"),
    Regtest("is-in-regtest"),
});

pub fn is_reserved_name(name: &str) -> bool {
    NativeVariables::lookup_by_name(name).is_some()
}

pub fn lookup_reserved_variable(
    name: &str,
    _context: &LocalContext,
    env: &mut Environment,
) -> Result<Option<Value>> {
    if let Some(variable) = NativeVariables::lookup_by_name(name) {
        match variable {
            NativeVariables::TxSender => {
                let sender = env
                    .sender
                    .clone()
                    .ok_or(RuntimeErrorType::NoSenderInContext)?;
                Ok(Some(sender))
            }
            NativeVariables::ContractCaller => {
                let sender = env
                    .caller
                    .clone()
                    .ok_or(RuntimeErrorType::NoSenderInContext)?;
                Ok(Some(sender))
            }
            NativeVariables::BlockHeight => {
                let block_height = env.global_context.database.get_current_block_height();
                Ok(Some(Value::UInt(block_height as u128)))
            }
            NativeVariables::BurnBlockHeight => {
                let burn_block_height = env
                    .global_context
                    .database
                    .get_current_burnchain_block_height();
                Ok(Some(Value::UInt(burn_block_height as u128)))
            }
            NativeVariables::NativeNone => Ok(Some(Value::none())),
            NativeVariables::NativeTrue => Ok(Some(Value::Bool(true))),
            NativeVariables::NativeFalse => Ok(Some(Value::Bool(false))),
            NativeVariables::TotalLiquidMicroSTX => {
                let liq = env.global_context.database.get_total_liquid_ustx();
                Ok(Some(Value::UInt(liq)))
            }
            NativeVariables::Regtest => {
                let reg = env.global_context.database.is_in_regtest();
                Ok(Some(Value::Bool(reg)))
            }
        }
    } else {
        Ok(None)
    }
}
