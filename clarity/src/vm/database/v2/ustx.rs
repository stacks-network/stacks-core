use stacks_common::types::StacksEpochId;
use crate::vm::{types::TypeSignature, Value, errors::{InterpreterError, RuntimeErrorType, InterpreterResult as Result}};
use crate::vm::errors::Error;

use super::ClarityDb;

pub trait ClarityDbUstx : ClarityDb {
    fn ustx_liquid_supply_key() -> &'static str {
        "_stx-data::ustx_liquid_supply"
    }
    
    /// Returns the _current_ total liquid ustx
    fn get_total_liquid_ustx(&mut self) -> Result<u128> {
        let key = Self::ustx_liquid_supply_key();

        let result = self.get_value(
            key,
            &TypeSignature::UIntType,
            &StacksEpochId::latest(),
        )
        .map_err(|_| {
            Error::Interpreter(InterpreterError::FailedToLoadClarityKey(key.to_string()))
        })?;

        if let Some(val) = result {
            if let Value::UInt(x) = val.value {
                Ok(x)
            } else {
                Err(Error::Interpreter(
                    InterpreterError::InterpreterError(
                        "Invalid value stored for ustx_liquid_supply Clarity key"
                        .to_string()),
                ))
            }
        } else {
            Ok(0)
        }
    }

    /// Sets the current USTX liquid supply.
    fn set_ustx_liquid_supply(&mut self, set_to: u128) -> Result<()> {
        self.put_value(
            Self::ustx_liquid_supply_key(),
            Value::UInt(set_to),
            // okay to pin epoch, because ustx_liquid_supply does not need to sanitize
            &StacksEpochId::Epoch21,
        ).map_err(|_| {
            Error::Interpreter(InterpreterError::FailedToStoreClarityKey(
                Self::ustx_liquid_supply_key().to_string(),
            ))
        })
    }

    /// Increases the current USTX liquid supply by `incr_by`.
    fn increment_ustx_liquid_supply(&mut self, incr_by: u128) -> Result<()> {
        let current = self.get_total_liquid_ustx()?;

        let next = current.checked_add(incr_by).ok_or_else(|| {
            error!("Overflowed `ustx-liquid-supply`");
            RuntimeErrorType::ArithmeticOverflow
        })?;

        self.set_ustx_liquid_supply(next)
    }

    /// Reduces the current USTX liquid supply by `decr_by`.
    fn decrement_ustx_liquid_supply(&mut self, decr_by: u128) -> Result<()> {
        let current = self.get_total_liquid_ustx()?;

        let next = current.checked_sub(decr_by).ok_or_else(|| {
            error!("`stx-burn?` accepted that reduces `ustx-liquid-supply` below 0");
            RuntimeErrorType::ArithmeticUnderflow
        })?;

        self.set_ustx_liquid_supply(next)
    }
}