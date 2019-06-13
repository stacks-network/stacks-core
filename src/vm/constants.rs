use::std::convert::TryFrom;
use vm::types::Value;
use vm::contexts::{LocalContext, Environment};
use vm::errors::{Error, ErrType, InterpreterResult as Result};

pub enum NativeConstants {
    TxSender, BlockHeight, BurnBlockHeight
}

impl NativeConstants {
    pub fn lookup_by_name(name: &str) -> Option<NativeConstants> {
        use vm::constants::NativeConstants::*;
        match name {
            "tx-sender" => Some(TxSender),
            "block-height" => Some(BlockHeight),
            "burn-block-height" => Some(BurnBlockHeight),
            _ => None
        }
    }
}

pub fn is_reserved_name(name: &str) -> bool {
    NativeConstants::lookup_by_name(name).is_some()
}

pub fn lookup_reserved_constant(name: &str, _context: &LocalContext, env: &Environment) -> Result<Option<Value>> {
    if let Some(constant) = NativeConstants::lookup_by_name(name) {
        match constant {
            NativeConstants::TxSender => {
                let sender = env.sender.clone()
                    .ok_or(Error::new(ErrType::InvalidArguments(
                        "No sender in current context. Did you attempt to (contract-call ...) from a non-contract aware environment?"
                            .to_string())))?;
                Ok(Some(sender))
            },
            NativeConstants::BlockHeight => {
                let block_height = env.global_context.get_block_height();
                Ok(Some(Value::Int(block_height as i128)))
            },
            NativeConstants::BurnBlockHeight => {
                Err(Error::new(ErrType::NotImplemented))
            }
        }
    } else {
        Ok(None)
    }
}
