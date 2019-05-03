use vm::types::Value;
use vm::contexts::{LocalContext, Environment};
use vm::errors::{Error, ErrType, InterpreterResult as Result};

pub enum NativeVariables {
    TxSender, BlockHeight, BurnBlockHeight
}

impl NativeVariables {
    pub fn lookup_by_name(name: &str) -> Option<NativeVariables> {
        use vm::variables::NativeVariables::*;
        match name {
            "tx-sender" => Some(TxSender),
            "block-height" => Some(BlockHeight),
            "burn-block-height" => Some(BurnBlockHeight),
            _ => None
        }
    }
}

pub fn is_reserved_variable(name: &str) -> bool {
    NativeVariables::lookup_by_name(name).is_some()
}

pub fn lookup_reserved_variable(name: &str, _context: &LocalContext, env: &Environment) -> Result<Option<Value>> {
    if let Some(variable) = NativeVariables::lookup_by_name(name) {
        match variable {
            NativeVariables::TxSender => {
                let sender = env.sender.clone()
                    .ok_or(Error::new(ErrType::InvalidArguments(
                        "No sender in current context. Did you attempt to (contract-call ...) from a non-contract aware environment?"
                            .to_string())))?;
                Ok(Some(sender))
            },
            NativeVariables::BlockHeight => {
                let block_height = env.global_context.get_block_height();
                
                Ok(Some(Value::Int(block_height)))
            },
            NativeVariables::BurnBlockHeight => {
                Err(Error::new(ErrType::NotImplemented))
            }
        }
    } else {
        Ok(None)
    }
}
