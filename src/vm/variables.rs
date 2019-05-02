use vm::types::Value;
use vm::contexts::{LocalContext, Environment};
use vm::errors::{Error, ErrType, InterpreterResult as Result};

pub const TX_SENDER: &str = "tx-sender";
pub const BLOCK_HEIGHT: &str = "block-height";

static RESERVED_VARIABLES: &[&str] = 
    &[TX_SENDER,
      BLOCK_HEIGHT,
      "burn-block-height"];

pub fn is_reserved_variable(name: &str) -> bool {
    RESERVED_VARIABLES.contains(&name)
}

pub fn lookup_reserved_variable(name: &str, _context: &LocalContext, env: &Environment) -> Result<Option<Value>> {
    match name {
        TX_SENDER => {
            let sender = env.sender.clone()
                .ok_or(Error::new(ErrType::InvalidArguments(
                    "No sender in current context. Did you attempt to (contract-call ...) from a non-contract aware environment?"
                        .to_string())))?;
            Ok(Some(sender))
        },
        BLOCK_HEIGHT => {
            let block_height = env.global_context.get_block_height();

            Ok(Some(Value::Int(block_height)))
        },
        _ => Ok(None)
    }
}
