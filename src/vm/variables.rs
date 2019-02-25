use vm::types::Value;
use vm::contexts::{LocalContext, Environment};
use vm::errors::{Error, InterpreterResult as Result};

pub const TX_SENDER: &str = "tx-sender";

static RESERVED_VARIABLES: &[&str] = 
    &[TX_SENDER,
      "block-height",
      "burn-block-height"];

pub fn is_reserved_variable(name: &str) -> bool {
    RESERVED_VARIABLES.contains(&name)
}

pub fn lookup_reserved_variable(name: &str, _context: &LocalContext, env: &Environment) -> Result<Option<Value>> {
    match name {
        TX_SENDER => {
            let sender = env.sender.clone()
                .ok_or(Error::InvalidArguments(
                    "No sender in current context. Did you attempt to (contract-call ...) from a non-contract aware environment?"
                        .to_string()))?;
            Ok(Some(sender))
        },
        _ => Ok(None)
    }
}
