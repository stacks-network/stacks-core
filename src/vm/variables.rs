// This currently is just serving as a place-holder for reserved variable
//   names. 

pub const TX_SENDER: &str = "tx-sender";

static RESERVED_VARIABLES: &[&str] = 
    &[TX_SENDER,
      "block-height",
      "burn-block-height"];

pub fn is_reserved_variable(name: &str) -> bool {
    RESERVED_VARIABLES.contains(&name)
}
