// This currently is just serving as a place-holder for reserved variable
//   names. 

static RESERVED_VARIABLES: &[&str] = 
    &["tx-sender",
      "block-height",
      "burn-block-height"];

pub fn is_reserved_variable(name: &str) -> bool {
    RESERVED_VARIABLES.contains(&name)
}
