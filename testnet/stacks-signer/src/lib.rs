pub mod config;
pub mod net;
pub mod signing_round;
pub mod state_machine;

// set via _compile-time_ envars
const GIT_BRANCH: Option<&'static str> = option_env!("GIT_BRANCH");
const GIT_COMMIT: Option<&'static str> = option_env!("GIT_COMMIT");

#[cfg(debug_assertions)]
const BUILD_TYPE: &'static str = "debug";
#[cfg(not(debug_assertions))]
const BUILD_TYPE: &'static str = "release";

pub fn version() -> String {
    format!(
        "stacks-signer {} {} {}",
        BUILD_TYPE,
        GIT_BRANCH.unwrap_or(""),
        GIT_COMMIT.unwrap_or("")
    )
}
