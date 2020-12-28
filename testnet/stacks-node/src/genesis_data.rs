// Uses the full production genesis chainstate.txt data when compiled regularly, .e.g. `cargo build`.
// Uses a small test chainstate.txt file when tests are ran regularly, .e.g. `cargo test`.
// The production file can be used in tests by specifying the `prod-genesis-chainstate` feature
// flag, .e.g. `cargo test --features prod-genesis-chainstate`

#[cfg(any(not(test), feature = "prod-genesis-chainstate"))]
pub const USE_TEST_GENESIS_CHAINSTATE: bool = false;

#[cfg(all(test, not(feature = "prod-genesis-chainstate")))]
pub const USE_TEST_GENESIS_CHAINSTATE: bool = true;
