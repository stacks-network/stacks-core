use slog::info;
use stacks_signer::config::{Config};
use stacks_signer::logger;

fn main() {
    let log = logger::setup();
    let config = Config::from_file("conf/stacker.toml").unwrap();
    info!(log, "{:?}", config);
}
