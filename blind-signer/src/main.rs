#[macro_use]
extern crate stacks_common;

use std::{process, thread::park};

use pico_args::Arguments;
use stacks::{
    chainstate::nakamoto::test_signers::TestSigners, util::secp256k1::Secp256k1PrivateKey,
};
use stacks_node::config::{Config, ConfigFile};

#[allow(unused_imports)]
#[macro_use(o, slog_log, slog_trace, slog_debug, slog_info, slog_warn, slog_error)]
extern crate slog;

fn main() {
    let mut args = Arguments::from_env();
    let config_path: String = args.value_from_str("--config").unwrap();
    args.finish();
    info!("Loading config at path {}", config_path);
    let config_file = match ConfigFile::from_path(&config_path) {
        Ok(config_file) => config_file,
        Err(e) => {
            warn!("Invalid config file: {}", e);
            process::exit(1);
        }
    };

    let conf = match Config::from_config_file(config_file) {
        Ok(conf) => conf,
        Err(e) => {
            warn!("Invalid config: {}", e);
            process::exit(1);
        }
    };

    let signers = TestSigners::default();
    let sender_signer_sk = Secp256k1PrivateKey::new();
    blind_signer::blind_signer(&conf, &signers, &sender_signer_sk);
    park();
}
