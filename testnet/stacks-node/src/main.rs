extern crate libc;
extern crate rand;
extern crate serde;

#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate serde_json;
#[macro_use]
extern crate stacks_common;

extern crate stacks;

#[allow(unused_imports)]
#[macro_use(o, slog_log, slog_trace, slog_debug, slog_info, slog_warn, slog_error)]
extern crate slog;

pub use stacks::util;
use stacks::util::hash::hex_bytes;

pub mod monitoring;

pub mod appchain;
pub mod burnchains;
pub mod config;
pub mod event_dispatcher;
pub mod genesis_data;
pub mod keychain;
pub mod neon_node;
pub mod node;
pub mod operations;
pub mod run_loop;
pub mod syncctl;
pub mod tenure;

pub use self::burnchains::{
    BitcoinRegtestController, BurnchainController, BurnchainTip, MocknetController,
    StacksController,
};
pub use self::config::{Config, ConfigFile};
pub use self::event_dispatcher::EventDispatcher;
pub use self::keychain::Keychain;
pub use self::node::{ChainTip, Node};
pub use self::run_loop::{helium, neon};
pub use self::tenure::Tenure;

use self::stacks::burnchains::Burnchain;
use self::stacks::chainstate::stacks::db::{ChainStateBootData, StacksChainState};
use self::stacks::util::get_epoch_time_secs;
use self::stacks::util_lib::boot::boot_code_addr;
use self::stacks::util_lib::strings::StacksString;
use self::stacks::vm::ContractName;

use pico_args::Arguments;
use std::env;

use std::collections::HashMap;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::fs;
use std::panic;
use std::path::PathBuf;
use std::process;

use backtrace::Backtrace;

fn main() {
    panic::set_hook(Box::new(|panic_info| {
        eprintln!("Process abort due to thread panic: {}", panic_info);
        let bt = Backtrace::new();
        eprintln!("{:?}", &bt);

        // force a core dump
        #[cfg(unix)]
        {
            let pid = process::id();
            eprintln!("Dumping core for pid {}", std::process::id());

            use libc::kill;
            use libc::SIGQUIT;

            // *should* trigger a core dump, if you run `ulimit -c unlimited` first!
            unsafe { kill(pid.try_into().unwrap(), SIGQUIT) };
        }

        // just in case
        process::exit(1);
    }));

    let mut args = Arguments::from_env();
    let subcommand = args.subcommand().unwrap().unwrap_or_default();

    info!("{}", version());

    let mine_start: Option<u64> = args
        .opt_value_from_str("--mine-at-height")
        .expect("Failed to parse --mine-at-height argument");

    if let Some(mine_start) = mine_start {
        info!(
            "Will begin mining once Stacks chain has synced to height >= {}",
            mine_start
        );
    }

    let mut boot_code_paths: Vec<String> = vec![];
    let mut expect_appchain = false;
    let mut appchain_genesis = false;

    let config_file = match subcommand.as_str() {
        "mocknet" => {
            args.finish().unwrap();
            ConfigFile::mocknet()
        }
        "helium" => {
            args.finish().unwrap();
            ConfigFile::helium()
        }
        "testnet" => {
            args.finish().unwrap();
            ConfigFile::xenon()
        }
        "mainnet" => {
            args.finish().unwrap();
            ConfigFile::mainnet()
        }
        "appchain" => {
            expect_appchain = true;
            let config_path: String = args.value_from_str("--config").unwrap();
            boot_code_paths = args.values_from_str("--boot-code").unwrap();
            args.finish().unwrap();
            ConfigFile::from_path(&config_path)
        }
        "appchain-genesis" => {
            expect_appchain = true;
            appchain_genesis = true;
            let config_path: String = args.value_from_str("--config").unwrap();
            boot_code_paths = args.values_from_str("--boot-code").unwrap();
            args.finish().unwrap();
            ConfigFile::from_path(&config_path)
        }
        "start" => {
            let config_path: String = args.value_from_str("--config").unwrap();
            args.finish().unwrap();
            info!("Loading config at path {}", config_path);
            ConfigFile::from_path(&config_path)
        }
        "version" => {
            println!("{}", &version());
            return;
        }
        "key-for-seed" => {
            let seed = {
                let config_path: Option<String> = args.opt_value_from_str("--config").unwrap();
                if let Some(config_path) = config_path {
                    let conf = Config::from_config_file(ConfigFile::from_path(&config_path));
                    args.finish().unwrap();
                    conf.node.seed
                } else {
                    let free_args = args.free().unwrap();
                    let seed_hex = free_args
                        .first()
                        .expect("`wif-for-seed` must be passed either a config file via the `--config` flag or a hex seed string");
                    hex_bytes(seed_hex).expect("Seed should be a hex encoded string")
                }
            };
            let keychain = Keychain::default(seed);
            println!(
                "Hex formatted secret key: {}",
                keychain.generate_op_signer().get_sk_as_hex()
            );
            println!(
                "WIF formatted secret key: {}",
                keychain.generate_op_signer().get_sk_as_wif()
            );
            return;
        }
        _ => {
            print_help();
            return;
        }
    };

    let mut conf = Config::from_config_file(config_file.clone());
    let mut boot_code_data = vec![];

    if expect_appchain {
        info!("Booting as appchain to finish self-configuring");
        let mut boot_code = HashMap::new();
        if boot_code_paths.len() > 0 {
            info!("Boot codes to load from disk:");
            for boot_code_path_str in boot_code_paths.iter() {
                let boot_code_path = PathBuf::from(&boot_code_path_str);
                let boot_code_filename = boot_code_path
                    .file_stem()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_string();

                info!(
                    "  {}.{}: {}",
                    boot_code_addr(conf.is_mainnet()),
                    &boot_code_filename,
                    boot_code_path_str
                );

                let boot_code_src = fs::read_to_string(&boot_code_path).unwrap();
                let boot_code_name = ContractName::try_from(boot_code_filename).unwrap();
                let boot_code_string = StacksString::from_string(&boot_code_src).unwrap();

                boot_code.insert(boot_code_name.clone(), boot_code_string.clone());
                boot_code_data.push((boot_code_name, boot_code_string));
            }
        }

        conf.boot_into_appchain(&boot_code);
    }

    if appchain_genesis {
        // only validating the boot code to get the genesis hash
        let appchain_runtime = conf.burnchain.appchain_runtime.clone().unwrap();
        let appchain_working_dir = format!("/tmp/appchain-genesis-{}", get_epoch_time_secs());
        let burnchain =
            Burnchain::new_appchain(&appchain_runtime.config, &appchain_working_dir).unwrap();

        let mut appchain_boot_data = ChainStateBootData::new_appchain(
            conf.is_mainnet(),
            &burnchain,
            appchain_runtime.config.initial_balances(),
            boot_code_data,
            appchain_runtime.config.genesis_hash(),
        );

        let (mut appchain_chainstate, _) = StacksChainState::open_and_exec(
            conf.is_mainnet(),
            appchain_runtime.config.chain_id(),
            &appchain_working_dir,
            Some(&mut appchain_boot_data),
        )
        .unwrap();

        eprintln!(
            "Appchain genesis state instantiated in {}",
            appchain_working_dir
        );

        let genesis_root = appchain_chainstate.get_genesis_state_index_root();
        eprintln!("Appchain genesis hash: {}", &genesis_root);
        process::exit(0);
    }

    debug!("node configuration {:?}", &conf.node);
    debug!("burnchain configuration {:?}", &conf.burnchain);
    debug!("connection configuration {:?}", &conf.connection_options);

    let num_round: u64 = 0; // Infinite number of rounds

    if conf.burnchain.mode == "helium" || conf.burnchain.mode == "mocknet" {
        assert!(
            !conf.describes_appchain(),
            "FATAL: cannot boot an appchain in `helium` or `mocknet` mode at this time"
        );
        let mut run_loop = helium::RunLoop::new(conf);
        if let Err(e) = run_loop.start(num_round) {
            warn!("Helium runloop exited: {}", e);
            return;
        }
    } else if conf.burnchain.mode == "neon"
        || conf.burnchain.mode == "xenon"
        || conf.burnchain.mode == "krypton"
        || conf.burnchain.mode == "mainnet"
    {
        let mut run_loop = neon::RunLoop::new(conf);
        run_loop.start(None, mine_start.unwrap_or(0));
    } else {
        println!("Burnchain mode '{}' not supported", conf.burnchain.mode);
    }
}

fn version() -> String {
    stacks::version_string(
        "stacks-node",
        option_env!("STACKS_NODE_VERSION")
            .or(option_env!("CARGO_PKG_VERSION"))
            .unwrap_or("0.0.0.0"),
    )
}

fn print_help() {
    let argv: Vec<_> = env::args().collect();

    eprintln!(
        "\
{} <SUBCOMMAND>
Run a stacks-node.

USAGE:
stacks-node <SUBCOMMAND>

SUBCOMMANDS:

mainnet\t\tStart a node that will join and stream blocks from the public mainnet.

mocknet\t\tStart a node based on a fast local setup emulating a burnchain. Ideal for smart contract development. 

helium\t\tStart a node based on a local setup relying on a local instance of bitcoind.
\t\tThe following bitcoin.conf is expected:
\t\t  chain=regtest
\t\t  disablewallet=0
\t\t  txindex=1
\t\t  server=1
\t\t  rpcuser=helium
\t\t  rpcpassword=helium

testnet\t\tStart a node that will join and stream blocks from the public testnet, relying on Bitcoin Testnet.

start\t\tStart a node with a config of your own. Can be used for joining a network, starting new chain, etc.
\t\tArguments:
\t\t  --config: path of the config (such as https://github.com/blockstack/stacks-blockchain/blob/master/testnet/stacks-node/conf/testnet-follower-conf.toml).
\t\tExample:
\t\t  stacks-node start --config=/path/to/config.toml

version\t\tDisplay information about the current version and our release cycle.

key-for-seed\tOutput the associated secret key for a burnchain signer created with a given seed.
\t\tCan be passed a config file for the seed via the `--config=<file>` option *or* by supplying the hex seed on
\t\tthe command line directly.

help\t\tDisplay this help.

OPTIONAL ARGUMENTS:

\t\t--mine-at-height=<height>: optional argument for a miner to not attempt mining until Stacks block has sync'ed to <height>

", argv[0]);
}

#[cfg(test)]
pub mod tests;
