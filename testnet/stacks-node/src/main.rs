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
extern crate stacks;

#[allow(unused_imports)]
#[macro_use(o, slog_log, slog_trace, slog_debug, slog_info, slog_warn, slog_error)]
extern crate slog;

pub use stacks::util;

pub mod monitoring;

pub mod burnchains;
pub mod config;
pub mod event_dispatcher;
pub mod keychain;
pub mod neon_node;
pub mod node;
pub mod operations;
pub mod run_loop;
pub mod syncctl;
pub mod tenure;

pub use self::burnchains::{
    BitcoinRegtestController, BurnchainController, BurnchainTip, MocknetController,
};
pub use self::config::{Config, ConfigFile};
pub use self::event_dispatcher::EventDispatcher;
pub use self::keychain::Keychain;
pub use self::neon_node::{InitializedNeonNode, NeonGenesisNode};
pub use self::node::{ChainTip, Node};
pub use self::run_loop::{helium, neon};
pub use self::tenure::Tenure;

use pico_args::Arguments;
use std::env;

use std::convert::TryInto;
use std::panic;
use std::process;

use backtrace::Backtrace;

fn main() {
    panic::set_hook(Box::new(|_| {
        eprintln!("Process abort due to thread panic");
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

    let config_file = match subcommand.as_str() {
        "mocknet" => {
            args.finish().unwrap();
            ConfigFile::mocknet()
        }
        "helium" => {
            args.finish().unwrap();
            ConfigFile::helium()
        }
        "neon" => {
            args.finish().unwrap();
            ConfigFile::neon()
        }
        "argon" => {
            args.finish().unwrap();
            ConfigFile::argon()
        }
        "krypton" => {
            args.finish().unwrap();
            ConfigFile::krypton()
        }
        "xenon" => {
            args.finish().unwrap();
            ConfigFile::xenon()
        }
        "start" => {
            let config_path: String = args.value_from_str("--config").unwrap();
            args.finish().unwrap();
            println!("==> {}", config_path);
            ConfigFile::from_path(&config_path)
        }
        "version" => {
            println!(
                "{}",
                &stacks::version_string(
                    option_env!("CARGO_PKG_NAME").unwrap_or("stacks-node"),
                    option_env!("CARGO_PKG_VERSION").unwrap_or("0.0.0.0")
                )
            );
            return;
        }
        _ => {
            print_help();
            return;
        }
    };

    let conf = Config::from_config_file(config_file);
    debug!("node configuration {:?}", &conf.node);
    debug!("burnchain configuration {:?}", &conf.burnchain);
    debug!("connection configuration {:?}", &conf.connection_options);
    debug!("block_limit {:?}", &conf.block_limit);

    let num_round: u64 = 0; // Infinite number of rounds

    if conf.burnchain.mode == "helium" || conf.burnchain.mode == "mocknet" {
        let mut run_loop = helium::RunLoop::new(conf);
        if let Err(e) = run_loop.start(num_round) {
            warn!("Helium runloop exited: {}", e);
            return;
        }
    } else if conf.burnchain.mode == "neon"
        || conf.burnchain.mode == "argon"
        || conf.burnchain.mode == "krypton"
        || conf.burnchain.mode == "xenon"
    {
        let mut run_loop = neon::RunLoop::new(conf);
        run_loop.start(num_round, None);
    } else {
        println!("Burnchain mode '{}' not supported", conf.burnchain.mode);
    }
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

mocknet\t\tStart a node based on a fast local setup emulating a burnchain. Ideal for smart contract development. 

helium\t\tStart a node based on a local setup relying on a local instance of bitcoind.
\t\tThe following bitcoin.conf is expected:
\t\t  chain=regtest
\t\t  disablewallet=0
\t\t  txindex=1
\t\t  server=1
\t\t  rpcuser=helium
\t\t  rpcpassword=helium

argon\t\tStart a node that will join and stream blocks from the public argon testnet, powered by Blockstack (Proof of Burn).

krypton\t\tStart a node that will join and stream blocks from the public krypton testnet, powered by Blockstack via (Proof of Transfer).

xenon\t\tStart a node that will join and stream blocks from the public xenon testnet, decentralized.

start\t\tStart a node with a config of your own. Can be used for joining a network, starting new chain, etc.
\t\tArguments:
\t\t  --config: path of the config (such as https://github.com/blockstack/stacks-blockchain/blob/master/testnet/Stacks.toml).
\t\tExample:
\t\t  stacks-node start --config=/path/to/config.toml

version\t\tDisplay informations about the current version and our release cycle.

help\t\tDisplay this help.

", argv[0]);
}

#[cfg(test)]
pub mod tests;
