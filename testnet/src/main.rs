extern crate rand;
extern crate mio;
extern crate serde;

#[macro_use] extern crate lazy_static;
#[macro_use] extern crate serde_derive;
#[macro_use] extern crate serde_json;
#[macro_use] extern crate stacks;


pub use stacks::util;

pub mod run_loop; 
pub mod keychain;
pub mod node;
pub mod tenure;
pub mod config;
pub mod event_dispatcher;
pub mod operations;
pub mod burnchains;

pub use self::keychain::{Keychain};
pub use self::node::{Node, ChainTip};
pub use self::burnchains::{MocknetController, BitcoinRegtestController, BurnchainTip, BurnchainController};
pub use self::tenure::{Tenure};
pub use self::config::{Config, ConfigFile};
pub use self::event_dispatcher::{EventDispatcher};
pub use self::run_loop::{neon, helium};


use std::env;

fn main() {

    util::log::set_loglevel(util::log::LOG_INFO).unwrap();

    let argv : Vec<String> = env::args().collect();

    let conf = match argv.len() {
        n if n >= 2 => {
            println!("Starting testnet with config {}...", argv[1]);
            Config::from_config_file_path(&argv[1])
        },
        _ => {
            println!("Starting testnet with default config...");
            Config::default()
        }
    };

    println!("Transactions can be posted on the endpoint:");
    println!("POST http://{}/v2/transactions", conf.node.rpc_bind);
    
    let num_round: u64 = 0; // Infinite number of rounds
    if conf.burnchain.mode == "helium" || conf.burnchain.mode == "mocknet" {
        let mut run_loop = helium::RunLoop::new(conf);
        run_loop.start(num_round);
    } else if conf.burnchain.mode == "neon" || conf.burnchain.mode == "neon-god" {
        let mut run_loop = neon::RunLoop::new(conf);
        run_loop.start(num_round);
    } else {
        println!("Burnchain mode '{}' not supported", conf.burnchain.mode);
    }
    return
}

#[cfg(test)]
pub mod tests;
