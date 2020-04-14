extern crate rand;
extern crate mio;
extern crate serde;

#[macro_use] extern crate lazy_static;
#[macro_use] extern crate serde_derive;
#[macro_use] extern crate serde_json;
#[macro_use] extern crate stacks;


pub use stacks::util;

pub mod run_loop; 
pub mod mem_pool;
pub mod keychain;
pub mod node;
pub mod tenure;
pub mod config;
pub mod event_dispatcher;
pub mod operations;
pub mod burnchains;

pub use self::mem_pool::{MemPool, MemPoolFS};
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

    println!("*** Mempool path: {}", conf.mempool.path);


    // ^C2020-04-14T15:36:48Z tor: Thread interrupt
    // 2020-04-14T15:36:48Z torcontrol thread exit
    // 2020-04-14T15:36:48Z opencon thread exit
    // 2020-04-14T15:36:48Z addcon thread exit
    // 2020-04-14T15:36:48Z Shutdown: In progress...
    // 2020-04-14T15:36:48Z net thread exit
    // 2020-04-14T15:36:48Z msghand thread exit
    // 2020-04-14T15:36:48Z scheduler thread interrupt
    // 2020-04-14T15:36:48Z Dumped mempool: 9e-06s to copy, 0.002823s to dump
    // 2020-04-14T15:36:48Z [default wallet] Releasing wallet
    // 2020-04-14T15:36:48Z Shutdown: done
    
    let num_round: u64 = 0; // Infinite number of rounds
    if conf.burnchain.mode == "helium" {
        let mut run_loop = helium::RunLoop::new(conf);
        run_loop.start(num_round);
    } else if conf.burnchain.mode == "neon" {
        let mut run_loop = neon::RunLoop::new(conf);
        run_loop.start(num_round);
    }
    return
}

#[cfg(test)]
pub mod tests;