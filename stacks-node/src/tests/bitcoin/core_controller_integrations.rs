// Copyright (C) 2025 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! Integration tests for [`BitcoinCoreController`]

use std::env;
use std::path::Path;

use crate::burnchains::bitcoin::core_controller::BitcoinCoreController;
use crate::{BitcoinRegtestController, BurnchainController};

mod utils {
    use std::net::TcpListener;

    use stacks::config::Config;
    use stacks::util::get_epoch_time_nanos;

    use crate::burnchains::bitcoin::core_controller::BURNCHAIN_CONFIG_PEER_PORT_DISABLED;

    pub fn create_config() -> Config {
        let mut config = Config::default();
        config.burnchain.magic_bytes = "T3".as_bytes().into();
        config.burnchain.username = Some(String::from("user"));
        config.burnchain.password = Some(String::from("12345"));
        // overriding default "0.0.0.0" because doesn't play nicely on Windows.
        config.burnchain.peer_host = String::from("127.0.0.1");
        // avoiding peer port biding to reduce the number of ports to bind to.
        config.burnchain.peer_port = BURNCHAIN_CONFIG_PEER_PORT_DISABLED;

        //Ask the OS for a free port. Not guaranteed to stay free,
        //after TcpListner is dropped, but good enough for testing
        //and starting bitcoind right after config is created
        let tmp_listener =
            TcpListener::bind("127.0.0.1:0").expect("Failed to bind to get a free port");
        let port = tmp_listener.local_addr().unwrap().port();

        config.burnchain.rpc_port = port;

        let now = get_epoch_time_nanos();
        let dir = format!("/tmp/regtest-ctrl-{port}-{now}");
        config.node.working_dir = dir;

        config
    }
}

#[test]
#[ignore]
fn test_bitcoind_start_and_stop() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let config = utils::create_config();
    let data_path_str = config.get_burnchain_path_str();
    let data_path = Path::new(data_path_str.as_str());

    let mut bitcoind = BitcoinCoreController::from_stx_config(&config);

    bitcoind.start_bitcoind().expect("should start!");
    assert!(bitcoind.is_running(), "should be running after start!");
    assert!(data_path.exists(), "data path should exists after start!");

    bitcoind.stop_bitcoind().expect("should stop!");
    assert!(!bitcoind.is_running(), "should not be running after stop!");
    assert!(data_path.exists(), "data path should exists after stop!");
}

#[test]
#[ignore]
fn test_bitcoind_start_and_kill() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let config = utils::create_config();
    let data_path_str = config.get_burnchain_path_str();
    let data_path = Path::new(data_path_str.as_str());

    let mut bitcoind = BitcoinCoreController::from_stx_config(&config);

    bitcoind.start_bitcoind().expect("should start!");
    assert!(bitcoind.is_running(), "should be running after start!");
    assert!(data_path.exists(), "data path should exists after start!");

    bitcoind.kill_bitcoind().expect("should kill!");
    assert!(!bitcoind.is_running(), "should not be running after kill!");
    assert!(data_path.exists(), "data path should exists after kill!");
}

#[test]
#[ignore]
fn test_bitcoind_restart_with_bootstrapped_chain_data() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let config = utils::create_config();

    let mut btcd_controller = BitcoinCoreController::from_stx_config(&config);
    btcd_controller
        .start_bitcoind()
        .expect("Failed starting bitcoind");

    let btc_controller = BitcoinRegtestController::new(config, None);
    btc_controller.bootstrap_chain(201);
    info!("Chain bootstrapped...");

    btcd_controller
        .stop_bitcoind()
        .expect("Failed to stop bitcoind");

    btcd_controller
        .start_bitcoind()
        .expect("Failed to restart bitcoind");

    btcd_controller
        .stop_bitcoind()
        .expect("Failed to re-stop bitcoind");
}
