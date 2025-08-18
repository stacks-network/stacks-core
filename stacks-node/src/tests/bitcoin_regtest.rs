use std::env;
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};

use clarity::vm::costs::ExecutionCost;
use stacks::chainstate::burn::operations::BlockstackOperationType::{
    LeaderBlockCommit, LeaderKeyRegister,
};
use stacks::chainstate::stacks::StacksPrivateKey;
use stacks::config::InitialBalance;
use stacks::core::StacksEpochId;
use stacks_common::util::hash::hex_bytes;

use super::PUBLISH_CONTRACT;
use crate::burnchains::rpc::bitcoin_rpc_client::BitcoinRpcClient;
use crate::helium::RunLoop;
use crate::tests::to_addr;
use crate::Config;

// Value usable as `BurnchainConfig::peer_port` to avoid bitcoind peer port binding
pub const BURNCHAIN_CONFIG_PEER_PORT_DISABLED: u16 = 0;

#[derive(Debug, thiserror::Error)]
pub enum BitcoinCoreError {
    #[error("bitcoind spawn failed: {0}")]
    SpawnFailed(String),
    #[error("bitcoind stop failed: {0}")]
    StopFailed(String),
    #[error("bitcoind kill failed: {0}")]
    KillFailed(String),
}

type BitcoinResult<T> = Result<T, BitcoinCoreError>;

/// Represent a bitcoind process instance
pub struct BitcoinCoreController {
    /// Process child reference
    bitcoind_process: Option<Child>,
    /// Arguments used to start the process
    args: Vec<String>,
    /// The data-dir path used by bitcoind
    data_path: String,
    /// An rpc client to call bitcoind rpc api
    rpc_client: BitcoinRpcClient,
}

impl BitcoinCoreController {
    /// Create a [`BitcoinCoreController`] from Stacks Configuration, mainly using [`stacks::config::BurnchainConfig`]
    pub fn from_stx_config(config: &Config) -> Self {
        let mut result = BitcoinCoreController {
            bitcoind_process: None,
            args: vec![],
            data_path: config.get_burnchain_path_str(),
            rpc_client: BitcoinRpcClient::from_stx_config(config)
                .expect("rpc client creation failed!"),
        };

        result.add_arg("-regtest");
        result.add_arg("-nodebug");
        result.add_arg("-nodebuglogfile");
        result.add_arg("-rest");
        result.add_arg("-persistmempool=1");
        result.add_arg("-dbcache=100");
        result.add_arg("-txindex=1");
        result.add_arg("-server=1");
        result.add_arg("-listenonion=0");
        result.add_arg("-rpcbind=127.0.0.1");
        result.add_arg(format!("-datadir={}", result.data_path));

        let peer_port = config.burnchain.peer_port;
        if peer_port == BURNCHAIN_CONFIG_PEER_PORT_DISABLED {
            info!("Peer Port is disabled. So `-listen=0` flag will be used");
            result.add_arg("-listen=0");
        } else {
            result.add_arg(format!("-port={peer_port}"));
        }

        result.add_arg(format!("-rpcport={}", config.burnchain.rpc_port));

        if let (Some(username), Some(password)) =
            (&config.burnchain.username, &config.burnchain.password)
        {
            result.add_arg(format!("-rpcuser={username}"));
            result.add_arg(format!("-rpcpassword={password}"));
        }

        result
    }

    /// Add argument (like "-name=value") to be used to run bitcoind process
    pub fn add_arg(&mut self, arg: impl Into<String>) -> &mut Self {
        self.args.push(arg.into());
        self
    }

    /// Start Bitcoind process
    pub fn start_bitcoind(&mut self) -> BitcoinResult<()> {
        std::fs::create_dir_all(&self.data_path).unwrap();

        let mut command = Command::new("bitcoind");
        command.stdout(Stdio::piped());

        command.args(self.args.clone());

        info!("bitcoind spawn: {command:?}");

        let mut process = match command.spawn() {
            Ok(child) => child,
            Err(e) => return Err(BitcoinCoreError::SpawnFailed(format!("{e:?}"))),
        };

        let mut out_reader = BufReader::new(process.stdout.take().unwrap());

        let mut line = String::new();
        while let Ok(bytes_read) = out_reader.read_line(&mut line) {
            if bytes_read == 0 {
                return Err(BitcoinCoreError::SpawnFailed(
                    "Bitcoind closed before spawning network".into(),
                ));
            }
            if line.contains("Done loading") {
                break;
            }
        }

        info!("bitcoind startup finished");

        self.bitcoind_process = Some(process);

        Ok(())
    }

    /// Gracefully stop bitcoind process
    pub fn stop_bitcoind(&mut self) -> BitcoinResult<()> {
        if let Some(mut bitcoind_process) = self.bitcoind_process.take() {
            let res = self
                .rpc_client
                .stop()
                .map_err(|e| BitcoinCoreError::StopFailed(format!("{e:?}")))?;
            info!("bitcoind stop started with message: '{res}'");
            bitcoind_process
                .wait()
                .map_err(|e| BitcoinCoreError::StopFailed(format!("{e:?}")))?;
            info!("bitcoind stop finished");
        }
        Ok(())
    }

    /// Kill bitcoind process
    pub fn kill_bitcoind(&mut self) -> BitcoinResult<()> {
        if let Some(mut bitcoind_process) = self.bitcoind_process.take() {
            info!("bitcoind kill started");
            bitcoind_process
                .kill()
                .map_err(|e| BitcoinCoreError::KillFailed(format!("{e:?}")))?;
            info!("bitcoind kill finished");
        }
        Ok(())
    }

    /// Check if bitcoind process is running
    pub fn is_running(&self) -> bool {
        self.bitcoind_process.is_some()
    }
}

impl Drop for BitcoinCoreController {
    fn drop(&mut self) {
        self.kill_bitcoind().unwrap();
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    mod utils {
        use std::net::TcpListener;

        use stacks::util::get_epoch_time_nanos;

        use super::*;

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
    fn test_bitcoind_start_and_stop() {
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
    fn test_bitcoind_start_and_kill() {
        let config = utils::create_config();
        let data_path_str = config.get_burnchain_path_str();
        let data_path = Path::new(data_path_str.as_str());

        let mut bitcoind = BitcoinCoreController::from_stx_config(&config);

        bitcoind.start_bitcoind().expect("should start!");
        assert!(bitcoind.is_running(), "should be running after start!");
        assert!(data_path.exists(), "data path should exists after start!");

        bitcoind.kill_bitcoind().expect("should kill!");
        assert!(!bitcoind.is_running(), "should not be running after stop!");
        assert!(data_path.exists(), "data path should exists after stop!");
    }
}

const BITCOIND_INT_TEST_COMMITS: u64 = 11000;

#[test]
#[ignore]
fn bitcoind_integration_test() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }
    bitcoind_integration(false);
}

#[test]
#[ignore]
fn bitcoind_integration_test_segwit() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }
    bitcoind_integration(true);
}

fn bitcoind_integration(segwit_flag: bool) {
    let mut conf = super::new_test_conf();
    conf.burnchain.commit_anchor_block_within = 2000;
    conf.burnchain.burn_fee_cap = BITCOIND_INT_TEST_COMMITS;
    conf.burnchain.mode = "helium".to_string();
    conf.burnchain.peer_host = "127.0.0.1".to_string();
    conf.burnchain.rpc_port = 18443;
    conf.burnchain.username = Some("helium-node".to_string());
    conf.burnchain.password = Some("secret".to_string());
    conf.burnchain.local_mining_public_key = Some("04ee0b1602eb18fef7986887a7e8769a30c9df981d33c8380d255edef003abdcd243a0eb74afdf6740e6c423e62aec631519a24cf5b1d62bf8a3e06ddc695dcb77".to_string());

    conf.miner.first_attempt_time_ms = i64::MAX as u64;
    conf.miner.subsequent_attempt_time_ms = i64::MAX as u64;
    conf.miner.segwit = segwit_flag;

    conf.initial_balances.push(InitialBalance {
        address: to_addr(
            &StacksPrivateKey::from_hex(
                "043ff5004e3d695060fa48ac94c96049b8c14ef441c50a184a6a3875d2a000f3",
            )
            .unwrap(),
        )
        .into(),
        amount: 1000,
    });
    conf.initial_balances.push(InitialBalance {
        address: to_addr(
            &StacksPrivateKey::from_hex(
                "b1cf9cee5083f421c84d7cb53be5edf2801c3c78d63d53917aee0bdc8bd160ee01",
            )
            .unwrap(),
        )
        .into(),
        amount: 1000,
    });

    // Setup up a bitcoind controller
    let mut controller = BitcoinCoreController::from_stx_config(&conf);
    // Start bitcoind
    let _res = controller.start_bitcoind();

    let num_rounds = 6;
    let mut run_loop = RunLoop::new(conf.clone());

    run_loop
        .callbacks
        .on_burn_chain_initialized(|burnchain_controller| {
            burnchain_controller.bootstrap_chain(2001);
        });

    // In this serie of tests, the callback is fired post-burnchain-sync, pre-stacks-sync
    run_loop
        .callbacks
        .on_new_burn_chain_state(|round, burnchain_tip, chain_tip| {
            let block = &burnchain_tip.block_snapshot;
            let expected_total_burn = BITCOIND_INT_TEST_COMMITS * (round + 1);
            assert_eq!(block.total_burn, expected_total_burn);
            assert!(block.sortition);
            assert_eq!(block.num_sortitions, round + 1);
            assert_eq!(block.block_height, round + 2003);
            let leader_key = "f888e0cab5c16de8edf72b544a189ece5c0b95cd9178606c970789ac71d17bb4";

            match round {
                0 => {
                    let state_transition = &burnchain_tip.state_transition;
                    assert!(state_transition.accepted_ops.len() == 1);
                    assert!(state_transition.consumed_leader_keys.len() == 1);

                    for op in &state_transition.accepted_ops {
                        match op {
                            LeaderKeyRegister(_op) => {
                                unreachable!();
                            }
                            LeaderBlockCommit(op) => {
                                assert_eq!(
                                    burnchain_tip.state_transition.consumed_leader_keys[0]
                                        .public_key
                                        .to_hex(),
                                    leader_key
                                );
                                assert!(op.parent_block_ptr == 0);
                                assert!(op.parent_vtxindex == 0);
                                assert_eq!(op.burn_fee, BITCOIND_INT_TEST_COMMITS);
                            }
                            _ => panic!("Unexpected operation"),
                        }
                    }
                }
                1 => {
                    let state_transition = &burnchain_tip.state_transition;
                    assert!(state_transition.accepted_ops.len() == 1);
                    assert!(state_transition.consumed_leader_keys.len() == 1);

                    for op in &state_transition.accepted_ops {
                        match op {
                            LeaderKeyRegister(_op) => {
                                unreachable!();
                            }
                            LeaderBlockCommit(op) => {
                                assert_eq!(
                                    burnchain_tip.state_transition.consumed_leader_keys[0]
                                        .public_key
                                        .to_hex(),
                                    leader_key
                                );
                                assert_eq!(op.parent_block_ptr, 2003);
                                assert_eq!(op.burn_fee, BITCOIND_INT_TEST_COMMITS);
                            }
                            _ => panic!("Unexpected operation"),
                        }
                    }

                    assert!(
                        burnchain_tip.block_snapshot.parent_burn_header_hash
                            == chain_tip.metadata.burn_header_hash
                    );
                }
                2 => {
                    let state_transition = &burnchain_tip.state_transition;
                    assert!(state_transition.accepted_ops.len() == 1);
                    assert!(state_transition.consumed_leader_keys.len() == 1);

                    for op in &state_transition.accepted_ops {
                        match op {
                            LeaderKeyRegister(_op) => {
                                unreachable!();
                            }
                            LeaderBlockCommit(op) => {
                                assert_eq!(
                                    burnchain_tip.state_transition.consumed_leader_keys[0]
                                        .public_key
                                        .to_hex(),
                                    leader_key
                                );
                                assert_eq!(op.parent_block_ptr, 2004);
                                assert_eq!(op.burn_fee, BITCOIND_INT_TEST_COMMITS);
                            }
                            _ => panic!("Unexpected operation"),
                        }
                    }

                    assert!(
                        burnchain_tip.block_snapshot.parent_burn_header_hash
                            == chain_tip.metadata.burn_header_hash
                    );
                }
                3 => {
                    let state_transition = &burnchain_tip.state_transition;
                    assert!(state_transition.accepted_ops.len() == 1);
                    assert!(state_transition.consumed_leader_keys.len() == 1);

                    for op in &state_transition.accepted_ops {
                        match op {
                            LeaderKeyRegister(_op) => {
                                unreachable!();
                            }
                            LeaderBlockCommit(op) => {
                                assert_eq!(
                                    burnchain_tip.state_transition.consumed_leader_keys[0]
                                        .public_key
                                        .to_hex(),
                                    leader_key
                                );
                                assert_eq!(op.parent_block_ptr, 2005);
                                assert_eq!(op.burn_fee, BITCOIND_INT_TEST_COMMITS);
                            }
                            _ => panic!("Unexpected operation"),
                        }
                    }

                    assert!(
                        burnchain_tip.block_snapshot.parent_burn_header_hash
                            == chain_tip.metadata.burn_header_hash
                    );
                }
                4 => {
                    let state_transition = &burnchain_tip.state_transition;
                    assert!(state_transition.accepted_ops.len() == 1);
                    assert!(state_transition.consumed_leader_keys.len() == 1);

                    for op in &state_transition.accepted_ops {
                        match op {
                            LeaderKeyRegister(_op) => {
                                unreachable!();
                            }
                            LeaderBlockCommit(op) => {
                                assert_eq!(
                                    burnchain_tip.state_transition.consumed_leader_keys[0]
                                        .public_key
                                        .to_hex(),
                                    leader_key
                                );
                                assert_eq!(op.parent_block_ptr, 2006);
                                assert_eq!(op.burn_fee, BITCOIND_INT_TEST_COMMITS);
                            }
                            _ => panic!("Unexpected operation"),
                        }
                    }

                    assert!(
                        burnchain_tip.block_snapshot.parent_burn_header_hash
                            == chain_tip.metadata.burn_header_hash
                    );
                }
                5 => {
                    let state_transition = &burnchain_tip.state_transition;
                    assert!(state_transition.accepted_ops.len() == 1);
                    assert!(state_transition.consumed_leader_keys.len() == 1);

                    for op in &state_transition.accepted_ops {
                        match op {
                            LeaderKeyRegister(_op) => {
                                unreachable!();
                            }
                            LeaderBlockCommit(op) => {
                                assert_eq!(
                                    burnchain_tip.state_transition.consumed_leader_keys[0]
                                        .public_key
                                        .to_hex(),
                                    leader_key
                                );
                                assert_eq!(op.parent_block_ptr, 2007);
                                assert_eq!(op.burn_fee, BITCOIND_INT_TEST_COMMITS);
                            }
                            _ => panic!("Unexpected operation"),
                        }
                    }

                    assert!(
                        burnchain_tip.block_snapshot.parent_burn_header_hash
                            == chain_tip.metadata.burn_header_hash
                    );
                }
                _ => {}
            }
        });

    // Use tenure's hook for submitting transactions
    run_loop.callbacks.on_new_tenure(|round, _burnchain_tip, chain_tip, tenure| {
        let mut chainstate_copy = tenure.open_chainstate();
            let sortdb = tenure.open_fake_sortdb();

        match round {
            1 => {
                // On round 1, publish the KV contract
                // $ cat /tmp/out.clar
                // (define-map store { key: (string-ascii 32) } { value: (string-ascii 32) })
                // (define-public (get-value (key (string-ascii 32)))
                //     (begin
                //         (print (concat "Getting key " key))
                //         (match (map-get? store { key: key })
                //             entry (ok (get value entry))
                //             (err 0))))
                // (define-public (set-value (key (string-ascii 32)) (value (string-ascii 32)))
                //     (begin
                //         (print (concat "Setting key " key))
                //         (map-set store { key: key } { value: value })
                //         (ok 'true)))
                // ./blockstack-cli --testnet publish 043ff5004e3d695060fa48ac94c96049b8c14ef441c50a184a6a3875d2a000f3 0 0 store /tmp/out.clar
                let header_hash = chain_tip.block.block_hash();
                let consensus_hash = chain_tip.metadata.consensus_hash;
                tenure.mem_pool.submit_raw(&mut chainstate_copy, &sortdb, &consensus_hash, &header_hash, PUBLISH_CONTRACT.to_owned(), &ExecutionCost::max_value(),
                                &StacksEpochId::Epoch20,).unwrap();
            },
            2 => {
                // On round 2, publish a "get:foo" transaction
                // ./blockstack-cli --testnet contract-call 043ff5004e3d695060fa48ac94c96049b8c14ef441c50a184a6a3875d2a000f3 10 1 STGT7GSMZG7EA0TS6MVSKT5JC1DCDFGZWJJZXN8A store get-value -e \"foo\"
                let header_hash = chain_tip.block.block_hash();
                let consensus_hash = chain_tip.metadata.consensus_hash;
                let get_foo = "8080000000040021a3c334fc0ee50359353799e8b2605ac6be1fe40000000000000001000000000000000a0100b7ff8b6c20c427b4f4f09c1ad7e50027e2b076b2ddc0ab55e64ef5ea3771dd4763a79bc5a2b1a79b72ce03dd146ccf24b84942d675a815819a8b85aa8065dfaa030200000000021a21a3c334fc0ee50359353799e8b2605ac6be1fe40573746f7265096765742d76616c7565000000010d00000003666f6f";
                tenure.mem_pool.submit_raw(&mut chainstate_copy, &sortdb, &consensus_hash, &header_hash,hex_bytes(get_foo).unwrap().to_vec(), &ExecutionCost::max_value(),
                                &StacksEpochId::Epoch20,).unwrap();
            },
            3 => {
                // On round 3, publish a "set:foo=bar" transaction
                // ./blockstack-cli --testnet contract-call 043ff5004e3d695060fa48ac94c96049b8c14ef441c50a184a6a3875d2a000f3 10 2 STGT7GSMZG7EA0TS6MVSKT5JC1DCDFGZWJJZXN8A store set-value -e \"foo\" -e \"bar\"
                let header_hash = chain_tip.block.block_hash();
                let consensus_hash = chain_tip.metadata.consensus_hash;
                let set_foo_bar = "8080000000040021a3c334fc0ee50359353799e8b2605ac6be1fe40000000000000002000000000000000a010142a01caf6a32b367664869182f0ebc174122a5a980937ba259d44cc3ebd280e769a53dd3913c8006ead680a6e1c98099fcd509ce94b0a4e90d9f4603b101922d030200000000021a21a3c334fc0ee50359353799e8b2605ac6be1fe40573746f7265097365742d76616c7565000000020d00000003666f6f0d00000003626172";
                tenure.mem_pool.submit_raw(&mut chainstate_copy, &sortdb, &consensus_hash, &header_hash,hex_bytes(set_foo_bar).unwrap().to_vec(), &ExecutionCost::max_value(),
                                &StacksEpochId::Epoch20,).unwrap();
            },
            4 => {
                // On round 4, publish a "get:foo" transaction
                // ./blockstack-cli --testnet contract-call 043ff5004e3d695060fa48ac94c96049b8c14ef441c50a184a6a3875d2a000f3 10 3 STGT7GSMZG7EA0TS6MVSKT5JC1DCDFGZWJJZXN8A store get-value -e \"foo\"
                let header_hash = chain_tip.block.block_hash();
                let consensus_hash = chain_tip.metadata.consensus_hash;
                let get_foo = "8080000000040021a3c334fc0ee50359353799e8b2605ac6be1fe40000000000000003000000000000000a010046c2c1c345231443fef9a1f64fccfef3e1deacc342b2ab5f97612bb3742aa799038b20aea456789aca6b883e52f84a31adfee0bc2079b740464877af8f2f87d2030200000000021a21a3c334fc0ee50359353799e8b2605ac6be1fe40573746f7265096765742d76616c7565000000010d00000003666f6f";
                tenure.mem_pool.submit_raw(&mut chainstate_copy, &sortdb, &consensus_hash, &header_hash,hex_bytes(get_foo).unwrap().to_vec(), &ExecutionCost::max_value(),
                                &StacksEpochId::Epoch20,).unwrap();
            },
            5 => {
                // On round 5, publish a stacks transaction
                // ./blockstack-cli --testnet token-transfer b1cf9cee5083f421c84d7cb53be5edf2801c3c78d63d53917aee0bdc8bd160ee01 10 0 ST195Q2HPXY576N4CT2A0R94D7DRYSX54A5X3YZTH 1000
                let header_hash = chain_tip.block.block_hash();
                let consensus_hash = chain_tip.metadata.consensus_hash;
                let transfer_1000_stx = "80800000000400b71a091b4b8b7661a661c620966ab6573bc2dcd30000000000000000000000000000000a0000393810832bacd44cfc4024980876135de6b95429bdb610d5ce96a92c9ee9bfd81ec77ea0f1748c8515fc9a1589e51d8b92bf028e3e84ade1249682c05271d5b803020000000000051a525b8a36ef8a73548cd0940c248d3b71ecf4a45100000000000003e800000000000000000000000000000000000000000000000000000000000000000000";
                tenure.mem_pool.submit_raw(&mut chainstate_copy, &sortdb, &consensus_hash, &header_hash,hex_bytes(transfer_1000_stx).unwrap().to_vec(), &ExecutionCost::max_value(),
                                &StacksEpochId::Epoch20,).unwrap();
            },
            _ => {}
        };
    });

    // Use block's hook for asserting expectations
    // In this serie of tests, the callback is fired post-burnchain-sync, post-stacks-sync
    run_loop.callbacks.on_new_stacks_chain_state(
        |round, burnchain_tip, chain_tip, _chain_state, _burn_dbconn| {
            match round {
                0 => {
                    // Inspecting the chain at round 0.
                    // - Chain length should be 1.
                    assert!(chain_tip.metadata.stacks_block_height == 1);

                    // Block #1 should only have 0 txs
                    assert!(chain_tip.block.txs.len() == 1);

                    assert!(
                        chain_tip.block.header.block_hash()
                            == burnchain_tip.block_snapshot.winning_stacks_block_hash
                    );
                }
                1 => {
                    // Inspecting the chain at round 1.
                    // - Chain length should be 2.
                    assert!(chain_tip.metadata.stacks_block_height == 2);

                    // Block #2 should only have 2 txs
                    assert!(chain_tip.block.txs.len() == 2);

                    assert!(
                        chain_tip.block.header.block_hash()
                            == burnchain_tip.block_snapshot.winning_stacks_block_hash
                    );
                }
                2 => {
                    // Inspecting the chain at round 2.
                    // - Chain length should be 3.
                    assert!(chain_tip.metadata.stacks_block_height == 3);

                    // Block #3 should only have 2 txs
                    assert!(chain_tip.block.txs.len() == 2);

                    assert!(
                        chain_tip.block.header.block_hash()
                            == burnchain_tip.block_snapshot.winning_stacks_block_hash
                    );
                }
                3 => {
                    // Inspecting the chain at round 3.
                    // - Chain length should be 4.
                    assert!(chain_tip.metadata.stacks_block_height == 4);

                    // Block #4 should only have 2 txs
                    assert!(chain_tip.block.txs.len() == 2);

                    assert!(
                        chain_tip.block.header.block_hash()
                            == burnchain_tip.block_snapshot.winning_stacks_block_hash
                    );
                }
                4 => {
                    // Inspecting the chain at round 4.
                    // - Chain length should be 5.
                    assert!(chain_tip.metadata.stacks_block_height == 5);

                    // Block #5 should only have 2 txs
                    assert!(chain_tip.block.txs.len() == 2);

                    assert!(
                        chain_tip.block.header.block_hash()
                            == burnchain_tip.block_snapshot.winning_stacks_block_hash
                    );
                }
                5 => {
                    // Inspecting the chain at round 5.
                    // - Chain length should be 6.
                    assert!(chain_tip.metadata.stacks_block_height == 6);

                    // Block #6 should only have 2 txs
                    assert!(chain_tip.block.txs.len() == 2);

                    assert!(
                        chain_tip.block.header.block_hash()
                            == burnchain_tip.block_snapshot.winning_stacks_block_hash
                    );
                }
                _ => {}
            }
        },
    );
    run_loop.start(num_rounds).unwrap();
}
