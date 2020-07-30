use std::process::{Command, Child, Stdio};

use crate::{Config};
use crate::helium::RunLoop;

use stacks::chainstate::burn::operations::BlockstackOperationType::{LeaderBlockCommit, LeaderKeyRegister};
use stacks::util::hash::{hex_bytes};

use std::env;
use std::io::{BufReader, BufRead};
use super::{PUBLISH_CONTRACT};

pub enum BitcoinCoreError {
    SpawnFailed(String)
}

type BitcoinResult<T> = Result<T, BitcoinCoreError>;

pub struct BitcoinCoreController {
    bitcoind_process: Option<Child>,
    config: Config,
}

impl BitcoinCoreController {

    pub fn new(config: Config) -> BitcoinCoreController {
        BitcoinCoreController {
            bitcoind_process: None,
            config
        }
    }

    pub fn start_bitcoind(&mut self) -> BitcoinResult<()> {
        std::fs::create_dir_all(&self.config.get_burnchain_path()).unwrap();
        
        let mut command = Command::new("bitcoind");
        command
            .stdout(Stdio::piped())
            .arg("-regtest")
            .arg("-nodebug")
            .arg("-nodebuglogfile")
            .arg("-rest")
            .arg("-txindex=1")
            .arg("-server=1")
            .arg("-listenonion=0")
            .arg("-rpcbind=127.0.0.1")
            .arg(&format!("-port={}", self.config.burnchain.peer_port))
            .arg(&format!("-datadir={}", self.config.get_burnchain_path()))
            .arg(&format!("-rpcport={}", self.config.burnchain.rpc_port));

        match (&self.config.burnchain.username, &self.config.burnchain.password) {
            (Some(username), Some(password)) => {
                command
                    .arg(&format!("-rpcuser={}", username))
                    .arg(&format!("-rpcpassword={}", password));
            },
            _ => {}
        }

        eprintln!("bitcoind spawn: {:?}", command);

        let mut process = match command.spawn() {
            Ok(child) => child,
            Err(e) => return Err(BitcoinCoreError::SpawnFailed(format!("{:?}", e)))
        };

        eprintln!("bitcoind spawned, waiting for startup");
        let mut out_reader = BufReader::new(process.stdout.take().unwrap());

        let mut line = String::new();
        while let Ok(bytes_read) = out_reader.read_line(&mut line) {
            if bytes_read == 0 {
                return Err(BitcoinCoreError::SpawnFailed("Bitcoind closed before spawning network".into()))
            }
            if line.contains("Done loading") {
                break;
            }
        }

        eprintln!("bitcoind startup finished");

        self.bitcoind_process = Some(process);

        Ok(())
    }


    pub fn kill_bitcoind(&mut self) {
        if let Some(mut bitcoind_process) = self.bitcoind_process.take() {
            bitcoind_process.kill().unwrap();
        }
    }
}

impl Drop for BitcoinCoreController {

    fn drop(&mut self) {
        self.kill_bitcoind();
    }
}

#[test]
#[ignore]
fn bitcoind_integration_test() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return
    }

    let mut conf = super::new_test_conf();
    conf.burnchain.commit_anchor_block_within = 2000;
    conf.burnchain.burn_fee_cap = 5000;
    conf.burnchain.mode = "helium".to_string();
    conf.burnchain.peer_host = "127.0.0.1".to_string();
    conf.burnchain.rpc_port = 18443;
    conf.burnchain.username = Some("helium-node".to_string());
    conf.burnchain.password = Some("secret".to_string());
    conf.burnchain.local_mining_public_key = Some("04ee0b1602eb18fef7986887a7e8769a30c9df981d33c8380d255edef003abdcd243a0eb74afdf6740e6c423e62aec631519a24cf5b1d62bf8a3e06ddc695dcb77".to_string());

    // Setup up a bitcoind controller
    let mut controller = BitcoinCoreController::new(conf.clone());
    // Start bitcoind
    let _res = controller.start_bitcoind();

    let num_rounds = 6;
    let mut run_loop = RunLoop::new(conf);

    run_loop.callbacks.on_burn_chain_initialized(|burnchain_controller| {
        burnchain_controller.bootstrap_chain(201);
    });

    // In this serie of tests, the callback is fired post-burnchain-sync, pre-stacks-sync
    run_loop.callbacks.on_new_burn_chain_state(|round, burnchain_tip, chain_tip| {
        match round {
            0 => {
                let block = &burnchain_tip.block_snapshot;
                assert!(block.block_height == 203);
                assert!(block.total_burn == 5000);
                assert!(block.num_sortitions == 1);
                assert!(block.sortition == true);

                let state_transition = &burnchain_tip.state_transition;
                assert!(state_transition.accepted_ops.len() == 2);
                assert!(state_transition.consumed_leader_keys.len() == 1);

                for op in &state_transition.accepted_ops {
                    match op {
                        LeaderKeyRegister(op) => {
                            assert_eq!(op.public_key.to_hex(), "325dfe3ba0b52e6b800f5cea1283dd2cd0aee88be0270e45dc8a6e01d19218b4");
                        },
                        LeaderBlockCommit(op) => {
                            assert!(op.parent_block_ptr == 0);
                            assert!(op.parent_vtxindex == 0);
                            assert!(op.burn_fee == 5000);
                        }
                        _ => assert!(false)
                    }
                }
            },
            1 => {
                let block = &burnchain_tip.block_snapshot;
                assert!(block.block_height == 204);
                assert!(block.total_burn == 10000);
                assert!(block.num_sortitions == 2);
                assert!(block.sortition == true);

                let state_transition = &burnchain_tip.state_transition;
                assert!(state_transition.accepted_ops.len() == 2);
                assert!(state_transition.consumed_leader_keys.len() == 1);

                for op in &state_transition.accepted_ops {
                    match op {
                        LeaderKeyRegister(op) => {
                            assert_eq!(op.public_key.to_hex(), "e131b0305f0146e2ce8bd7d6b5004200bf19538b32e29c20d2002e9cd8d7907f");
                        },
                        LeaderBlockCommit(op) => {
                            assert!(op.parent_block_ptr == 203);
                            assert!(op.burn_fee == 5000);
                        }
                        _ => assert!(false)
                    }
                }

                assert!(burnchain_tip.block_snapshot.parent_burn_header_hash == chain_tip.metadata.burn_header_hash);
            },
            2 => {
                let block = &burnchain_tip.block_snapshot;
                assert!(block.block_height == 205);
                assert!(block.total_burn == 15000);
                assert!(block.num_sortitions == 3);
                assert!(block.sortition == true);

                let state_transition = &burnchain_tip.state_transition;
                assert!(state_transition.accepted_ops.len() == 2);
                assert!(state_transition.consumed_leader_keys.len() == 1);

                for op in &state_transition.accepted_ops {
                    match op {
                        LeaderKeyRegister(op) => {
                            assert_eq!(op.public_key.to_hex(), "1840db439989068a9bfe32beaab4a2ce1ab46b0149f54b20c330333a5de51b3d");
                        },
                        LeaderBlockCommit(op) => {
                            assert!(op.parent_block_ptr == 204);
                            assert!(op.burn_fee == 5000);
                        }
                        _ => assert!(false)
                    }
                }           
            
                assert!(burnchain_tip.block_snapshot.parent_burn_header_hash == chain_tip.metadata.burn_header_hash);
            },
            3 => {
                let block = &burnchain_tip.block_snapshot;
                assert!(block.block_height == 206);
                assert!(block.total_burn == 20000);
                assert!(block.num_sortitions == 4);
                assert!(block.sortition == true);

                let state_transition = &burnchain_tip.state_transition;
                assert!(state_transition.accepted_ops.len() == 2);
                assert!(state_transition.consumed_leader_keys.len() == 1);

                for op in &state_transition.accepted_ops {
                    match op {
                        LeaderKeyRegister(op) => {
                            assert_eq!(op.public_key.to_hex(), "d5f8569cc5aeadfb508b93f8a5740144bb52ef409d9f0afbe5a2e1d11a57f4a3");
                        },
                        LeaderBlockCommit(op) => {
                            assert!(op.parent_block_ptr == 205);
                            assert!(op.burn_fee == 5000);
                        }
                        _ => assert!(false)
                    }
                }            

                assert!(burnchain_tip.block_snapshot.parent_burn_header_hash == chain_tip.metadata.burn_header_hash);
            },
            4 => {
                let block = &burnchain_tip.block_snapshot;
                assert!(block.block_height == 207);
                assert!(block.total_burn == 25000);
                assert!(block.num_sortitions == 5);
                assert!(block.sortition == true);

                let state_transition = &burnchain_tip.state_transition;
                assert!(state_transition.accepted_ops.len() == 2);
                assert!(state_transition.consumed_leader_keys.len() == 1);

                for op in &state_transition.accepted_ops {
                    match op {
                        LeaderKeyRegister(op) => {
                            assert_eq!(op.public_key.to_hex(), "81a60590f859300f994f725cd35e510d2ffa05789d0e2b2dc71bf7bc09eca576");
                        },
                        LeaderBlockCommit(op) => {
                            assert!(op.parent_block_ptr == 206);
                            assert!(op.burn_fee == 5000);
                        }
                        _ => assert!(false)
                    }
                }

                assert!(burnchain_tip.block_snapshot.parent_burn_header_hash == chain_tip.metadata.burn_header_hash);
            },
            5 => {
                let block = &burnchain_tip.block_snapshot;
                assert!(block.block_height == 208);
                assert!(block.total_burn == 30000);
                assert!(block.num_sortitions == 6);
                assert!(block.sortition == true);

                let state_transition = &burnchain_tip.state_transition;
                assert!(state_transition.accepted_ops.len() == 2);
                assert!(state_transition.consumed_leader_keys.len() == 1);

                for op in &state_transition.accepted_ops {
                    match op {
                        LeaderKeyRegister(op) => {
                            assert_eq!(op.public_key.to_hex(), "e8de363ffd6baec1ddf629eab0a6eff6a56385d34e4d7f0f2caff8febe74acc4");
                        },
                        LeaderBlockCommit(op) => {
                            assert!(op.parent_block_ptr == 207);
                            assert!(op.burn_fee == 5000);
                        }
                        _ => assert!(false)
                    }
                }
                
                assert!(burnchain_tip.block_snapshot.parent_burn_header_hash == chain_tip.metadata.burn_header_hash);
            },
            _ => {}
        }
    });

    // Use tenure's hook for submitting transactions
    run_loop.callbacks.on_new_tenure(|round, _burnchain_tip, chain_tip, tenure| {
        match round {
            1 => {
                // On round 1, publish the KV contract
                // $ cat /tmp/out.clar 
                // (define-map store ((key (string-ascii 32))) ((value (string-ascii 32))))
                // (define-public (get-value (key (string-ascii 32)))
                //     (begin
                //         (print (concat "Getting key " key))
                //         (match (map-get? store ((key key)))
                //             entry (ok (get value entry))
                //             (err 0))))
                // (define-public (set-value (key (string-ascii 32)) (value (string-ascii 32)))
                //     (begin
                //         (print (concat "Setting key " key))
                //         (map-set store ((key key)) ((value value)))
                //         (ok 'true)))
                // ./blockstack-cli --testnet publish 043ff5004e3d695060fa48ac94c96049b8c14ef441c50a184a6a3875d2a000f3 0 0 store /tmp/out.clar
                let header_hash = chain_tip.block.block_hash();
                let burn_header_hash = chain_tip.metadata.burn_header_hash;
                tenure.mem_pool.submit_raw(&burn_header_hash, &header_hash, PUBLISH_CONTRACT.to_owned()).unwrap();
            },
            2 => {
                // On round 2, publish a "get:foo" transaction
                // ./blockstack-cli --testnet contract-call 043ff5004e3d695060fa48ac94c96049b8c14ef441c50a184a6a3875d2a000f3 0 1 STGT7GSMZG7EA0TS6MVSKT5JC1DCDFGZWJJZXN8A store get-value -e \"foo\"
                let header_hash = chain_tip.block.block_hash();
                let burn_header_hash = chain_tip.metadata.burn_header_hash;
                let get_foo = "8080000000040021a3c334fc0ee50359353799e8b2605ac6be1fe4000000000000000000000000000000000101f98bb1103bc18d98f82984ae68729bc8987202bce2dd63151766f1facf6839c13f321960f1e7926e7c6ac81e0e6586d0b877d8768c579720c2b710210bb14067030200000000010573746f7265000001ec28646566696e652d6d61702073746f72652028286b65792028737472696e672d617363696920333229292920282876616c75652028737472696e672d6173636969203332292929290a28646566696e652d7075626c696320286765742d76616c756520286b65792028737472696e672d61736369692033322929290a2020202028626567696e0a2020202020202020287072696e742028636f6e636174202247657474696e67206b65792022206b657929290a2020202020202020286d6174636820286d61702d6765743f2073746f72652028286b6579206b65792929290a202020202020202020202020656e74727920286f6b20286765742076616c756520656e74727929290a202020202020202020202020286572722030292929290a28646566696e652d7075626c696320287365742d76616c756520286b65792028737472696e672d61736369692033322929202876616c75652028737472696e672d61736369692033322929290a2020202028626567696e0a2020202020202020287072696e742028636f6e636174202253657474696e67206b65792022206b657929290a2020202020202020286d61702d7365742073746f72652028286b6579206b6579292920282876616c75652076616c75652929290a2020202020202020286f6b2027747275652929290a";
                tenure.mem_pool.submit_raw(&burn_header_hash, &header_hash,hex_bytes(get_foo).unwrap().to_vec()).unwrap();
            },
            3 => {
                // On round 3, publish a "set:foo=bar" transaction
                // ./blockstack-cli --testnet contract-call 043ff5004e3d695060fa48ac94c96049b8c14ef441c50a184a6a3875d2a000f3 0 1 STGT7GSMZG7EA0TS6MVSKT5JC1DCDFGZWJJZXN8A store set-value -e \"foo\" -e \"bar\"
                let header_hash = chain_tip.block.block_hash();
                let burn_header_hash = chain_tip.metadata.burn_header_hash;
                let set_foo_bar = "8080000000040021a3c334fc0ee50359353799e8b2605ac6be1fe40000000000000001000000000000000001017112764d8a0c0a5476fc6ec37de6bc564259c6ccd4ef8ce06c1cd23f58c66a114485df6bbdf147ded8ae4fc6dda87686052bc9aa4734265c3ae4b64613b2ceb1030200000000021a21a3c334fc0ee50359353799e8b2605ac6be1fe40573746f7265097365742d76616c7565000000020d00000003666f6f0d00000003626172";
                tenure.mem_pool.submit_raw(&burn_header_hash, &header_hash,hex_bytes(set_foo_bar).unwrap().to_vec()).unwrap();
            },
            4 => {
                // On round 4, publish a "get:foo" transaction
                // ./blockstack-cli --testnet contract-call 043ff5004e3d695060fa48ac94c96049b8c14ef441c50a184a6a3875d2a000f3 0 3 STGT7GSMZG7EA0TS6MVSKT5JC1DCDFGZWJJZXN8A store get-value -e \"foo\"
                let header_hash = chain_tip.block.block_hash();
                let burn_header_hash = chain_tip.metadata.burn_header_hash;
                let get_foo = "8080000000040021a3c334fc0ee50359353799e8b2605ac6be1fe4000000000000000300000000000000000101fd27e1727f78c38620dc155ca9940a02e964d08fcd35ac4fc8fbc56d62caac585891f537751626dc87fc7f212b3e7586845d36800e742c3f2b0c0a05cf81435e030200000000021a21a3c334fc0ee50359353799e8b2605ac6be1fe40573746f7265096765742d76616c7565000000010d00000003666f6f";
                tenure.mem_pool.submit_raw(&burn_header_hash, &header_hash,hex_bytes(get_foo).unwrap().to_vec()).unwrap();
            },
            5 => {
                // On round 5, publish a stacks transaction
                // ./blockstack-cli --testnet token-transfer b1cf9cee5083f421c84d7cb53be5edf2801c3c78d63d53917aee0bdc8bd160ee01 0 0 ST195Q2HPXY576N4CT2A0R94D7DRYSX54A5X3YZTH 1000
                let header_hash = chain_tip.block.block_hash();
                let burn_header_hash = chain_tip.metadata.burn_header_hash;
                let transfer_1000_stx = "80800000000400b71a091b4b8b7661a661c620966ab6573bc2dcd3000000000000000000000000000000000000cf44fd240b404ec42a4e419ef2059add056980fed6f766e2f11e4b03a41afb885cfd50d2552ec3fff5c470d6975dfe4010cd17bef45e24e0c6e30c8ae6604b2f03020000000000051a525b8a36ef8a73548cd0940c248d3b71ecf4a45100000000000003e800000000000000000000000000000000000000000000000000000000000000000000";
                tenure.mem_pool.submit_raw(&burn_header_hash, &header_hash,hex_bytes(transfer_1000_stx).unwrap().to_vec()).unwrap();
            },
            _ => {}
        };
        return
    });

    // Use block's hook for asserting expectations
    // In this serie of tests, the callback is fired post-burnchain-sync, post-stacks-sync
    run_loop.callbacks.on_new_stacks_chain_state(|round, burnchain_tip, chain_tip, _chain_state| {
        match round {
            0 => {
                // Inspecting the chain at round 0.
                // - Chain length should be 1.
                assert!(chain_tip.metadata.block_height == 1);
                
                // Block #1 should only have 0 txs
                assert!(chain_tip.block.txs.len() == 1);

                assert!(chain_tip.block.header.block_hash() == burnchain_tip.block_snapshot.winning_stacks_block_hash);
            },
            1 => {
                // Inspecting the chain at round 1.
                // - Chain length should be 2.
                assert!(chain_tip.metadata.block_height == 2);
                
                // Block #2 should only have 2 txs
                assert!(chain_tip.block.txs.len() == 2);

                assert!(chain_tip.block.header.block_hash() == burnchain_tip.block_snapshot.winning_stacks_block_hash);

            },
            2 => {
                // Inspecting the chain at round 2.
                // - Chain length should be 3.
                assert!(chain_tip.metadata.block_height == 3);
                
                // Block #3 should only have 2 txs
                assert!(chain_tip.block.txs.len() == 2);

                assert!(chain_tip.block.header.block_hash() == burnchain_tip.block_snapshot.winning_stacks_block_hash);

            },
            3 => {
                // Inspecting the chain at round 3.
                // - Chain length should be 4.
                assert!(chain_tip.metadata.block_height == 4);
                
                // Block #4 should only have 2 txs
                assert!(chain_tip.block.txs.len() == 2);

                assert!(chain_tip.block.header.block_hash() == burnchain_tip.block_snapshot.winning_stacks_block_hash);
            },
            4 => {
                // Inspecting the chain at round 4.
                // - Chain length should be 5.
                assert!(chain_tip.metadata.block_height == 5);
                
                // Block #5 should only have 2 txs
                assert!(chain_tip.block.txs.len() == 2);

                assert!(chain_tip.block.header.block_hash() == burnchain_tip.block_snapshot.winning_stacks_block_hash);

            },
            5 => {
                // Inspecting the chain at round 5.
                // - Chain length should be 6.
                assert!(chain_tip.metadata.block_height == 6);
                
                // Block #6 should only have 2 txs
                assert!(chain_tip.block.txs.len() == 2);

                assert!(chain_tip.block.header.block_hash() == burnchain_tip.block_snapshot.winning_stacks_block_hash);
            },
            _ => {}
        }
    });
    run_loop.start(num_rounds);

    controller.kill_bitcoind();
}
