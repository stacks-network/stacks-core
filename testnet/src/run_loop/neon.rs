use std::process;
use crate::{Config, NeonGenesisNode, BurnchainController, 
            BitcoinRegtestController, Keychain};
use stacks::chainstate::burn::db::burndb::BurnDB;
use stacks::burnchains::bitcoin::address::BitcoinAddress;
use stacks::burnchains::Address;
use stacks::burnchains::bitcoin::{BitcoinNetworkType, 
                                  address::{BitcoinAddressType}};

use super::RunLoopCallbacks;

/// Coordinating a node running in neon mode.
pub struct RunLoop {
    config: Config,
    pub callbacks: RunLoopCallbacks,
}

impl RunLoop {

    /// Sets up a runloop and node, given a config.
    pub fn new(config: Config) -> Self {
        Self {
            config,
            callbacks: RunLoopCallbacks::new()
        }
    }

    /// Starts the testnet runloop.
    /// 
    /// This function will block by looping infinitely.
    /// It will start the burnchain (separate thread), set-up a channel in
    /// charge of coordinating the new blocks coming from the burnchain and 
    /// the nodes, taking turns on tenures.  
    pub fn start(&mut self, _expected_num_rounds: u64) {

        // Initialize and start the burnchain.
        let mut burnchain = BitcoinRegtestController::new(self.config.clone());

        // self.callbacks.invoke_burn_chain_initialized(&mut burnchain);

        let mut burnchain_tip = burnchain.start();

        let is_miner = if self.config.node.miner {
            let keychain = Keychain::default(self.config.node.seed.clone());
            let btc_addr = BitcoinAddress::from_bytes(
                BitcoinNetworkType::Regtest,
                BitcoinAddressType::PublicKeyHash,
                &Keychain::address_from_burnchain_signer(&keychain.get_burnchain_signer()).to_bytes())
                .unwrap();
            info!("Configured as a miner: checking if we have UTXOs at address: {}", btc_addr);

            let utxos = burnchain.get_utxos(
                &keychain.generate_op_signer().get_public_key(), 1);
            if utxos.is_none() {
                error!("I have no UTXOs... spawning as a follower. Restart node when you get some UTXOs.");
                false
            } else {
                info!("Have UTXOs, starting up as miner");
                true
            }
        } else {
            false
        };

        let mut block_height = burnchain_tip.block_snapshot.block_height;

        // setup genesis
        let node = NeonGenesisNode::new(self.config.clone(), |_| {});
        let mut node = if is_miner {
            node.into_initialized_leader_node(burnchain_tip.clone())
        } else {
            node.into_initialized_node(burnchain_tip.clone())
        };

        // Start the runloop
        info!("Begin run loop");
        loop {
            burnchain_tip = burnchain.sync();

            let next_height = burnchain_tip.block_snapshot.block_height;
            if next_height <= block_height {
                warn!("burnchain.sync() did not progress block height");
                continue;
            }

            // first, let's process all blocks in (block_height, next_height]
            for block_to_process in (block_height+1)..(next_height+1) {
                let block = {
                    let mut tx = burnchain.burndb_mut().tx_begin().unwrap();
                    BurnDB::get_ancestor_snapshot(
                        &mut tx, block_to_process, &burnchain_tip.block_snapshot.burn_header_hash)
                        .unwrap()
                        .expect("Failed to find block in fork processed by bitcoin indexer")
                };
                let burn_header_hash = block.burn_header_hash;

                // Have the node process the new block, that can include, or not, a sortition.
                node.process_burnchain_state(burnchain.burndb_mut(), 
                                             &burn_header_hash);
                // Now, tell the relayer to check if it won a sortition during this block,
                //   and, if so, to process and advertize the block
                //
                // _this will block if the relayer's buffer is full_
                if !node.relayer_sortition_notify() {
                    // relayer hung up, exit.
                    error!("Block relayer and miner hung up, exiting.");
                    process::exit(1);
                }
            }
            // now, let's tell the miner to try and mine.
            if !node.relayer_issue_tenure() {
                // relayer hung up, exit.
                error!("Block relayer and miner hung up, exiting.");
                process::exit(1);
            }

            block_height = next_height;

        }
    }
}
