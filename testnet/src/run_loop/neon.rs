use crate::{Config, Node, BurnchainController, BitcoinRegtestController, ChainTip};

use stacks::chainstate::stacks::db::ClarityTx;
use super::RunLoopCallbacks;

/// Coordinating a node running in neon mode.
pub struct RunLoop {
    config: Config,
    pub node: Node,
    pub callbacks: RunLoopCallbacks,
}

impl RunLoop {
    pub fn new(config: Config) -> Self {
        RunLoop::new_with_boot_exec(config, |_| {})
    }

    /// Sets up a runloop and node, given a config.
    pub fn new_with_boot_exec<F>(config: Config, boot_exec: F) -> Self
    where F: Fn(&mut ClarityTx) -> () {

        // Build node based on config
        let node = Node::new(config.clone(), boot_exec);

        Self {
            config,
            node,
            callbacks: RunLoopCallbacks::new()
        }
    }

    /// Starts the testnet runloop.
    /// 
    /// This function will block by looping infinitely.
    /// It will start the burnchain (separate thread), set-up a channel in
    /// charge of coordinating the new blocks coming from the burnchain and 
    /// the nodes, taking turns on tenures.  
    pub fn start(&mut self, expected_num_rounds: u64) {

        // Initialize and start the burnchain.
        let mut burnchain: Box<dyn BurnchainController> = BitcoinRegtestController::generic(self.config.clone());

        self.callbacks.invoke_burn_chain_initialized(&mut burnchain);

        let mut burnchain_tip = burnchain.start();

        // TODO: enable this once available
        // self.node.spawn_peer_server();
        
        // todo(ludo): ensure that burnchain_state and chain_state are consistent
        // todo(ludo): node should retrieve prior keys, thanks to burnchain
        self.node.process_burnchain_state(&burnchain_tip);

        self.node.setup(&mut burnchain);

        let mut round_index: u64 = 1;

        let mut leader_tenure = None;

        let mut chain_tip = ChainTip::genesis(); // todo(ludo): fix
        
        // Start the runloop
        loop {
            if expected_num_rounds == round_index {
                return;
            }

            // Run the last initialized tenure
            let artifacts_from_tenure = match leader_tenure {
                Some(mut tenure) => {
                    self.callbacks.invoke_new_tenure(round_index, &burnchain_tip, &chain_tip, &tenure);
                    tenure.run()
                },
                None => None
            };

            match artifacts_from_tenure {
                Some(ref artifacts) => {
                    self.node.commit_artifacts(
                        &artifacts.anchored_block, 
                        &artifacts.parent_block, 
                        &mut burnchain, 
                        artifacts.burn_fee);
                },
                None => {}
            }

            burnchain_tip = burnchain.sync();
            self.callbacks.invoke_new_burn_chain_state(round_index, &burnchain_tip, &chain_tip);
    
            leader_tenure = None;

            // Have each node process the new block, that can include, or not, a sortition.
            let (sortitioned_block, won_sortition) = self.node.process_burnchain_state(&burnchain_tip);

            match (artifacts_from_tenure, sortitioned_block) {
                // Pass if we're missing the artifacts from the current tenure.
                (Some(ref artifacts), Some(ref last_sortitioned_block)) => {
                    // Have each node process the previous tenure.
                    // We should have some additional checks here, and ensure that the previous artifacts are legit.
                    chain_tip = self.node.process_tenure(
                        &artifacts.anchored_block, 
                        &last_sortitioned_block.block_snapshot.burn_header_hash, 
                        &last_sortitioned_block.block_snapshot.parent_burn_header_hash,             
                        artifacts.microblocks.clone(),
                        burnchain.burndb_mut());

                        self.callbacks.invoke_new_stacks_chain_state(
                            round_index, 
                            &burnchain_tip, 
                            &chain_tip, 
                            &mut self.node.chain_state);
                },
                (_, _) => continue,
            };
            
            // If the node we're looping on won the sortition, initialize and configure the next tenure
            if won_sortition {
                leader_tenure = self.node.initiate_new_tenure();
            } 
            
            round_index += 1;
        }
    }
}