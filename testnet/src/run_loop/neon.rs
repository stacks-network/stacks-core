use crate::{Config, Node, BurnchainController, BitcoinRegtestController, ChainTip, BurnchainTip, Tenure};

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
    pub fn start(&mut self, expected_num_rounds: u64) {

        // Initialize and start the burnchain.
        let mut burnchain: Box<dyn BurnchainController> = BitcoinRegtestController::generic(self.config.clone());

        self.callbacks.invoke_burn_chain_initialized(&mut burnchain);

        let burnchain_tip = burnchain.start();
        let total_burn = burnchain_tip.block_snapshot.total_burn; 
        let (mut node, mut chain_tip, mut burnchain_tip, mut tenure) = match total_burn {
            0 => self.exec_genesis_boot_sequence(&mut burnchain),
            _ => self.exec_standard_boot_sequence(&mut burnchain)
        };

        let mut round_index: u64 = 1; // todo(ludo): careful with this round_index
        
        // Start the runloop
        loop {
            if expected_num_rounds == round_index {
                return;
            }

            // Run the last initialized tenure
            let artifacts_from_tenure = match tenure {
                Some(mut tenure) => {
                    self.callbacks.invoke_new_tenure(round_index, &burnchain_tip, &chain_tip, &mut tenure);
                    tenure.run()
                },
                None => None
            };

            match artifacts_from_tenure {
                Some(ref artifacts) => {
                    node.commit_artifacts(
                        &artifacts.anchored_block, 
                        &artifacts.parent_block, 
                        &mut burnchain, 
                        artifacts.burn_fee);
                },
                None => {}
            }

            burnchain_tip = burnchain.sync();
            self.callbacks.invoke_new_burn_chain_state(round_index, &burnchain_tip, &chain_tip);
    
            tenure = None;

            // Have each node process the new block, that can include, or not, a sortition.
            let (sortitioned_block, won_sortition) = node.process_burnchain_state(&burnchain_tip);

            match (artifacts_from_tenure, sortitioned_block) {
                // Pass if we're missing the artifacts from the current tenure.
                (Some(ref artifacts), Some(ref last_sortitioned_block)) => {
                    // Have each node process the previous tenure.
                    // We should have some additional checks here, and ensure that the previous artifacts are legit.
                    chain_tip = node.process_tenure(
                        &artifacts.anchored_block, 
                        &last_sortitioned_block.block_snapshot.burn_header_hash, 
                        &last_sortitioned_block.block_snapshot.parent_burn_header_hash,             
                        artifacts.microblocks.clone(),
                        burnchain.burndb_mut());

                        self.callbacks.invoke_new_stacks_chain_state(
                            round_index, 
                            &burnchain_tip, 
                            &chain_tip, 
                            &mut node.chain_state);
                },
                (_, _) => continue,
            };
            
            // If the node we're looping on won the sortition, initialize and configure the next tenure
            if won_sortition {
                tenure = node.initiate_new_tenure();
            } 
            
            round_index += 1;
        }
    }

    // In this boot sequence, a node will be initializing a chainstate from scratch, 
    // loading the boot smart contracts and the initial balances.
    // It will then register a key, build a genesis stack block and create a block commit.
    // This method will return a tenure, that can then be run.  
    fn exec_genesis_boot_sequence(&self, burnchain_controller: &mut Box<dyn BurnchainController>) -> (Node, ChainTip, BurnchainTip, Option<Tenure>) {
        let mut node = Node::new(self.config.clone(), |_| {});

        // Sync and update node with this new block.
        node.setup(burnchain_controller);
        let genesis_burnchain_tip = burnchain_controller.sync();
        node.process_burnchain_state(&genesis_burnchain_tip);
        
        let mut chain_tip = ChainTip::genesis();

        // Bootstrap the chain: node will start a new tenure,
        // using the sortition hash from block #1 for generating a VRF.
        let mut first_tenure = match node.initiate_genesis_tenure(&genesis_burnchain_tip) {
            Some(res) => res,
            None => panic!("Error while initiating genesis tenure")
        };
        self.callbacks.invoke_new_tenure(0, &genesis_burnchain_tip, &chain_tip, &mut first_tenure);

        // Run the tenure, keep the artifacts
        let artifacts_from_1st_tenure = match first_tenure.run() {
            Some(res) => res,
            None => panic!("Error while running 1st tenure")
        };

        // Tenures are instantiating their own chainstate, so that nodes can keep a clean chainstate,
        // while having the option of running multiple tenures concurrently and try different strategies.
        // As a result, once the tenure ran and we have the artifacts (anchored_blocks, microblocks),
        // we have the 1st node (leading) updating its chainstate with the artifacts from its own tenure.
        node.commit_artifacts(
            &artifacts_from_1st_tenure.anchored_block, 
            &artifacts_from_1st_tenure.parent_block, 
            burnchain_controller, 
            artifacts_from_1st_tenure.burn_fee);

        let burnchain_tip = burnchain_controller.sync();
        self.callbacks.invoke_new_burn_chain_state(0, &burnchain_tip, &chain_tip);


        let (last_sortitioned_block, won_sortition) = match node.process_burnchain_state(&burnchain_tip) {
            (Some(sortitioned_block), won_sortition) => (sortitioned_block, won_sortition),
            (None, _) => panic!("Node should have a sortitioned block")
        };
        
        if won_sortition == false {
            panic!("Unable to bootstrap chain");
        }

        // Have the node process its own tenure.
        // We should have some additional checks here, and ensure that the previous artifacts are legit.
        chain_tip = node.process_tenure(
            &artifacts_from_1st_tenure.anchored_block, 
            &last_sortitioned_block.block_snapshot.burn_header_hash, 
            &last_sortitioned_block.block_snapshot.parent_burn_header_hash, 
            artifacts_from_1st_tenure.microblocks.clone(),
            burnchain_controller.burndb_mut());

        self.callbacks.invoke_new_stacks_chain_state(
            0, 
            &burnchain_tip, 
            &chain_tip, 
            &mut node.chain_state);

        let tenure = node.initiate_new_tenure();

        node.spawn_peer_server();

        (node, chain_tip, burnchain_tip, tenure)
    }

    // In this boot sequence, a node will be initializing a chainstate from network, ignoring
    // the boot contrats, initial balances etc.
    // Instead, it would sync with the peer networks and build a chainstate consistent with
    // the burnchain_tip previously fetched. 
    fn exec_standard_boot_sequence(&self, burnchain_controller: &mut Box<dyn BurnchainController>) -> (Node, ChainTip, BurnchainTip, Option<Tenure>) {
        let node = Node::init_and_sync(self.config.clone(), burnchain_controller);
        
        let burnchain_tip = node.burnchain_tip.clone()
            .expect("Unable to get a chaintip from the burnchain");

        let chain_tip = node.chain_tip.clone()
            .expect("Unable to get a chaintip from the stacks chain");

        (node, chain_tip, burnchain_tip, None)
    }
}