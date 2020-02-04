use super::{Config, Node, BurnchainSimulator, BurnchainState, LeaderTenure};

use std::time;
use std::thread;

use chainstate::burn::{ConsensusHash};
use chainstate::stacks::db::{StacksHeaderInfo, StacksChainState};
use chainstate::burn::{BlockHeaderHash};

/// RunLoop is coordinating a simulated burnchain and some simulated nodes
/// taking turns in producing blocks.
pub struct RunLoop {
    config: Config,
    nodes: Vec<Node>,
    new_burnchain_state_callback: Option<fn(u8, &BurnchainState)>,
    new_tenure_callback: Option<fn(u8, &LeaderTenure)>,
    new_chain_state_callback: Option<fn(u8, &mut StacksChainState, &BlockHeaderHash)>,
}

impl RunLoop {

    /// Sets up a runloop and nodes, given a config.
    pub fn new(config: Config) -> Self {
        // Build a vec of nodes based on config
        let mut nodes = vec![]; 
        let mut nodes_confs = config.node_config.clone();
        for conf in nodes_confs.drain(..) {
            let node = Node::new(conf, config.burnchain_block_time);
            nodes.push(node);
        }

        Self {

            config,
            nodes,
            new_burnchain_state_callback: None,
            new_tenure_callback: None,
            new_chain_state_callback: None,        
        }
    }

    /// Starts the testnet runloop.
    /// 
    /// This function will block by looping infinitely.
    /// It will start the burnchain (separate thread), set-up a channel in
    /// charge of coordinating the new blocks coming from the burnchain and 
    /// the nodes, taking turns on tenures.  
    pub fn start(&mut self, expected_num_rounds: u8) {

        // Initialize and start the burnchain.
        let mut burnchain = BurnchainSimulator::new();

        // Start the burnchain - happening on a separate thread. 
        // Keep a mpsc::Receiver (burnchain_block_rx), used for receiving blocks, and
        // a mpsc::Sender, cloned by each node and used for submitting ops (key registrations, 
        // block commits) on the burnchain.
        let (burnchain_block_rx, burnchain_op_tx) = burnchain.start(&self.config);

        // Setup each node with a mpsc::Sender used for channeling ops to the burnchain
        for node in self.nodes.iter_mut() {
            node.setup(burnchain_op_tx.clone());
        }

        // Wait on the genesis state from the burnchain.
        let genesis_state = match burnchain_block_rx.recv() {
            Ok(res) => res,
            Err(err) => panic!("Error while expecting genesis block from burnchain: {:?}", err)
        };

        // Update each node with the genesis block.
        for node in self.nodes.iter_mut() {
            node.process_burnchain_state(&genesis_state);
        }

        // Waiting on the 1st block (post-genesis) from the burnchain, containing the first key registrations 
        // that will be used for bootstraping the chain.
        let mut round_index = 0;
        let state_1 = match burnchain_block_rx.recv() {
            Ok(res) => res,
            Err(err) => panic!("Error while expecting block #1 from burnchain: {:?}", err)
        };

        // Update each node with this new block.
        for node in self.nodes.iter_mut() {
            node.process_burnchain_state(&state_1);
        }

        // Bootstrap the chain: the first node (could be random) will start a new tenure,
        // using the sortition hash from block #1 for generating a VRF.
        let leader = &mut self.nodes[0];
        let mut first_tenure = match leader.initiate_genesis_tenure(&state_1.chain_tip) {
            Some(res) => res,
            None => panic!("Error while initiating genesis tenure")
        };

        RunLoop::handle_new_tenure_cb(&self.new_tenure_callback, round_index, &first_tenure);

        // Run the tenure, keep the artifacts
        let artifacts_from_1st_tenure = match first_tenure.run() {
            Some(res) => res,
            None => panic!("Error while running 1st tenure")
        };

        let (anchored_block_1, microblocks, parent_block_1) = artifacts_from_1st_tenure;

        // Tenures are instantiating their own chainstate, so that nodes can keep their chainstate clean,
        // while having the option of running multiple tenures concurrently and try different strategies.
        // As a result, once the tenure ran and we have the artifacts (anchored_blocks, microblocks),
        // we have the 1st node (leading) updating its chainstate with the artifacts from its tenure.
        leader.receive_tenure_artifacts(&anchored_block_1, &parent_block_1);

        // Bootstraping phase is done. Waiting on the next block from the burnchain, that 
        // will include a block commit op and consequently a sortition.
        let mut burnchain_state = match burnchain_block_rx.recv() {
            Ok(res) => res,
            Err(err) => panic!("Error while expecting block #2 from burnchain: {:?}", err)
        };

        RunLoop::handle_burnchain_state_cb(&self.new_burnchain_state_callback, round_index, &burnchain_state);

        let mut leader_tenure = None;

        for node in self.nodes.iter_mut() {
            // Have each node process the new block, that should include a sortition thanks to the
            // 1st tenure.
            let (last_sortitioned_block, won_sortition) = match node.process_burnchain_state(&burnchain_state) {
                (Some(sortitioned_block), won_sortition) => (sortitioned_block, won_sortition),
                (None, _) => panic!("Node should have a sortitioned block")
            };
            
            // Have each node process the previous tenure.
            // We should have some additional checks here, and ensure that the previous artifacts are legit.
            // Note: we're cloning ARC<burn_db>, not burn_db instances.

            node.process_tenure(
                &anchored_block_1, 
                &last_sortitioned_block.burn_header_hash, 
                &last_sortitioned_block.parent_burn_header_hash, 
                microblocks.clone(), 
                burnchain_state.db.clone());

            let index_bhh = anchored_block_1.header.index_block_hash(
                &last_sortitioned_block.burn_header_hash);
            RunLoop::handle_new_chain_state_cb(&self.new_chain_state_callback, round_index, &mut node.chain_state, &index_bhh);

            // If the node we're looping on won the sortition, initialize and configure the next tenure
            if won_sortition {
                leader_tenure = node.initiate_new_tenure(&last_sortitioned_block);
            }
        }

        // Start the runloop
        round_index = 1;
        loop {
            if expected_num_rounds == round_index {
                return;
            }

            // Run the last initialized tenure
            let artifacts_from_tenure = match leader_tenure {
                Some(mut tenure) => {
                    RunLoop::handle_new_tenure_cb(&self.new_tenure_callback, round_index, &tenure);
                    tenure.run()
                },
                None => None
            };

            match artifacts_from_tenure {
                Some(ref artifacts) => {
                    // Have each node receive artifacts from the current tenure
                    let (anchored_block, _, parent_block) = artifacts;
                    for node in self.nodes.iter_mut() {
                        node.receive_tenure_artifacts(&anchored_block, &parent_block);                    
                    }    
                },
                None => {}
            }

            // Wait on the next block from the burnchain.
            burnchain_state = match burnchain_block_rx.recv() {
                Ok(res) => res,
                Err(err) => panic!("Error while expecting block from burnchain: {:?}", err)
            };
            RunLoop::handle_burnchain_state_cb(&self.new_burnchain_state_callback, round_index, &burnchain_state);
    
            leader_tenure = None;

            for node in self.nodes.iter_mut() {
                // Have each node process the new block, that can include, or not, a sortition.
                let (last_sortitioned_block, won_sortition) = match node.process_burnchain_state(&burnchain_state) {
                    (Some(sortitioned_block), won_sortition) => (sortitioned_block, won_sortition),
                    (None, _) => panic!("Node should have a sortitioned block")
                };

                match artifacts_from_tenure {
                    // Pass if we're missing the artifacts from the current tenure.
                    None => continue,
                    Some(ref artifacts) => {
                        // Have each node process the previous tenure.
                        // We should have some additional checks here, and ensure that the previous artifacts are legit.
                        let (anchored_block, microblocks, _) = artifacts;
                        node.process_tenure(
                            &anchored_block, 
                            &burnchain_state.chain_tip.burn_header_hash, 
                            &burnchain_state.chain_tip.parent_burn_header_hash,             
                            microblocks.to_vec(), 
                            burnchain_state.db.clone());
                        let index_bhh = anchored_block.header.index_block_hash(
                            &burnchain_state.chain_tip.burn_header_hash);
                        RunLoop::handle_new_chain_state_cb(&self.new_chain_state_callback, round_index,
                                                           &mut node.chain_state, &index_bhh);
                    },
                };
                
                // If the node we're looping on won the sortition, initialize and configure the next tenure
                if won_sortition {
                    leader_tenure = node.initiate_new_tenure(&last_sortitioned_block);
                } 
            }
            
            round_index += 1;
        }
    }

    pub fn apply_on_new_burnchain_states(&mut self, f: fn(u8, &BurnchainState)) {
        self.new_burnchain_state_callback = Some(f);
    }

    pub fn apply_on_new_tenures(&mut self, f: fn(u8, &LeaderTenure)) {
        self.new_tenure_callback = Some(f);
    }
    
    pub fn apply_on_new_chain_states(&mut self, f: fn(u8, &mut StacksChainState, &BlockHeaderHash)) {
        self.new_chain_state_callback = Some(f);
    }

    fn handle_new_tenure_cb(new_tenure_callback: &Option<fn(u8, &LeaderTenure)>,
                            round_index: u8, tenure: &LeaderTenure) {
        new_tenure_callback.map(|cb| cb(round_index, tenure));
    }

    fn handle_burnchain_state_cb(burn_callback: &Option<fn(u8, &BurnchainState)>,
                                 round_index: u8, state: &BurnchainState) {
        burn_callback.map(|cb| cb(round_index, state));
    }

    fn handle_new_chain_state_cb(chain_state_callback: &Option<fn(u8, &mut StacksChainState, &BlockHeaderHash)>,
                                 round_index: u8, state: &mut StacksChainState, id_hash: &BlockHeaderHash) {
        chain_state_callback.map(|cb| cb(round_index, state, &id_hash));
    }

}
