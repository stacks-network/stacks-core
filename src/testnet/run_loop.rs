use super::{Config, Node, BurnchainSimulator};

use std::time;
use std::thread;

use chainstate::burn::{ConsensusHash};

/// RunLoop is coordinating a simulated burnchain and some simulated nodes
/// taking turns in producing blocks.
pub struct RunLoop {
    config: Config,
    nodes: Vec<Node>,
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
        }
    }

    /// Starts the testnet runloop.
    /// 
    /// This function will block by looping infinitely.
    /// It will start the burnchain (separate thread), set-up a channel in
    /// charge of coordinating the new blocks coming from the burnchain and 
    /// the nodes, taking turns on tenures.  
    pub fn start(&mut self) {

        // Initialize and start the burnchain.
        let mut burnchain = BurnchainSimulator::new();

        // Start the burnchain - happening on a separate thread. 
        // Keep a mpsc::Receiver (burnchain_block_rx), used for receiving blocks, and
        // a mpsc::Sender, cloned by each node and used for submitting ops (key registrations, 
        // block commits) on the burnchain.
        let (burnchain_block_rx, burnchain_op_tx) = burnchain.start(&self.config);

        // Tear-up each node with a mpsc::Sender channeling ops to the burnchain
        for node in self.nodes.iter_mut() {
            node.tear_up(burnchain_op_tx.clone(), ConsensusHash::empty());
        }

        // Wait on the genesis block from the burnchain.
        let (genesis_block, ops, _) = burnchain_block_rx.recv().unwrap();

        // Update each node with the genesis block.
        for node in self.nodes.iter_mut() {
            node.process_burnchain_block(&genesis_block, &ops);
        }

        // When producing an anchored block, we need a block from the burnchain, and its parent.
        // We'll wait on the next block from the burnchain for starting the bootstrap.
        let (burnchain_block_1, ops, _) = burnchain_block_rx.recv().unwrap();

        // Update each node with this new block.
        for node in self.nodes.iter_mut() {
            node.process_burnchain_block(&burnchain_block_1, &ops);
        }

        // Bootstrap the chain: the first node (could be random) will start a new tenure,
        // using SortitionHash::genesis for generating a VRF.
        let mut first_tenure = self.nodes[0].initiate_genesis_tenure(&genesis_block).unwrap();

        // Run the tenure, keep the artifacts
        let artifacts_from_1st_tenure = first_tenure.run();
        let (anchored_block_1, microblocks, parent_block_1) = artifacts_from_1st_tenure.clone();

        // Tenures are instantiating their own chainstate, so that nodes can keep some clean chainstates,
        // and have the option of running multiple tenures concurrently and try different strategies.
        // As a result, once the tenure ran and we have the artifacts (anchored_blocks, microblocks),
        // we have the 1st node (leading) updating its chainstate with the artifacts from its tenure.
        self.nodes[0].receive_tenure_artefacts(anchored_block_1.unwrap(), parent_block_1.clone());

        // Bootstraping phase is done. Waiting on the next block from the burnchain, that 
        // will include a block commit op and consequently a sortition.
        let (burnchain_block, ops, burn_db) = burnchain_block_rx.recv().unwrap();
        
        // Declare and bind some mutable variables, that will be updated on each cycle.  
        let mut burnchain_block = burnchain_block;
        let mut ops = ops;
        let mut burn_db = burn_db;
        let mut leader_tenure = None;
        let mut last_sortitioned_block = None;

        for node in self.nodes.iter_mut() {
            // Have each node process the new block, that should include a sortition thanks to the
            // 1st tenure.
            let (sortitioned_block, won_sortition) = node.process_burnchain_block(&burnchain_block, &ops);
            last_sortitioned_block = sortitioned_block.clone();

            let (anchored_block, microblocks, _) = artifacts_from_1st_tenure.clone();

            // Have each node process the previous tenure.
            // We should have some additional checks here, and ensure that the previous artifacts are legit.
            node.process_tenure(anchored_block.unwrap(), last_sortitioned_block.clone().unwrap(), microblocks, burn_db);

            // If the node we're looping on won the sortition, initialize and configure the next tenure
            if won_sortition {
                let parent_block = last_sortitioned_block.clone().unwrap();
                leader_tenure = node.initiate_new_tenure(&parent_block);
            } 
            // todo(ludo): get rid of this.
            break;
        }

        // Start the (infinite) runloop
        loop {
            // Run the last initialized tenure
            let artifacts_from_tenure = match leader_tenure {
                Some(mut tenure) => Some(tenure.run()),
                None => None
            };

            if artifacts_from_tenure.is_some() {
                // Have each node receive artifacts from the current tenure
                for node in self.nodes.iter_mut() {
                    let (anchored_block, _, parent_block) = artifacts_from_tenure.clone().unwrap();
                    node.receive_tenure_artefacts(anchored_block.unwrap(), parent_block);                    
                }
            } else {
                println!("NO SORTITION");
            }

            // Wait on the next block from the burnchain.
            let (new_block, new_ops, new_db) = burnchain_block_rx.recv().unwrap();
            burnchain_block = new_block;
            ops = new_ops;
            burn_db = new_db;
            leader_tenure = None;

            for node in self.nodes.iter_mut() {
                // Have each node process the new block, that can include, or not, a sortition.
                let (sortitioned_block, won_sortition) = node.process_burnchain_block(&burnchain_block, &ops);

                // Pass if we're missing the artifacts from the current tenure.
                if artifacts_from_tenure.is_none() {
                    continue;
                }

                // Have each node process the previous tenure.
                // We should have some additional checks here, and ensure that the previous artifacts are legit.
                last_sortitioned_block = sortitioned_block;
                let (anchored_block, microblocks, parent_block) = artifacts_from_tenure.clone().unwrap();
                node.process_tenure(anchored_block.unwrap(), last_sortitioned_block.clone().unwrap(), microblocks, burn_db);

                // If the node we're looping on won the sortition, initialize and configure the next tenure
                if won_sortition {
                    let parent_block = last_sortitioned_block.clone().unwrap();
                    leader_tenure = node.initiate_new_tenure(&parent_block);
                } 
                // todo(ludo): get rid of this.
                break;
            }
        }
    }
}
