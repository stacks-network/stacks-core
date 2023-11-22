use stacks::chainstate::stacks::db::ClarityTx;
use stacks_common::types::chainstate::BurnchainHeaderHash;

use super::RunLoopCallbacks;
use crate::burnchains::Error as BurnchainControllerError;
use crate::{
    BitcoinRegtestController, BurnchainController, ChainTip, Config, MocknetController, Node,
};

/// RunLoop is coordinating a simulated burnchain and some simulated nodes
/// taking turns in producing blocks.
pub struct RunLoop {
    config: Config,
    pub node: Node,
    pub callbacks: RunLoopCallbacks,
}

impl RunLoop {
    pub fn new(config: Config) -> Self {
        RunLoop::new_with_boot_exec(config, Box::new(|_| {}))
    }

    /// Sets up a runloop and node, given a config.
    pub fn new_with_boot_exec(
        config: Config,
        boot_exec: Box<dyn FnOnce(&mut ClarityTx) -> ()>,
    ) -> Self {
        // Build node based on config
        let node = Node::new(config.clone(), boot_exec);

        Self {
            config,
            node,
            callbacks: RunLoopCallbacks::new(),
        }
    }

    /// Starts the testnet runloop.
    ///
    /// This function will block by looping infinitely.
    /// It will start the burnchain (separate thread), set-up a channel in
    /// charge of coordinating the new blocks coming from the burnchain and
    /// the nodes, taking turns on tenures.  
    pub fn start(&mut self, expected_num_rounds: u64) -> Result<(), BurnchainControllerError> {
        // Initialize and start the burnchain.
        let mut burnchain: Box<dyn BurnchainController> = match &self.config.burnchain.mode[..] {
            "helium" => Box::new(BitcoinRegtestController::new(self.config.clone(), None)),
            "mocknet" => MocknetController::generic(self.config.clone()),
            _ => unreachable!(),
        };

        self.callbacks.invoke_burn_chain_initialized(&mut burnchain);

        let (initial_state, _) = burnchain.start(None)?;

        // Update each node with the genesis block.
        self.node.process_burnchain_state(&initial_state);

        // make first non-genesis block, with initial VRF keys
        self.node.setup(&mut burnchain);

        // Waiting on the 1st block (post-genesis) from the burnchain, containing the first key registrations
        // that will be used for bootstraping the chain.
        let mut round_index: u64 = 0;

        // Sync and update node with this new block.
        let (burnchain_tip, _) = burnchain.sync(None)?;
        self.node.process_burnchain_state(&burnchain_tip); // todo(ludo): should return genesis?
        let mut chain_tip = ChainTip::genesis(&BurnchainHeaderHash::zero(), 0, 0);

        self.node.spawn_peer_server();

        // Bootstrap the chain: node will start a new tenure,
        // using the sortition hash from block #1 for generating a VRF.
        let leader = &mut self.node;
        let mut first_tenure = match leader.initiate_genesis_tenure(&burnchain_tip) {
            Some(res) => res,
            None => panic!("Error while initiating genesis tenure"),
        };

        self.callbacks.invoke_new_tenure(
            round_index,
            &burnchain_tip,
            &chain_tip,
            &mut first_tenure,
        );

        // TODO (hack) instantiate db
        let _ = burnchain.sortdb_mut();

        // Run the tenure, keep the artifacts
        let artifacts_from_1st_tenure = match first_tenure.run(&burnchain.sortdb_ref().index_conn())
        {
            Some(res) => res,
            None => panic!("Error while running 1st tenure"),
        };

        // Tenures are instantiating their own chainstate, so that nodes can keep a clean chainstate,
        // while having the option of running multiple tenures concurrently and try different strategies.
        // As a result, once the tenure ran and we have the artifacts (anchored_blocks, microblocks),
        // we have the 1st node (leading) updating its chainstate with the artifacts from its own tenure.
        leader.commit_artifacts(
            &artifacts_from_1st_tenure.anchored_block,
            &artifacts_from_1st_tenure.parent_block,
            &mut burnchain,
            artifacts_from_1st_tenure.burn_fee,
        );

        let (mut burnchain_tip, _) = burnchain.sync(None)?;

        self.callbacks
            .invoke_new_burn_chain_state(round_index, &burnchain_tip, &chain_tip);

        let mut leader_tenure = None;

        let (last_sortitioned_block, won_sortition) =
            match self.node.process_burnchain_state(&burnchain_tip) {
                (Some(sortitioned_block), won_sortition) => (sortitioned_block, won_sortition),
                (None, _) => panic!("Node should have a sortitioned block"),
            };

        // Have the node process its own tenure.
        // We should have some additional checks here, and ensure that the previous artifacts are legit.
        let mut atlas_db = self.node.make_atlas_db();

        chain_tip = self.node.process_tenure(
            &artifacts_from_1st_tenure.anchored_block,
            &last_sortitioned_block.block_snapshot.consensus_hash,
            artifacts_from_1st_tenure.microblocks.clone(),
            burnchain.sortdb_mut(),
            &mut atlas_db,
        );

        self.callbacks.invoke_new_stacks_chain_state(
            round_index,
            &burnchain_tip,
            &chain_tip,
            &mut self.node.chain_state,
            &burnchain.sortdb_ref().index_conn(),
        );

        // If the node we're looping on won the sortition, initialize and configure the next tenure
        if won_sortition {
            leader_tenure = self.node.initiate_new_tenure();
        }

        // Start the runloop
        round_index = 1;
        loop {
            if expected_num_rounds == round_index {
                return Ok(());
            }

            // Run the last initialized tenure
            let artifacts_from_tenure = match leader_tenure {
                Some(mut tenure) => {
                    self.callbacks.invoke_new_tenure(
                        round_index,
                        &burnchain_tip,
                        &chain_tip,
                        &mut tenure,
                    );
                    tenure.run(&burnchain.sortdb_ref().index_conn())
                }
                None => None,
            };

            match artifacts_from_tenure {
                Some(ref artifacts) => {
                    // Have each node receive artifacts from the current tenure
                    self.node.commit_artifacts(
                        &artifacts.anchored_block,
                        &artifacts.parent_block,
                        &mut burnchain,
                        artifacts.burn_fee,
                    );
                }
                None => {}
            }

            let (new_burnchain_tip, _) = burnchain.sync(None)?;
            burnchain_tip = new_burnchain_tip;

            self.callbacks
                .invoke_new_burn_chain_state(round_index, &burnchain_tip, &chain_tip);

            leader_tenure = None;

            // Have each node process the new block, that can include, or not, a sortition.
            let (last_sortitioned_block, won_sortition) =
                match self.node.process_burnchain_state(&burnchain_tip) {
                    (Some(sortitioned_block), won_sortition) => (sortitioned_block, won_sortition),
                    (None, _) => panic!("Node should have a sortitioned block"),
                };

            match artifacts_from_tenure {
                // Pass if we're missing the artifacts from the current tenure.
                None => continue,
                Some(ref artifacts) => {
                    // Have the node process its tenure.
                    // We should have some additional checks here, and ensure that the previous artifacts are legit.
                    let mut atlas_db = self.node.make_atlas_db();

                    chain_tip = self.node.process_tenure(
                        &artifacts.anchored_block,
                        &last_sortitioned_block.block_snapshot.consensus_hash,
                        artifacts.microblocks.clone(),
                        burnchain.sortdb_mut(),
                        &mut atlas_db,
                    );

                    self.callbacks.invoke_new_stacks_chain_state(
                        round_index,
                        &burnchain_tip,
                        &chain_tip,
                        &mut self.node.chain_state,
                        &burnchain.sortdb_ref().index_conn(),
                    );
                }
            };

            // If won sortition, initialize and configure the next tenure
            if won_sortition {
                leader_tenure = self.node.initiate_new_tenure();
            }

            round_index += 1;
        }
    }
}
