use super::{Config, Node, BurnchainSimulator, BurnchainState, LeaderTenure};

use chainstate::burn::{ConsensusHash};
use chainstate::stacks::db::{StacksHeaderInfo, StacksChainState};
use chainstate::burn::{BlockHeaderHash};
use chainstate::stacks::{TransactionAuth, TransactionSpendingCondition, SinglesigSpendingCondition, TransactionPayload};
use burnchains::Address;

use util::sleep_ms;

/// RunLoop is coordinating a simulated burnchain and some simulated nodes
/// taking turns in producing blocks.
pub struct RunLoop {
    config: Config,
    node: Node,
    new_burnchain_state_callback: Option<fn(u8, &BurnchainState)>,
    new_tenure_callback: Option<fn(u8, &LeaderTenure)>,
    new_chain_state_callback: Option<fn(u8, &mut StacksChainState, &BlockHeaderHash)>,
}

#[allow(unused_macros)]
macro_rules! info_blue {
    ($($arg:tt)*) => ({
        eprintln!("\x1b[0;96m{}\x1b[0m", format!($($arg)*));
    })
}

macro_rules! info_yellow {
    ($($arg:tt)*) => ({
        eprintln!("\x1b[0;33m{}\x1b[0m", format!($($arg)*));
    })
}

macro_rules! info_green {
    ($($arg:tt)*) => ({
        eprintln!("\x1b[0;32m{}\x1b[0m", format!($($arg)*));
    })
}

impl RunLoop {

    /// Sets up a runloop and nodes, given a config.
    pub fn new(config: Config) -> Self {
        // Build node based on config
        let node = Node::new(config.clone());

        Self {
            config,
            node,
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
        let mut burnchain = BurnchainSimulator::new(self.config.clone());

        let genesis_state = burnchain.make_genesis_block();

        // Update each node with the genesis block.
        self.node.process_burnchain_state(&genesis_state);

        // make first non-genesis block, with initial VRF keys
        let mut initial_ops = vec![];
        let key_op = self.node.setup();
        initial_ops.push(key_op);

        // Waiting on the 1st block (post-genesis) from the burnchain, containing the first key registrations 
        // that will be used for bootstraping the chain.
        let mut round_index = 0;

        let state_1 = burnchain.make_next_block(initial_ops);

        // Update each node with this new block.
        self.node.process_burnchain_state(&state_1);

        // Bootstrap the chain: the first node (could be random) will start a new tenure,
        // using the sortition hash from block #1 for generating a VRF.
        let leader = &mut self.node;
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
        let block_ops_2 = leader.receive_tenure_artifacts(&anchored_block_1, &parent_block_1);
        
        let mut burnchain_state = burnchain.make_next_block(block_ops_2);
        RunLoop::handle_burnchain_state_cb(&self.new_burnchain_state_callback, round_index, &burnchain_state);

        let mut leader_tenure = None;

        // Have each node process the new block, that should include a sortition thanks to the
        // 1st tenure.
        let (last_sortitioned_block, won_sortition) = match self.node.process_burnchain_state(&burnchain_state) {
            (Some(sortitioned_block), won_sortition) => (sortitioned_block, won_sortition),
            (None, _) => panic!("Node should have a sortitioned block")
        };
        
        // Have each node process the previous tenure.
        // We should have some additional checks here, and ensure that the previous artifacts are legit.

        self.node.process_tenure(
            &anchored_block_1, 
            &last_sortitioned_block.burn_header_hash, 
            &last_sortitioned_block.parent_burn_header_hash, 
            microblocks.clone(),
            burnchain.burndb_mut());

        let index_bhh = anchored_block_1.header.index_block_hash(&last_sortitioned_block.burn_header_hash);
        RunLoop::handle_new_chain_state_cb(&self.new_chain_state_callback, round_index, &mut self.node.chain_state, &index_bhh);

        // If the node we're looping on won the sortition, initialize and configure the next tenure
        if won_sortition {
            leader_tenure = self.node.initiate_new_tenure(&last_sortitioned_block);
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

            let mut next_burn_ops = vec![];
            match artifacts_from_tenure {
                Some(ref artifacts) => {
                    // Have each node receive artifacts from the current tenure
                    let (anchored_block, _, parent_block) = artifacts;
                    let mut ops = self.node.receive_tenure_artifacts(&anchored_block, &parent_block);
                    next_burn_ops.append(&mut ops);
                },
                None => {}
            }

            burnchain_state = burnchain.make_next_block(next_burn_ops);
            RunLoop::handle_burnchain_state_cb(&self.new_burnchain_state_callback, round_index, &burnchain_state);
    
            leader_tenure = None;

            // Have each node process the new block, that can include, or not, a sortition.
            let (last_sortitioned_block, won_sortition) = match self.node.process_burnchain_state(&burnchain_state) {
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

                    self.node.process_tenure(
                        &anchored_block, 
                        &burnchain_state.chain_tip.burn_header_hash, 
                        &burnchain_state.chain_tip.parent_burn_header_hash,             
                        microblocks.to_vec(),
                        burnchain.burndb_mut());

                    let index_bhh = anchored_block.header.index_block_hash(
                        &burnchain_state.chain_tip.burn_header_hash);
                    RunLoop::handle_new_chain_state_cb(&self.new_chain_state_callback, round_index,
                                                        &mut self.node.chain_state, &index_bhh);
                },
            };
            
            // If the node we're looping on won the sortition, initialize and configure the next tenure
            if won_sortition {
                leader_tenure = self.node.initiate_new_tenure(&last_sortitioned_block);
            } 
            
            round_index += 1;

            sleep_ms(self.config.burnchain.block_time);
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
        info_yellow!("Node starting new tenure with VRF {:?}", tenure.vrf_seed);
        new_tenure_callback.map(|cb| cb(round_index, tenure));
    }

    fn handle_burnchain_state_cb(burn_callback: &Option<fn(u8, &BurnchainState)>,
                                 round_index: u8, state: &BurnchainState) {
        info_yellow!("Burnchain block #{} ({}) was produced with sortition #{}", state.chain_tip.block_height, state.chain_tip.burn_header_hash, state.chain_tip.sortition_hash);
        burn_callback.map(|cb| cb(round_index, state));
    }

    fn handle_new_chain_state_cb(chain_state_callback: &Option<fn(u8, &mut StacksChainState, &BlockHeaderHash)>,
                                 round_index: u8, state: &mut StacksChainState, id_hash: &BlockHeaderHash) {
        let blocks = StacksChainState::list_blocks(&state.blocks_db).unwrap();
        let chain_tip = blocks.last().unwrap();
        let block = StacksChainState::load_block(&state.blocks_path, &chain_tip.0, &chain_tip.1).unwrap().unwrap();
        info_green!("Stacks block #{} ({}) successfully produced, including {} transactions", blocks.len(), id_hash, block.txs.len());
        for tx in block.txs.iter() {
            match &tx.auth {            
                TransactionAuth::Standard(TransactionSpendingCondition::Singlesig(auth)) => println!("-> Tx issued by {:?} (fee: {}, nonce: {})", auth.signer, auth.fee_rate, auth.nonce),
                _ => println!("-> Tx {:?}", tx.auth)
            }
            match &tx.payload { 
                TransactionPayload::Coinbase(_) => println!("   Coinbase"),
                TransactionPayload::SmartContract(contract) => println!("   Publish smart contract\n**************************\n{:?}\n**************************", contract.code_body),
                TransactionPayload::TokenTransfer(recipent, amount, _) => println!("   Transfering {} µSTX to {}", amount, recipent.to_string()),
                _ => println!("   {:?}", tx.payload)
            }
        }
        chain_state_callback.map(|cb| cb(round_index, state, &id_hash));
    }

}
