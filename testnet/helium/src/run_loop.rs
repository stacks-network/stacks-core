use super::{Config, Node, BurnchainController, MocknetController, BitcoinRegtestController, BurnchainTip, Tenure};

use stacks::chainstate::stacks::db::{StacksHeaderInfo, StacksChainState, ClarityTx};
use stacks::chainstate::stacks::{StacksBlock, TransactionAuth, TransactionSpendingCondition, TransactionPayload};
use stacks::chainstate::stacks::events::StacksTransactionReceipt;

/// RunLoop is coordinating a simulated burnchain and some simulated nodes
/// taking turns in producing blocks.
pub struct RunLoop {
    config: Config,
    pub node: Node,
    burnchain_initialized_callback: Option<fn(&mut Box<dyn BurnchainController>)>,
    new_burnchain_state_callback: Option<fn(u64, &BurnchainTip)>,
    new_tenure_callback: Option<fn(u64, &Tenure)>,
    new_chain_state_callback: Option<fn(u64, &mut StacksChainState, StacksBlock, StacksHeaderInfo, Vec<StacksTransactionReceipt>)>,
}

macro_rules! info_blue {
    ($($arg:tt)*) => ({
        eprintln!("\x1b[0;96m{}\x1b[0m", format!($($arg)*));
    })
}

#[allow(unused_macros)]
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
            burnchain_initialized_callback: None,
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
    pub fn start(&mut self, expected_num_rounds: u64) {

        // Initialize and start the burnchain.
        let mut burnchain: Box<dyn BurnchainController> = match &self.config.burnchain.mode[..] {
            "helium" | "neon" => {
                BitcoinRegtestController::generic(self.config.clone())
            },
            "mocknet" => {
                MocknetController::generic(self.config.clone())
            }
            _ => unreachable!()
        };

        RunLoop::handle_burnchain_initialized_cb(
            &self.burnchain_initialized_callback, 
            &mut burnchain);

        let genesis_state = burnchain.start();

        // Update each node with the genesis block.
        self.node.process_burnchain_state(genesis_state);

        // make first non-genesis block, with initial VRF keys
        self.node.setup(&mut burnchain);

        // Waiting on the 1st block (post-genesis) from the burnchain, containing the first key registrations 
        // that will be used for bootstraping the chain.
        let mut round_index: u64 = 0;

        // Sync and update node with this new block.
        let burnchain_tip = burnchain.sync();
        self.node.process_burnchain_state(burnchain_tip.clone());

        if self.config.burnchain.mode == "mocknet" {
            self.node.spawn_peer_server();
        }

        // Bootstrap the chain: node will start a new tenure,
        // using the sortition hash from block #1 for generating a VRF.
        let leader = &mut self.node;
        let mut first_tenure = match leader.initiate_genesis_tenure(&burnchain_tip) {
            Some(res) => res,
            None => panic!("Error while initiating genesis tenure")
        };

        RunLoop::handle_new_tenure_cb(&self.new_tenure_callback, round_index, &first_tenure);

        // Run the tenure, keep the artifacts
        let artifacts_from_1st_tenure = match first_tenure.run() {
            Some(res) => res,
            None => panic!("Error while running 1st tenure")
        };

        // Tenures are instantiating their own chainstate, so that nodes can keep a clean chainstate,
        // while having the option of running multiple tenures concurrently and try different strategies.
        // As a result, once the tenure ran and we have the artifacts (anchored_blocks, microblocks),
        // we have the 1st node (leading) updating its chainstate with the artifacts from its own tenure.
        leader.commit_artifacts(
            &artifacts_from_1st_tenure.anchored_block, 
            &artifacts_from_1st_tenure.parent_block, 
            &mut burnchain, 
            artifacts_from_1st_tenure.burn_fee);

        let mut burnchain_tip = burnchain.sync();
        RunLoop::handle_burnchain_state_cb(&self.new_burnchain_state_callback, round_index, &burnchain_tip);

        let mut leader_tenure = None;

        // Have each node process the new block, that should include a sortition thanks to the
        // 1st tenure.
        let (last_sortitioned_block, won_sortition) = match self.node.process_burnchain_state(burnchain_tip) {
            (Some(sortitioned_block), won_sortition) => (sortitioned_block, won_sortition),
            (None, _) => panic!("Node should have a sortitioned block")
        };
        
        // Have each node process the previous tenure.
        // We should have some additional checks here, and ensure that the previous artifacts are legit.

        let (chain_tip, chain_tip_info, receipts) = self.node.process_tenure(
            &artifacts_from_1st_tenure.anchored_block, 
            &last_sortitioned_block.block_snapshot.burn_header_hash, 
            &last_sortitioned_block.block_snapshot.parent_burn_header_hash, 
            artifacts_from_1st_tenure.microblocks.clone(),
            burnchain.burndb_mut());

        RunLoop::handle_new_chain_state_cb(&self.new_chain_state_callback, round_index, &mut self.node.chain_state, chain_tip, chain_tip_info, receipts);

        // If the node we're looping on won the sortition, initialize and configure the next tenure
        if won_sortition {
            leader_tenure = self.node.initiate_new_tenure();
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
                    self.node.commit_artifacts(
                        &artifacts.anchored_block, 
                        &artifacts.parent_block, 
                        &mut burnchain, 
                        artifacts.burn_fee);
                },
                None => {}
            }

            burnchain_tip = burnchain.sync();
            RunLoop::handle_burnchain_state_cb(&self.new_burnchain_state_callback, round_index, &burnchain_tip);
    
            leader_tenure = None;

            // Have each node process the new block, that can include, or not, a sortition.
            let (last_sortitioned_block, won_sortition) = match self.node.process_burnchain_state(burnchain_tip) {
                (Some(sortitioned_block), won_sortition) => (sortitioned_block, won_sortition),
                (None, _) => panic!("Node should have a sortitioned block")
            };

            match artifacts_from_tenure {
                // Pass if we're missing the artifacts from the current tenure.
                None => continue,
                Some(ref artifacts) => {
                    // Have each node process the previous tenure.
                    // We should have some additional checks here, and ensure that the previous artifacts are legit.
                    let (chain_tip, chain_tip_info, events) = self.node.process_tenure(
                        &artifacts.anchored_block, 
                        &last_sortitioned_block.block_snapshot.burn_header_hash, 
                        &last_sortitioned_block.block_snapshot.parent_burn_header_hash,             
                        artifacts.microblocks.clone(),
                        burnchain.burndb_mut());

                    RunLoop::handle_new_chain_state_cb(
                        &self.new_chain_state_callback, 
                        round_index,
                        &mut self.node.chain_state,
                        chain_tip,
                        chain_tip_info,
                        events
                    );
                },
            };
            
            // If the node we're looping on won the sortition, initialize and configure the next tenure
            if won_sortition {
                leader_tenure = self.node.initiate_new_tenure();
            } 
            
            round_index += 1;
        }
    }

    pub fn apply_once_burnchain_initialized(&mut self, f: fn(&mut Box<dyn BurnchainController>)) {
        self.burnchain_initialized_callback = Some(f);
    }

    pub fn apply_on_new_burnchain_states(&mut self, f: fn(u64, &BurnchainTip)) {
        self.new_burnchain_state_callback = Some(f);
    }

    pub fn apply_on_new_tenures(&mut self, f: fn(u64, &Tenure)) {
        self.new_tenure_callback = Some(f);
    }
    
    pub fn apply_on_new_chain_states(&mut self, f: fn(u64, &mut StacksChainState, StacksBlock, StacksHeaderInfo, Vec<StacksTransactionReceipt>)) {
        self.new_chain_state_callback = Some(f);
    }

    fn handle_burnchain_initialized_cb(burnchain_initialized_callback: &Option<fn(&mut Box<dyn BurnchainController>)>, burnchain_controller: &mut Box<dyn BurnchainController>) {
        burnchain_initialized_callback.map(|cb| cb(burnchain_controller));
    }

    fn handle_new_tenure_cb(new_tenure_callback: &Option<fn(u64, &Tenure)>,
                            round_index: u64, tenure: &Tenure) {
        new_tenure_callback.map(|cb| cb(round_index, tenure));
    }

    fn handle_burnchain_state_cb(burn_callback: &Option<fn(u64, &BurnchainTip)>,
                                 round_index: u64, state: &BurnchainTip) {
        info_blue!("Burnchain block #{} ({}) was produced with sortition #{}", state.block_snapshot.block_height, state.block_snapshot.burn_header_hash, state.block_snapshot.sortition_hash);
        burn_callback.map(|cb| cb(round_index, state));
    }

    fn handle_new_chain_state_cb(chain_state_callback: &Option<fn(u64, &mut StacksChainState, StacksBlock, StacksHeaderInfo, Vec<StacksTransactionReceipt>)>,
                                 round_index: u64, state: &mut StacksChainState, chain_tip: StacksBlock, chain_tip_info: StacksHeaderInfo, receipts: Vec<StacksTransactionReceipt>) {
        info_green!("Stacks block #{} ({}) successfully produced, including {} transactions", chain_tip_info.block_height, chain_tip_info.index_block_hash(), chain_tip.txs.len());
        for tx in chain_tip.txs.iter() {
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
        chain_state_callback.map(|cb| cb(round_index, state, chain_tip, chain_tip_info, receipts));
    }

}
