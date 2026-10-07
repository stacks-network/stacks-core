use stacks::chainstate::stacks::db::ClarityTx;
use stacks::chainstate::stacks::{
    TransactionAuth, TransactionPayload, TransactionSpendingCondition,
};

use crate::burnchains::Error as BurnchainControllerError;
use crate::{BitcoinRegtestController, BurnchainTip, ChainTip, Config, Node};

/// RunLoop coordinates a single node with a local bitcoind regtest, taking
/// turns producing burnchain and Stacks blocks.
pub struct RunLoop {
    config: Config,
    pub node: Node,
}

impl RunLoop {
    pub fn new(config: Config) -> Self {
        RunLoop::new_with_boot_exec(config, Box::new(|_| {}))
    }

    /// Sets up a runloop and node, given a config.
    pub fn new_with_boot_exec(config: Config, boot_exec: Box<dyn FnOnce(&mut ClarityTx)>) -> Self {
        // Apply config-driven process-wide state before any chainstate is opened.
        // Helium opens chainstate inside `Node::new`, so this must run first.
        config.apply_runtime_state();

        // Build node based on config
        let node = Node::new(config.clone(), boot_exec);

        Self { config, node }
    }

    /// Starts the testnet runloop.
    ///
    /// This function will block by looping infinitely.
    /// It will start the burnchain (separate thread), set-up a channel in
    /// charge of coordinating the new blocks coming from the burnchain and
    /// the nodes, taking turns on tenures.  
    pub fn start(&mut self, expected_num_rounds: u64) -> Result<(), BurnchainControllerError> {
        // Mode is already constrained upstream (config validation + the dispatch in main.rs);
        // this run loop only handles helium. Assert it so a future dispatch mistake fails fast
        // instead of silently running helium under the wrong mode.
        assert_eq!(
            self.config.burnchain.mode, "helium",
            "helium run loop requires burnchain.mode = \"helium\""
        );

        // Initialize and start the burnchain.
        let mut burnchain = BitcoinRegtestController::new(self.config.clone(), None);

        let (initial_state, _) = burnchain.start(None)?;

        // Update each node with the genesis block.
        self.node.process_burnchain_state(&initial_state);

        // make first non-genesis block, with initial VRF keys
        self.node.setup(&mut burnchain);

        // Waiting on the 1st block (post-genesis) from the burnchain, containing the first key registrations
        // that will be used for bootstraping the chain.
        // Sync and update node with this new block.
        let (burnchain_tip, _) = burnchain.sync(None)?;
        self.node.process_burnchain_state(&burnchain_tip); // todo(ludo): should return genesis?

        self.node.spawn_peer_server();

        // Bootstrap the chain: node will start a new tenure,
        // using the sortition hash from block #1 for generating a VRF.
        let leader = &mut self.node;
        let mut first_tenure = match leader.initiate_genesis_tenure(&burnchain_tip) {
            Some(res) => res,
            None => panic!("Error while initiating genesis tenure"),
        };

        // TODO (hack) instantiate db
        let _ = burnchain.sortdb_mut();

        // Run the tenure, keep the artifacts
        let artifacts_from_1st_tenure = match first_tenure.run(
            &burnchain
                .sortdb_ref()
                .index_handle(&burnchain_tip.block_snapshot.sortition_id),
        ) {
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

        log_new_burn_chain_state(&burnchain_tip);

        let mut leader_tenure = None;

        let (last_sortitioned_block, won_sortition) =
            match self.node.process_burnchain_state(&burnchain_tip) {
                (Some(sortitioned_block), won_sortition) => (sortitioned_block, won_sortition),
                (None, _) => panic!("Node should have a sortitioned block"),
            };

        // Have the node process its own tenure.
        // We should have some additional checks here, and ensure that the previous artifacts are legit.
        let mut atlas_db = self.node.make_atlas_db();

        let mut chain_tip = self.node.process_tenure(
            &artifacts_from_1st_tenure.anchored_block,
            &last_sortitioned_block.block_snapshot.consensus_hash,
            artifacts_from_1st_tenure.microblocks.clone(),
            burnchain.sortdb_mut(),
            &mut atlas_db,
        );

        log_new_stacks_chain_state(&chain_tip);

        // If the node we're looping on won the sortition, initialize and configure the next tenure
        if won_sortition {
            leader_tenure = self.node.initiate_new_tenure();
        }

        // Start the runloop
        let mut round_index: u64 = 1;
        loop {
            if expected_num_rounds == round_index {
                return Ok(());
            }

            // Run the last initialized tenure
            let artifacts_from_tenure = match leader_tenure {
                Some(mut tenure) => tenure.run(
                    &burnchain
                        .sortdb_ref()
                        .index_handle(&burnchain_tip.block_snapshot.sortition_id),
                ),
                None => None,
            };

            if let Some(artifacts) = &artifacts_from_tenure {
                // Have each node receive artifacts from the current tenure
                self.node.commit_artifacts(
                    &artifacts.anchored_block,
                    &artifacts.parent_block,
                    &mut burnchain,
                    artifacts.burn_fee,
                );
            }

            let (new_burnchain_tip, _) = burnchain.sync(None)?;
            burnchain_tip = new_burnchain_tip;

            log_new_burn_chain_state(&burnchain_tip);

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

                    log_new_stacks_chain_state(&chain_tip);
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

fn log_new_burn_chain_state(burnchain_tip: &BurnchainTip) {
    eprintln!(
        "\x1b[0;96mBurnchain block #{} ({}) was produced with sortition #{}\x1b[0m",
        burnchain_tip.block_snapshot.block_height,
        burnchain_tip.block_snapshot.burn_header_hash,
        burnchain_tip.block_snapshot.sortition_hash
    );
}

fn log_new_stacks_chain_state(chain_tip: &ChainTip) {
    eprintln!(
        "\x1b[0;32mStacks block #{} ({}) successfully produced, including {} transactions\x1b[0m",
        chain_tip.metadata.stacks_block_height,
        chain_tip.metadata.index_block_hash(),
        chain_tip.block.txs.len()
    );
    for tx in chain_tip.block.txs.iter() {
        match &tx.auth {
            TransactionAuth::Standard(TransactionSpendingCondition::Singlesig(auth)) => {
                println!(
                    "-> Tx issued by {:?} (fee: {}, nonce: {})",
                    auth.signer, auth.tx_fee, auth.nonce
                )
            }
            _ => println!("-> Tx {:?}", tx.auth),
        }
        match &tx.payload {
            TransactionPayload::Coinbase(..) => println!("   Coinbase"),
            TransactionPayload::SmartContract(contract, ..) => println!("   Publish smart contract\n**************************\n{:?}\n**************************", contract.code_body),
            TransactionPayload::TokenTransfer(recipent, amount, _) => println!("   Transfering {amount} µSTX to {recipent}"),
            _ => println!("   {:?}", tx.payload)
        }
    }
}
