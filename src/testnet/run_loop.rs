use super::{Config, Leader, BurnchainSimulator, SortitionedBlock};

use std::sync::mpsc::Sender;
use std::time;
use std::thread;

use chainstate::burn::{ConsensusHash, SortitionHash};
use net::StacksMessageType;

pub struct RunLoop {
    config: Config,
    leaders: Vec<Leader>,
    leaders_txs: Vec<Sender<StacksMessageType>>
}

impl RunLoop {

    pub fn new(config: Config) -> Self {

        // Build a vec of leaders based on the config
        let mut leaders = vec![]; 
        let mut leaders_txs = vec![]; 
        let mut confs = config.leader_config.clone();
        for conf in confs.drain(..) {
            let leader = Leader::new(conf, config.burchain_block_time);
            leaders_txs.push(leader.tx.clone());
            leaders.push(leader);
        }

        Self {
            config,
            leaders,
            leaders_txs
        }
    }

    pub fn start(&mut self) {

        // Initialize and start the burnchain
        let mut burnchain = BurnchainSimulator::new();
        let (burnchain_block_rx, burnchain_op_tx) = burnchain.start(&self.config);;

        // Tear-up each leader with the op_tx (mpsc::Sender<ops>) 
        // returned by the burnchain, so that each leader can commit
        // its ops independently.
        for leader in self.leaders.iter_mut() {
            leader.tear_up(burnchain_op_tx.clone(), ConsensusHash::empty());
        }

        let mut bootstrap_chain = true;
        let mut prev_tenure_artefacts = (None, None);

        loop {
            // Wait for incoming block from the burnchain
            let (burnchain_block, ops) = burnchain_block_rx.recv().unwrap();

            let mut leader_tenure = None;

            // Dispatch incoming block to the leaders            
            for leader in self.leaders.iter_mut() {

                let (anchored_block, microblocks) = prev_tenure_artefacts.clone();

                let won_sortition = leader.process_burnchain_block(&burnchain_block, &ops);

                leader.process_previous_tenure(anchored_block, microblocks);

                leader.maintain_leadership_eligibility();

                let parent_block = match (won_sortition, bootstrap_chain) {
                    (true, _) => leader.last_sortitioned_block.clone().unwrap(),
                    (false, true) => {
                        bootstrap_chain = false;
                        SortitionedBlock::genesis()
                    },
                    (false, false) => { continue; },
                };
                // Initiate and detach a new tenure targeting the initial sortition hash
                leader_tenure = Some(leader.initiate_new_tenure(parent_block));
            }

            if leader_tenure.is_some() {
                // run tenure
                // get blocks + micro-blocks
                prev_tenure_artefacts = leader_tenure.unwrap().run();
            }
        }
    }

    pub fn tear_down(&self) {
        // todo(ludo): Clean dirs
    }
}
