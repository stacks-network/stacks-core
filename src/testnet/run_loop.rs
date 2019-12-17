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
        let (block_rx, op_tx) = burnchain.start(&self.config);;

        // Tear-up each leader with the op_tx (mpsc::Sender<ops>) 
        // returned by the burnchain, so that each leader can commit
        // its ops independently.
        for leader in self.leaders.iter_mut() {
            leader.tear_up(op_tx.clone(), ConsensusHash::empty());
        }

        let mut bootstrap_chain = true;

        loop {
            // Wait for incoming block from the burnchain
            let (burnchain_block, ops) = block_rx.recv().unwrap();

            // Dispatch incoming block to the leaders
            for leader in self.leaders.iter_mut() {

                // todo(ludo): process_burnchain_block should return a Result, instead of Option
                let mut result = leader.process_burnchain_block(&burnchain_block, &ops);

                let sortitioned_block = match (result, bootstrap_chain) {
                    (Some(sortitioned_block), _) => sortitioned_block,
                    (None, true) => {
                        bootstrap_chain = false;
                        SortitionedBlock::genesis()
                    },
                    (None, false) => { continue; },
                };
                // Initiate and detach a new tenure targeting the initial sortition hash
                let mut tenure = leader.initiate_new_tenure(sortitioned_block);
                // thread::spawn(move || {
                    tenure.run();
                // });
            }
        }
    }


    pub fn tear_down(&self) {
        // todo(ludo): Clean files
    }
}
