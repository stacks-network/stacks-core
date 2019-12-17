use super::{Config, Leader, BurnchainSimulator, SortitionedBlock};

use std::time;
use std::thread;

use chainstate::burn::{ConsensusHash, SortitionHash};

pub struct RunLoop {
    config: Config,
    leaders: Vec<Leader>,
}

impl RunLoop {

    pub fn new(config: Config) -> Self {

        // Build a vec of leaders based on the config
        let mut leaders = vec![]; 
        let mut confs = config.leader_config.clone();
        for conf in confs.drain(..) {
            leaders.push(Leader::new(conf, config.burchain_block_time));
        }

        Self {
            config,
            leaders: leaders,
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

                let mut result = leader.process_burnchain_block(&burnchain_block, &ops);

                // Bootstrap chain if required
                if bootstrap_chain == true {
                    bootstrap_chain = false;
                    // Initiate and detach a new tenure targeting the initial sortition hash
                    let mut tenure = leader.initiate_new_tenure(SortitionedBlock::genesis());
                    thread::spawn(move || {
                        tenure.run();
                    });
                } else {
                    // If block processing returned a tenure, detach a new thread and run it
                    match result {
                        None => continue,
                        Some(mut tenure) => thread::spawn(move || {
                            tenure.run();
                        })
                    };
                }
            }
        }
    }


    pub fn tear_down(&self) {
        // todo(ludo): Clean files
    }
}
