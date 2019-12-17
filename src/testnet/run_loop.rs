use super::{Config, Leader, BurnchainSimulator, SortitionedBlock};

use std::time;
use std::thread;

use chainstate::burn::{ConsensusHash, SortitionHash};

pub struct RunLoop {
    config: Config,
    vtxindex: u16,
    leaders: Vec<Leader>,
}

impl RunLoop {

    pub fn new(config: Config) -> RunLoop {
        
        let mut leaders = vec![]; 
        let mut confs = config.leader_config.clone();
        for conf in confs.drain(..) {
            leaders.push(Leader::new(conf, config.burchain_block_time));
        }

        Self {
            config,
            leaders: leaders,
            vtxindex: 0,
        }
    }

    pub fn tear_down(&self) {
        // todo(ludo): Clean files
    }

    pub fn start(&mut self) {

        let mut burnchain = BurnchainSimulator::new();
    
        let (block_rx, op_tx) = burnchain.start(&self.config);;

        for leader in self.leaders.iter_mut() {
            leader.tear_up(op_tx.clone(), ConsensusHash::empty());
        }

        let mut bootstrap_chain = true;

        loop {
            // Handling incoming blocks from the burnchain
            let (burnchain_block, ops) = block_rx.recv().unwrap();

            for leader in self.leaders.iter_mut() {

                let mut result = leader.process_burnchain_block(&burnchain_block, &ops);

                // Bootstrap chain
                if bootstrap_chain == false {
                    match result {
                        None => continue,
                        Some(mut tenure) => thread::spawn(move || {
                            tenure.run();
                        })
                    };
                } else {
                    bootstrap_chain = false;
                    let mut tenure = leader.initiate_new_tenure(SortitionedBlock::genesis());
                    thread::spawn(move || {
                        tenure.run();
                    });
                }
            }
        }
    }
}
