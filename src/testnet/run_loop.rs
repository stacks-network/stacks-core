use super::{Config, Leader, BurnchainSimulator};

use std::time;

use chainstate::burn::{ConsensusHash};

pub struct RunLoop<'a> {
    config: Config,
    vtxindex: u16,
    leaders: Vec<Leader<'a>>,
}

impl <'a> RunLoop <'a> {

    pub fn new(config: Config) -> RunLoop<'a> {
        
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
    }

    pub fn start(&mut self) {

        let mut burnchain = BurnchainSimulator::new();
    
        let (block_rx, op_tx) = burnchain.start(
            time::Duration::from_millis(self.config.burchain_block_time), 
            self.config.burchain_path.to_string(), 
            self.config.testnet_name.to_string());

        for leader in self.leaders.iter_mut() {
            leader.tear_up(op_tx.clone(), ConsensusHash::empty());
        }

        // The goal of this run loop is too: 
        // 1) Handle incoming blocks from the burnchain 
        // 2) Pump and exaust the mempool (detached thread)

        loop {
            // Handling incoming blocks
            let (burnchain_block, ops) = block_rx.recv().unwrap();

            println!("Incoming block - {:?}", burnchain_block);
            println!("Incoming ops - {:?}", ops);

            if burnchain_block.sortition == false {
                continue;
            }
            
            let sortition_hash = burnchain_block.sortition_hash;

            // Mark registered keys as approved, if any.

            // When receiving a new block from the burnchain, if there's a block commit op,
            // we should be:
            // 1) Get the sortition hash
            // 2) Start a new tenure

            for leader in self.leaders.iter_mut() {
                // leader.handle_burnchain_block();
            }
        }
    }
}
