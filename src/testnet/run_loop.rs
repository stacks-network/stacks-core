use super::{Config, Node, BurnchainSimulator, SortitionedBlock};

use std::sync::mpsc::Sender;
use std::time;
use std::thread;

use chainstate::burn::{ConsensusHash, SortitionHash};
use net::StacksMessageType;

pub struct RunLoop {
    config: Config,
    nodes: Vec<Node>,
    nodes_txs: Vec<Sender<StacksMessageType>>
}

impl RunLoop {

    pub fn new(config: Config) -> Self {

        // Build a vec of nodes based on the config
        let mut nodes = vec![]; 
        let mut nodes_txs = vec![]; 
        let mut confs = config.node_config.clone();
        for conf in confs.drain(..) {
            let node = Node::new(conf, config.burnchain_block_time);
            nodes_txs.push(node.tx.clone());
            nodes.push(node);
        }

        Self {
            config,
            nodes,
            nodes_txs
        }
    }

    pub fn start(&mut self) {

        // Initialize and start the burnchain
        let mut burnchain = BurnchainSimulator::new();
        let (burnchain_block_rx, burnchain_op_tx) = burnchain.start(&self.config);

        // Tear-up each leader with the op_tx (mpsc::Sender<ops>) 
        // returned by the burnchain, so that each leader can commit
        // its ops independently.
        for node in self.nodes.iter_mut() {
            node.tear_up(burnchain_op_tx.clone(), ConsensusHash::empty());
        }

        let mut bootstrap_chain = true;

        loop {
            // Wait for incoming block from the burnchain
            let (burnchain_block, ops, burn_db) = burnchain_block_rx.recv().unwrap();

            // for each leader:
                // process the block:
                    // does the block include a sortition?
                        // did i won sortition?
                    // does the block include a registered key that I've submitted earlier?

                // if sortition
                    // get the blocks and latest microblocks from the previous leader (if was not me)
                    // submit block_commit_op
                    // if winner 
                        // start tenure
                        // dispatch artefacts to other nodes at T/2
                        // keep building microblocks until block from burnchain arrives.

            let mut leader_tenure = None;
            
            for node in self.nodes.iter_mut() {

                let (sortitioned_block, won_sortition) = node.process_burnchain_block(&burnchain_block, &ops);

                // Should the node bootstrap the chain and start a tenure on top of genesis.
                if bootstrap_chain {
                    leader_tenure = node.initiate_genesis_tenure(&burnchain_block);
                    if leader_tenure.is_some() {
                        bootstrap_chain = false;
                    }
                    continue;
                }

                if won_sortition {
                    // This node is in charge of the new tenure
                    let parent_block = match sortitioned_block {
                        Some(parent_block) => parent_block,
                        None => unreachable!()
                    };
                    let tenure = node.initiate_new_tenure(&parent_block);
                    leader_tenure = Some(tenure);
                } else {
                    // This node need to get the blocks from the current leader

                }

                // println!("About to initiate new tenure with {:?}", parent_block);
                // // Initiate and detach a new tenure targeting the initial sortition hash
                // leader_tenure = Some(node.initiate_new_tenure(parent_block));
            }

            if leader_tenure.is_some() {
                let mut tenure = leader_tenure.unwrap();
                let artefacts = tenure.run();

                for node in self.nodes.iter_mut() {
                    let (anchored_block, microblocks) = artefacts.clone();
    
                    node.process_tenure(anchored_block.unwrap(), microblocks, burn_db);
    
                    node.maintain_leadership_eligibility();

                    break;
                }
            } else {
                println!("NO SORTITION");
            }


            // let tenure_artefacts = {
                
            //     let mut leader_tenure = None;

            //     // Dispatch incoming block to the nodes            
            //     for node in self.nodes.iter_mut() {
    
            //         let won_sortition = node.process_burnchain_block(&burnchain_block, &ops);
    
            //         // todo(ludo): refactor (at least naming)
            //         let parent_block = match (won_sortition, bootstrap_chain) {
            //             (true, _) => node.last_sortitioned_block.clone().unwrap(),
            //             (false, true) => {
            //                 bootstrap_chain = false;
            //                 SortitionedBlock::genesis()
            //             },
            //             (false, false) => { continue; },
            //         };


            //         println!("About to initiate new tenure with {:?}", parent_block);
            //         // Initiate and detach a new tenure targeting the initial sortition hash
            //         leader_tenure = Some(node.initiate_new_tenure(parent_block));
            //     }
    
            //     if leader_tenure.is_none() {
            //         continue;
            //     }
    
            //     // run tenure
            //     // get blocks + micro-blocks
            //     leader_tenure.unwrap().run()
            // };

            // // Dispatch tenure artefacts (anchored_block + microblocks) to the other nodes            
            // for node in self.nodes.iter_mut() {
            //     let (anchored_block, microblocks) = tenure_artefacts.clone();

            //     node.process_tenure(anchored_block, microblocks);

            //     node.maintain_leadership_eligibility();
            // }
        }
    }

    pub fn tear_down(&self) {
        // todo(ludo): Clean dirs
    }
}
