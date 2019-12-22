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

        let (burnchain_block, ops, burn_db) = burnchain_block_rx.recv().unwrap();

        let mut bootstrap_chain = true;
        let mut burnchain_block = burnchain_block;
        let mut ops = ops;
        let mut burn_db = burn_db;
        let mut leader_tenure = None;

        for node in self.nodes.iter_mut() {
            let (sortitioned_block, won_sortition) = node.process_burnchain_block(&burnchain_block, &ops);
        }

        leader_tenure = self.nodes[0].initiate_genesis_tenure(&burnchain_block);
        // let artefacts_from_tenure = match leader_tenure {
        //     Some(mut tenure) => Some(tenure.run()),
        //     None => None
        // };
    
        // if artefacts_from_tenure.is_some() {

        //     for node in self.nodes.iter_mut() {
        //         let (anchored_block, _) = artefacts_from_tenure.clone().unwrap();
    
        //         node.receive_tenure_artefacts(anchored_block.unwrap());

        //         break; // todo(ludo): get rid of this.
        //     }
        // } else {
        //     println!("NO SORTITION");
        // }

        // let (new_block, new_ops, new_db) = burnchain_block_rx.recv().unwrap();
        // burnchain_block = new_block;
        // ops = new_ops;
        // burn_db = new_db;

        // leader_tenure = None;

        // for node in self.nodes.iter_mut() {

        //     let (sortitioned_block, won_sortition) = node.process_burnchain_block(&burnchain_block, &ops);
    
        //     if won_sortition {
        //         // This node is in charge of the new tenure
        //         let parent_block = match sortitioned_block {
        //             Some(parent_block) => parent_block,
        //             None => unreachable!()
        //         };
        //         let tenure = node.initiate_new_tenure(&parent_block);
        //         leader_tenure = Some(tenure);
        //     } 
        // }

        // if artefacts_from_tenure.is_some() {

        //     for node in self.nodes.iter_mut() {
        //         let (anchored_block, microblocks) = artefacts_from_tenure.clone().unwrap();
    
        //         node.process_tenure(anchored_block.unwrap(), microblocks, burn_db);

        //         break; // todo(ludo): get rid of this.
        //     }
        // } else {
        //     println!("NO SORTITION");
        // }


        loop {
            println!("=======================================================");
            println!("NEW EPOCH");
            println!("BURNCHAIN: {:?} {:?} {:?}", burnchain_block.block_height, burnchain_block.burn_header_hash, burnchain_block.parent_burn_header_hash);
            // if leader_tenure.is_some() {
            //     println!("{}", leader_tenure.unwrap());
            // }
            println!("=======================================================");
    
            // Wait for incoming block from the burnchain

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

            let artefacts_from_tenure = match leader_tenure {
                Some(mut tenure) => Some(tenure.run()),
                None => None
            };

            if artefacts_from_tenure.is_some() {

                for node in self.nodes.iter_mut() {
                    let (anchored_block, _, _) = artefacts_from_tenure.clone().unwrap();
        
                    node.receive_tenure_artefacts(anchored_block.unwrap());

                    break; // todo(ludo): get rid of this.
                }
            } else {
                println!("NO SORTITION");
            }

            let (new_block, new_ops, new_db) = burnchain_block_rx.recv().unwrap();
            burnchain_block = new_block;
            ops = new_ops;
            burn_db = new_db;
    
            leader_tenure = None;

            for node in self.nodes.iter_mut() {

                let (sortitioned_block, won_sortition) = node.process_burnchain_block(&burnchain_block, &ops);
        
                if won_sortition {
                    // This node is in charge of the new tenure
                    let parent_block = match sortitioned_block {
                        Some(parent_block) => parent_block,
                        None => unreachable!()
                    };
                    leader_tenure = node.initiate_new_tenure(&parent_block);
                } 
            }

            if artefacts_from_tenure.is_some() {

                for node in self.nodes.iter_mut() {
                    let (anchored_block, microblocks, _) = artefacts_from_tenure.clone().unwrap();
        
                    node.process_tenure(anchored_block.unwrap(), microblocks, burn_db);

                    break; // todo(ludo): get rid of this.
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

    pub fn bootstrap(&mut self) {

    }

    pub fn tear_down(&self) {
        // todo(ludo): Clean dirs
    }
}
