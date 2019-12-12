use super::{MemPool, Config, Keychain, TestnetNode, TestnetBurnchainNode, TestnetMiner, MemPoolObserver};

use std::fs;
use std::env;
use std::process;
use net::StacksMessageCodec;
use chainstate::stacks::*;
use util::hash::hex_bytes;

use chainstate::stacks::db::{StacksChainState, StacksHeaderInfo};
use chainstate::stacks::{StacksBlock, StacksTransactionSigner, StacksMicroblock, CoinbasePayload, StacksBlockBuilder, TransactionAuth};
use chainstate::burn::db::burndb::{BurnDB};
use address::AddressHashMode;
use burnchains::{Burnchain, BurnchainHeaderHash, Txid, PrivateKey, BurnchainBlock};
use burnchains::bitcoin::BitcoinBlock;
use chainstate::stacks::{StacksPrivateKey};
use chainstate::burn::operations::{BlockstackOperationType, LeaderKeyRegisterOp, LeaderBlockCommitOp};
use chainstate::burn::{SortitionHash, BlockSnapshot};
use util::vrf::{VRF, VRFProof, VRFPublicKey, VRFPrivateKey};
use util::hash::Sha256Sum;
use std::collections::HashMap;
use rusqlite::{Connection, OpenFlags, NO_PARAMS};
use rand::RngCore;
use util::hash::{to_hex};
use std::{thread, time};

struct LeaderTenure {
    started_at: std::time::Instant,
    block_builder: StacksBlockBuilder,
}

impl LeaderTenure {

    pub fn new(parent_block: StacksHeaderInfo, vrf_proof: VRFProof, microblock_secret_key: StacksPrivateKey) -> LeaderTenure {
        let now = time::Instant::now();
        
        let ratio = StacksWorkScore {
            burn: 1, // todo(ludo): get burn from burnchain_tip.
            work: 0
        };

        let block_builder = StacksBlockBuilder::from_parent(&parent_block, &ratio, &vrf_proof, &microblock_secret_key);

        Self {
            started_at: now,
            block_builder
        }
    }

    pub fn handle_txs(&mut self, txs: Vec<StacksTransaction>) {

    }
}



    //                     // building off an existing stacks block
    //                     let parent_stacks_block_snapshot = {
    //                         let mut tx = self.burn.burndb.tx_begin().unwrap();
    //                         let parent_stacks_block_snapshot = BurnDB::get_block_snapshot_for_winning_stacks_block(&mut tx, &burn_block.parent_snapshot.burn_header_hash, &parent_stacks_block.block_hash()).unwrap().unwrap();
    //                         let burned_last = BurnDB::get_block_burn_amount(&mut tx, burn_block.parent_snapshot.block_height, &burn_block.parent_snapshot.burn_header_hash).unwrap();
    //                         parent_stacks_block_snapshot
    //                     };
    
    //                     let parent_chain_tip = StacksChainState::get_anchored_block_header_info(&self.chainstate.headers_db, &parent_stacks_block_snapshot.burn_header_hash, &parent_stacks_block.header.block_hash()).unwrap().unwrap();
    
    //                     let new_work = StacksWorkScore {
    //                         burn: parent_stacks_block_snapshot.total_burn,
    //                         work: 0
    //                     };
    
    //                     test_debug!("Burned in {} {}: {}", burn_block.block_height, burn_block.parent_snapshot.burn_header_hash.to_hex(), new_work.burn);
    //                     let builder = StacksBlockBuilder::from_parent(&parent_chain_tip, &new_work, &proof, &miner.next_microblock_privkey());
    //                     (builder, Some(parent_stacks_block_snapshot))
    
    // pub fn from_parent(parent_header: &StacksBlockHeader,
    //                    parent_microblock_header: Option<&StacksMicroblockHeader>,
    //                    total_work: &StacksWorkScore,
    //                    proof: &VRFProof,
    //                    tx_merkle_root: &Sha512Trunc256Sum,
    //                    state_index_root: &TrieHash,
    //                    microblock_pubkey_hash: &Hash160) -> StacksBlockHeader {


pub struct RunLoop<'a> {
    burn_db: BurnDB,
    burnchain: Burnchain,
    burnchain_tip: Option<BlockSnapshot>,
    chain_state: StacksChainState,
    chain_tip: Option<StacksHeaderInfo>,
    config: Config,
    keychain: Keychain,
    mem_pool: &'a MemPool<'a>,
    previous_tenures: Vec<LeaderTenure>,
}

impl <'a> RunLoop <'a> {

    pub fn new(config: Config, keychain: Keychain, mem_pool: &'a MemPool<'a>) -> RunLoop<'a> {

        let first_block_height = 0;

        let first_block_hash = BurnchainHeaderHash([0u8; 32]);
        
        let burn_db = BurnDB::connect(&config.db_path, first_block_height, &first_block_hash, true).unwrap();

        let burnchain = Burnchain::new(&config.db_path.to_string(), &"bitcoin".to_string(), &config.name).unwrap();

        let chain_state = StacksChainState::open(false, 0x80000000, &config.name).unwrap();

        Self {
            config,
            mem_pool,
            previous_tenures: vec![],
            chain_state,
            burn_db,
            burnchain,
            burnchain_tip: None,
            chain_tip: None,
            keychain,
        }
    }

    pub fn tear_up(&mut self, vrf_public_key: VRFPublicKey) {
        let genesis = BurnDB::get_first_block_snapshot(self.burn_db.conn()).unwrap();    
        self.burnchain_tip = Some(genesis.clone());

        // On a local "testnet", a miner constantly registers a new vrf and start its tenure immediately,
        // since there's only one miner. 

        let key_reg_op = self.generate_leader_key_register_op(vrf_public_key);

        let ops = vec![key_reg_op];

        let burn_header_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000001").unwrap();

        let next_block = BurnchainBlock::Bitcoin(BitcoinBlock::new(
            genesis.block_height + 1,
            &burn_header_hash, 
            &genesis.burn_header_hash, 
            &vec![]));
        let next_block_header = next_block.header(&genesis);

        let mut burn_tx = self.burn_db.tx_begin().unwrap();
        let burnchain_tip = Burnchain::process_block_ops(
            &mut burn_tx, 
            &self.burnchain, 
            &genesis, 
            &next_block_header, 
            &ops).unwrap();
        burn_tx.commit().unwrap();

        self.burnchain_tip = Some(burnchain_tip);

        // todo(ludo): Genesis should probably attached to a block in the burnchain.
        self.chain_tip = Some(StacksHeaderInfo::genesis());
    }

    pub fn tear_down(&self) {
    }

    fn generate_leader_key_register_op(&self, vrf_public_key: VRFPublicKey) -> BlockstackOperationType {
        let (consensus_hash, burn_header_hash) = match self.burnchain_tip {
            Some(ref s) => (s.consensus_hash.clone(), s.burn_header_hash),
            _ => panic!()
        };

        BlockstackOperationType::LeaderKeyRegister(LeaderKeyRegisterOp {
            public_key: vrf_public_key,
            memo: vec![],
            address: self.keychain.get_address(),
            consensus_hash,
            burn_header_hash,
            txid: Txid([0u8; 32]),
            vtxindex: 0,
            block_height: 0,
        })
    }

    fn initiate_new_tenure(&mut self, vrf_public_key: VRFPublicKey) -> LeaderTenure {
        // Guard condition:

        let sortition_hash = match self.burnchain_tip {
            Some(ref b) => b.sortition_hash,
            _ => panic!()
        };

        let chain_tip = match self.chain_tip {
            Some(ref b) => b.clone(),
            _ => panic!()
        };

        let vrf_proof = self.keychain.generate_proof(vrf_public_key, sortition_hash.as_bytes()).unwrap();

        let microblock_secret_key = self.keychain.rotate_microblock_keypair();

        let mut tenure = LeaderTenure::new(chain_tip, vrf_proof, microblock_secret_key);

        let coinbase_tx = {
            let tx_auth = self.keychain.get_transaction_auth().unwrap();

            let mut tx = StacksTransaction::new(
                TransactionVersion::Testnet, 
                tx_auth, 
                TransactionPayload::Coinbase(CoinbasePayload([0u8; 32])));
            tx.chain_id = 0x80000000;
            tx.anchor_mode = TransactionAnchorMode::OnChainOnly;
            let mut tx_signer = StacksTransactionSigner::new(&tx);
            self.keychain.sign_as_origin(&mut tx_signer);
            tx_signer.get_tx().unwrap()
        };

        tenure.handle_txs(vec![coinbase_tx]);

        tenure
    }

    fn generate_block_commitment_op(&mut self) {
        let burnchain_tip = self.burnchain_tip.take().unwrap();

        let vrf_pk = self.keychain.rotate_vrf_keypair();
        let key_reg_op = self.generate_leader_key_register_op(vrf_pk);
        
        let ops = vec![key_reg_op];

        let burn_header_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000001").unwrap();

        let next_block = BurnchainBlock::Bitcoin(BitcoinBlock::new(
            burnchain_tip.block_height + 1,
            &burnchain_tip.burn_header_hash, 
            &burn_header_hash, 
            &vec![]));
        let next_block_header = next_block.header(&burnchain_tip);

        let mut burn_tx = self.burn_db.tx_begin().unwrap();
        let new_snapshot = Burnchain::process_block_ops(
            &mut burn_tx, 
            &self.burnchain, 
            &burnchain_tip, 
            &next_block_header, 
            &ops).unwrap();
        burn_tx.commit().unwrap();

        self.burnchain_tip = Some(new_snapshot);
    }

    pub fn start(&mut self) {

        let mut vrf_pk = self.keychain.rotate_vrf_keypair();
        self.tear_up(vrf_pk.clone());

        loop {
            let mut tenure = self.initiate_new_tenure(vrf_pk);

            // A tenure should end when
            // 1 - blocktime is about to expire

            let mut ops = vec![];
            // Prepare commit block operation
            // let commit_block_op = self.generate_block_commitment_op(tenure);
            // ops.push(commit_block_op);
            // Register a new vrf
            vrf_pk = self.keychain.rotate_vrf_keypair();
            let reg_key_op = self.generate_leader_key_register_op(vrf_pk.clone());
            ops.push(reg_key_op);
            
            let burn_header_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000001").unwrap();

            let burnchain_tip = self.burnchain_tip.take().unwrap();

            let next_block_header = {
                let block = BurnchainBlock::Bitcoin(BitcoinBlock::new(
                    burnchain_tip.block_height + 1,
                    &burn_header_hash, 
                    &burnchain_tip.burn_header_hash, 
                    &vec![]));
                block.header(&burnchain_tip)
            };

            let mut burn_tx = self.burn_db.tx_begin().unwrap();
            let burnchain_tip = Burnchain::process_block_ops(
                &mut burn_tx, 
                &self.burnchain, 
                &burnchain_tip, 
                &next_block_header, 
                &ops).unwrap();
            burn_tx.commit().unwrap();
            self.burnchain_tip = Some(burnchain_tip);
    
            self.chain_tip = Some(StacksHeaderInfo::genesis());

            let block_time = time::Duration::from_millis(5000);
            let now = time::Instant::now();
            thread::sleep(block_time);
            println!("Tick");
        }

        // self.current_tenure = Some(tenure);

        // let block_time = time::Duration::from_millis(10000);
        // loop {
        //     self.tick();
        //     thread::sleep(block_time);
        // }
        // self.commit_tenure();



        // let mut node = TestnetNode::new();
        // let mut miner = TestnetMiner::new(&node.burnchain_node.chain, 1, 1, AddressHashMode::SerializeP2PKH);

        // let (vrf_sk, vrf_pk) = miner.first_VRF_keypair();
        // let snapshot_1 = BurnDB::get_first_block_snapshot(node.burnchain_node.db.conn()).unwrap();    

        // let key_register_op = LeaderKeyRegisterOp {
        //     public_key: vrf_pk.clone(),
        //     memo: vec![],
        //     address: miner.get_address(),

        //     consensus_hash: snapshot_1.consensus_hash.clone(),
        //     burn_header_hash: snapshot_1.burn_header_hash,
        //     txid: Txid([0u8; 32]),
        //     vtxindex: 0,
        //     block_height: 0,
        // };

        // let burnchain_tip = self.burnchain_tip.take().unwrap();

        // let proof = miner.make_proof(&vrf_pk, &burnchain_tip.sortition_hash).unwrap();

        // let mut builder = StacksBlockBuilder::first(&snapshot_1.burn_header_hash, &proof, &miner.first_microblock_secret_key());

        // let mut tx_coinbase = StacksTransaction::new(
        //     TransactionVersion::Testnet, 
        //     TransactionAuth::from_p2pkh(&miner.privks[0]).unwrap(), 
        //     TransactionPayload::Coinbase(CoinbasePayload([0u8; 32])));
        // tx_coinbase.chain_id = 0x80000000;
        // tx_coinbase.anchor_mode = TransactionAnchorMode::OnChainOnly;
        // let mut tx_signer = StacksTransactionSigner::new(&tx_coinbase);

        // miner.sign_as_origin(&mut tx_signer);
        // let tx_coinbase_signed = tx_signer.get_tx().unwrap();

        // let (stacks_block) = {            
        //     let mut epoch = builder.epoch_begin(&mut node.chainstate, &tx_coinbase_signed).unwrap();
        //     let anchored_block = builder.mine_anchored_block(&mut epoch);
        //     builder.epoch_finish(epoch);

        //     (anchored_block)
        // };

            //////////
            //////////
            
        // let proof = miner.make_proof(&miner_key.public_key, &burn_block.parent_snapshot.sortition_hash).unwrap();
        // let (mut builder, parent_block_snapshot_opt) = match parent_stacks_block {
        //     None => {
        //         // first stacks block
        //         let builder = StacksBlockBuilder::first(&burn_block.parent_snapshot.burn_header_hash, &proof, &miner.next_microblock_privkey());
        //         (builder, None)
        //     },
        //     Some(parent_stacks_block) => {
        //         // building off an existing stacks block
        //         let parent_stacks_block_snapshot = {
        //             let mut tx = self.burn.burndb.tx_begin().unwrap();
        //             let parent_stacks_block_snapshot = BurnDB::get_block_snapshot_for_winning_stacks_block(&mut tx, &burn_block.parent_snapshot.burn_header_hash, &parent_stacks_block.block_hash()).unwrap().unwrap();
        //             let burned_last = BurnDB::get_block_burn_amount(&mut tx, burn_block.parent_snapshot.block_height, &burn_block.parent_snapshot.burn_header_hash).unwrap();
        //             parent_stacks_block_snapshot
        //         };

        //         let parent_chain_tip = StacksChainState::get_anchored_block_header_info(&self.chainstate.headers_db, &parent_stacks_block_snapshot.burn_header_hash, &parent_stacks_block.header.block_hash()).unwrap().unwrap();

        //         let new_work = StacksWorkScore {
        //             burn: parent_stacks_block_snapshot.total_burn,
        //             work: 0
        //         };

        //         test_debug!("Burned in {} {}: {}", burn_block.block_height, burn_block.parent_snapshot.burn_header_hash.to_hex(), new_work.burn);
        //         let builder = StacksBlockBuilder::from_parent(&parent_chain_tip, &new_work, &proof, &miner.next_microblock_privkey());
        //         (builder, Some(parent_stacks_block_snapshot))
        //     }
        // };

        // test_debug!("Assemble stacks block");

        // let (stacks_block, microblocks) = block_assembler(&mut builder, miner);
        // self.anchored_blocks.push(stacks_block.clone());
        // self.microblocks.push(microblocks.clone());
        
        // test_debug!("Commit to stacks block {}", stacks_block.block_hash());

        // // send block commit for this block (block i)
        // let block_commit_op = self.add_block_commit(burn_block, miner, &stacks_block.block_hash(), burn_amount, miner_key, parent_block_snapshot_opt.as_ref());
        // self.commit_ops.insert(block_commit_op.block_header_hash.clone(), self.anchored_blocks.len()-1);

        // (stacks_block, microblocks, block_commit_op)
        
            //////////
            //////////

        // loop {
        //     let block_time = time::Duration::from_millis(10000);
        //     let now = time::Instant::now();
        //     thread::sleep(block_time);
        //     println!("Tick");

        //     let mempool = fs::read_dir("./mempool").unwrap();
        //     for tx in mempool {
        //         println!("Name: {}", tx.unwrap().path().display())
        //     }
        // }
    }
}

impl <'a> MemPoolObserver for RunLoop <'a> {
    /// todo(ludo): define fn
    fn handle_received_tx(&mut self, tx: Txid) {

    }

    /// todo(ludo): define fn
    fn handle_archived_tx(&mut self, tx: Txid) {

    }
}
