use super::{Config, BurnchainTip};
use super::node::{TESTNET_CHAIN_ID, ChainTip};

use std::time::{Instant, Duration};
use std::thread;

use stacks::burnchains::Txid;
use stacks::chainstate::stacks::db::{StacksChainState, ClarityTx};
use stacks::chainstate::stacks::{StacksPrivateKey, StacksBlock, StacksWorkScore, StacksTransaction, StacksMicroblock, StacksBlockBuilder};
use stacks::chainstate::burn::VRFSeed;
use stacks::core::mempool::MemPoolDB;
use stacks::util::vrf::VRFProof;

pub struct TenureArtifacts {
    pub anchored_block: StacksBlock,
    pub microblocks: Vec<StacksMicroblock>,
    pub parent_block: BurnchainTip,
    pub burn_fee: u64
}

pub struct Tenure {
    block_builder: StacksBlockBuilder,
    coinbase_tx: StacksTransaction,
    config: Config,
    pub burnchain_tip: BurnchainTip,
    pub parent_block: ChainTip, 
    pub mem_pool: MemPoolDB,
    pub vrf_seed: VRFSeed,
    burn_fee_cap: u64,
}

impl <'a> Tenure {

    pub fn new(parent_block: ChainTip, 
               coinbase_tx: StacksTransaction,
               config: Config,
               mem_pool: MemPoolDB,
               microblock_secret_key: StacksPrivateKey,  
               burnchain_tip: BurnchainTip,
               vrf_proof: VRFProof,
               burn_fee_cap: u64) -> Tenure {

        let ratio = StacksWorkScore {
            burn: burnchain_tip.block_snapshot.total_burn,
            work: parent_block.metadata.anchored_header.total_work.work + 1,
        };

        let block_builder = match burnchain_tip.block_snapshot.total_burn {
            0 => StacksBlockBuilder::first(
                1, 
                &parent_block.metadata.burn_header_hash, 
                parent_block.metadata.burn_header_timestamp, 
                &vrf_proof, 
                &microblock_secret_key),
            _ => StacksBlockBuilder::from_parent(
                1, 
                &parent_block.metadata, 
                &ratio, 
                &vrf_proof, 
                &microblock_secret_key)
        };

        Self {
            block_builder,
            coinbase_tx,
            config,
            burnchain_tip,
            mem_pool,
            parent_block,
            vrf_seed: VRFSeed::from_proof(&vrf_proof),
            burn_fee_cap,
        }
    }

    pub fn handle_txs(&mut self, clarity_tx: &mut ClarityTx<'a>, txs_in_mempool: Vec<StacksTransaction>, candidates: &mut Vec<Txid>) {
        for tx in txs_in_mempool {
            if candidates.contains(&tx.txid()) {
                continue;
            }

            let res = self.block_builder.try_mine_tx(clarity_tx, &tx);
            match res {
                Err(e) => error!("Failed mining transaction - {}", e),
                Ok(_) => {
                    candidates.push(tx.txid());
                },
            };
        }
    }

    pub fn run(&mut self) -> Option<TenureArtifacts> {
        info!("Node starting new tenure with VRF {:?}", self.vrf_seed);

        let mut chain_state = StacksChainState::open_with_block_limit(
            false, 
            TESTNET_CHAIN_ID, 
            &self.config.get_chainstate_path(),
            self.config.block_limit.clone()).unwrap();

        let burn_header_hash = self.parent_block.metadata.burn_header_hash;
        let block_hash= self.parent_block.block.block_hash();

        let mut clarity_tx = self.block_builder.epoch_begin(&mut chain_state).unwrap();
        let mut candidates= vec![];

        self.handle_txs(&mut clarity_tx, vec![self.coinbase_tx.clone()], &mut candidates);

        let duration_left: u128 = self.config.burnchain.commit_anchor_block_within as u128;
        let mut elapsed = Instant::now().duration_since(self.burnchain_tip.received_at);
        while duration_left.saturating_sub(elapsed.as_millis()) > 0 {
            let txs_in_mempool = self.mem_pool.poll(&burn_header_hash, &block_hash);
            self.handle_txs(&mut clarity_tx, txs_in_mempool, &mut candidates);
            thread::sleep(Duration::from_millis(1000));
            elapsed = Instant::now().duration_since(self.burnchain_tip.received_at);
        } 

        let anchored_block = self.block_builder.mine_anchored_block(&mut clarity_tx);

        clarity_tx.rollback_block();

        let artifact = TenureArtifacts {
            anchored_block,
            microblocks: vec![],
            parent_block: self.burnchain_tip.clone(),
            burn_fee: self.burn_fee_cap
        };
        Some(artifact)
    }
}
