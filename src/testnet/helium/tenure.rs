use super::{MemPoolDB, Config};
use super::node::{SortitionedBlock, TESTNET_CHAIN_ID};

use std::thread;
use std::time;

use burnchains::{BurnchainHeaderHash, Txid};
use chainstate::stacks::db::{StacksChainState, StacksHeaderInfo, ClarityTx};
use chainstate::stacks::{StacksPrivateKey, StacksBlock, StacksWorkScore, StacksAddress, StacksTransactionSigner, StacksTransaction, TransactionVersion, StacksMicroblock, CoinbasePayload, StacksBlockBuilder, TransactionAnchorMode};
use chainstate::stacks::{MINER_BLOCK_BURN_HEADER_HASH, MINER_BLOCK_HEADER_HASH};
use chainstate::burn::{VRFSeed, BlockHeaderHash};
use util::vrf::{VRFProof};

pub struct LeaderTenure {
    average_block_time: u64,
    block_builder: StacksBlockBuilder,
    coinbase_tx: StacksTransaction,
    config: Config,
    last_sortitioned_block: SortitionedBlock,
    pub mem_pool: MemPoolDB,
    pub parent_block: StacksHeaderInfo,
    started_at: std::time::Instant,
    pub vrf_seed: VRFSeed,
}

impl <'a> LeaderTenure {

    pub fn new(parent_block: StacksHeaderInfo, 
               average_block_time: u64,
               coinbase_tx: StacksTransaction,
               config: Config,
               mem_pool: MemPoolDB,
               microblock_secret_key: StacksPrivateKey,  
               last_sortitioned_block: SortitionedBlock,
               vrf_proof: VRFProof) -> LeaderTenure {

        let now = time::Instant::now();

        let ratio = StacksWorkScore {
            burn: parent_block.anchored_header.total_work.burn + 1,
            work: parent_block.anchored_header.total_work.work + 1,
        };

        let block_builder = match last_sortitioned_block.block_height {
            1 => StacksBlockBuilder::first(1, &parent_block.burn_header_hash, parent_block.burn_header_timestamp, &vrf_proof, &microblock_secret_key),
            _ => StacksBlockBuilder::from_parent(1, &parent_block, &ratio, &vrf_proof, &microblock_secret_key)
        };

        Self {
            average_block_time,
            block_builder,
            coinbase_tx,
            config,
            mem_pool,
            last_sortitioned_block,
            parent_block,
            started_at: now,
            vrf_seed: VRFSeed::from_proof(&vrf_proof),
        }
    }

    pub fn handle_txs(&mut self, clarity_tx: &mut ClarityTx<'a>, txs: Vec<StacksTransaction>) {
        for tx in txs {
            let res = self.block_builder.try_mine_tx(clarity_tx, &tx);
            match res {
                Err(e) => error!("Failed mining transaction - {}", e),
                Ok(_) => {},
            };
        }
    }

    pub fn run(&mut self) -> Option<(StacksBlock, Vec<StacksMicroblock>, SortitionedBlock)> {

        let mut chain_state = StacksChainState::open_with_block_limit(
            false,
            TESTNET_CHAIN_ID, 
            &self.config.get_chainstate_path(),
            self.config.block_limit.clone()).unwrap();

        let (burn_header_hash, block_hash) = (self.parent_block.burn_header_hash.clone(), self.parent_block.anchored_header.block_hash());

        let mut clarity_tx = self.block_builder.epoch_begin(&mut chain_state).unwrap();

        self.handle_txs(&mut clarity_tx, vec![self.coinbase_tx.clone()]);

        let txs = self.mem_pool.poll(&burn_header_hash, &block_hash);
        self.handle_txs(&mut clarity_tx, txs);

        let anchored_block = self.block_builder.mine_anchored_block(&mut clarity_tx);

        clarity_tx.rollback_block();

        Some((anchored_block, vec![], self.last_sortitioned_block.clone()))
    }
}
