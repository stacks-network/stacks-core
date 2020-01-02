use super::{MemPool, MemPoolFS, NodeConfig};
use super::node::{SortitionedBlock};

use std::thread;
use std::time;

use burnchains::{BurnchainHeaderHash, Txid};
use chainstate::stacks::db::{StacksChainState, StacksHeaderInfo, ClarityTx};
use chainstate::stacks::{StacksPrivateKey, StacksBlock, TransactionPayload, StacksWorkScore, StacksAddress, StacksTransactionSigner, StacksTransaction, TransactionVersion, StacksMicroblock, CoinbasePayload, StacksBlockBuilder, TransactionAnchorMode};
use chainstate::burn::{VRFSeed, BlockHeaderHash};
use util::vrf::{VRFProof};

pub struct LeaderTenure {
    average_block_time: u64,
    block_builder: StacksBlockBuilder,
    coinbase_tx: StacksTransaction,
    config: NodeConfig,
    last_sortitioned_block: SortitionedBlock,
    mem_pool: MemPoolFS,
    parent_block: StacksHeaderInfo,
    started_at: std::time::Instant,
    vrf_seed: VRFSeed,
}

impl <'a> LeaderTenure {

    pub fn new(parent_block: StacksHeaderInfo, 
               average_block_time: u64,
               coinbase_tx: StacksTransaction,
               config: NodeConfig,
               mem_pool: MemPoolFS,
               microblock_secret_key: StacksPrivateKey,  
               last_sortitioned_block: SortitionedBlock,
               vrf_proof: VRFProof) -> LeaderTenure {

        let now = time::Instant::now();

        let ratio = StacksWorkScore {
            burn: parent_block.anchored_header.total_work.burn + 1,
            work: parent_block.anchored_header.total_work.work + 1,
        };

        let block_builder = match last_sortitioned_block.block_height {
            0 => StacksBlockBuilder::first(1, &parent_block.burn_header_hash, &vrf_proof, &microblock_secret_key),
            _ => StacksBlockBuilder::from_parent(1, &parent_block, &ratio, &vrf_proof, &microblock_secret_key)
        };

        Self {
            average_block_time,
            block_builder,
            coinbase_tx,
            config,
            last_sortitioned_block,
            mem_pool,
            parent_block,
            started_at: now,
            vrf_seed: VRFSeed::from_proof(&vrf_proof),
        }
    }

    pub fn handle_txs(&mut self, clarity_tx: &mut ClarityTx<'a>, txs: Vec<StacksTransaction>) {
        for tx in txs {
            self.block_builder.try_mine_tx(clarity_tx, &tx).unwrap();
        }
    }

    pub fn run(&mut self) -> (Option<StacksBlock>, Vec<StacksMicroblock>, SortitionedBlock) {

        let mut chain_state = StacksChainState::open(false, 0x80000000, &self.config.path).unwrap();

        let mut clarity_tx = match self.last_sortitioned_block.block_height {
            0 => {
                chain_state.block_begin(
                &BurnchainHeaderHash([0u8; 32]),
                &BlockHeaderHash([0u8; 32]),
                &BurnchainHeaderHash([1u8; 32]), 
                &BlockHeaderHash([1u8; 32]))
            },
            _ => chain_state.block_begin(
                &self.last_sortitioned_block.burn_header_hash, 
                &self.parent_block.anchored_header.block_hash(), 
                &BurnchainHeaderHash([1u8; 32]), 
                &BlockHeaderHash([1u8; 32])),
        };

        let mempool_poll_interval = time::Duration::from_millis(250);
        let tenure_duration = time::Duration::from_millis(self.average_block_time * 1 / 2);
        let should_commit_block_at = self.started_at.checked_add(tenure_duration).unwrap();

        self.handle_txs(&mut clarity_tx, vec![self.coinbase_tx.clone()]);

        while time::Instant::now() < should_commit_block_at {
            let txs = self.mem_pool.poll();
            self.handle_txs(&mut clarity_tx, txs);
            thread::sleep(mempool_poll_interval);
        }

        let mut b = self.block_builder.clone();
        let anchored_block = self.block_builder.mine_anchored_block(&mut clarity_tx);

        clarity_tx.rollback_block();

        (Some(anchored_block), vec![], self.last_sortitioned_block.clone())
    }
}