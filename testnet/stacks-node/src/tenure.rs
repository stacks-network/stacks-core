use std::thread;
use std::time::{Duration, Instant};

#[cfg(test)]
use stacks::burnchains::PoxConstants;
#[cfg(test)]
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::burn::db::sortdb::SortitionDBConn;
use stacks::chainstate::stacks::db::StacksChainState;
use stacks::chainstate::stacks::miner::BlockBuilderSettings;
use stacks::chainstate::stacks::{
    StacksBlock, StacksBlockBuilder, StacksMicroblock, StacksPrivateKey, StacksPublicKey,
    StacksTransaction,
};
use stacks::core::mempool::MemPoolDB;
use stacks_common::types::chainstate::VRFSeed;
use stacks_common::util::hash::Hash160;
use stacks_common::util::vrf::VRFProof;

/// Only used by the Helium (Mocknet) node
use super::node::ChainTip;
use super::{BurnchainTip, Config};

pub struct TenureArtifacts {
    pub anchored_block: StacksBlock,
    pub microblocks: Vec<StacksMicroblock>,
    pub parent_block: BurnchainTip,
    pub burn_fee: u64,
}

pub struct Tenure {
    coinbase_tx: StacksTransaction,
    config: Config,
    pub burnchain_tip: BurnchainTip,
    pub parent_block: ChainTip,
    pub mem_pool: MemPoolDB,
    pub vrf_seed: VRFSeed,
    burn_fee_cap: u64,
    vrf_proof: VRFProof,
    microblock_pubkeyhash: Hash160,
    parent_block_total_burn: u64,
}

impl<'a> Tenure {
    pub fn new(
        parent_block: ChainTip,
        coinbase_tx: StacksTransaction,
        config: Config,
        mem_pool: MemPoolDB,
        microblock_secret_key: StacksPrivateKey,
        burnchain_tip: BurnchainTip,
        vrf_proof: VRFProof,
        burn_fee_cap: u64,
    ) -> Tenure {
        let mut microblock_pubkey = StacksPublicKey::from_private(&microblock_secret_key);
        microblock_pubkey.set_compressed(true);
        let microblock_pubkeyhash = Hash160::from_node_public_key(&microblock_pubkey);

        let parent_block_total_burn = burnchain_tip.block_snapshot.total_burn;

        Self {
            coinbase_tx,
            config,
            burnchain_tip,
            mem_pool,
            parent_block,
            vrf_seed: VRFSeed::from_proof(&vrf_proof),
            vrf_proof,
            burn_fee_cap,
            microblock_pubkeyhash,
            parent_block_total_burn,
        }
    }

    pub fn run(&mut self, burn_dbconn: &SortitionDBConn) -> Option<TenureArtifacts> {
        info!("Node starting new tenure with VRF {:?}", self.vrf_seed);

        let duration_left: u128 = self.config.burnchain.commit_anchor_block_within as u128;
        let mut elapsed = Instant::now().duration_since(self.burnchain_tip.received_at);
        while duration_left.saturating_sub(elapsed.as_millis()) > 0 {
            thread::sleep(Duration::from_millis(1000));
            elapsed = Instant::now().duration_since(self.burnchain_tip.received_at);
        }

        let (mut chain_state, _) = StacksChainState::open(
            self.config.is_mainnet(),
            self.config.burnchain.chain_id,
            &self.config.get_chainstate_path_str(),
            Some(self.config.node.get_marf_opts()),
        )
        .unwrap();

        let (anchored_block, _, _) = StacksBlockBuilder::build_anchored_block(
            &mut chain_state,
            burn_dbconn,
            &mut self.mem_pool,
            &self.parent_block.metadata,
            self.parent_block_total_burn,
            self.vrf_proof.clone(),
            self.microblock_pubkeyhash.clone(),
            &self.coinbase_tx,
            BlockBuilderSettings::limited(),
            None,
            &self.config.get_burnchain(),
        )
        .unwrap();

        info!("Finish tenure: {}", anchored_block.block_hash());

        let artifact = TenureArtifacts {
            anchored_block,
            microblocks: vec![],
            parent_block: self.burnchain_tip.clone(),
            burn_fee: self.burn_fee_cap,
        };
        Some(artifact)
    }

    #[cfg(test)]
    pub fn open_chainstate(&self) -> StacksChainState {
        use stacks::core::CHAIN_ID_TESTNET;

        let (chain_state, _) = StacksChainState::open(
            false,
            CHAIN_ID_TESTNET,
            &self.config.get_chainstate_path_str(),
            Some(self.config.node.get_marf_opts()),
        )
        .unwrap();
        chain_state
    }

    #[cfg(test)]
    pub fn open_fake_sortdb(&self) -> SortitionDB {
        SortitionDB::open(
            &self.config.get_burn_db_file_path(),
            true,
            PoxConstants::testnet_default(),
        )
        .unwrap()
    }
}
