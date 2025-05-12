use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use madhouse::{Command, CommandWrapper};
use proptest::prelude::{Just, Strategy};
use stacks::chainstate::stacks::TenureChangeCause;
use tracing::info;

use super::context::{SignerTestContext, SignerTestState};
use crate::tests::neon_integrations::get_chain_info;
use crate::tests::signer::v0::{wait_for_block_pushed_by_miner_key, MultipleMinerTest};

pub struct MineBitcoinBlockTenureChangeMiner1 {
    miners: Arc<Mutex<MultipleMinerTest>>,
}

impl MineBitcoinBlockTenureChangeMiner1 {
    pub fn new(miners: Arc<Mutex<MultipleMinerTest>>) -> Self {
        Self { miners }
    }
}

impl Command<SignerTestState, SignerTestContext> for MineBitcoinBlockTenureChangeMiner1 {
    fn check(&self, state: &SignerTestState) -> bool {
        let (conf_1, _) = self.miners.lock().unwrap().get_node_configs();
        let burn_height = get_chain_info(&conf_1).burn_block_height;
        let miner_1_submitted_commit_last_burn_height = self
            .miners
            .lock()
            .unwrap()
            .get_primary_submitted_commit_last_burn_height()
            .0
            .load(Ordering::SeqCst);
        let miner_2_submitted_commit_last_burn_height = self
            .miners
            .lock()
            .unwrap()
            .get_secondary_submitted_commit_last_burn_height()
            .0
            .load(Ordering::SeqCst);

        info!(
            "Checking: Miner 1 mining Bitcoin block and tenure change tx. Result: {:?} && {:?} && {:?}",
            state.is_booted_to_nakamoto, burn_height == miner_1_submitted_commit_last_burn_height, burn_height > miner_2_submitted_commit_last_burn_height
        );
        state.is_booted_to_nakamoto
            && burn_height == miner_1_submitted_commit_last_burn_height
            && burn_height > miner_2_submitted_commit_last_burn_height
    }

    fn apply(&self, _state: &mut SignerTestState) {
        info!("Applying: Miner 1 mining Bitcoin block and tenure change tx");

        let (stacks_height_before, conf_1, miner_pk_1) = {
            let mut miners = self.miners.lock().unwrap();
            let stacks_height_before = miners.get_peer_stacks_tip_height();
            let (conf_1, _) = miners.get_node_configs();
            let burnchain = conf_1.get_burnchain();
            let sortdb = burnchain.open_sortition_db(true).unwrap();

            miners
                .mine_bitcoin_block_and_tenure_change_tx(&sortdb, TenureChangeCause::BlockFound, 60)
                .expect("Failed to mine BTC block");

            let (miner_pk_1, _) = miners.get_miner_public_keys();

            (stacks_height_before, conf_1, miner_pk_1)
        };

        info!(
            "Waiting for Nakamoto block {} pushed by miner 1",
            stacks_height_before + 1
        );

        let miner_1_block =
            wait_for_block_pushed_by_miner_key(30, stacks_height_before + 1, &miner_pk_1)
                .expect("Failed to get block");

        let mined_block_height = miner_1_block.header.chain_length;
        info!(
            "Miner 1 mined Nakamoto block height: {}",
            mined_block_height
        );

        let info_after = get_chain_info(&conf_1);
        assert_eq!(info_after.stacks_tip, miner_1_block.header.block_hash());
        assert_eq!(info_after.stacks_tip_height, mined_block_height);
        assert_eq!(mined_block_height, stacks_height_before + 1);
    }

    fn label(&self) -> String {
        "MINE_BITCOIN_BLOCK_AND_TENURE_CHANGE_MINER_1".to_string()
    }

    fn build(
        ctx: Arc<SignerTestContext>,
    ) -> impl Strategy<Value = CommandWrapper<SignerTestState, SignerTestContext>> {
        Just(CommandWrapper::new(
            MineBitcoinBlockTenureChangeMiner1::new(ctx.miners.clone()),
        ))
    }
}

pub struct MineBitcoinBlockTenureChangeMiner2 {
    miners: Arc<Mutex<MultipleMinerTest>>,
}

impl MineBitcoinBlockTenureChangeMiner2 {
    pub fn new(miners: Arc<Mutex<MultipleMinerTest>>) -> Self {
        Self { miners }
    }
}

impl Command<SignerTestState, SignerTestContext> for MineBitcoinBlockTenureChangeMiner2 {
    fn check(&self, state: &SignerTestState) -> bool {
        let (conf_1, _) = self.miners.lock().unwrap().get_node_configs();
        let burn_height = get_chain_info(&conf_1).burn_block_height;
        let miner_1_submitted_commit_last_burn_height = self
            .miners
            .lock()
            .unwrap()
            .get_primary_submitted_commit_last_burn_height()
            .0
            .load(Ordering::SeqCst);
        let miner_2_submitted_commit_last_burn_height = self
            .miners
            .lock()
            .unwrap()
            .get_secondary_submitted_commit_last_burn_height()
            .0
            .load(Ordering::SeqCst);

        info!(
            "Checking: Miner 2 mining Bitcoin block and tenure change tx. Result: {:?} && {:?} && {:?}",
            state.is_booted_to_nakamoto, burn_height == miner_1_submitted_commit_last_burn_height, burn_height > miner_2_submitted_commit_last_burn_height
        );
        state.is_booted_to_nakamoto
            && burn_height == miner_2_submitted_commit_last_burn_height
            && burn_height > miner_1_submitted_commit_last_burn_height
    }

    fn apply(&self, _state: &mut SignerTestState) {
        info!("Applying: Miner 2 mining Bitcoin block and tenure change tx");

        let stacks_height_before = self.miners.lock().unwrap().get_peer_stacks_tip_height();

        let (conf_1, conf_2) = self.miners.lock().unwrap().get_node_configs();
        let burnchain = conf_1.get_burnchain();
        let sortdb = burnchain.open_sortition_db(true).unwrap();
        self.miners
            .lock()
            .unwrap()
            .mine_bitcoin_block_and_tenure_change_tx(&sortdb, TenureChangeCause::BlockFound, 60)
            .expect("Failed to mine BTC block");

        let (_, miner_pk_2) = self.miners.lock().unwrap().get_miner_public_keys();

        info!(
            "Waiting for Nakamoto block {} pushed by miner 2",
            stacks_height_before + 1
        );

        let secondary_miner_block =
            wait_for_block_pushed_by_miner_key(30, stacks_height_before + 1, &miner_pk_2)
                .expect("Failed to get block N");

        let mined_block_height = secondary_miner_block.header.chain_length;

        let info_after = get_chain_info(&conf_2);
        assert_eq!(
            info_after.stacks_tip,
            secondary_miner_block.header.block_hash()
        );
        assert_eq!(info_after.stacks_tip_height, mined_block_height);
        assert_eq!(mined_block_height, stacks_height_before + 1);
    }

    fn label(&self) -> String {
        "MINE_BITCOIN_BLOCK_AND_TENURE_CHANGE_MINER_2".to_string()
    }

    fn build(
        ctx: Arc<SignerTestContext>,
    ) -> impl Strategy<Value = CommandWrapper<SignerTestState, SignerTestContext>> {
        Just(CommandWrapper::new(
            MineBitcoinBlockTenureChangeMiner2::new(ctx.miners.clone()),
        ))
    }
}

pub struct MineBitcoinBlock {
    miners: Arc<Mutex<MultipleMinerTest>>,
    timeout_secs: u64,
}

impl MineBitcoinBlock {
    pub fn new(miners: Arc<Mutex<MultipleMinerTest>>, timeout_secs: u64) -> Self {
        Self {
            miners,
            timeout_secs,
        }
    }
}

impl Command<SignerTestState, SignerTestContext> for MineBitcoinBlock {
    fn check(&self, _state: &SignerTestState) -> bool {
        info!("Checking: Mining tenure. Result: {:?}", true);
        true
    }

    fn apply(&self, _state: &mut SignerTestState) {
        info!(
            "Applying: Mining tenure and waiting for it for {:?} seconds",
            self.timeout_secs
        );

        let sortdb = {
            let miners = self.miners.lock().unwrap();
            let (conf_1, _) = miners.get_node_configs();
            let burnchain = conf_1.get_burnchain();
            let sortdb = burnchain.open_sortition_db(true).unwrap();
            sortdb
        };

        {
            let mut miners = self.miners.lock().unwrap();
            miners
                .mine_bitcoin_blocks_and_confirm(&sortdb, 1, self.timeout_secs)
                .expect("Failed to mine BTC block");
        }
    }

    fn label(&self) -> String {
        "MINE_BITCOIN_BLOCK".to_string()
    }

    fn build(
        ctx: Arc<SignerTestContext>,
    ) -> impl Strategy<Value = CommandWrapper<SignerTestState, SignerTestContext>> {
        (60u64..90u64).prop_map(move |timeout_secs| {
            CommandWrapper::new(MineBitcoinBlock::new(ctx.miners.clone(), timeout_secs))
        })
    }
}
