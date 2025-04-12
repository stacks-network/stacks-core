use super::context::{SignerTestContext, SignerTestState};
use crate::tests::signer::v0::{
    get_chain_info_wrapper, wait_for_block_pushed_by_miner_key, MultipleMinerTest,
};
use madhouse::{Command, CommandWrapper};
use proptest::prelude::{Just, Strategy};
use stacks::chainstate::stacks::TenureChangeCause;
use std::sync::{Arc, Mutex};
use tracing::info;

pub struct MineBitcoinBlockTenureChangePrimaryMinerCommand {
    miners: Arc<Mutex<MultipleMinerTest>>,
}

impl MineBitcoinBlockTenureChangePrimaryMinerCommand {
    pub fn new(miners: Arc<Mutex<MultipleMinerTest>>) -> Self {
        Self { miners }
    }
}

impl Command<SignerTestState, SignerTestContext>
    for MineBitcoinBlockTenureChangePrimaryMinerCommand
{
    fn check(&self, state: &SignerTestState) -> bool {
        println!(
            "Checking: Miner 1 mining Bitcoin block and tenure change tx. Result: {:?}",
            state.is_booted_to_nakamoto
        );
        state.is_booted_to_nakamoto
    }

    fn apply(&self, _state: &mut SignerTestState) {
        println!("Applying: Miner 1 mining Bitcoin block and tenure change tx");

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

        println!(
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

        let info_after = get_chain_info_wrapper(&conf_1);
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
            MineBitcoinBlockTenureChangePrimaryMinerCommand::new(ctx.miners.clone()),
        ))
    }
}

pub struct MineBitcoinBlockTenureChangeSecondaryMinerCommand {
    miners: Arc<Mutex<MultipleMinerTest>>,
}

impl MineBitcoinBlockTenureChangeSecondaryMinerCommand {
    pub fn new(miners: Arc<Mutex<MultipleMinerTest>>) -> Self {
        Self { miners }
    }
}

impl Command<SignerTestState, SignerTestContext>
    for MineBitcoinBlockTenureChangeSecondaryMinerCommand
{
    fn check(&self, state: &SignerTestState) -> bool {
        println!(
            "Checking: Miner 2 mining Bitcoin block and tenure change tx. Result: {:?}",
            state.is_booted_to_nakamoto
        );
        state.is_booted_to_nakamoto
    }

    fn apply(&self, _state: &mut SignerTestState) {
        println!("Applying: Miner 2 mining Bitcoin block and tenure change tx");

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

        println!(
            "Waiting for Nakamoto block {} pushed by miner 2",
            stacks_height_before + 1
        );

        let secondary_miner_block =
            wait_for_block_pushed_by_miner_key(30, stacks_height_before + 1, &miner_pk_2)
                .expect("Failed to get block N");

        let mined_block_height = secondary_miner_block.header.chain_length;

        let info_after = get_chain_info_wrapper(&conf_2);
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
            MineBitcoinBlockTenureChangeSecondaryMinerCommand::new(ctx.miners.clone()),
        ))
    }
}
