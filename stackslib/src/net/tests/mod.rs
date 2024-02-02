// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2023 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

pub mod httpcore;
pub mod inv;
pub mod neighbors;

use clarity::vm::clarity::ClarityConnection;
use clarity::vm::types::PrincipalData;
use rand::prelude::SliceRandom;
use rand::{thread_rng, Rng, RngCore};
use stacks_common::address::{AddressHashMode, C32_ADDRESS_VERSION_TESTNET_SINGLESIG};
use stacks_common::consts::{FIRST_BURNCHAIN_CONSENSUS_HASH, FIRST_STACKS_BLOCK_HASH};
use stacks_common::types::chainstate::{
    StacksAddress, StacksBlockId, StacksPrivateKey, StacksPublicKey,
};
use stacks_common::types::Address;
use stacks_common::util::vrf::VRFProof;
use wsts::curve::point::Point;

use crate::burnchains::PoxConstants;
use crate::chainstate::burn::db::sortdb::{SortitionDB, SortitionHandle};
use crate::chainstate::burn::operations::BlockstackOperationType;
use crate::chainstate::coordinator::tests::p2pkh_from;
use crate::chainstate::nakamoto::coordinator::tests::boot_nakamoto;
use crate::chainstate::nakamoto::tests::get_account;
use crate::chainstate::nakamoto::tests::node::{TestSigners, TestStacker};
use crate::chainstate::nakamoto::{NakamotoBlock, NakamotoChainState};
use crate::chainstate::stacks::address::PoxAddress;
use crate::chainstate::stacks::boot::test::{
    key_to_stacks_addr, make_pox_4_aggregate_key, make_pox_4_lockup,
};
use crate::chainstate::stacks::boot::MINERS_NAME;
use crate::chainstate::stacks::db::{MinerPaymentTxFees, StacksAccount, StacksChainState};
use crate::chainstate::stacks::events::TransactionOrigin;
use crate::chainstate::stacks::{
    CoinbasePayload, StacksTransaction, StacksTransactionSigner, TenureChangeCause,
    TenureChangePayload, TokenTransferMemo, TransactionAnchorMode, TransactionAuth,
    TransactionPayload, TransactionVersion,
};
use crate::clarity::vm::types::StacksAddressExtensions;
use crate::core::{StacksEpoch, StacksEpochExtension};
use crate::net::relay::Relayer;
use crate::net::stackerdb::StackerDBConfig;
use crate::net::test::{TestEventObserver, TestPeer, TestPeerConfig};
use crate::util_lib::boot::boot_code_id;

/// One step of a simulated Nakamoto node's bootup procedure.
#[derive(Debug, PartialEq, Clone)]
pub enum NakamotoBootStep {
    Block(Vec<StacksTransaction>),
    TenureExtend(Vec<StacksTransaction>),
}

#[derive(Debug, PartialEq, Clone)]
pub enum NakamotoBootTenure {
    Sortition(Vec<NakamotoBootStep>),
    NoSortition(Vec<NakamotoBootStep>),
}

pub struct NakamotoBootPlan {
    pub test_name: String,
    pub pox_constants: PoxConstants,
    pub private_key: StacksPrivateKey,
    pub initial_balances: Vec<(PrincipalData, u64)>,
    pub test_stackers: Option<Vec<TestStacker>>,
    pub test_signers: Option<TestSigners>,
    pub observer: Option<TestEventObserver>,
}

impl NakamotoBootPlan {
    pub fn new(test_name: &str) -> Self {
        Self {
            test_name: test_name.to_string(),
            pox_constants: TestPeerConfig::default().burnchain.pox_constants,
            private_key: StacksPrivateKey::from_seed(&[2]),
            initial_balances: vec![],
            test_stackers: None,
            test_signers: None,
            observer: Some(TestEventObserver::new()),
        }
    }

    pub fn with_private_key(mut self, privk: StacksPrivateKey) -> Self {
        self.private_key = privk;
        self
    }

    pub fn with_pox_constants(mut self, cycle_length: u32, prepare_length: u32) -> Self {
        let new_consts = PoxConstants::new(
            cycle_length,
            prepare_length,
            (80 * prepare_length / 100).max(1),
            0,
            0,
            u64::MAX,
            u64::MAX,
            // v1 unlocks at start of second reward cycle
            cycle_length + 2,
            // v2 unlocks at start of third cycle
            2 * cycle_length + 1,
            // v3 unlocks at start of fourth cycle
            3 * cycle_length + 1,
            // pox-3 activates at start of third cycle, just before v2 unlock
            2 * cycle_length + 1,
            // pox-4 activates at start of fourth reward cycle, just before v3 unlock
            3 * cycle_length + 1,
        );
        self.pox_constants = new_consts;
        self
    }

    pub fn with_initial_balances(mut self, initial_balances: Vec<(PrincipalData, u64)>) -> Self {
        self.initial_balances = initial_balances;
        self
    }

    pub fn with_test_stackers(mut self, test_stackers: Vec<TestStacker>) -> Self {
        self.test_stackers = Some(test_stackers);
        self
    }

    pub fn with_test_signers(mut self, test_signers: TestSigners) -> Self {
        self.test_signers = Some(test_signers);
        self
    }

    /// This is the first tenure in which nakamoto blocks will be built.
    /// However, it is also the last sortition for an epoch 2.x block.
    pub fn nakamoto_start_burn_height(pox_consts: &PoxConstants) -> u64 {
        (pox_consts.pox_4_activation_height + pox_consts.reward_cycle_length).into()
    }

    /// This is the first tenure which is a nakamoto sortition.
    pub fn nakamoto_first_tenure_height(pox_consts: &PoxConstants) -> u64 {
        Self::nakamoto_start_burn_height(pox_consts) + 1
    }

    /// Check the boot plan transactions against the generated blocks
    fn check_blocks_against_boot_plan(
        blocks: &[NakamotoBlock],
        boot_steps: &[NakamotoBootStep],
        num_expected_transactions: usize,
    ) {
        assert_eq!(blocks.len(), boot_steps.len());
        let mut num_transactions = 0;
        for (block, boot_step) in blocks.iter().zip(boot_steps.iter()) {
            num_transactions += block.txs.len();
            let boot_step_txs = match boot_step {
                NakamotoBootStep::TenureExtend(txs) => txs.clone(),
                NakamotoBootStep::Block(txs) => txs.clone(),
            };
            let mut planned_txs = vec![];
            for tx in block.txs.iter() {
                match tx.payload {
                    TransactionPayload::Coinbase(..) | TransactionPayload::TenureChange(..) => {
                        continue;
                    }
                    _ => {
                        planned_txs.push(tx.clone());
                    }
                }
            }
            assert_eq!(planned_txs.len(), boot_step_txs.len());
            for (block_tx, boot_step_tx) in planned_txs.iter().zip(boot_step_txs.iter()) {
                assert_eq!(block_tx.txid(), boot_step_tx.txid());
            }
        }
        assert_eq!(
            num_expected_transactions, num_transactions,
            "Failed to mine at least one transaction in this block"
        );
    }

    /// Make a peer and transition it into the Nakamoto epoch.
    /// The node needs to be stacking; otherwise, Nakamoto won't activate.
    fn boot_nakamoto<'a>(
        mut self,
        aggregate_public_key: Point,
        observer: Option<&'a TestEventObserver>,
    ) -> TestPeer<'a> {
        let mut peer_config = TestPeerConfig::new(&self.test_name, 0, 0);
        peer_config.private_key = self.private_key.clone();
        let addr = StacksAddress::from_public_keys(
            C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
            &AddressHashMode::SerializeP2PKH,
            1,
            &vec![StacksPublicKey::from_private(&self.private_key)],
        )
        .unwrap();

        // reward cycles are 5 blocks long
        // first 25 blocks are boot-up
        // reward cycle 6 instantiates pox-3
        // we stack in reward cycle 7 so pox-3 is evaluated to find reward set participation
        peer_config.aggregate_public_key = Some(aggregate_public_key.clone());
        peer_config
            .stacker_dbs
            .push(boot_code_id(MINERS_NAME, false));
        peer_config.epochs = Some(StacksEpoch::unit_test_3_0_only(
            (self.pox_constants.pox_4_activation_height
                + self.pox_constants.reward_cycle_length
                + 1)
            .into(),
        ));
        peer_config.initial_balances =
            vec![(addr.to_account_principal(), 1_000_000_000_000_000_000)];
        peer_config
            .initial_balances
            .append(&mut self.initial_balances.clone());

        let test_stackers: Vec<TestStacker> = if let Some(stackers) = self.test_stackers.take() {
            stackers.into_iter().collect()
        } else {
            // Create a list of test Stackers and their signer keys
            let num_keys = self
                .test_signers
                .as_ref()
                .unwrap_or(&TestSigners::default())
                .num_keys;
            (0..num_keys)
                .map(|index| {
                    let stacker_private_key = StacksPrivateKey::from_seed(&index.to_be_bytes());
                    let signer_private_key =
                        StacksPrivateKey::from_seed(&(index + 1000).to_be_bytes());
                    TestStacker {
                        stacker_private_key,
                        signer_private_key,
                        amount: 1_000_000_000_000_000_000,
                    }
                })
                .collect()
        };

        // Create some balances for test Stackers
        let mut stacker_balances = test_stackers
            .iter()
            .map(|test_stacker| {
                (
                    PrincipalData::from(key_to_stacks_addr(&test_stacker.stacker_private_key)),
                    u64::try_from(test_stacker.amount).expect("Stacking amount too large"),
                )
            })
            .collect();

        peer_config.initial_balances.append(&mut stacker_balances);
        peer_config.test_stackers = Some(test_stackers.clone());
        peer_config.burnchain.pox_constants = self.pox_constants.clone();
        let mut peer = TestPeer::new_with_observer(peer_config, observer);
        self.advance_to_nakamoto(&mut peer);
        peer
    }

    /// Bring a TestPeer into the Nakamoto Epoch
    fn advance_to_nakamoto(&self, peer: &mut TestPeer) {
        let mut peer_nonce = 0;
        let addr = StacksAddress::from_public_keys(
            C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
            &AddressHashMode::SerializeP2PKH,
            1,
            &vec![StacksPublicKey::from_private(&self.private_key)],
        )
        .unwrap();

        let tip = {
            let sort_db = peer.sortdb.as_mut().unwrap();
            let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
            tip
        };

        debug!("\n\n======================");
        debug!("PoxConstants = {:#?}", &peer.config.burnchain.pox_constants);
        debug!("tip = {}", tip.block_height);
        debug!("========================\n\n");

        // advance to just past pox-3 unlock
        let mut sortition_height = tip.block_height;
        while sortition_height
            <= peer
                .config
                .burnchain
                .pox_constants
                .pox_4_activation_height
                .into()
        {
            peer.tenure_with_txs(&vec![], &mut peer_nonce);
            let tip = {
                let sort_db = peer.sortdb.as_mut().unwrap();
                let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
                tip
            };
            sortition_height = tip.block_height;
        }

        debug!("\n\n======================");
        debug!("Make PoX-4 lockups");
        debug!("========================\n\n");

        // Make all the test Stackers stack
        let stack_txs: Vec<_> = peer
            .config
            .test_stackers
            .clone()
            .unwrap_or(vec![])
            .iter()
            .map(|test_stacker| {
                make_pox_4_lockup(
                    &test_stacker.stacker_private_key,
                    0,
                    test_stacker.amount,
                    PoxAddress::from_legacy(AddressHashMode::SerializeP2PKH, addr.bytes.clone()),
                    12,
                    StacksPublicKey::from_private(&test_stacker.signer_private_key),
                    34,
                )
            })
            .collect();

        peer.tenure_with_txs(&stack_txs, &mut peer_nonce);

        debug!("\n\n======================");
        debug!("Advance to Epoch 3.0");
        debug!("========================\n\n");

        // advance to the start of epoch 3.0
        while sortition_height
            < Self::nakamoto_start_burn_height(&peer.config.burnchain.pox_constants)
        {
            peer.tenure_with_txs(&vec![], &mut peer_nonce);
            let tip = {
                let sort_db = peer.sortdb.as_mut().unwrap();
                let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
                tip
            };
            sortition_height = tip.block_height;
        }

        debug!("\n\n======================");
        debug!("Welcome to Nakamoto!");
        debug!("========================\n\n");
    }

    pub fn boot_into_nakamoto_peer<'a>(
        self,
        boot_plan: Vec<NakamotoBootTenure>,
        observer: Option<&'a TestEventObserver>,
    ) -> TestPeer<'a> {
        let mut test_signers = self.test_signers.clone().unwrap_or(TestSigners::default());
        let mut peer = self.boot_nakamoto(test_signers.aggregate_public_key.clone(), observer);

        let mut all_blocks = vec![];
        let mut rc_burn_ops = vec![];
        let mut consensus_hashes = vec![];
        let mut last_tenure_change: Option<TenureChangePayload> = None;
        let mut blocks_since_last_tenure = 0;
        let stx_miner_key = peer.miner.nakamoto_miner_key();

        debug!("\n\nProcess plan with {} steps", boot_plan.len());

        for (x, plan_tenure) in boot_plan.into_iter().enumerate() {
            debug!("\n\nProcess plan step {} {:?}", &x, &plan_tenure);

            match plan_tenure {
                NakamotoBootTenure::NoSortition(boot_steps) => {
                    assert!(boot_steps.len() > 0);
                    // just extend the last sortition
                    let (burn_ops, tenure_change_extend, miner_key) =
                        peer.begin_nakamoto_tenure(TenureChangeCause::Extended);
                    let (_, _, next_consensus_hash) = peer.next_burnchain_block(burn_ops.clone());

                    rc_burn_ops.push(burn_ops);

                    let tenure_change = last_tenure_change.clone().unwrap();
                    let blocks: Vec<NakamotoBlock> = all_blocks.last().cloned().unwrap();

                    // extending last tenure
                    let tenure_change_extend = tenure_change.extend(
                        next_consensus_hash,
                        blocks.last().cloned().unwrap().header.block_id(),
                        blocks_since_last_tenure,
                    );
                    let tenure_change_tx = peer
                        .miner
                        .make_nakamoto_tenure_change(tenure_change_extend.clone());

                    debug!("\n\nExtend across empty sortition {}: blocks.len() = {}, blocks_since_last_tenure = {}\n\n", &next_consensus_hash, blocks.len(), blocks_since_last_tenure);

                    let mut i = 0;
                    let mut num_expected_transactions = 1; // expect tenure-extension

                    let blocks_and_sizes = peer.make_nakamoto_tenure_extension(
                        tenure_change_tx,
                        &mut test_signers,
                        |miner, chainstate, sortdb, blocks_so_far| {
                            if i >= boot_steps.len() {
                                return vec![];
                            }
                            let next_step = &boot_steps[i];
                            i += 1;

                            let mut txs = vec![];
                            let last_block_opt = blocks_so_far
                                .last()
                                .as_ref()
                                .map(|(block, _size, _cost)| block.header.block_id());

                            match next_step {
                                NakamotoBootStep::TenureExtend(transactions) => {
                                    assert!(transactions.len() > 0);
                                    if let Some(last_block) = last_block_opt {
                                        let tenure_extension = tenure_change.extend(
                                            next_consensus_hash.clone(),
                                            last_block.clone(),
                                            blocks_since_last_tenure
                                        );
                                        let tenure_extension_tx =
                                            miner.make_nakamoto_tenure_change(tenure_extension.clone());

                                        txs.push(tenure_extension_tx);
                                        txs.extend_from_slice(&transactions[..]);
                                        num_expected_transactions += 1 + transactions.len();
                                    }
                                    debug!("\n\nExtend current tenure in empty tenure {} (blocks so far: {}, blocks_since_last_tenure = {}, steps so far: {})\n\n", &next_consensus_hash, blocks_so_far.len(), blocks_since_last_tenure, i);
                                }
                                NakamotoBootStep::Block(transactions) => {
                                    assert!(transactions.len() > 0);
                                    debug!("\n\nMake block {} with {} transactions in empty tenure {}\n\n", blocks_so_far.len(), transactions.len(), &next_consensus_hash);
                                    txs.extend_from_slice(&transactions[..]);
                                    num_expected_transactions += transactions.len();
                                }
                            }

                            blocks_since_last_tenure += 1;
                            txs
                        });

                    consensus_hashes.push(next_consensus_hash);

                    let blocks: Vec<NakamotoBlock> = blocks_and_sizes
                        .into_iter()
                        .map(|(block, _, _)| block)
                        .collect();

                    Self::check_blocks_against_boot_plan(
                        &blocks,
                        &boot_steps,
                        num_expected_transactions,
                    );
                    all_blocks.push(blocks);
                }
                NakamotoBootTenure::Sortition(boot_steps) => {
                    assert!(boot_steps.len() > 0);
                    let (burn_ops, mut tenure_change, miner_key) =
                        peer.begin_nakamoto_tenure(TenureChangeCause::BlockFound);
                    let (_, _, consensus_hash) = peer.next_burnchain_block(burn_ops.clone());
                    let vrf_proof = peer.make_nakamoto_vrf_proof(miner_key);

                    tenure_change.tenure_consensus_hash = consensus_hash.clone();
                    tenure_change.burn_view_consensus_hash = consensus_hash.clone();

                    last_tenure_change = Some(tenure_change.clone());

                    let tenure_change_tx = peer
                        .miner
                        .make_nakamoto_tenure_change(tenure_change.clone());

                    let coinbase_tx = peer.miner.make_nakamoto_coinbase(None, vrf_proof);

                    debug!("\n\nNew tenure: {}\n\n", &consensus_hash);

                    let mut i = 0;
                    let mut num_expected_transactions = 2; // tenure-change and coinbase
                    blocks_since_last_tenure = 0;

                    let blocks_and_sizes = peer.make_nakamoto_tenure(
                        tenure_change_tx,
                        coinbase_tx,
                        &mut test_signers,
                        |miner, chainstate, sortdb, blocks_so_far| {
                            if i >= boot_steps.len() {
                                return vec![];
                            }
                            let next_step = &boot_steps[i];
                            i += 1;

                            let mut txs = vec![];
                            let last_block_opt = blocks_so_far
                                .last()
                                .as_ref()
                                .map(|(block, _size, _cost)| block.header.block_id());

                            match next_step {
                                NakamotoBootStep::TenureExtend(transactions) => {
                                    assert!(transactions.len() > 0);
                                    if let Some(last_block) = last_block_opt {
                                        let tenure_extension = tenure_change.extend(
                                            consensus_hash.clone(),
                                            last_block.clone(),
                                            blocks_since_last_tenure // blocks_so_far.len() as u32,
                                        );
                                        let tenure_extension_tx =
                                            miner.make_nakamoto_tenure_change(tenure_extension.clone());

                                        txs.push(tenure_extension_tx);
                                        txs.extend_from_slice(&transactions[..]);
                                        num_expected_transactions += 1 + transactions.len();
                                    }
                                    debug!("\n\nExtend current tenure {} (blocks so far: {}, steps so far: {})\n\n", &consensus_hash, blocks_so_far.len(), i);
                                }
                                NakamotoBootStep::Block(transactions) => {
                                    assert!(transactions.len() > 0);
                                    debug!("\n\nMake block {} with {} transactions in tenure {}\n\n", blocks_so_far.len(), transactions.len(), &consensus_hash);
                                    txs.extend_from_slice(&transactions[..]);
                                    num_expected_transactions += transactions.len();
                                }
                            }

                            blocks_since_last_tenure += 1;
                            txs
                        });

                    consensus_hashes.push(consensus_hash);
                    let blocks: Vec<NakamotoBlock> = blocks_and_sizes
                        .into_iter()
                        .map(|(block, _, _)| block)
                        .collect();

                    Self::check_blocks_against_boot_plan(
                        &blocks,
                        &boot_steps,
                        num_expected_transactions,
                    );

                    all_blocks.push(blocks);
                }
            }
        }
        // check that our tenure-extends have been getting applied
        let (highest_tenure, sort_tip) = {
            let chainstate = &mut peer.stacks_node.as_mut().unwrap().chainstate;
            let sort_db = peer.sortdb.as_mut().unwrap();
            let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
            let tenure =
                NakamotoChainState::get_highest_nakamoto_tenure(chainstate.db(), sort_db.conn())
                    .unwrap()
                    .unwrap();
            (tenure, tip)
        };

        let last_block = all_blocks
            .last()
            .as_ref()
            .cloned()
            .unwrap()
            .last()
            .cloned()
            .unwrap();
        assert_eq!(
            highest_tenure.tenure_id_consensus_hash,
            last_block.header.consensus_hash
        );
        assert_eq!(
            highest_tenure.burn_view_consensus_hash,
            sort_tip.consensus_hash
        );

        // verify all transactions succeeded.
        // already checked that `all_blocks` matches the boot plan, so just check that each
        // transaction in `all_blocks` ran to completion
        if let Some(observer) = observer {
            let observed_blocks = observer.get_blocks();
            let mut block_idx = (peer.config.burnchain.pox_constants.pox_4_activation_height
                + peer.config.burnchain.pox_constants.reward_cycle_length
                - 25) as usize;
            for tenure in all_blocks {
                for block in tenure {
                    let observed_block = &observed_blocks[block_idx];
                    block_idx += 1;

                    assert_eq!(
                        observed_block.metadata.anchored_header.block_hash(),
                        block.header.block_hash()
                    );

                    // each transaction was mined in the same order as described in the boot plan,
                    // and it succeeded.
                    let mut burn_receipts = vec![];
                    let mut stacks_receipts = vec![];
                    for receipt in observed_block.receipts.iter() {
                        match &receipt.transaction {
                            TransactionOrigin::Stacks(..) => {
                                stacks_receipts.push(receipt);
                            }
                            TransactionOrigin::Burn(..) => burn_receipts.push(receipt),
                        }
                    }

                    assert_eq!(stacks_receipts.len(), block.txs.len());
                    for (receipt, tx) in stacks_receipts.iter().zip(block.txs.iter()) {
                        // transactions processed in the same order
                        assert_eq!(receipt.transaction.txid(), tx.txid());
                        // no CheckErrors
                        assert!(receipt.vm_error.is_none());
                        // transaction was not aborted post-hoc
                        assert!(!receipt.post_condition_aborted);
                    }
                }
            }
        }
        peer
    }
}

#[test]
fn test_boot_nakamoto_peer() {
    let private_key = StacksPrivateKey::from_seed(&[2]);
    let addr = StacksAddress::from_public_keys(
        C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
        &AddressHashMode::SerializeP2PKH,
        1,
        &vec![StacksPublicKey::from_private(&private_key)],
    )
    .unwrap();
    let recipient_addr =
        StacksAddress::from_string("ST2YM3J4KQK09V670TD6ZZ1XYNYCNGCWCVTASN5VM").unwrap();

    let mut sender_nonce = 0;

    let mut next_stx_transfer = || {
        let mut stx_transfer = StacksTransaction::new(
            TransactionVersion::Testnet,
            TransactionAuth::from_p2pkh(&private_key).unwrap(),
            TransactionPayload::TokenTransfer(
                recipient_addr.clone().to_account_principal(),
                1,
                TokenTransferMemo([0x00; 34]),
            ),
        );
        stx_transfer.chain_id = 0x80000000;
        stx_transfer.anchor_mode = TransactionAnchorMode::OnChainOnly;
        stx_transfer.set_tx_fee(1);
        stx_transfer.auth.set_origin_nonce(sender_nonce);
        sender_nonce += 1;

        let mut tx_signer = StacksTransactionSigner::new(&stx_transfer);
        tx_signer.sign_origin(&private_key).unwrap();
        let stx_transfer_signed = tx_signer.get_tx().unwrap();

        stx_transfer_signed
    };

    let boot_tenures = vec![
        // reward cycle 1
        NakamotoBootTenure::Sortition(vec![
            NakamotoBootStep::Block(vec![next_stx_transfer()]),
            NakamotoBootStep::Block(vec![next_stx_transfer()]),
            NakamotoBootStep::Block(vec![next_stx_transfer()]),
            NakamotoBootStep::Block(vec![next_stx_transfer()]),
            NakamotoBootStep::Block(vec![next_stx_transfer()]),
            NakamotoBootStep::Block(vec![next_stx_transfer()]),
            NakamotoBootStep::Block(vec![next_stx_transfer()]),
            NakamotoBootStep::Block(vec![next_stx_transfer()]),
            NakamotoBootStep::Block(vec![next_stx_transfer()]),
            NakamotoBootStep::Block(vec![next_stx_transfer()]),
        ]),
        NakamotoBootTenure::Sortition(vec![NakamotoBootStep::Block(vec![next_stx_transfer()])]),
        NakamotoBootTenure::Sortition(vec![NakamotoBootStep::Block(vec![next_stx_transfer()])]),
        NakamotoBootTenure::Sortition(vec![NakamotoBootStep::Block(vec![next_stx_transfer()])]),
        NakamotoBootTenure::Sortition(vec![
            NakamotoBootStep::Block(vec![next_stx_transfer()]),
            NakamotoBootStep::TenureExtend(vec![next_stx_transfer()]),
            NakamotoBootStep::Block(vec![next_stx_transfer()]),
            NakamotoBootStep::TenureExtend(vec![next_stx_transfer()]),
            NakamotoBootStep::Block(vec![next_stx_transfer()]),
            NakamotoBootStep::TenureExtend(vec![next_stx_transfer()]),
            NakamotoBootStep::Block(vec![next_stx_transfer()]),
            NakamotoBootStep::TenureExtend(vec![next_stx_transfer()]),
        ]),
        NakamotoBootTenure::NoSortition(vec![NakamotoBootStep::Block(vec![next_stx_transfer()])]),
        // prepare phase for 2
        NakamotoBootTenure::NoSortition(vec![NakamotoBootStep::Block(vec![next_stx_transfer()])]),
        NakamotoBootTenure::Sortition(vec![NakamotoBootStep::Block(vec![next_stx_transfer()])]),
        NakamotoBootTenure::Sortition(vec![NakamotoBootStep::Block(vec![next_stx_transfer()])]),
        // reward cycle 2
        NakamotoBootTenure::Sortition(vec![NakamotoBootStep::Block(vec![next_stx_transfer()])]),
        NakamotoBootTenure::NoSortition(vec![NakamotoBootStep::Block(vec![next_stx_transfer()])]),
        NakamotoBootTenure::NoSortition(vec![NakamotoBootStep::Block(vec![next_stx_transfer()])]),
        NakamotoBootTenure::NoSortition(vec![NakamotoBootStep::Block(vec![next_stx_transfer()])]),
        NakamotoBootTenure::NoSortition(vec![NakamotoBootStep::Block(vec![next_stx_transfer()])]),
        NakamotoBootTenure::NoSortition(vec![NakamotoBootStep::Block(vec![next_stx_transfer()])]),
        NakamotoBootTenure::NoSortition(vec![NakamotoBootStep::Block(vec![next_stx_transfer()])]),
        // prepare phase for 3
        NakamotoBootTenure::Sortition(vec![
            NakamotoBootStep::Block(vec![next_stx_transfer()]),
            NakamotoBootStep::TenureExtend(vec![next_stx_transfer()]),
            NakamotoBootStep::Block(vec![next_stx_transfer()]),
            NakamotoBootStep::TenureExtend(vec![next_stx_transfer()]),
            NakamotoBootStep::Block(vec![next_stx_transfer()]),
            NakamotoBootStep::TenureExtend(vec![next_stx_transfer()]),
            NakamotoBootStep::Block(vec![next_stx_transfer()]),
            NakamotoBootStep::TenureExtend(vec![next_stx_transfer()]),
        ]),
        NakamotoBootTenure::Sortition(vec![
            NakamotoBootStep::Block(vec![next_stx_transfer()]),
            NakamotoBootStep::TenureExtend(vec![next_stx_transfer()]),
            NakamotoBootStep::Block(vec![next_stx_transfer()]),
            NakamotoBootStep::TenureExtend(vec![next_stx_transfer()]),
            NakamotoBootStep::Block(vec![next_stx_transfer()]),
            NakamotoBootStep::TenureExtend(vec![next_stx_transfer()]),
            NakamotoBootStep::Block(vec![next_stx_transfer()]),
            NakamotoBootStep::TenureExtend(vec![next_stx_transfer()]),
        ]),
        NakamotoBootTenure::Sortition(vec![
            NakamotoBootStep::Block(vec![next_stx_transfer()]),
            NakamotoBootStep::TenureExtend(vec![next_stx_transfer()]),
            NakamotoBootStep::Block(vec![next_stx_transfer()]),
            NakamotoBootStep::TenureExtend(vec![next_stx_transfer()]),
            NakamotoBootStep::Block(vec![next_stx_transfer()]),
            NakamotoBootStep::TenureExtend(vec![next_stx_transfer()]),
            NakamotoBootStep::Block(vec![next_stx_transfer()]),
            NakamotoBootStep::TenureExtend(vec![next_stx_transfer()]),
        ]),
        // reward cycle 3
        NakamotoBootTenure::Sortition(vec![NakamotoBootStep::Block(vec![next_stx_transfer()])]),
    ];

    let plan = NakamotoBootPlan::new(&function_name!())
        .with_private_key(private_key)
        .with_pox_constants(10, 3)
        .with_initial_balances(vec![(addr.into(), 1_000_000)]);

    let observer = TestEventObserver::new();
    let peer = plan.boot_into_nakamoto_peer(boot_tenures, Some(&observer));
}
