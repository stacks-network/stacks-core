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

pub mod convergence;
pub mod download;
pub mod httpcore;
pub mod inv;
pub mod mempool;
pub mod neighbors;
pub mod relay;

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use clarity::types::{EpochList, StacksEpochId};
use clarity::vm::costs::ExecutionCost;
use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier};
use libstackerdb::StackerDBChunkData;
use rand::Rng;
use stacks_common::address::{AddressHashMode, C32_ADDRESS_VERSION_TESTNET_SINGLESIG};
use stacks_common::bitvec::BitVec;
use stacks_common::types::chainstate::{
    BurnchainHeaderHash, ConsensusHash, StacksAddress, StacksBlockId, StacksPrivateKey,
    StacksPublicKey, TrieHash,
};
use stacks_common::types::net::PeerAddress;
use stacks_common::types::Address;
use stacks_common::util::hash::Sha512Trunc256Sum;
use stacks_common::util::secp256k1::MessageSignature;

use crate::burnchains::PoxConstants;
use crate::chainstate::burn::db::sortdb::{SortitionDB, SortitionHandle};
use crate::chainstate::burn::operations::BlockstackOperationType;
use crate::chainstate::nakamoto::coordinator::tests::boot_nakamoto;
use crate::chainstate::nakamoto::staging_blocks::NakamotoBlockObtainMethod;
use crate::chainstate::nakamoto::test_signers::TestSigners;
use crate::chainstate::nakamoto::tests::get_account;
use crate::chainstate::nakamoto::tests::node::TestStacker;
use crate::chainstate::nakamoto::{NakamotoBlock, NakamotoBlockHeader, NakamotoChainState};
use crate::chainstate::stacks::boot::test::key_to_stacks_addr;
use crate::chainstate::stacks::boot::{
    MINERS_NAME, SIGNERS_VOTING_FUNCTION_NAME, SIGNERS_VOTING_NAME,
};
use crate::chainstate::stacks::db::blocks::test::make_empty_coinbase_block;
use crate::chainstate::stacks::events::TransactionOrigin;
use crate::chainstate::stacks::test::make_codec_test_microblock;
use crate::chainstate::stacks::{
    StacksTransaction, StacksTransactionSigner, TenureChangeCause, TenureChangePayload,
    TokenTransferMemo, TransactionAnchorMode, TransactionAuth, TransactionContractCall,
    TransactionPayload, TransactionVersion,
};
use crate::chainstate::tests::{TestChainstate, TestChainstateConfig};
use crate::clarity::vm::types::StacksAddressExtensions;
use crate::core::{StacksEpoch, StacksEpochExtension};
use crate::net::relay::Relayer;
use crate::net::test::{RPCHandlerArgsType, TestEventObserver, TestPeer, TestPeerConfig};
use crate::net::{
    BlocksData, BlocksDatum, MicroblocksData, NakamotoBlocksData, NeighborKey, NetworkResult,
    PingData, StackerDBPushChunkData, StacksMessage, StacksMessageType, StacksNodeState,
};
use crate::util_lib::boot::boot_code_id;

/// One step of a simulated Nakamoto node's bootup procedure.
#[derive(Debug, Clone)]
pub enum NakamotoBootStep {
    Block(Vec<StacksTransaction>),
    TenureExtend(Vec<StacksTransaction>),
    TenureCause(Vec<StacksTransaction>, TenureChangeCause),
}

#[derive(Debug, Clone)]
pub enum NakamotoBootTenure {
    Sortition(Vec<NakamotoBootStep>),
    NoSortition(Vec<NakamotoBootStep>),
}

pub struct NakamotoBootPlan {
    pub test_name: String,
    pub pox_constants: PoxConstants,
    pub private_key: StacksPrivateKey,
    pub initial_balances: Vec<(PrincipalData, u128)>,
    pub test_stackers: Vec<TestStacker>,
    pub test_signers: TestSigners,
    pub observer: Option<TestEventObserver>,
    pub num_peers: usize,
    /// Whether to add an initial balance for `private_key`'s account
    pub add_default_balance: bool,
    /// Whether or not to produce malleablized blocks
    pub malleablized_blocks: bool,
    pub network_id: u32,
    pub txindex: bool,
    pub epochs: Option<EpochList<ExecutionCost>>,
    /// Additional transactions to include in the tip block
    pub tip_transactions: Vec<StacksTransaction>,
    /// Additional tenures to include at the end of the boot plan
    pub extra_tenures: Vec<NakamotoBootTenure>,
    /// Do not fail if a transaction returns error (by default the BootPlan will stop on tx failure)
    pub ignore_transaction_errors: bool,
}

impl NakamotoBootPlan {
    pub fn new(test_name: &str) -> Self {
        let (test_signers, test_stackers) = TestStacker::common_signing_set();
        let default_config = TestChainstateConfig::default();
        Self {
            test_name: test_name.to_string(),
            pox_constants: default_config.burnchain.pox_constants,
            private_key: StacksPrivateKey::from_seed(&[2]),
            initial_balances: vec![],
            test_stackers,
            test_signers,
            observer: Some(TestEventObserver::new()),
            num_peers: 0,
            add_default_balance: true,
            malleablized_blocks: true,
            network_id: default_config.network_id,
            txindex: false,
            extra_tenures: vec![],
            epochs: None,
            tip_transactions: vec![],
            ignore_transaction_errors: false,
        }
    }

    // Builds a TestChainstateConfig with shared parameters
    fn build_nakamoto_chainstate_config(&self) -> TestChainstateConfig {
        let mut chainstate_config = TestChainstateConfig::new(&self.test_name);
        chainstate_config.network_id = self.network_id;
        chainstate_config.txindex = self.txindex;

        let addr = StacksAddress::from_public_keys(
            C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
            &AddressHashMode::SerializeP2PKH,
            1,
            &vec![StacksPublicKey::from_private(&self.private_key)],
        )
        .unwrap();

        let default_epoch = StacksEpoch::unit_test_3_0_only(
            (self.pox_constants.pox_4_activation_height
                + self.pox_constants.reward_cycle_length
                + 1)
            .into(),
        );
        chainstate_config.epochs = Some(self.epochs.clone().unwrap_or(default_epoch));
        chainstate_config.initial_balances = vec![];
        if self.add_default_balance {
            chainstate_config
                .initial_balances
                .push((addr.to_account_principal(), 1_000_000_000_000_000_000));
        }
        chainstate_config
            .initial_balances
            .extend(self.initial_balances.clone());

        let fee_payment_balance = 10_000;
        let stacker_balances = self.test_stackers.iter().map(|test_stacker| {
            (
                PrincipalData::from(key_to_stacks_addr(&test_stacker.stacker_private_key)),
                test_stacker.amount,
            )
        });
        let signer_balances = self.test_stackers.iter().map(|test_stacker| {
            (
                PrincipalData::from(key_to_stacks_addr(&test_stacker.signer_private_key)),
                fee_payment_balance,
            )
        });

        chainstate_config.initial_balances.extend(stacker_balances);
        chainstate_config.initial_balances.extend(signer_balances);
        chainstate_config.test_signers = Some(self.test_signers.clone());
        chainstate_config.test_stackers = Some(self.test_stackers.clone());
        chainstate_config.burnchain.pox_constants = self.pox_constants.clone();

        if let Some(epochs) = chainstate_config.epochs.as_ref() {
            StacksEpoch::validate_nakamoto_transition_schedule(
                epochs,
                &chainstate_config.burnchain,
            );
        }

        chainstate_config
    }

    pub fn with_private_key(mut self, privk: StacksPrivateKey) -> Self {
        self.private_key = privk;
        self
    }

    pub fn with_network_id(mut self, network_id: u32) -> Self {
        self.network_id = network_id;
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
        );
        self.pox_constants = new_consts;
        self
    }

    pub fn with_epochs(mut self, epochs: EpochList<ExecutionCost>) -> Self {
        self.epochs = Some(epochs);
        self
    }

    pub fn with_initial_balances(mut self, initial_balances: Vec<(PrincipalData, u128)>) -> Self {
        self.initial_balances = initial_balances;
        self
    }

    pub fn with_tip_transactions(mut self, tip_transactions: Vec<StacksTransaction>) -> Self {
        self.tip_transactions = tip_transactions;
        self
    }

    pub fn with_ignore_transaction_errors(mut self, ignore_transaction_errors: bool) -> Self {
        self.ignore_transaction_errors = ignore_transaction_errors;
        self
    }

    pub fn with_test_stackers(mut self, test_stackers: Vec<TestStacker>) -> Self {
        self.test_stackers = test_stackers;
        self
    }

    pub fn with_test_signers(mut self, test_signers: TestSigners) -> Self {
        self.test_signers = test_signers;
        self
    }

    pub fn with_extra_peers(mut self, num_peers: usize) -> Self {
        self.num_peers = num_peers;
        self
    }

    pub fn with_malleablized_blocks(mut self, malleablized_blocks: bool) -> Self {
        self.malleablized_blocks = malleablized_blocks;
        self
    }

    pub fn with_txindex(mut self, txindex: bool) -> Self {
        self.txindex = txindex;
        self
    }

    pub fn with_boot_tenures(mut self, boot_tenures: Vec<NakamotoBootTenure>) -> Self {
        self.extra_tenures = boot_tenures;
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
                NakamotoBootStep::TenureCause(txs, ..) => txs.clone(),
            };
            let planned_txs: Vec<_> = block
                .txs
                .iter()
                .filter(|tx| match &tx.payload {
                    TransactionPayload::Coinbase(..) | TransactionPayload::TenureChange(..) => {
                        false
                    }
                    TransactionPayload::ContractCall(TransactionContractCall {
                        contract_name,
                        address,
                        function_name,
                        ..
                    }) => {
                        if contract_name.as_str() == SIGNERS_VOTING_NAME
                            && address.is_burn()
                            && function_name.as_str() == SIGNERS_VOTING_FUNCTION_NAME
                        {
                            false
                        } else {
                            true
                        }
                    }
                    _ => true,
                })
                .collect();
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

    /// Apply burn ops and blocks to the peer replicas
    fn apply_blocks_to_other_peers(
        burn_ops: &[BlockstackOperationType],
        blocks: &[NakamotoBlock],
        malleablized_blocks: &[NakamotoBlock],
        other_peers: &mut [TestPeer],
    ) {
        info!("Applying block to other peers"; "block_height" => ?burn_ops.first().map(|op| op.block_height()));
        for (i, peer) in other_peers.iter_mut().enumerate() {
            peer.next_burnchain_block(burn_ops.to_vec());

            let sortdb = peer.chain.sortdb.take().unwrap();
            let mut node = peer.chain.stacks_node.take().unwrap();

            let sort_tip = SortitionDB::get_canonical_sortition_tip(sortdb.conn()).unwrap();
            let mut sort_handle = sortdb.index_handle(&sort_tip);

            let mut possible_chain_tips = HashSet::new();

            for block in blocks {
                debug!(
                    "Apply block {} (sighash {}) to peer {i} ({})",
                    &block.block_id(),
                    &block.header.signer_signature_hash(),
                    &peer.to_neighbor().addr
                );
                let block_id = block.block_id();
                let accepted = Relayer::process_new_nakamoto_block(
                    &peer.network.burnchain,
                    &sortdb,
                    &mut sort_handle,
                    &mut node.chainstate,
                    &peer.network.stacks_tip.block_id(),
                    block,
                    None,
                    NakamotoBlockObtainMethod::Pushed,
                )
                .unwrap();
                assert!(
                    accepted.is_accepted(),
                    "Did NOT accept Nakamoto block {block_id} to other peer {i}"
                );
                test_debug!("Accepted Nakamoto block {block_id} to other peer {i}");
                peer.chain.coord.handle_new_nakamoto_stacks_block().unwrap();

                possible_chain_tips.insert(block.block_id());

                // process it
                peer.chain.coord.handle_new_stacks_block().unwrap();
                peer.chain.coord.handle_new_nakamoto_stacks_block().unwrap();
            }

            for block in malleablized_blocks {
                debug!(
                    "Apply malleablized block {} (sighash {}) to peer {i} ({})",
                    &block.block_id(),
                    &block.header.signer_signature_hash(),
                    &peer.to_neighbor().addr
                );
                let block_id = block.block_id();
                let accepted = Relayer::process_new_nakamoto_block(
                    &peer.network.burnchain,
                    &sortdb,
                    &mut sort_handle,
                    &mut node.chainstate,
                    &peer.network.stacks_tip.block_id(),
                    block,
                    None,
                    NakamotoBlockObtainMethod::Pushed,
                )
                .unwrap();
                assert!(
                    accepted.is_accepted(),
                    "Did NOT accept malleablized Nakamoto block {block_id} to other peer {i}"
                );
                test_debug!("Accepted malleablized Nakamoto block {block_id} to other peer {i}");
                peer.chain.coord.handle_new_nakamoto_stacks_block().unwrap();

                possible_chain_tips.insert(block.block_id());

                // process it
                peer.chain.coord.handle_new_stacks_block().unwrap();
                peer.chain.coord.handle_new_nakamoto_stacks_block().unwrap();
            }

            peer.chain.sortdb = Some(sortdb);
            peer.chain.stacks_node = Some(node);
            peer.refresh_burnchain_view();

            assert!(possible_chain_tips.contains(&peer.network.stacks_tip.block_id()));
        }
    }

    /// Make a chainstate capable of transitioning into the Nakamoto epoch.
    /// The node needs to be stacking; otherwise, Nakamoto won't activate.
    pub fn to_chainstate(
        self,
        observer: Option<&TestEventObserver>,
        current_block: Option<u64>,
    ) -> TestChainstate<'_> {
        let mut chainstate_config = self.build_nakamoto_chainstate_config();
        if let Some(current_block) = current_block {
            chainstate_config.current_block = current_block;
        }
        let mut chain = TestChainstate::new_with_observer(chainstate_config, observer);
        chain.mine_malleablized_blocks = self.malleablized_blocks;
        chain
    }

    /// Make a peer and transition it into the Nakamoto epoch.
    /// The node needs to be stacking; otherwise, Nakamoto won't activate.
    /// Boot a TestPeer and followers into the Nakamoto epoch
    pub fn boot_nakamoto_peers(
        self,
        observer: Option<&TestEventObserver>,
    ) -> (TestPeer<'_>, Vec<TestPeer<'_>>) {
        let mut peer_config = TestPeerConfig::new(&self.test_name, 0, 0);
        peer_config.chain_config = self.build_nakamoto_chainstate_config();
        peer_config.private_key = self.private_key.clone();
        peer_config.connection_opts.auth_token = Some("password".to_string());
        peer_config
            .stacker_dbs
            .push(boot_code_id(MINERS_NAME, false));

        let mut peer = TestPeer::new_with_observer(peer_config.clone(), observer);
        peer.chain.mine_malleablized_blocks = self.malleablized_blocks;

        let mut other_peers = vec![];
        for i in 0..self.num_peers {
            let mut other_config = peer_config.clone();
            other_config.chain_config.test_name =
                format!("{}.follower", &peer_config.chain_config.test_name);
            other_config.server_port = 0;
            other_config.http_port = 0;
            other_config.chain_config.test_stackers =
                peer_config.chain_config.test_stackers.clone();
            other_config.private_key = StacksPrivateKey::from_seed(&(i as u128).to_be_bytes());
            other_config.add_neighbor(&peer.to_neighbor());

            let mut other_peer = TestPeer::new_with_observer(other_config, None);
            other_peer.chain.mine_malleablized_blocks = self.malleablized_blocks;
            other_peers.push(other_peer);
        }

        // Advance primary peer and other peers to Nakamoto epoch
        peer.chain
            .advance_to_epoch_boundary(&self.private_key, StacksEpochId::Epoch30);
        for other_peer in &mut other_peers {
            other_peer
                .chain
                .advance_to_epoch_boundary(&self.private_key, StacksEpochId::Epoch30);
        }

        (peer, other_peers)
    }

    pub fn boot_into_nakamoto_peers(
        self,
        mut boot_plan: Vec<NakamotoBootTenure>,
        observer: Option<&TestEventObserver>,
    ) -> (TestPeer<'_>, Vec<TestPeer<'_>>) {
        let test_signers = self.test_signers.clone();
        let pox_constants = self.pox_constants.clone();
        let test_stackers = self.test_stackers.clone();
        let ignore_transaction_errors = self.ignore_transaction_errors;

        boot_plan.extend(self.extra_tenures.clone());

        let (mut peer, mut other_peers) = self.boot_nakamoto_peers(observer);
        if boot_plan.is_empty() {
            debug!("No boot plan steps supplied -- returning once nakamoto epoch has been reached");
            return (peer, other_peers);
        }

        let mut all_blocks = vec![];
        let mut malleablized_block_ids = HashSet::new();
        let mut last_tenure_change: Option<TenureChangePayload> = None;
        let mut blocks_since_last_tenure = 0;

        debug!("\n\nProcess plan with {} steps", boot_plan.len());

        for (x, plan_tenure) in boot_plan.into_iter().enumerate() {
            debug!("\n\nProcess plan step {} {:?}", &x, &plan_tenure);

            match plan_tenure {
                NakamotoBootTenure::NoSortition(boot_steps) => {
                    assert!(!boot_steps.is_empty());
                    // just extend the last sortition
                    let (burn_ops, tenure_change_extend, miner_key) =
                        peer.begin_nakamoto_tenure(TenureChangeCause::Extended);
                    let (_, _, next_consensus_hash) = peer.next_burnchain_block(burn_ops.clone());

                    let tenure_change = last_tenure_change.clone().unwrap();
                    let blocks: Vec<NakamotoBlock> = all_blocks.last().cloned().unwrap();

                    // extending last tenure
                    let tenure_change_extend = tenure_change.extend(
                        next_consensus_hash.clone(),
                        blocks.last().cloned().unwrap().header.block_id(),
                        blocks_since_last_tenure,
                    );
                    let tenure_change_tx = peer
                        .chain
                        .miner
                        .make_nakamoto_tenure_change(tenure_change_extend.clone());

                    debug!("\n\nExtend across empty sortition {}: blocks.len() = {}, blocks_since_last_tenure = {}\n\n", &next_consensus_hash, blocks.len(), blocks_since_last_tenure);

                    let mut i = 0;
                    let mut num_expected_transactions = 1; // expect tenure-extension

                    let blocks_and_sizes = peer.make_nakamoto_tenure_extension(
                        tenure_change_tx,
                        &mut test_signers.clone(),
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
                                    assert!(!transactions.is_empty());
                                    if let Some(last_block) = last_block_opt {
                                        let tenure_extension = tenure_change.extend(
                                            next_consensus_hash.clone(),
                                            last_block.clone(),
                                            blocks_since_last_tenure
                                        );
                                        let tenure_extension_tx =
                                            miner.make_nakamoto_tenure_change(tenure_extension);

                                        txs.push(tenure_extension_tx);
                                        txs.extend_from_slice(&transactions[..]);
                                        num_expected_transactions += 1 + transactions.len();
                                    }
                                    debug!("\n\nExtend current tenure in empty tenure {} (blocks so far: {}, blocks_since_last_tenure = {}, steps so far: {})\n\n", &next_consensus_hash, blocks_so_far.len(), blocks_since_last_tenure, i);
                                }
                                NakamotoBootStep::TenureCause(transactions, tenure_cause) => {
                                    assert!(!transactions.is_empty());
                                    if let Some(last_block) = last_block_opt {
                                        let tenure_extension = tenure_change.extend_with_cause(
                                            next_consensus_hash.clone(),
                                            last_block.clone(),
                                            blocks_since_last_tenure,
                                            *tenure_cause,
                                        );
                                        let tenure_extension_tx =
                                            miner.make_nakamoto_tenure_change(tenure_extension);

                                        txs.push(tenure_extension_tx);
                                        txs.extend_from_slice(&transactions[..]);
                                        num_expected_transactions += 1 + transactions.len();
                                    }
                                    debug!("\n\nExtend-with-cause {:?} current tenure in empty tenure {} (blocks so far: {}, blocks_since_last_tenure = {}, steps so far: {})\n\n", tenure_cause, &next_consensus_hash, blocks_so_far.len(), blocks_since_last_tenure, i);
                                }
                                NakamotoBootStep::Block(transactions) => {
                                    assert!(!transactions.is_empty());
                                    debug!("\n\nMake block {} with {} transactions in empty tenure {}\n\n", blocks_so_far.len(), transactions.len(), &next_consensus_hash);
                                    txs.extend_from_slice(&transactions[..]);
                                    num_expected_transactions += transactions.len();
                                }
                            }

                            blocks_since_last_tenure += 1;
                            txs
                        });

                    peer.refresh_burnchain_view();

                    let blocks: Vec<NakamotoBlock> = blocks_and_sizes
                        .into_iter()
                        .map(|(block, _, _)| block)
                        .collect();

                    let malleablized_blocks =
                        std::mem::replace(&mut peer.chain.malleablized_blocks, vec![]);
                    for mblk in malleablized_blocks.iter() {
                        malleablized_block_ids.insert(mblk.block_id());
                    }

                    Self::check_blocks_against_boot_plan(
                        &blocks,
                        &boot_steps,
                        num_expected_transactions,
                    );

                    Self::apply_blocks_to_other_peers(
                        &burn_ops,
                        &blocks,
                        &malleablized_blocks,
                        &mut other_peers,
                    );
                    all_blocks.push(blocks);
                }
                NakamotoBootTenure::Sortition(boot_steps) => {
                    assert!(!boot_steps.is_empty());
                    let (burn_ops, mut tenure_change, miner_key) =
                        peer.begin_nakamoto_tenure(TenureChangeCause::BlockFound);
                    let (burn_ht, _, consensus_hash) = peer.next_burnchain_block(burn_ops.clone());
                    let vrf_proof = peer.make_nakamoto_vrf_proof(miner_key);

                    tenure_change.tenure_consensus_hash = consensus_hash.clone();
                    tenure_change.burn_view_consensus_hash = consensus_hash.clone();

                    last_tenure_change = Some(tenure_change.clone());

                    let tenure_change_tx = peer
                        .chain
                        .miner
                        .make_nakamoto_tenure_change(tenure_change.clone());

                    let coinbase_tx = peer.chain.miner.make_nakamoto_coinbase(None, vrf_proof);

                    debug!("\n\nNew tenure: {}\n\n", &consensus_hash);

                    let mut i = 0;
                    let mut num_expected_transactions = 2; // tenure-change and coinbase
                    blocks_since_last_tenure = 0;

                    let first_burn_ht = peer.sortdb().first_block_height;

                    let blocks_and_sizes = peer.make_nakamoto_tenure(
                        tenure_change_tx,
                        coinbase_tx,
                        &mut test_signers.clone(),
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
                                    assert!(!transactions.is_empty());
                                    if let Some(last_block) = last_block_opt {
                                        let tenure_extension = tenure_change.extend(
                                            consensus_hash.clone(),
                                            last_block.clone(),
                                            blocks_since_last_tenure // blocks_so_far.len() as u32,
                                        );
                                        let tenure_extension_tx =
                                            miner.make_nakamoto_tenure_change(tenure_extension);

                                        txs.push(tenure_extension_tx);
                                        txs.extend_from_slice(&transactions[..]);
                                        num_expected_transactions += 1 + transactions.len();
                                    }
                                    debug!("\n\nExtend current tenure {} (blocks so far: {}, steps so far: {})\n\n", &consensus_hash, blocks_so_far.len(), i);
                                }
                                NakamotoBootStep::TenureCause(transactions, tenure_cause) => {
                                    assert!(!transactions.is_empty());
                                    if let Some(last_block) = last_block_opt {
                                        let tenure_extension = tenure_change.extend_with_cause(
                                            consensus_hash.clone(),
                                            last_block.clone(),
                                            blocks_since_last_tenure,
                                            *tenure_cause,
                                        );
                                        let tenure_extension_tx =
                                            miner.make_nakamoto_tenure_change(tenure_extension);

                                        txs.push(tenure_extension_tx);
                                        txs.extend_from_slice(&transactions[..]);
                                        num_expected_transactions += 1 + transactions.len();
                                    }
                                    debug!("\n\nExtend-with-cause {:?} current tenure {} (blocks so far: {}, steps so far: {})\n\n", tenure_cause, &consensus_hash, blocks_so_far.len(), i);
                                }
                                NakamotoBootStep::Block(transactions) => {
                                    assert!(!transactions.is_empty());
                                    debug!("\n\nMake block {} with {} transactions in tenure {}\n\n", blocks_so_far.len(), transactions.len(), &consensus_hash);
                                    txs.extend_from_slice(&transactions[..]);
                                    num_expected_transactions += transactions.len();
                                }
                            }

                            blocks_since_last_tenure += 1;
                            txs
                        });
                    peer.refresh_burnchain_view();

                    let blocks: Vec<NakamotoBlock> = blocks_and_sizes
                        .into_iter()
                        .map(|(block, _, _)| block)
                        .collect();

                    let malleablized_blocks =
                        std::mem::replace(&mut peer.chain.malleablized_blocks, vec![]);
                    for mblk in malleablized_blocks.iter() {
                        malleablized_block_ids.insert(mblk.block_id());
                    }

                    Self::check_blocks_against_boot_plan(
                        &blocks,
                        &boot_steps,
                        num_expected_transactions,
                    );
                    Self::apply_blocks_to_other_peers(
                        &burn_ops,
                        &blocks,
                        &malleablized_blocks,
                        &mut other_peers,
                    );

                    all_blocks.push(blocks);
                }
            }
        }

        // check that our tenure-extends have been getting applied
        let (highest_tenure, sort_tip) = {
            let chainstate = &mut peer.chain.stacks_node.as_mut().unwrap().chainstate;
            let sort_db = peer.chain.sortdb.as_mut().unwrap();
            let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
            let tenure = NakamotoChainState::get_ongoing_tenure(
                &mut chainstate.index_conn(),
                &sort_db
                    .index_handle_at_tip()
                    .get_nakamoto_tip_block_id()
                    .unwrap()
                    .unwrap(),
            )
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
            let mut observed_blocks = observer.get_blocks();
            let mut block_idx = (peer
                .config
                .chain_config
                .burnchain
                .pox_constants
                .pox_4_activation_height
                + peer
                    .config
                    .chain_config
                    .burnchain
                    .pox_constants
                    .reward_cycle_length
                - 25) as usize;

            // filter out observed blocks that are malleablized
            observed_blocks.retain(|blk| {
                if let Some(nakamoto_block_header) =
                    blk.metadata.anchored_header.as_stacks_nakamoto()
                {
                    !malleablized_block_ids.contains(&nakamoto_block_header.block_id())
                } else {
                    true
                }
            });

            for tenure in all_blocks.iter() {
                for block in tenure.iter() {
                    let observed_block = &observed_blocks[block_idx];
                    block_idx += 1;

                    assert_eq!(
                        observed_block.metadata.anchored_header.block_hash(),
                        block.header.block_hash()
                    );

                    // each transaction was mined in the same order as described in the boot plan,
                    // and it succeeded.
                    let mut stacks_receipts = vec![];
                    for receipt in observed_block.receipts.iter() {
                        match &receipt.transaction {
                            TransactionOrigin::Stacks(..) => {
                                stacks_receipts.push(receipt);
                            }
                            TransactionOrigin::Burn(..) => {}
                        }
                    }

                    assert_eq!(stacks_receipts.len(), block.txs.len());
                    for (receipt, tx) in stacks_receipts.iter().zip(block.txs.iter()) {
                        // transactions processed in the same order
                        assert_eq!(receipt.transaction.txid(), tx.txid());
                        // no CheckErrors
                        if !ignore_transaction_errors {
                            assert!(
                                receipt.vm_error.is_none(),
                                "Receipt had a CheckErrors: {:?}",
                                &receipt
                            );
                            // transaction was not aborted post-hoc
                            assert!(!receipt.post_condition_aborted);
                        }
                    }
                }
            }
        }

        // verify that all other peers kept pace with this peer
        for other_peer in other_peers.iter_mut() {
            let (other_highest_tenure, other_sort_tip) = {
                let chainstate = &mut other_peer.chain.stacks_node.as_mut().unwrap().chainstate;
                let sort_db = other_peer.chain.sortdb.as_mut().unwrap();
                let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
                let tenure = NakamotoChainState::get_ongoing_tenure(
                    &mut chainstate.index_conn(),
                    &sort_db
                        .index_handle_at_tip()
                        .get_nakamoto_tip_block_id()
                        .unwrap()
                        .unwrap(),
                )
                .unwrap()
                .unwrap();
                (tenure, tip)
            };

            assert_eq!(other_highest_tenure, highest_tenure);
            assert_eq!(other_sort_tip, sort_tip);
        }

        // flatten
        let all_blocks: Vec<NakamotoBlock> = all_blocks.into_iter().flatten().collect();

        peer.check_nakamoto_migration();
        peer.check_malleablized_blocks(all_blocks.clone(), 2);
        for other_peer in other_peers.iter_mut() {
            other_peer.check_nakamoto_migration();
            other_peer.check_malleablized_blocks(all_blocks.clone(), 2);
        }
        (peer, other_peers)
    }

    pub fn boot_into_nakamoto_peer(
        self,
        boot_plan: Vec<NakamotoBootTenure>,
        observer: Option<&TestEventObserver>,
    ) -> TestPeer<'_> {
        self.boot_into_nakamoto_peers(boot_plan, observer).0
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
        NakamotoBootTenure::Sortition(vec![
            NakamotoBootStep::Block(vec![next_stx_transfer()]),
            NakamotoBootStep::Block(vec![next_stx_transfer()]),
        ]),
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

    // make malleablized blocks
    let (test_signers, test_stackers) = TestStacker::multi_signing_set(&[
        0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3,
    ]);

    let plan = NakamotoBootPlan::new(function_name!())
        .with_private_key(private_key)
        .with_pox_constants(10, 3)
        .with_initial_balances(vec![(addr.into(), 1_000_000)])
        .with_extra_peers(2)
        .with_test_signers(test_signers)
        .with_test_stackers(test_stackers);

    let observer = TestEventObserver::new();
    let (peer, other_peers) = plan.boot_into_nakamoto_peers(boot_tenures, Some(&observer));
}

#[test]
fn test_network_result_update() {
    let mut network_result_1 = NetworkResult::new(
        StacksBlockId([0x11; 32]),
        1,
        1,
        1,
        1,
        1,
        1,
        1,
        ConsensusHash([0x11; 20]),
        HashMap::new(),
    );

    let mut network_result_2 = NetworkResult::new(
        StacksBlockId([0x22; 32]),
        2,
        2,
        2,
        2,
        2,
        2,
        2,
        ConsensusHash([0x22; 20]),
        HashMap::new(),
    );

    let nk1 = NeighborKey {
        peer_version: 1,
        network_id: 1,
        addrbytes: PeerAddress([0x11; 16]),
        port: 1,
    };

    let nk2 = NeighborKey {
        peer_version: 2,
        network_id: 2,
        addrbytes: PeerAddress([0x22; 16]),
        port: 2,
    };

    let msg1 = StacksMessage::new(
        1,
        1,
        1,
        &BurnchainHeaderHash([0x11; 32]),
        1,
        &BurnchainHeaderHash([0x11; 32]),
        StacksMessageType::Ping(PingData { nonce: 1 }),
    );

    let mut msg2 = StacksMessage::new(
        2,
        2,
        2,
        &BurnchainHeaderHash([0x22; 32]),
        2,
        &BurnchainHeaderHash([0x22; 32]),
        StacksMessageType::Ping(PingData { nonce: 2 }),
    );
    msg2.sign(2, &StacksPrivateKey::random()).unwrap();

    let pkey_1 = StacksPrivateKey::random();
    let pkey_2 = StacksPrivateKey::random();

    let pushed_pkey_1 = StacksPrivateKey::random();
    let pushed_pkey_2 = StacksPrivateKey::random();

    let uploaded_pkey_1 = StacksPrivateKey::random();
    let uploaded_pkey_2 = StacksPrivateKey::random();

    let blk1 = make_empty_coinbase_block(&pkey_1);
    let blk2 = make_empty_coinbase_block(&pkey_2);

    let pushed_blk1 = make_empty_coinbase_block(&pushed_pkey_1);
    let pushed_blk2 = make_empty_coinbase_block(&pushed_pkey_2);

    let uploaded_blk1 = make_empty_coinbase_block(&uploaded_pkey_1);
    let uploaded_blk2 = make_empty_coinbase_block(&uploaded_pkey_2);

    let mblk1 = make_codec_test_microblock(1);
    let mblk2 = make_codec_test_microblock(2);

    let pushed_mblk1 = make_codec_test_microblock(3);
    let pushed_mblk2 = make_codec_test_microblock(4);

    let uploaded_mblk1 = make_codec_test_microblock(5);
    let uploaded_mblk2 = make_codec_test_microblock(6);

    let pushed_tx1 = make_codec_test_microblock(3).txs[2].clone();
    let pushed_tx2 = make_codec_test_microblock(4).txs[3].clone();

    let uploaded_tx1 = make_codec_test_microblock(5).txs[4].clone();
    let uploaded_tx2 = make_codec_test_microblock(6).txs[5].clone();

    let synced_tx1 = make_codec_test_microblock(7).txs[6].clone();
    let synced_tx2 = make_codec_test_microblock(8).txs[7].clone();

    let naka_header_1 = NakamotoBlockHeader {
        version: 1,
        chain_length: 1,
        burn_spent: 1,
        consensus_hash: ConsensusHash([0x01; 20]),
        parent_block_id: StacksBlockId([0x01; 32]),
        tx_merkle_root: Sha512Trunc256Sum([0x01; 32]),
        state_index_root: TrieHash([0x01; 32]),
        timestamp: 1,
        miner_signature: MessageSignature::empty(),
        signer_signature: vec![],
        pox_treatment: BitVec::zeros(1).unwrap(),
    };

    let naka_header_2 = NakamotoBlockHeader {
        version: 2,
        chain_length: 2,
        burn_spent: 2,
        consensus_hash: ConsensusHash([0x02; 20]),
        parent_block_id: StacksBlockId([0x02; 32]),
        tx_merkle_root: Sha512Trunc256Sum([0x02; 32]),
        state_index_root: TrieHash([0x02; 32]),
        timestamp: 2,
        miner_signature: MessageSignature::empty(),
        signer_signature: vec![],
        pox_treatment: BitVec::zeros(1).unwrap(),
    };

    let naka_pushed_header_1 = NakamotoBlockHeader {
        version: 3,
        chain_length: 3,
        burn_spent: 3,
        consensus_hash: ConsensusHash([0x03; 20]),
        parent_block_id: StacksBlockId([0x03; 32]),
        tx_merkle_root: Sha512Trunc256Sum([0x03; 32]),
        state_index_root: TrieHash([0x03; 32]),
        timestamp: 3,
        miner_signature: MessageSignature::empty(),
        signer_signature: vec![],
        pox_treatment: BitVec::zeros(1).unwrap(),
    };

    let naka_pushed_header_2 = NakamotoBlockHeader {
        version: 4,
        chain_length: 4,
        burn_spent: 4,
        consensus_hash: ConsensusHash([0x04; 20]),
        parent_block_id: StacksBlockId([0x04; 32]),
        tx_merkle_root: Sha512Trunc256Sum([0x04; 32]),
        state_index_root: TrieHash([0x04; 32]),
        timestamp: 4,
        miner_signature: MessageSignature::empty(),
        signer_signature: vec![],
        pox_treatment: BitVec::zeros(1).unwrap(),
    };

    let naka_uploaded_header_1 = NakamotoBlockHeader {
        version: 5,
        chain_length: 5,
        burn_spent: 5,
        consensus_hash: ConsensusHash([0x05; 20]),
        parent_block_id: StacksBlockId([0x05; 32]),
        tx_merkle_root: Sha512Trunc256Sum([0x05; 32]),
        state_index_root: TrieHash([0x05; 32]),
        timestamp: 5,
        miner_signature: MessageSignature::empty(),
        signer_signature: vec![],
        pox_treatment: BitVec::zeros(1).unwrap(),
    };

    let naka_uploaded_header_2 = NakamotoBlockHeader {
        version: 6,
        chain_length: 6,
        burn_spent: 6,
        consensus_hash: ConsensusHash([0x06; 20]),
        parent_block_id: StacksBlockId([0x06; 32]),
        tx_merkle_root: Sha512Trunc256Sum([0x06; 32]),
        state_index_root: TrieHash([0x06; 32]),
        timestamp: 6,
        miner_signature: MessageSignature::empty(),
        signer_signature: vec![],
        pox_treatment: BitVec::zeros(1).unwrap(),
    };

    let nblk1 = NakamotoBlock {
        header: naka_header_1,
        txs: vec![],
    };
    let nblk2 = NakamotoBlock {
        header: naka_header_2,
        txs: vec![],
    };

    let pushed_nblk1 = NakamotoBlock {
        header: naka_pushed_header_1,
        txs: vec![],
    };
    let pushed_nblk2 = NakamotoBlock {
        header: naka_pushed_header_2,
        txs: vec![],
    };

    let uploaded_nblk1 = NakamotoBlock {
        header: naka_uploaded_header_1,
        txs: vec![],
    };
    let uploaded_nblk2 = NakamotoBlock {
        header: naka_uploaded_header_2,
        txs: vec![],
    };

    let pushed_stackerdb_chunk_1 = StackerDBPushChunkData {
        contract_id: QualifiedContractIdentifier::transient(),
        rc_consensus_hash: ConsensusHash([0x11; 20]),
        chunk_data: StackerDBChunkData {
            slot_id: 1,
            slot_version: 1,
            sig: MessageSignature::empty(),
            data: vec![1],
        },
    };

    let pushed_stackerdb_chunk_2 = StackerDBPushChunkData {
        contract_id: QualifiedContractIdentifier::transient(),
        rc_consensus_hash: ConsensusHash([0x22; 20]),
        chunk_data: StackerDBChunkData {
            slot_id: 2,
            slot_version: 2,
            sig: MessageSignature::empty(),
            data: vec![2],
        },
    };

    let uploaded_stackerdb_chunk_1 = StackerDBPushChunkData {
        contract_id: QualifiedContractIdentifier::transient(),
        rc_consensus_hash: ConsensusHash([0x33; 20]),
        chunk_data: StackerDBChunkData {
            slot_id: 3,
            slot_version: 3,
            sig: MessageSignature::empty(),
            data: vec![3],
        },
    };

    let uploaded_stackerdb_chunk_2 = StackerDBPushChunkData {
        contract_id: QualifiedContractIdentifier::transient(),
        rc_consensus_hash: ConsensusHash([0x44; 20]),
        chunk_data: StackerDBChunkData {
            slot_id: 4,
            slot_version: 4,
            sig: MessageSignature::empty(),
            data: vec![4],
        },
    };

    network_result_1
        .unhandled_messages
        .insert(nk1.clone(), vec![msg1]);
    network_result_1
        .blocks
        .push((ConsensusHash([0x11; 20]), blk1, 1));
    network_result_1
        .confirmed_microblocks
        .push((ConsensusHash([0x11; 20]), vec![mblk1], 1));
    network_result_1
        .nakamoto_blocks
        .insert(nblk1.block_id(), nblk1.clone());
    network_result_1
        .pushed_transactions
        .insert(nk1.clone(), vec![(vec![], pushed_tx1)]);
    network_result_1.pushed_blocks.insert(
        nk1.clone(),
        vec![BlocksData {
            blocks: vec![BlocksDatum(ConsensusHash([0x11; 20]), pushed_blk1)],
        }],
    );
    network_result_1.pushed_microblocks.insert(
        nk1.clone(),
        vec![(
            vec![],
            MicroblocksData {
                index_anchor_block: StacksBlockId([0x11; 32]),
                microblocks: vec![pushed_mblk1],
            },
        )],
    );
    network_result_1.pushed_nakamoto_blocks.insert(
        nk1.clone(),
        vec![(
            vec![],
            NakamotoBlocksData {
                blocks: vec![pushed_nblk1],
            },
        )],
    );
    network_result_1.uploaded_transactions.push(uploaded_tx1);
    network_result_1.uploaded_blocks.push(BlocksData {
        blocks: vec![BlocksDatum(ConsensusHash([0x11; 20]), uploaded_blk1)],
    });
    network_result_1.uploaded_microblocks.push(MicroblocksData {
        index_anchor_block: StacksBlockId([0x11; 32]),
        microblocks: vec![uploaded_mblk1],
    });
    network_result_1
        .uploaded_nakamoto_blocks
        .push(uploaded_nblk1);
    network_result_1
        .pushed_stackerdb_chunks
        .push(pushed_stackerdb_chunk_1);
    network_result_1
        .uploaded_stackerdb_chunks
        .push(uploaded_stackerdb_chunk_1);
    network_result_1.synced_transactions.push(synced_tx1);

    network_result_2
        .unhandled_messages
        .insert(nk2.clone(), vec![msg2.clone()]);
    network_result_2
        .blocks
        .push((ConsensusHash([0x22; 20]), blk2, 2));
    network_result_2
        .confirmed_microblocks
        .push((ConsensusHash([0x22; 20]), vec![mblk2], 2));
    network_result_2
        .nakamoto_blocks
        .insert(nblk2.block_id(), nblk2);
    network_result_2
        .pushed_transactions
        .insert(nk2.clone(), vec![(vec![], pushed_tx2)]);
    network_result_2.pushed_blocks.insert(
        nk2.clone(),
        vec![BlocksData {
            blocks: vec![BlocksDatum(ConsensusHash([0x22; 20]), pushed_blk2)],
        }],
    );
    network_result_2.pushed_microblocks.insert(
        nk2.clone(),
        vec![(
            vec![],
            MicroblocksData {
                index_anchor_block: StacksBlockId([0x22; 32]),
                microblocks: vec![pushed_mblk2],
            },
        )],
    );
    network_result_2.pushed_nakamoto_blocks.insert(
        nk2.clone(),
        vec![(
            vec![],
            NakamotoBlocksData {
                blocks: vec![pushed_nblk2],
            },
        )],
    );
    network_result_2.uploaded_transactions.push(uploaded_tx2);
    network_result_2.uploaded_blocks.push(BlocksData {
        blocks: vec![BlocksDatum(ConsensusHash([0x22; 20]), uploaded_blk2)],
    });
    network_result_2.uploaded_microblocks.push(MicroblocksData {
        index_anchor_block: StacksBlockId([0x22; 32]),
        microblocks: vec![uploaded_mblk2],
    });
    network_result_2
        .uploaded_nakamoto_blocks
        .push(uploaded_nblk2);
    network_result_2
        .pushed_stackerdb_chunks
        .push(pushed_stackerdb_chunk_2);
    network_result_2
        .uploaded_stackerdb_chunks
        .push(uploaded_stackerdb_chunk_2);
    network_result_2.synced_transactions.push(synced_tx2);

    let mut network_result_union = network_result_2.clone();
    let mut n1 = network_result_1.clone();
    network_result_union
        .unhandled_messages
        .extend(n1.unhandled_messages);
    network_result_union.blocks.append(&mut n1.blocks);
    network_result_union
        .confirmed_microblocks
        .append(&mut n1.confirmed_microblocks);
    network_result_union
        .nakamoto_blocks
        .extend(n1.nakamoto_blocks);
    network_result_union
        .pushed_transactions
        .extend(n1.pushed_transactions);
    network_result_union.pushed_blocks.extend(n1.pushed_blocks);
    network_result_union
        .pushed_microblocks
        .extend(n1.pushed_microblocks);
    network_result_union
        .pushed_nakamoto_blocks
        .extend(n1.pushed_nakamoto_blocks);
    network_result_union
        .uploaded_transactions
        .append(&mut n1.uploaded_transactions);
    network_result_union
        .uploaded_blocks
        .append(&mut n1.uploaded_blocks);
    network_result_union
        .uploaded_microblocks
        .append(&mut n1.uploaded_microblocks);
    network_result_union
        .uploaded_nakamoto_blocks
        .append(&mut n1.uploaded_nakamoto_blocks);
    // stackerdb chunks from n1 get dropped since their rc_consensus_hash no longer matches
    network_result_union
        .synced_transactions
        .append(&mut n1.synced_transactions);

    // update is idempotent
    let old = network_result_1.clone();
    let new = network_result_1.clone();
    assert_eq!(old.update(new), network_result_1);

    // disjoint results get unioned, except for stackerdb chunks
    let old = network_result_1.clone();
    let new = network_result_2.clone();
    assert_eq!(old.update(new), network_result_union);

    // merging a subset is idempotent
    assert_eq!(
        network_result_1
            .clone()
            .update(network_result_union.clone()),
        network_result_union
    );
    assert_eq!(
        network_result_2
            .clone()
            .update(network_result_union.clone()),
        network_result_union
    );

    // stackerdb uploaded chunks get consolidated correctly
    let mut old = NetworkResult::new(
        StacksBlockId([0xaa; 32]),
        10,
        10,
        10,
        10,
        10,
        10,
        10,
        ConsensusHash([0xaa; 20]),
        HashMap::new(),
    );
    let mut new = old.clone();

    let old_chunk_1 = StackerDBPushChunkData {
        contract_id: QualifiedContractIdentifier::transient(),
        rc_consensus_hash: ConsensusHash([0xaa; 20]),
        chunk_data: StackerDBChunkData {
            slot_id: 1,
            slot_version: 1,
            sig: MessageSignature::empty(),
            data: vec![3],
        },
    };

    let new_chunk_1 = StackerDBPushChunkData {
        contract_id: QualifiedContractIdentifier::transient(),
        rc_consensus_hash: ConsensusHash([0xaa; 20]),
        chunk_data: StackerDBChunkData {
            slot_id: 1,
            slot_version: 2,
            sig: MessageSignature::empty(),
            data: vec![3],
        },
    };

    let new_chunk_2 = StackerDBPushChunkData {
        contract_id: QualifiedContractIdentifier::transient(),
        rc_consensus_hash: ConsensusHash([0xaa; 20]),
        chunk_data: StackerDBChunkData {
            slot_id: 2,
            slot_version: 2,
            sig: MessageSignature::empty(),
            data: vec![3],
        },
    };

    old.uploaded_stackerdb_chunks.push(old_chunk_1);
    // replaced
    new.uploaded_stackerdb_chunks.push(new_chunk_1.clone());
    // included
    new.uploaded_stackerdb_chunks.push(new_chunk_2.clone());

    assert_eq!(
        old.update(new).uploaded_stackerdb_chunks,
        vec![new_chunk_1, new_chunk_2]
    );

    // stackerdb pushed chunks get consolidated correctly
    let mut old = NetworkResult::new(
        StacksBlockId([0xaa; 32]),
        10,
        10,
        10,
        10,
        10,
        10,
        10,
        ConsensusHash([0xaa; 20]),
        HashMap::new(),
    );
    let mut new = old.clone();

    let old_chunk_1 = StackerDBPushChunkData {
        contract_id: QualifiedContractIdentifier::transient(),
        rc_consensus_hash: ConsensusHash([0xaa; 20]),
        chunk_data: StackerDBChunkData {
            slot_id: 1,
            slot_version: 1,
            sig: MessageSignature::empty(),
            data: vec![3],
        },
    };

    let new_chunk_1 = StackerDBPushChunkData {
        contract_id: QualifiedContractIdentifier::transient(),
        rc_consensus_hash: ConsensusHash([0xaa; 20]),
        chunk_data: StackerDBChunkData {
            slot_id: 1,
            slot_version: 2,
            sig: MessageSignature::empty(),
            data: vec![3],
        },
    };

    let new_chunk_2 = StackerDBPushChunkData {
        contract_id: QualifiedContractIdentifier::transient(),
        rc_consensus_hash: ConsensusHash([0xaa; 20]),
        chunk_data: StackerDBChunkData {
            slot_id: 2,
            slot_version: 2,
            sig: MessageSignature::empty(),
            data: vec![3],
        },
    };

    old.pushed_stackerdb_chunks.push(old_chunk_1);
    // replaced
    new.pushed_stackerdb_chunks.push(new_chunk_1.clone());
    // included
    new.pushed_stackerdb_chunks.push(new_chunk_2.clone());

    assert_eq!(
        old.update(new).pushed_stackerdb_chunks,
        vec![new_chunk_1, new_chunk_2]
    );

    // nakamoto blocks obtained via download, upload, or pushed get consoldated
    let mut old = NetworkResult::new(
        StacksBlockId([0xbb; 32]),
        11,
        11,
        11,
        11,
        11,
        11,
        11,
        ConsensusHash([0xbb; 20]),
        HashMap::new(),
    );
    old.nakamoto_blocks.insert(nblk1.block_id(), nblk1.clone());
    old.pushed_nakamoto_blocks.insert(
        nk1,
        vec![(
            vec![],
            NakamotoBlocksData {
                blocks: vec![nblk1.clone()],
            },
        )],
    );
    old.uploaded_nakamoto_blocks.push(nblk1.clone());

    let new = NetworkResult::new(
        StacksBlockId([0xbb; 32]),
        11,
        11,
        11,
        11,
        11,
        11,
        11,
        ConsensusHash([0xbb; 20]),
        HashMap::new(),
    );

    let mut new_pushed = new.clone();
    let mut new_uploaded = new.clone();
    let mut new_downloaded = new;

    new_downloaded
        .nakamoto_blocks
        .insert(nblk1.block_id(), nblk1.clone());
    new_pushed.pushed_nakamoto_blocks.insert(
        nk2.clone(),
        vec![(
            vec![],
            NakamotoBlocksData {
                blocks: vec![nblk1.clone()],
            },
        )],
    );
    new_uploaded.uploaded_nakamoto_blocks.push(nblk1.clone());

    debug!("====");
    let updated_downloaded = old.clone().update(new_downloaded);
    assert_eq!(updated_downloaded.nakamoto_blocks.len(), 1);
    assert_eq!(
        updated_downloaded
            .nakamoto_blocks
            .get(&nblk1.block_id())
            .unwrap(),
        &nblk1
    );
    assert!(updated_downloaded.pushed_nakamoto_blocks.is_empty());
    assert!(updated_downloaded.uploaded_nakamoto_blocks.is_empty());

    debug!("====");
    let updated_pushed = old.clone().update(new_pushed);
    assert!(updated_pushed.nakamoto_blocks.is_empty());
    assert_eq!(updated_pushed.pushed_nakamoto_blocks.len(), 1);
    assert_eq!(
        updated_pushed
            .pushed_nakamoto_blocks
            .get(&nk2)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        updated_pushed.pushed_nakamoto_blocks.get(&nk2).unwrap()[0]
            .1
            .blocks
            .len(),
        1
    );
    assert_eq!(
        updated_pushed.pushed_nakamoto_blocks.get(&nk2).unwrap()[0]
            .1
            .blocks[0],
        nblk1
    );
    assert!(updated_pushed.uploaded_nakamoto_blocks.is_empty());

    debug!("====");
    let updated_uploaded = old.clone().update(new_uploaded);
    assert!(updated_uploaded.nakamoto_blocks.is_empty());
    assert!(updated_uploaded.pushed_nakamoto_blocks.is_empty());
    assert_eq!(updated_uploaded.uploaded_nakamoto_blocks.len(), 1);
    assert_eq!(updated_uploaded.uploaded_nakamoto_blocks[0], nblk1);
}

#[rstest]
#[case(None, None, false)]
#[case(None, Some(10), true)]
#[case(Some(10), None, false)]
#[case(Some(10), Some(20), true)]
#[case(Some(20), Some(10), false)]
fn test_update_highest_stacks_height_of_neighbors(
    #[case] old_height: Option<u64>,
    #[case] new_height: Option<u64>,
    #[case] is_update_accepted: bool,
) {
    let peer_config = TestPeerConfig::new(function_name!(), 0, 0);
    let mut peer = TestPeer::new(peer_config);

    let prev_highest_neighbor =
        old_height.map(|h| (SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080), h));
    peer.network.highest_stacks_neighbor = prev_highest_neighbor;

    let peer_sortdb = peer.chain.sortdb.take().unwrap();
    let mut peer_stacks_node = peer.chain.stacks_node.take().unwrap();
    let mut peer_mempool = peer.mempool.take().unwrap();
    let rpc_args = RPCHandlerArgsType::make_default();
    let mut node_state = StacksNodeState::new(
        &mut peer.network,
        &peer_sortdb,
        &mut peer_stacks_node.chainstate,
        &mut peer_mempool,
        &rpc_args,
        false,
        false,
    );

    let new_peer_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8081);
    node_state.update_highest_stacks_neighbor(&new_peer_addr, new_height);

    let expected_highest_peer = if is_update_accepted {
        Some((new_peer_addr, new_height.unwrap()))
    } else {
        prev_highest_neighbor
    };

    assert_eq!(peer.network.highest_stacks_neighbor, expected_highest_peer);
}
