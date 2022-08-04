use std::cmp;
use std::collections::HashMap;
use std::collections::{HashSet, VecDeque};
use std::convert::{TryFrom, TryInto};
use std::default::Default;
use std::net::SocketAddr;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{atomic::Ordering, Arc, Mutex};
use std::time::Duration;
use std::{thread, thread::JoinHandle};

use stacks::burnchains::BurnchainSigner;
use stacks::burnchains::{Burnchain, BurnchainParameters, Txid};
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::burn::operations::{
    leader_block_commit::{RewardSetInfo, BURN_BLOCK_MINED_AT_MODULUS},
    BlockstackOperationType, LeaderBlockCommitOp, LeaderKeyRegisterOp,
};
use stacks::chainstate::burn::BlockSnapshot;
use stacks::chainstate::burn::ConsensusHash;
use stacks::chainstate::coordinator::comm::CoordinatorChannels;
use stacks::chainstate::coordinator::{get_next_recipients, OnChainRewardSetProvider};
use stacks::chainstate::stacks::db::unconfirmed::UnconfirmedTxMap;
use stacks::chainstate::stacks::db::StacksHeaderInfo;
use stacks::chainstate::stacks::db::{StacksChainState, MINER_REWARD_MATURITY};
use stacks::chainstate::stacks::Error as ChainstateError;
use stacks::chainstate::stacks::StacksPublicKey;
use stacks::chainstate::stacks::{
    miner::BlockBuilderSettings, miner::StacksMicroblockBuilder, StacksBlockBuilder,
    StacksBlockHeader,
};
use stacks::chainstate::stacks::{
    CoinbasePayload, StacksBlock, StacksMicroblock, StacksTransaction, StacksTransactionSigner,
    TransactionAnchorMode, TransactionPayload, TransactionVersion,
};
use stacks::codec::StacksMessageCodec;
use stacks::core::mempool::MemPoolDB;
use stacks::core::FIRST_BURNCHAIN_CONSENSUS_HASH;
use stacks::core::STACKS_EPOCH_2_05_MARKER;
use stacks::cost_estimates::metrics::UnitMetric;
use stacks::cost_estimates::UnitEstimator;
use stacks::monitoring::{increment_stx_blocks_mined_counter, update_active_miners_count_gauge};
use stacks::net::{
    atlas::{AtlasConfig, AtlasDB, AttachmentInstance},
    db::{LocalPeer, PeerDB},
    dns::DNSResolver,
    p2p::PeerNetwork,
    relay::Relayer,
    rpc::RPCHandlerArgs,
    Error as NetError, NetworkResult, PeerAddress, ServiceFlags,
};
use stacks::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, SortitionId, StacksAddress, VRFSeed,
};
use stacks::util::get_epoch_time_ms;
use stacks::util::get_epoch_time_secs;
use stacks::util::hash::{to_hex, Hash160, Sha256Sum};
use stacks::util::secp256k1::Secp256k1PrivateKey;
use stacks::util::vrf::VRFPublicKey;
use stacks::util_lib::strings::{UrlString, VecDisplay};
use stacks::vm::costs::ExecutionCost;

use crate::burnchains::bitcoin_regtest_controller::BitcoinRegtestController;
use crate::burnchains::bitcoin_regtest_controller::SerializedTx;
use crate::run_loop::neon::Counters;
use crate::run_loop::neon::RunLoop;
use crate::run_loop::RegisteredKey;
use crate::ChainTip;

use super::{BurnchainController, BurnchainTip, Config, EventDispatcher, Keychain};
use crate::stacks::vm::database::BurnStateDB;
use stacks::monitoring;

use clarity::vm::types::PrincipalData;

use crate::operations::BurnchainOpSigner;

use stacks_common::types::StacksEpochId;

pub const RELAYER_MAX_BUFFER: usize = 100;

lazy_static! {
    static ref DELAYED_TXS: Mutex<HashMap<u64, Vec<SerializedTx>>> = Mutex::new(HashMap::new());
}

#[cfg(test)]
fn store_delayed_tx(tx: SerializedTx, send_height: u64) {
    match DELAYED_TXS.lock() {
        Ok(ref mut tx_map) => {
            if let Some(tx_list) = tx_map.get_mut(&send_height) {
                tx_list.push(tx);
            } else {
                tx_map.insert(send_height, vec![tx]);
            }
        }
        Err(_) => {
            panic!("Poisoned DELAYED_TXS mutex");
        }
    }
}

#[cfg(not(test))]
fn store_delayed_tx(_tx: SerializedTx, _send_height: u64) {}

#[cfg(test)]
fn get_delayed_txs(height: u64) -> Vec<SerializedTx> {
    match DELAYED_TXS.lock() {
        Ok(tx_map) => tx_map.get(&height).cloned().unwrap_or(vec![]),
        Err(_) => {
            panic!("Poisoned DELAYED_TXS mutex");
        }
    }
}

#[cfg(not(test))]
fn get_delayed_txs(_height: u64) -> Vec<SerializedTx> {
    vec![]
}

/// Inject a fault into the system: delay sending a transaction by one block, and send all
/// transactions that were previosuly delayed to the given burnchain block.  Return `true` if the
/// burnchain transaction should be sent; `false` if not.
#[cfg(test)]
fn fault_injection_delay_transactions(
    bitcoin_controller: &mut BitcoinRegtestController,
    cur_burn_chain_height: u64,
    stacks_block_burn_height: u64,
    op: &BlockstackOperationType,
    op_signer: &mut BurnchainOpSigner,
    attempt: u64,
) -> bool {
    // fault injection for testing: force the use of a bad burn modulus
    let mut do_fault = false;
    let mut send_tx = true;
    if let Ok(bad_height_str) = std::env::var("STX_TEST_LATE_BLOCK_COMMIT") {
        if let Ok(bad_height) = bad_height_str.parse::<u64>() {
            if bad_height == cur_burn_chain_height {
                do_fault = true;
            }
        }
    }
    if do_fault {
        test_debug!(
            "Fault injection: don't send the block-commit right away; hold onto it for one block"
        );
        bitcoin_controller.set_allow_rbf(false);
        let tx = bitcoin_controller
            .make_operation_tx(op.clone(), op_signer, attempt)
            .unwrap();
        store_delayed_tx(tx, stacks_block_burn_height + 1);

        // don't actually send it yet
        send_tx = false;
    }

    // send all delayed txs for this block height
    let delayed_txs = get_delayed_txs(stacks_block_burn_height);
    for tx in delayed_txs.into_iter() {
        test_debug!("Fault injection: submit delayed tx {}", &to_hex(&tx.bytes));
        let res = bitcoin_controller.send_transaction(tx.clone());
        if !res {
            test_debug!(
                "Fault injection: failed to send delayed tx {}",
                &to_hex(&tx.bytes)
            );
        }
    }

    send_tx
}

#[cfg(not(test))]
fn fault_injection_delay_transactions(
    _bitcoin_controller: &mut BitcoinRegtestController,
    _cur_burn_chain_height: u64,
    _stacks_block_burn_height: u64,
    _op: &BlockstackOperationType,
    _op_signer: &mut BurnchainOpSigner,
    _attempt: u64,
) -> bool {
    true
}

fn get_coinbase_with_recipient(config: &Config, epoch_id: StacksEpochId) -> Option<PrincipalData> {
    if epoch_id < StacksEpochId::Epoch21 && config.miner.block_reward_recipient.is_some() {
        warn!("Coinbase pay-to-contract is not supported in the current epoch");
        None
    } else {
        config.miner.block_reward_recipient.clone()
    }
}

struct AssembledAnchorBlock {
    parent_consensus_hash: ConsensusHash,
    my_burn_hash: BurnchainHeaderHash,
    anchored_block: StacksBlock,
    attempt: u64,
}

struct MicroblockMinerState {
    parent_consensus_hash: ConsensusHash,
    parent_block_hash: BlockHeaderHash,
    miner_key: Secp256k1PrivateKey,
    frequency: u64,
    last_mined: u128,
    quantity: u64,
    cost_so_far: ExecutionCost,
    settings: BlockBuilderSettings,
}

enum RelayerDirective {
    HandleNetResult(NetworkResult),
    ProcessTenure(ConsensusHash, BurnchainHeaderHash, BlockHeaderHash),
    RunTenure(RegisteredKey, BlockSnapshot, u128), // (vrf key, chain tip, time of issuance in ms)
    RegisterKey(BlockSnapshot),
    RunMicroblockTenure(BlockSnapshot, u128), // time of issuance in ms
    Exit,
}

pub struct StacksNode {
    config: Config,
    relay_channel: SyncSender<RelayerDirective>,
    last_sortition: Arc<Mutex<Option<BlockSnapshot>>>,
    burnchain_signer: BurnchainSigner,
    is_miner: bool,
    pub atlas_config: AtlasConfig,
    leader_key_registration_state: LeaderKeyRegistrationState,
    pub p2p_thread_handle: JoinHandle<()>,
    pub relayer_thread_handle: JoinHandle<()>,
}

#[cfg(test)]
fn fault_injection_long_tenure() {
    // simulated slow block
    match std::env::var("STX_TEST_SLOW_TENURE") {
        Ok(tenure_str) => match tenure_str.parse::<u64>() {
            Ok(tenure_time) => {
                info!(
                    "Fault injection: sleeping for {} milliseconds to simulate a long tenure",
                    tenure_time
                );
                stacks::util::sleep_ms(tenure_time);
            }
            Err(_) => {
                error!("Parse error for STX_TEST_SLOW_TENURE");
                panic!();
            }
        },
        _ => {}
    }
}

#[cfg(not(test))]
fn fault_injection_long_tenure() {}

enum Error {
    HeaderNotFoundForChainTip,
    WinningVtxNotFoundForChainTip,
    SnapshotNotFoundForChainTip,
    BurnchainTipChanged,
}

struct MiningTenureInformation {
    stacks_parent_header: StacksHeaderInfo,
    /// the consensus hash of the sortition that selected the Stacks block parent
    parent_consensus_hash: ConsensusHash,
    /// the burn block height of the sortition that selected the Stacks block parent
    parent_block_burn_height: u64,
    /// the total amount burned in the sortition that selected the Stacks block parent
    parent_block_total_burn: u64,
    parent_winning_vtxindex: u16,
    coinbase_nonce: u64,
}

/// Process artifacts from the tenure.
/// At this point, we're modifying the chainstate, and merging the artifacts from the previous tenure.
fn inner_process_tenure(
    anchored_block: &StacksBlock,
    consensus_hash: &ConsensusHash,
    parent_consensus_hash: &ConsensusHash,
    burn_db: &mut SortitionDB,
    chain_state: &mut StacksChainState,
    coord_comms: &CoordinatorChannels,
) -> Result<bool, ChainstateError> {
    let stacks_blocks_processed = coord_comms.get_stacks_blocks_processed();

    if StacksChainState::has_stored_block(
        &chain_state.db(),
        &chain_state.blocks_path,
        consensus_hash,
        &anchored_block.block_hash(),
    )? {
        // already processed my tenure
        return Ok(true);
    }

    let ic = burn_db.index_conn();

    // Preprocess the anchored block
    chain_state.preprocess_anchored_block(
        &ic,
        consensus_hash,
        &anchored_block,
        &parent_consensus_hash,
        0,
    )?;

    if !coord_comms.announce_new_stacks_block() {
        return Ok(false);
    }
    if !coord_comms.wait_for_stacks_blocks_processed(stacks_blocks_processed, 15000) {
        warn!("ChainsCoordinator timed out while waiting for new stacks block to be processed");
    }

    Ok(true)
}

fn inner_generate_coinbase_tx(
    keychain: &mut Keychain,
    nonce: u64,
    is_mainnet: bool,
    chain_id: u32,
    alt_recipient: Option<PrincipalData>,
) -> StacksTransaction {
    let mut tx_auth = keychain.get_transaction_auth().unwrap();
    tx_auth.set_origin_nonce(nonce);

    let version = if is_mainnet {
        TransactionVersion::Mainnet
    } else {
        TransactionVersion::Testnet
    };
    let mut tx = StacksTransaction::new(
        version,
        tx_auth,
        TransactionPayload::Coinbase(CoinbasePayload([0u8; 32]), alt_recipient),
    );
    tx.chain_id = chain_id;
    tx.anchor_mode = TransactionAnchorMode::OnChainOnly;
    let mut tx_signer = StacksTransactionSigner::new(&tx);
    keychain.sign_as_origin(&mut tx_signer);

    tx_signer.get_tx().unwrap()
}

fn inner_generate_poison_microblock_tx(
    keychain: &mut Keychain,
    nonce: u64,
    poison_payload: TransactionPayload,
    is_mainnet: bool,
    chain_id: u32,
) -> StacksTransaction {
    let mut tx_auth = keychain.get_transaction_auth().unwrap();
    tx_auth.set_origin_nonce(nonce);

    let version = if is_mainnet {
        TransactionVersion::Mainnet
    } else {
        TransactionVersion::Testnet
    };
    let mut tx = StacksTransaction::new(version, tx_auth, poison_payload);
    tx.chain_id = chain_id;
    tx.anchor_mode = TransactionAnchorMode::OnChainOnly;
    let mut tx_signer = StacksTransactionSigner::new(&tx);
    keychain.sign_as_origin(&mut tx_signer);

    tx_signer.get_tx().unwrap()
}

/// Constructs and returns a LeaderKeyRegisterOp out of the provided params
fn inner_generate_leader_key_register_op(
    address: StacksAddress,
    vrf_public_key: VRFPublicKey,
    consensus_hash: &ConsensusHash,
) -> BlockstackOperationType {
    BlockstackOperationType::LeaderKeyRegister(LeaderKeyRegisterOp {
        public_key: vrf_public_key,
        memo: vec![],
        address,
        consensus_hash: consensus_hash.clone(),
        vtxindex: 0,
        txid: Txid([0u8; 32]),
        block_height: 0,
        burn_header_hash: BurnchainHeaderHash::zero(),
    })
}

fn rotate_vrf_and_register(
    is_mainnet: bool,
    keychain: &mut Keychain,
    burn_block: &BlockSnapshot,
    btc_controller: &mut BitcoinRegtestController,
) -> bool {
    let vrf_pk = keychain.rotate_vrf_keypair(burn_block.block_height);
    let burnchain_tip_consensus_hash = &burn_block.consensus_hash;
    let op = inner_generate_leader_key_register_op(
        keychain.get_address(is_mainnet),
        vrf_pk,
        burnchain_tip_consensus_hash,
    );

    let mut one_off_signer = keychain.generate_op_signer();
    btc_controller.submit_operation(op, &mut one_off_signer, 1)
}

/// Constructs and returns a LeaderBlockCommitOp out of the provided params
fn inner_generate_block_commit_op(
    sender: BurnchainSigner,
    block_header_hash: BlockHeaderHash,
    burn_fee: u64,
    key: &RegisteredKey,
    parent_burnchain_height: u32,
    parent_winning_vtx: u16,
    vrf_seed: VRFSeed,
    commit_outs: Vec<StacksAddress>,
    current_burn_height: u64,
) -> BlockstackOperationType {
    let (parent_block_ptr, parent_vtxindex) = (parent_burnchain_height, parent_winning_vtx);

    let burn_parent_modulus = (current_burn_height % BURN_BLOCK_MINED_AT_MODULUS) as u8;

    BlockstackOperationType::LeaderBlockCommit(LeaderBlockCommitOp {
        block_header_hash,
        burn_fee,
        input: (Txid([0; 32]), 0),
        apparent_sender: sender,
        key_block_ptr: key.block_height as u32,
        key_vtxindex: key.op_vtxindex as u16,
        memo: vec![STACKS_EPOCH_2_05_MARKER],
        new_seed: vrf_seed,
        parent_block_ptr,
        parent_vtxindex,
        vtxindex: 0,
        txid: Txid([0u8; 32]),
        block_height: 0,
        burn_header_hash: BurnchainHeaderHash::zero(),
        burn_parent_modulus,
        commit_outs,
    })
}

/// Mine and broadcast a single microblock, unconditionally.
fn mine_one_microblock(
    microblock_state: &mut MicroblockMinerState,
    sortdb: &SortitionDB,
    chainstate: &mut StacksChainState,
    mempool: &mut MemPoolDB,
    event_dispatcher: &EventDispatcher,
) -> Result<StacksMicroblock, ChainstateError> {
    debug!(
        "Try to mine one microblock off of {}/{} (total: {})",
        &microblock_state.parent_consensus_hash,
        &microblock_state.parent_block_hash,
        chainstate
            .unconfirmed_state
            .as_ref()
            .map(|us| us.num_microblocks())
            .unwrap_or(0)
    );

    let mint_result = {
        let ic = sortdb.index_conn();
        let mut microblock_miner = match StacksMicroblockBuilder::resume_unconfirmed(
            chainstate,
            &ic,
            &microblock_state.cost_so_far,
            microblock_state.settings.clone(),
        ) {
            Ok(x) => x,
            Err(e) => {
                let msg = format!(
                    "Failed to create a microblock miner at chaintip {}/{}: {:?}",
                    &microblock_state.parent_consensus_hash,
                    &microblock_state.parent_block_hash,
                    &e
                );
                error!("{}", msg);
                return Err(e);
            }
        };

        let t1 = get_epoch_time_ms();

        let mblock = microblock_miner.mine_next_microblock(
            mempool,
            &microblock_state.miner_key,
            event_dispatcher,
        )?;
        let new_cost_so_far = microblock_miner.get_cost_so_far().expect("BUG: cannot read cost so far from miner -- indicates that the underlying Clarity Tx is somehow in use still.");
        let t2 = get_epoch_time_ms();

        info!(
            "Mined microblock {} ({}) with {} transactions in {}ms",
            mblock.block_hash(),
            mblock.header.sequence,
            mblock.txs.len(),
            t2.saturating_sub(t1)
        );

        Ok((mblock, new_cost_so_far))
    };

    let (mined_microblock, new_cost) = match mint_result {
        Ok(x) => x,
        Err(e) => {
            warn!("Failed to mine microblock: {}", e);
            return Err(e);
        }
    };

    // preprocess the microblock locally
    chainstate.preprocess_streamed_microblock(
        &microblock_state.parent_consensus_hash,
        &microblock_state.parent_block_hash,
        &mined_microblock,
    )?;

    // update unconfirmed state cost
    microblock_state.cost_so_far = new_cost;
    microblock_state.quantity += 1;
    return Ok(mined_microblock);
}

fn try_mine_microblock(
    config: &Config,
    microblock_miner_state: &mut Option<MicroblockMinerState>,
    chainstate: &mut StacksChainState,
    sortdb: &SortitionDB,
    mem_pool: &mut MemPoolDB,
    winning_tip: (ConsensusHash, BlockHeaderHash, Secp256k1PrivateKey),
    event_dispatcher: &EventDispatcher,
) -> Result<Option<StacksMicroblock>, NetError> {
    let ch = winning_tip.0;
    let bhh = winning_tip.1;
    let microblock_privkey = winning_tip.2;

    let mut next_microblock = None;
    if microblock_miner_state.is_none() {
        debug!(
            "Instantiate microblock mining state off of {}/{}",
            &ch, &bhh
        );
        // we won a block! proceed to build a microblock tail if we've stored it
        match StacksChainState::get_anchored_block_header_info(chainstate.db(), &ch, &bhh) {
            Ok(Some(_)) => {
                let parent_index_hash = StacksBlockHeader::make_index_block_hash(&ch, &bhh);
                let cost_so_far = StacksChainState::get_stacks_block_anchored_cost(
                    chainstate.db(),
                    &parent_index_hash,
                )?
                .ok_or(NetError::NotFoundError)?;
                microblock_miner_state.replace(MicroblockMinerState {
                    parent_consensus_hash: ch.clone(),
                    parent_block_hash: bhh.clone(),
                    miner_key: microblock_privkey.clone(),
                    frequency: config.node.microblock_frequency,
                    last_mined: 0,
                    quantity: 0,
                    cost_so_far: cost_so_far,
                    settings: config.make_block_builder_settings(0, true),
                });
            }
            Ok(None) => {
                warn!(
                    "No such anchored block: {}/{}.  Cannot mine microblocks",
                    ch, bhh
                );
            }
            Err(e) => {
                warn!(
                    "Failed to get anchored block cost for {}/{}: {:?}",
                    ch, bhh, &e
                );
            }
        }
    }

    if let Some(mut microblock_miner) = microblock_miner_state.take() {
        if microblock_miner.parent_consensus_hash == ch && microblock_miner.parent_block_hash == bhh
        {
            if microblock_miner.last_mined + (microblock_miner.frequency as u128)
                < get_epoch_time_ms()
            {
                // opportunistically try and mine, but only if there are no attachable blocks in
                // recent history (i.e. in the last 10 minutes)
                let num_attachable = StacksChainState::count_attachable_staging_blocks(
                    chainstate.db(),
                    1,
                    get_epoch_time_secs() - 600,
                )?;
                if num_attachable == 0 {
                    match mine_one_microblock(
                        &mut microblock_miner,
                        sortdb,
                        chainstate,
                        mem_pool,
                        event_dispatcher,
                    ) {
                        Ok(microblock) => {
                            // will need to relay this
                            next_microblock = Some(microblock);
                        }
                        Err(ChainstateError::NoTransactionsToMine) => {
                            info!("Will keep polling mempool for transactions to include in a microblock");
                        }
                        Err(e) => {
                            warn!("Failed to mine one microblock: {:?}", &e);
                        }
                    }
                } else {
                    debug!("Will not mine microblocks yet -- have {} attachable blocks that arrived in the last 10 minutes", num_attachable);
                }
            }
            microblock_miner.last_mined = get_epoch_time_ms();
            microblock_miner_state.replace(microblock_miner);
        }
        // otherwise, we're not the sortition winner, and the microblock miner state can be
        // discarded.
    }

    Ok(next_microblock)
}

fn run_microblock_tenure(
    config: &Config,
    microblock_miner_state: &mut Option<MicroblockMinerState>,
    chainstate: &mut StacksChainState,
    sortdb: &mut SortitionDB,
    mem_pool: &mut MemPoolDB,
    relayer: &mut Relayer,
    miner_tip: (ConsensusHash, BlockHeaderHash, Secp256k1PrivateKey),
    counters: &Counters,
    event_dispatcher: &EventDispatcher,
) {
    // TODO: this is sensitive to poll latency -- can we call this on a fixed
    // schedule, regardless of network activity?
    let parent_consensus_hash = &miner_tip.0;
    let parent_block_hash = &miner_tip.1;

    debug!(
        "Run microblock tenure for {}/{}",
        parent_consensus_hash, parent_block_hash
    );

    // Mine microblocks, if we're active
    let next_microblock_opt = match try_mine_microblock(
        &config,
        microblock_miner_state,
        chainstate,
        sortdb,
        mem_pool,
        miner_tip.clone(),
        event_dispatcher,
    ) {
        Ok(x) => x,
        Err(e) => {
            warn!("Failed to mine next microblock: {:?}", &e);
            None
        }
    };

    // did we mine anything?
    if let Some(next_microblock) = next_microblock_opt {
        // apply it
        let microblock_hash = next_microblock.block_hash();

        let processed_unconfirmed_state = Relayer::refresh_unconfirmed(chainstate, sortdb);
        let num_mblocks = chainstate
            .unconfirmed_state
            .as_ref()
            .map(|ref unconfirmed| unconfirmed.num_microblocks())
            .unwrap_or(0);

        info!(
            "Mined one microblock: {} seq {} (total processed: {})",
            &microblock_hash, next_microblock.header.sequence, num_mblocks
        );
        counters.set_microblocks_processed(num_mblocks);

        let parent_index_block_hash =
            StacksBlockHeader::make_index_block_hash(parent_consensus_hash, parent_block_hash);
        event_dispatcher
            .process_new_microblocks(parent_index_block_hash, processed_unconfirmed_state);

        // send it off
        if let Err(e) =
            relayer.broadcast_microblock(parent_consensus_hash, parent_block_hash, next_microblock)
        {
            error!(
                "Failure trying to broadcast microblock {}: {}",
                microblock_hash, e
            );
        }
    }
}

/// Grant the p2p thread a copy of the unconfirmed microblock transaction list, so it can serve it
/// out via the unconfirmed transaction API.
/// Not the prettiest way to do this, but the least disruptive way to do this.
fn send_unconfirmed_txs(
    chainstate: &StacksChainState,
    unconfirmed_txs: Arc<Mutex<UnconfirmedTxMap>>,
) {
    if let Some(ref unconfirmed) = chainstate.unconfirmed_state {
        match unconfirmed_txs.lock() {
            Ok(mut txs) => {
                txs.clear();
                txs.extend(unconfirmed.mined_txs.clone());
            }
            Err(e) => {
                // can only happen due to a thread panic in the relayer
                error!("FATAL: unconfirmed tx arc mutex is poisoned: {:?}", &e);
                panic!();
            }
        };
    }
}

/// Have the p2p thread receive unconfirmed txs
fn recv_unconfirmed_txs(
    chainstate: &mut StacksChainState,
    unconfirmed_txs: Arc<Mutex<UnconfirmedTxMap>>,
) {
    if let Some(ref mut unconfirmed) = chainstate.unconfirmed_state {
        match unconfirmed_txs.lock() {
            Ok(txs) => {
                unconfirmed.mined_txs.clear();
                unconfirmed.mined_txs.extend(txs.clone());
            }
            Err(e) => {
                // can only happen due to a thread panic in the relayer
                error!("FATAL: unconfirmed arc mutex is poisoned: {:?}", &e);
                panic!();
            }
        };
    }
}

fn spawn_peer(
    runloop: &RunLoop,
    mut this: PeerNetwork,
    p2p_sock: &SocketAddr,
    rpc_sock: &SocketAddr,
    poll_timeout: u64,
    relay_channel: SyncSender<RelayerDirective>,
    attachments_rx: Receiver<HashSet<AttachmentInstance>>,
    unconfirmed_txs: Arc<Mutex<UnconfirmedTxMap>>,
) -> Result<JoinHandle<()>, NetError> {
    let config = runloop.config().clone();
    let mut sync_comms = runloop.get_pox_sync_comms();
    let event_dispatcher = runloop.get_event_dispatcher();
    let should_keep_running = runloop.get_termination_switch();
    let burnchain = runloop.get_burnchain();
    let pox_constants = burnchain.pox_constants;

    let is_mainnet = config.is_mainnet();
    let burn_db_path = config.get_burn_db_file_path();
    let stacks_chainstate_path = config.get_chainstate_path_str();
    let exit_at_block_height = config.burnchain.process_exit_at_block_height;

    this.bind(p2p_sock, rpc_sock).unwrap();
    let (mut dns_resolver, mut dns_client) = DNSResolver::new(10);
    let sortdb =
        SortitionDB::open(&burn_db_path, false, pox_constants).map_err(NetError::DBError)?;

    let (mut chainstate, _) = StacksChainState::open(
        is_mainnet,
        config.burnchain.chain_id,
        &stacks_chainstate_path,
        Some(config.node.get_marf_opts()),
    )
    .map_err(|e| NetError::ChainstateError(e.to_string()))?;

    // buffer up blocks to store without stalling the p2p thread
    let mut results_with_data = VecDeque::new();

    let server_thread = thread::Builder::new()
        .name("p2p".to_string())
        .spawn(move || {
            // create estimators, metric instances for RPC handler
            let cost_estimator = config
                .make_cost_estimator()
                .unwrap_or_else(|| Box::new(UnitEstimator));
            let metric = config
                .make_cost_metric()
                .unwrap_or_else(|| Box::new(UnitMetric));
            let fee_estimator = config.make_fee_estimator();

            let mut mem_pool = MemPoolDB::open(
                is_mainnet,
                config.burnchain.chain_id,
                &stacks_chainstate_path,
                cost_estimator,
                metric,
            )
            .expect("Database failure opening mempool");

            let cost_estimator = config
                .make_cost_estimator()
                .unwrap_or_else(|| Box::new(UnitEstimator));
            let metric = config
                .make_cost_metric()
                .unwrap_or_else(|| Box::new(UnitMetric));

            let handler_args = RPCHandlerArgs {
                exit_at_block_height: exit_at_block_height.as_ref(),
                genesis_chainstate_hash: Sha256Sum::from_hex(stx_genesis::GENESIS_CHAINSTATE_HASH)
                    .unwrap(),
                event_observer: Some(&event_dispatcher),
                cost_estimator: Some(cost_estimator.as_ref()),
                cost_metric: Some(metric.as_ref()),
                fee_estimator: fee_estimator.as_ref().map(|x| x.as_ref()),
                ..RPCHandlerArgs::default()
            };

            let mut num_p2p_state_machine_passes = 0;
            let mut num_inv_sync_passes = 0;
            let mut num_download_passes = 0;
            let mut mblock_deadline = 0;

            while should_keep_running.load(Ordering::SeqCst) {
                // initial block download?
                let ibd = sync_comms.get_ibd();
                let download_backpressure = results_with_data.len() > 0;
                let poll_ms = if !download_backpressure && this.has_more_downloads() {
                    // keep getting those blocks -- drive the downloader state-machine
                    debug!(
                        "P2P: backpressure: {}, more downloads: {}",
                        download_backpressure,
                        this.has_more_downloads()
                    );
                    1
                } else {
                    cmp::min(poll_timeout, config.node.microblock_frequency)
                };

                let mut expected_attachments = match attachments_rx.try_recv() {
                    Ok(expected_attachments) => {
                        debug!("Atlas: received attachments: {:?}", &expected_attachments);
                        expected_attachments
                    }
                    _ => {
                        debug!("Atlas: attachment channel is empty");
                        HashSet::new()
                    }
                };

                let _ = Relayer::setup_unconfirmed_state_readonly(&mut chainstate, &sortdb);
                recv_unconfirmed_txs(&mut chainstate, unconfirmed_txs.clone());

                match this.run(
                    &sortdb,
                    &mut chainstate,
                    &mut mem_pool,
                    Some(&mut dns_client),
                    download_backpressure,
                    ibd,
                    poll_ms,
                    &handler_args,
                    &mut expected_attachments,
                ) {
                    Ok(network_result) => {
                        if num_p2p_state_machine_passes < network_result.num_state_machine_passes {
                            // p2p state-machine did a full pass. Notify anyone listening.
                            sync_comms.notify_p2p_state_pass();
                            num_p2p_state_machine_passes = network_result.num_state_machine_passes;
                        }

                        if num_inv_sync_passes < network_result.num_inv_sync_passes {
                            // inv-sync state-machine did a full pass. Notify anyone listening.
                            sync_comms.notify_inv_sync_pass();
                            num_inv_sync_passes = network_result.num_inv_sync_passes;
                        }

                        if num_download_passes < network_result.num_download_passes {
                            // download state-machine did a full pass.  Notify anyone listening.
                            sync_comms.notify_download_pass();
                            num_download_passes = network_result.num_download_passes;
                        }

                        if network_result.has_data_to_store() {
                            results_with_data
                                .push_back(RelayerDirective::HandleNetResult(network_result));
                        }

                        // only do this on the Ok() path, even if we're mining, because an error in
                        // network dispatching is likely due to resource exhaustion
                        if mblock_deadline < get_epoch_time_ms() {
                            debug!("P2P: schedule microblock tenure");
                            results_with_data.push_back(RelayerDirective::RunMicroblockTenure(
                                this.burnchain_tip.clone(),
                                get_epoch_time_ms(),
                            ));
                            mblock_deadline =
                                get_epoch_time_ms() + (config.node.microblock_frequency as u128);
                        }
                    }
                    Err(e) => {
                        // this is only reachable if the network is not instantiated correctly --
                        // i.e. you didn't connect it
                        panic!("P2P: Failed to process network dispatch: {:?}", &e);
                    }
                };

                while let Some(next_result) = results_with_data.pop_front() {
                    // have blocks, microblocks, and/or transactions (don't care about anything else),
                    // or a directive to mine microblocks
                    if let Err(e) = relay_channel.try_send(next_result) {
                        debug!(
                            "P2P: {:?}: download backpressure detected",
                            &this.local_peer
                        );
                        match e {
                            TrySendError::Full(directive) => {
                                if let RelayerDirective::RunMicroblockTenure(..) = directive {
                                    // can drop this
                                } else if let RelayerDirective::RunTenure(..) = directive {
                                    // can drop this
                                } else {
                                    // don't lose this data -- just try it again
                                    results_with_data.push_front(directive);
                                }
                                break;
                            }
                            TrySendError::Disconnected(_) => {
                                info!("P2P: Relayer hang up with p2p channel");
                                should_keep_running.store(false, Ordering::SeqCst);
                                break;
                            }
                        }
                    } else {
                        debug!("P2P: Dispatched result to Relayer!");
                    }
                }
            }

            while let Err(TrySendError::Full(_)) = relay_channel.try_send(RelayerDirective::Exit) {
                warn!("Failed to direct relayer thread to exit, sleeping and trying again");
                thread::sleep(Duration::from_secs(5));
            }
            info!("P2P thread exit!");
        })
        .unwrap();

    let _jh = thread::Builder::new()
        .name("dns-resolver".to_string())
        .spawn(move || {
            dns_resolver.thread_main();
        })
        .unwrap();

    Ok(server_thread)
}

fn get_last_sortition(last_sortition: &Arc<Mutex<Option<BlockSnapshot>>>) -> Option<BlockSnapshot> {
    match last_sortition.lock() {
        Ok(sort_opt) => sort_opt.clone(),
        Err(_) => {
            error!("Sortition mutex poisoned!");
            panic!();
        }
    }
}

fn set_last_sortition(
    last_sortition: &mut Arc<Mutex<Option<BlockSnapshot>>>,
    block_snapshot: BlockSnapshot,
) {
    match last_sortition.lock() {
        Ok(mut sortition_opt) => {
            sortition_opt.replace(block_snapshot);
        }
        Err(_) => {
            error!("Sortition mutex poisoned!");
            panic!();
        }
    };
}

fn spawn_miner_relayer(
    runloop: &RunLoop,
    mut relayer: Relayer,
    local_peer: LocalPeer,
    mut keychain: Keychain,
    relay_channel: Receiver<RelayerDirective>,
    last_sortition: Arc<Mutex<Option<BlockSnapshot>>>,
    coord_comms: CoordinatorChannels,
    unconfirmed_txs: Arc<Mutex<UnconfirmedTxMap>>,
) -> Result<JoinHandle<()>, NetError> {
    let config = runloop.config().clone();
    let event_dispatcher = runloop.get_event_dispatcher();
    let counters = runloop.get_counters();
    let sync_comms = runloop.get_pox_sync_comms();
    let burnchain = runloop.get_burnchain();

    let is_mainnet = config.is_mainnet();
    let chain_id = config.burnchain.chain_id;
    let burn_db_path = config.get_burn_db_file_path();
    let stacks_chainstate_path = config.get_chainstate_path_str();

    // Note: the chainstate coordinator is *the* block processor, it is responsible for writes to
    // the chainstate -- eventually, no other codepaths should be writing to it.
    //
    // the relayer _should not_ be modifying the sortdb,
    //   however, it needs a mut reference to create read TXs.
    //   should address via #1449
    let mut sortdb = SortitionDB::open(&burn_db_path, true, burnchain.pox_constants.clone())
        .map_err(NetError::DBError)?;

    let (mut chainstate, _) = StacksChainState::open(
        is_mainnet,
        chain_id,
        &stacks_chainstate_path,
        Some(config.node.get_marf_opts()),
    )
    .map_err(|e| NetError::ChainstateError(e.to_string()))?;

    let mut last_mined_blocks: HashMap<
        BurnchainHeaderHash,
        Vec<(AssembledAnchorBlock, Secp256k1PrivateKey)>,
    > = HashMap::new();
    let burn_fee_cap = config.burnchain.burn_fee_cap;

    let mut bitcoin_controller = BitcoinRegtestController::new_dummy(config.clone());
    let mut microblock_miner_state: Option<MicroblockMinerState> = None;
    let mut miner_tip = None; // only set if we won the last sortition
    let mut last_microblock_tenure_time = 0;
    let mut last_tenure_issue_time = 0;

    let relayer_handle = thread::Builder::new().name("relayer".to_string()).spawn(move || {
        let cost_estimator = config.make_cost_estimator()
            .unwrap_or_else(|| Box::new(UnitEstimator));
        let metric = config.make_cost_metric()
            .unwrap_or_else(|| Box::new(UnitMetric));

        let mut mem_pool = MemPoolDB::open(is_mainnet, chain_id, &stacks_chainstate_path, cost_estimator, metric)
            .expect("Database failure opening mempool");

        while let Ok(mut directive) = relay_channel.recv() {
            match directive {
                RelayerDirective::HandleNetResult(ref mut net_result) => {
                    debug!("Relayer: Handle network result");
                    let net_receipts = relayer
                        .process_network_result(
                            &local_peer,
                            net_result,
                            &mut sortdb,
                            &mut chainstate,
                            &mut mem_pool,
                            sync_comms.get_ibd(),
                            Some(&coord_comms),
                            Some(&event_dispatcher),
                        )
                        .expect("BUG: failure processing network results");

                    let mempool_txs_added = net_receipts.mempool_txs_added.len();
                    if mempool_txs_added > 0 {
                        event_dispatcher.process_new_mempool_txs(net_receipts.mempool_txs_added);
                    }

                    let num_unconfirmed_microblock_tx_receipts = net_receipts.processed_unconfirmed_state.receipts.len();
                    if num_unconfirmed_microblock_tx_receipts > 0 {
                        if let Some(unconfirmed_state) = chainstate.unconfirmed_state.as_ref() {
                            let canonical_tip = unconfirmed_state.confirmed_chain_tip.clone();
                            event_dispatcher.process_new_microblocks(canonical_tip, net_receipts.processed_unconfirmed_state);
                        } else {
                            warn!("Relayer: oops, unconfirmed state is uninitialized but there are microblock events");
                        }
                    }

                    // Dispatch retrieved attachments, if any.
                    if net_result.has_attachments() {
                        event_dispatcher.process_new_attachments(&net_result.attachments);
                    }

                    // synchronize unconfirmed tx index to p2p thread
                    send_unconfirmed_txs(&chainstate, unconfirmed_txs.clone());
                }
                RelayerDirective::ProcessTenure(consensus_hash, burn_hash, block_header_hash) => {
                    debug!(
                        "Relayer: Process tenure {}/{} in {}",
                        &consensus_hash, &block_header_hash, &burn_hash
                    );
                    if let Some(last_mined_blocks_at_burn_hash) =
                        last_mined_blocks.remove(&burn_hash)
                    {
                        for (last_mined_block, microblock_privkey) in
                            last_mined_blocks_at_burn_hash.into_iter()
                        {
                            let AssembledAnchorBlock {
                                parent_consensus_hash,
                                anchored_block: mined_block,
                                my_burn_hash: mined_burn_hash,
                                attempt: _,
                            } = last_mined_block;
                            if mined_block.block_hash() == block_header_hash
                                && burn_hash == mined_burn_hash
                            {
                                // we won!
                                let reward_block_height = mined_block.header.total_work.work + MINER_REWARD_MATURITY;
                                info!("Won sortition! Mining reward will be received in {} blocks (block #{})", MINER_REWARD_MATURITY, reward_block_height);
                                debug!("Won sortition!";
                                      "stacks_header" => %block_header_hash,
                                      "burn_hash" => %mined_burn_hash,
                                );

                                increment_stx_blocks_mined_counter();

                                match inner_process_tenure(
                                    &mined_block,
                                    &consensus_hash,
                                    &parent_consensus_hash,
                                    &mut sortdb,
                                    &mut chainstate,
                                    &coord_comms,
                                ) {
                                    Ok(coordinator_running) => {
                                        if !coordinator_running {
                                            warn!(
                                                "Coordinator stopped, stopping relayer thread..."
                                            );
                                            return;
                                        }
                                    }
                                    Err(e) => {
                                        warn!(
                                            "Error processing my tenure, bad block produced: {}",
                                            e
                                        );
                                        warn!(
                                            "Bad block";
                                            "stacks_header" => %block_header_hash,
                                            "data" => %to_hex(&mined_block.serialize_to_vec()),
                                        );
                                        continue;
                                    }
                                };

                                // advertize _and_ push blocks for now
                                let blocks_available = Relayer::load_blocks_available_data(
                                    &sortdb,
                                    vec![consensus_hash.clone()],
                                )
                                .expect("Failed to obtain block information for a block we mined.");

                                let block_data = {
                                    let mut bd = HashMap::new();
                                    bd.insert(consensus_hash.clone(), mined_block.clone());
                                    bd
                                };

                                if let Err(e) = relayer.advertize_blocks(blocks_available, block_data) {
                                    warn!("Failed to advertise new block: {}", e);
                                }

                                let snapshot = SortitionDB::get_block_snapshot_consensus(
                                    sortdb.conn(),
                                    &consensus_hash,
                                )
                                .expect("Failed to obtain snapshot for block")
                                .expect("Failed to obtain snapshot for block");
                                if !snapshot.pox_valid {
                                    warn!(
                                        "Snapshot for {} is no longer valid; discarding {}...",
                                        &consensus_hash,
                                        &mined_block.block_hash()
                                    );
                                    miner_tip = None;

                                } else {
                                    let ch = snapshot.consensus_hash.clone();
                                    let bh = mined_block.block_hash();

                                    if let Err(e) = relayer
                                        .broadcast_block(snapshot.consensus_hash, mined_block)
                                    {
                                        warn!("Failed to push new block: {}", e);
                                    }

                                    // proceed to mine microblocks
                                    debug!(
                                        "Microblock miner tip is now {}/{} ({})",
                                        &consensus_hash, &block_header_hash, StacksBlockHeader::make_index_block_hash(&consensus_hash, &block_header_hash)
                                    );
                                    miner_tip = Some((ch, bh, microblock_privkey));

                                    Relayer::refresh_unconfirmed(&mut chainstate, &mut sortdb);
                                    send_unconfirmed_txs(&chainstate, unconfirmed_txs.clone());
                                }
                            } else {
                                debug!("Did not win sortition, my blocks [burn_hash= {}, block_hash= {}], their blocks [parent_consenus_hash= {}, burn_hash= {}, block_hash ={}]",
                                  mined_burn_hash, mined_block.block_hash(), parent_consensus_hash, burn_hash, block_header_hash);

                                miner_tip = None;
                            }
                        }
                    }
                }
                RelayerDirective::RunTenure(registered_key, last_burn_block, issue_timestamp_ms) => {
                    if let Some(cur_sortition) = get_last_sortition(&last_sortition) {
                        if last_burn_block.sortition_id != cur_sortition.sortition_id {
                            debug!("Drop stale RunTenure for {}: current sortition is for {}", &last_burn_block.burn_header_hash, &cur_sortition.burn_header_hash);
                            counters.bump_missed_tenures();
                            continue;
                        }
                    }

                    let burn_header_hash = last_burn_block.burn_header_hash.clone();
                    let burn_chain_sn = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn())
                        .expect("FATAL: failed to query sortition DB for canonical burn chain tip");

                    let burn_chain_tip = burn_chain_sn
                        .burn_header_hash
                        .clone();

                    let mut burn_tenure_snapshot = last_burn_block.clone();
                    if burn_chain_tip == burn_header_hash {
                        // no burnchain change, so only re-run block tenure every so often in order
                        // to give microblocks a chance to collect
                        if issue_timestamp_ms < last_tenure_issue_time + (config.node.wait_time_for_microblocks as u128) {
                            debug!("Relayer: will NOT run tenure since issuance at {} is too fresh (wait until {} + {} = {})",
                                    issue_timestamp_ms / 1000, last_tenure_issue_time / 1000, config.node.wait_time_for_microblocks / 1000, (last_tenure_issue_time + (config.node.wait_time_for_microblocks as u128)) / 1000);
                            continue;
                        }
                    }
                    else {
                        // burnchain has changed since this directive was sent, so mine immediately
                        burn_tenure_snapshot = burn_chain_sn;
                        if issue_timestamp_ms + (config.node.wait_time_for_microblocks as u128) < get_epoch_time_ms() {
                            // still waiting for microblocks to arrive
                            debug!("Relayer: will NOT run tenure since still waiting for microblocks to arrive ({} <= {})", (issue_timestamp_ms + (config.node.wait_time_for_microblocks as u128)) / 1000, get_epoch_time_secs());
                            continue;
                        }
                        debug!("Relayer: burnchain has advanced from {} to {}", &burn_header_hash, &burn_chain_tip);
                    }

                    debug!(
                        "Relayer: Run tenure";
                        "height" => last_burn_block.block_height,
                        "burn_header_hash" => %burn_chain_tip,
                        "last_burn_header_hash" => %burn_header_hash
                    );

                    let tenure_begin = get_epoch_time_ms();
                    fault_injection_long_tenure();

                    let mut last_mined_blocks_vec = last_mined_blocks
                        .remove(&burn_header_hash)
                        .unwrap_or_default();

                    let last_mined_block_opt = StacksNode::relayer_run_tenure(
                        &config,
                        registered_key,
                        &mut chainstate,
                        &mut sortdb,
                        &burnchain,
                        burn_tenure_snapshot,
                        &mut keychain,
                        &mut mem_pool,
                        burn_fee_cap,
                        &mut bitcoin_controller,
                        &last_mined_blocks_vec.iter().map(|(blk, _)| blk).collect(),
                        &event_dispatcher,
                    );
                    if let Some((last_mined_block, microblock_privkey)) = last_mined_block_opt {
                        if last_mined_blocks_vec.len() == 0 {
                            counters.bump_blocks_processed();
                        }
                        last_mined_blocks_vec.push((last_mined_block, microblock_privkey));
                    }
                    last_mined_blocks.insert(burn_header_hash, last_mined_blocks_vec);

                    last_tenure_issue_time = get_epoch_time_ms();
                    debug!("Relayer: RunTenure finished at {} (in {}ms)", last_tenure_issue_time, last_tenure_issue_time.saturating_sub(tenure_begin));
                }
                RelayerDirective::RegisterKey(ref last_burn_block) => {
                    rotate_vrf_and_register(
                        is_mainnet,
                        &mut keychain,
                        last_burn_block,
                        &mut bitcoin_controller,
                    );
                    counters.bump_blocks_processed();
                }
                RelayerDirective::RunMicroblockTenure(burnchain_tip, tenure_issue_ms) => {
                    if last_microblock_tenure_time > tenure_issue_ms {
                        // stale request
                        continue;
                    }
                    if let Some(cur_sortition) = get_last_sortition(&last_sortition) {
                        if burnchain_tip.sortition_id != cur_sortition.sortition_id {
                            debug!("Drop stale RunMicroblockTenure for {}/{}: current sortition is for {} ({})", &burnchain_tip.consensus_hash, &burnchain_tip.winning_stacks_block_hash, &cur_sortition.consensus_hash, &cur_sortition.burn_header_hash);
                            continue;
                        }
                    }

                    debug!("Relayer: Run microblock tenure");

                    // unconfirmed state must be consistent with the chain tip, as must the
                    // microblock mining state.
                    if let Some((ch, bh, mblock_pkey)) = miner_tip.clone() {
                        if let Some(miner_state) = microblock_miner_state.take() {
                            if miner_state.parent_consensus_hash == ch || miner_state.parent_block_hash == bh {
                                // preserve -- chaintip is unchanged
                                microblock_miner_state = Some(miner_state);
                            }
                            else {
                                debug!("Relayer: reset microblock miner state");
                                microblock_miner_state = None;
                                counters.set_microblocks_processed(0);
                            }
                        }

                        run_microblock_tenure(
                            &config,
                            &mut microblock_miner_state,
                            &mut chainstate,
                            &mut sortdb,
                            &mut mem_pool,
                            &mut relayer,
                            (ch, bh, mblock_pkey),
                            &counters,
                            &event_dispatcher,
                        );

                        // synchronize unconfirmed tx index to p2p thread
                        send_unconfirmed_txs(&chainstate, unconfirmed_txs.clone());
                        last_microblock_tenure_time = get_epoch_time_ms();
                    }
                    else {
                        debug!("Relayer: reset unconfirmed state to 0 microblocks");
                        counters.set_microblocks_processed(0);
                        microblock_miner_state = None;
                    }
                }
                RelayerDirective::Exit => break
            }
        }
        debug!("Relayer exit!");
    }).unwrap();

    Ok(relayer_handle)
}

enum LeaderKeyRegistrationState {
    Inactive,
    Pending,
    Active(RegisteredKey),
}

impl StacksNode {
    pub fn spawn(
        runloop: &RunLoop,
        last_burn_block: Option<BlockSnapshot>,
        coord_comms: CoordinatorChannels,
        attachments_rx: Receiver<HashSet<AttachmentInstance>>,
    ) -> StacksNode {
        let config = runloop.config().clone();
        let miner = runloop.is_miner();
        let burnchain = runloop.get_burnchain();
        let atlas_config = AtlasConfig::default(config.is_mainnet());
        let mut keychain = Keychain::default(config.node.seed.clone());

        // we can call _open_ here rather than _connect_, since connect is first called in
        //   make_genesis_block
        let sortdb = SortitionDB::open(
            &config.get_burn_db_file_path(),
            false,
            burnchain.pox_constants.clone(),
        )
        .expect("Error while instantiating sortition db");

        let epochs = SortitionDB::get_stacks_epochs(sortdb.conn())
            .expect("Error while loading stacks epochs");

        let view = {
            let sortition_tip = SortitionDB::get_canonical_burn_chain_tip(&sortdb.conn())
                .expect("Failed to get sortition tip");
            SortitionDB::get_burnchain_view(&sortdb.conn(), &burnchain, &sortition_tip).unwrap()
        };

        // create a new peerdb
        let data_url = UrlString::try_from(format!("{}", &config.node.data_url)).unwrap();
        let initial_neighbors = config.node.bootstrap_node.clone();
        if initial_neighbors.len() > 0 {
            info!(
                "Will bootstrap from peers {}",
                VecDisplay(&initial_neighbors)
            );
        } else {
            warn!("Without a peer to bootstrap from, the node will start mining a new chain");
        }

        let p2p_sock: SocketAddr = config.node.p2p_bind.parse().expect(&format!(
            "Failed to parse socket: {}",
            &config.node.p2p_bind
        ));
        let rpc_sock = config.node.rpc_bind.parse().expect(&format!(
            "Failed to parse socket: {}",
            &config.node.rpc_bind
        ));
        let p2p_addr: SocketAddr = config.node.p2p_address.parse().expect(&format!(
            "Failed to parse socket: {}",
            &config.node.p2p_address
        ));
        let node_privkey = {
            let mut re_hashed_seed = config.node.local_peer_seed.clone();
            let my_private_key = loop {
                match Secp256k1PrivateKey::from_slice(&re_hashed_seed[..]) {
                    Ok(sk) => break sk,
                    Err(_) => {
                        re_hashed_seed = Sha256Sum::from_data(&re_hashed_seed[..])
                            .as_bytes()
                            .to_vec()
                    }
                }
            };
            my_private_key
        };

        let mut peerdb = PeerDB::connect(
            &config.get_peer_db_file_path(),
            true,
            config.burnchain.chain_id,
            burnchain.network_id,
            Some(node_privkey),
            config.connection_options.private_key_lifetime.clone(),
            PeerAddress::from_socketaddr(&p2p_addr),
            p2p_sock.port(),
            data_url,
            &vec![],
            Some(&initial_neighbors),
        )
        .map_err(|e| {
            eprintln!(
                "Failed to open {}: {:?}",
                &config.get_peer_db_file_path(),
                &e
            );
            panic!();
        })
        .unwrap();

        {
            // bootstrap nodes *always* allowed
            let mut tx = peerdb.tx_begin().unwrap();
            for initial_neighbor in initial_neighbors.iter() {
                // update peer in case public key changed
                PeerDB::update_peer(&mut tx, &initial_neighbor).unwrap();
                PeerDB::set_allow_peer(
                    &mut tx,
                    initial_neighbor.addr.network_id,
                    &initial_neighbor.addr.addrbytes,
                    initial_neighbor.addr.port,
                    -1,
                )
                .unwrap();
            }
            tx.commit().unwrap();
        }

        if !config.node.deny_nodes.is_empty() {
            warn!("Will ignore nodes {:?}", &config.node.deny_nodes);
        }

        {
            let mut tx = peerdb.tx_begin().unwrap();
            for denied in config.node.deny_nodes.iter() {
                PeerDB::set_deny_peer(
                    &mut tx,
                    denied.addr.network_id,
                    &denied.addr.addrbytes,
                    denied.addr.port,
                    get_epoch_time_secs() + 24 * 365 * 3600,
                )
                .unwrap();
            }
            tx.commit().unwrap();
        }

        // update services to indicate we can support mempool sync
        {
            let mut tx = peerdb.tx_begin().unwrap();
            PeerDB::set_local_services(
                &mut tx,
                (ServiceFlags::RPC as u16) | (ServiceFlags::RELAY as u16),
            )
            .unwrap();
            tx.commit().unwrap();
        }

        let atlasdb =
            AtlasDB::connect(atlas_config.clone(), &config.get_atlas_db_file_path(), true).unwrap();

        let local_peer = match PeerDB::get_local_peer(peerdb.conn()) {
            Ok(local_peer) => local_peer,
            _ => panic!("Unable to retrieve local peer"),
        };

        // force early mempool instantiation
        let cost_estimator = config
            .make_cost_estimator()
            .unwrap_or_else(|| Box::new(UnitEstimator));
        let metric = config
            .make_cost_metric()
            .unwrap_or_else(|| Box::new(UnitMetric));

        let _ = MemPoolDB::open(
            config.is_mainnet(),
            config.burnchain.chain_id,
            &config.get_chainstate_path_str(),
            cost_estimator,
            metric,
        )
        .expect("BUG: failed to instantiate mempool");

        // now we're ready to instantiate a p2p network object, the relayer, and the event dispatcher
        let mut p2p_net = PeerNetwork::new(
            peerdb,
            atlasdb,
            local_peer.clone(),
            config.burnchain.peer_version,
            burnchain.clone(),
            view,
            config.connection_options.clone(),
            epochs,
        );

        // setup the relayer channel
        let (relay_send, relay_recv) = sync_channel(RELAYER_MAX_BUFFER);

        let last_sortition = Arc::new(Mutex::new(last_burn_block));

        let burnchain_signer = keychain.get_burnchain_signer();
        match monitoring::set_burnchain_signer(burnchain_signer.clone()) {
            Err(e) => {
                warn!("Failed to set global burnchain signer: {:?}", &e);
            }
            _ => {}
        }

        let relayer = Relayer::from_p2p(&mut p2p_net);
        let shared_unconfirmed_txs = Arc::new(Mutex::new(UnconfirmedTxMap::new()));

        let leader_key_registration_state = if config.node.mock_mining {
            // mock mining, pretend to have a registered key
            let vrf_public_key = keychain.rotate_vrf_keypair(1);
            LeaderKeyRegistrationState::Active(RegisteredKey {
                block_height: 1,
                op_vtxindex: 1,
                vrf_public_key,
            })
        } else {
            LeaderKeyRegistrationState::Inactive
        };

        let relayer_thread_handle = spawn_miner_relayer(
            runloop,
            relayer,
            local_peer,
            keychain,
            relay_recv,
            last_sortition.clone(),
            coord_comms,
            shared_unconfirmed_txs.clone(),
        )
        .expect("Failed to initialize mine/relay thread");

        let p2p_thread_handle = spawn_peer(
            runloop,
            p2p_net,
            &p2p_sock,
            &rpc_sock,
            5000,
            relay_send.clone(),
            attachments_rx,
            shared_unconfirmed_txs,
        )
        .expect("Failed to initialize p2p thread");

        info!("Start HTTP server on: {}", &config.node.rpc_bind);
        info!("Start P2P server on: {}", &config.node.p2p_bind);

        let is_miner = miner;

        StacksNode {
            config,
            relay_channel: relay_send,
            last_sortition,
            burnchain_signer,
            is_miner,
            atlas_config,
            leader_key_registration_state,
            p2p_thread_handle,
            relayer_thread_handle,
        }
    }

    /// Tell the relayer to fire off a tenure and a block commit op,
    /// if it is time to do so.
    pub fn relayer_issue_tenure(&mut self) -> bool {
        if !self.is_miner {
            // node is a follower, don't try to issue a tenure
            return true;
        }

        if let Some(burnchain_tip) = get_last_sortition(&self.last_sortition) {
            match self.leader_key_registration_state {
                LeaderKeyRegistrationState::Active(ref key) => {
                    debug!(
                        "Tenure: Using key {:?} off of {}",
                        &key.vrf_public_key, &burnchain_tip.burn_header_hash
                    );

                    self.relay_channel
                        .send(RelayerDirective::RunTenure(
                            key.clone(),
                            burnchain_tip,
                            get_epoch_time_ms(),
                        ))
                        .is_ok()
                }
                LeaderKeyRegistrationState::Inactive => {
                    warn!(
                        "Tenure: skipped tenure because no active VRF key. Trying to register one."
                    );
                    self.leader_key_registration_state = LeaderKeyRegistrationState::Pending;
                    self.relay_channel
                        .send(RelayerDirective::RegisterKey(burnchain_tip))
                        .is_ok()
                }
                LeaderKeyRegistrationState::Pending => true,
            }
        } else {
            warn!("Tenure: Do not know the last burn block. As a miner, this is bad.");
            true
        }
    }

    /// Notify the relayer of a sortition, telling it to process the block
    ///  and advertize it if it was mined by the node.
    /// returns _false_ if the relayer hung up the channel.
    pub fn relayer_sortition_notify(&self) -> bool {
        if !self.is_miner {
            // node is a follower, don't try to process my own tenure.
            return true;
        }

        if let Some(snapshot) = get_last_sortition(&self.last_sortition) {
            debug!(
                "Tenure: Notify sortition!";
                "consensus_hash" => %snapshot.consensus_hash,
                "burn_block_hash" => %snapshot.burn_header_hash,
                "winning_stacks_block_hash" => %snapshot.winning_stacks_block_hash,
                "burn_block_height" => &snapshot.block_height,
                "sortition_id" => %snapshot.sortition_id
            );
            if snapshot.sortition {
                return self
                    .relay_channel
                    .send(RelayerDirective::ProcessTenure(
                        snapshot.consensus_hash.clone(),
                        snapshot.parent_burn_header_hash.clone(),
                        snapshot.winning_stacks_block_hash.clone(),
                    ))
                    .is_ok();
            }
        } else {
            debug!("Tenure: Notify sortition! No last burn block");
        }
        true
    }

    fn get_mining_tenure_information(
        chain_state: &mut StacksChainState,
        burn_db: &mut SortitionDB,
        check_burn_block: &BlockSnapshot,
        miner_address: StacksAddress,
        mine_tip_ch: &ConsensusHash,
        mine_tip_bh: &BlockHeaderHash,
    ) -> Result<MiningTenureInformation, Error> {
        let stacks_tip_header = StacksChainState::get_anchored_block_header_info(
            chain_state.db(),
            &mine_tip_ch,
            &mine_tip_bh,
        )
        .unwrap()
        .ok_or_else(|| {
            error!(
                "Could not mine new tenure, since could not find header for known chain tip.";
                "tip_consensus_hash" => %mine_tip_ch,
                "tip_stacks_block_hash" => %mine_tip_bh
            );
            Error::HeaderNotFoundForChainTip
        })?;

        // the stacks block I'm mining off of's burn header hash and vtxindex:
        let parent_snapshot =
            SortitionDB::get_block_snapshot_consensus(burn_db.conn(), mine_tip_ch)
                .expect("Failed to look up block's parent snapshot")
                .expect("Failed to look up block's parent snapshot");

        let parent_sortition_id = &parent_snapshot.sortition_id;
        let parent_winning_vtxindex =
            SortitionDB::get_block_winning_vtxindex(burn_db.conn(), parent_sortition_id)
                .expect("SortitionDB failure.")
                .ok_or_else(|| {
                    error!(
                        "Failed to find winning vtx index for the parent sortition";
                        "parent_sortition_id" => %parent_sortition_id
                    );
                    Error::WinningVtxNotFoundForChainTip
                })?;

        let parent_block = SortitionDB::get_block_snapshot(burn_db.conn(), parent_sortition_id)
            .expect("SortitionDB failure.")
            .ok_or_else(|| {
                error!(
                    "Failed to find block snapshot for the parent sortition";
                    "parent_sortition_id" => %parent_sortition_id
                );
                Error::SnapshotNotFoundForChainTip
            })?;

        // don't mine off of an old burnchain block
        let burn_chain_tip = SortitionDB::get_canonical_burn_chain_tip(burn_db.conn())
            .expect("FATAL: failed to query sortition DB for canonical burn chain tip");

        if burn_chain_tip.consensus_hash != check_burn_block.consensus_hash {
            info!(
                "New canonical burn chain tip detected. Will not try to mine.";
                "new_consensus_hash" => %burn_chain_tip.consensus_hash,
                "old_consensus_hash" => %check_burn_block.consensus_hash,
                "new_burn_height" => burn_chain_tip.block_height,
                "old_burn_height" => check_burn_block.block_height
            );
            return Err(Error::BurnchainTipChanged);
        }

        debug!("Mining tenure's last consensus hash: {} (height {} hash {}), stacks tip consensus hash: {} (height {} hash {})",
               &check_burn_block.consensus_hash, check_burn_block.block_height, &check_burn_block.burn_header_hash,
               mine_tip_ch, parent_snapshot.block_height, &parent_snapshot.burn_header_hash);

        let coinbase_nonce = {
            let principal = miner_address.into();
            let account = chain_state
                .with_read_only_clarity_tx(
                    &burn_db.index_conn(),
                    &StacksBlockHeader::make_index_block_hash(mine_tip_ch, mine_tip_bh),
                    |conn| StacksChainState::get_account(conn, &principal),
                )
                .expect(&format!(
                    "BUG: stacks tip block {}/{} no longer exists after we queried it",
                    mine_tip_ch, mine_tip_bh
                ));
            account.nonce
        };

        Ok(MiningTenureInformation {
            stacks_parent_header: stacks_tip_header,
            parent_consensus_hash: mine_tip_ch.clone(),
            parent_block_burn_height: parent_block.block_height,
            parent_block_total_burn: parent_block.total_burn,
            parent_winning_vtxindex,
            coinbase_nonce,
        })
    }

    /// Return the assembled anchor block info and microblock private key on success.
    /// Return None if we couldn't build a block for whatever reason
    fn relayer_run_tenure(
        config: &Config,
        registered_key: RegisteredKey,
        chain_state: &mut StacksChainState,
        burn_db: &mut SortitionDB,
        burnchain: &Burnchain,
        burn_block: BlockSnapshot,
        keychain: &mut Keychain,
        mem_pool: &mut MemPoolDB,
        burn_fee_cap: u64,
        bitcoin_controller: &mut BitcoinRegtestController,
        last_mined_blocks: &Vec<&AssembledAnchorBlock>,
        event_dispatcher: &EventDispatcher,
    ) -> Option<(AssembledAnchorBlock, Secp256k1PrivateKey)> {
        let stacks_epoch = burn_db
            .index_conn()
            .get_stacks_epoch(burn_block.block_height as u32)
            .expect("Could not find a stacks epoch.");

        let MiningTenureInformation {
            mut stacks_parent_header,
            parent_consensus_hash,
            parent_block_burn_height,
            parent_block_total_burn,
            parent_winning_vtxindex,
            coinbase_nonce,
        } = if let Some(stacks_tip) = chain_state
            .get_stacks_chain_tip(burn_db)
            .expect("FATAL: could not query chain tip")
        {
            let miner_address = keychain.origin_address(config.is_mainnet()).unwrap();
            Self::get_mining_tenure_information(
                chain_state,
                burn_db,
                &burn_block,
                miner_address,
                &stacks_tip.consensus_hash,
                &stacks_tip.anchored_block_hash,
            )
            .ok()?
        } else {
            debug!("No Stacks chain tip known, will return a genesis block");
            let (network, _) = config.burnchain.get_bitcoin_network();
            let burnchain_params =
                BurnchainParameters::from_params(&config.burnchain.chain, &network)
                    .expect("Bitcoin network unsupported");

            let chain_tip = ChainTip::genesis(
                &burnchain_params.first_block_hash,
                burnchain_params.first_block_height.into(),
                burnchain_params.first_block_timestamp.into(),
            );

            MiningTenureInformation {
                stacks_parent_header: chain_tip.metadata,
                parent_consensus_hash: FIRST_BURNCHAIN_CONSENSUS_HASH.clone(),
                parent_block_burn_height: 0,
                parent_block_total_burn: 0,
                parent_winning_vtxindex: 0,
                coinbase_nonce: 0,
            }
        };

        // has the tip changed from our previously-mined block for this epoch?
        let attempt = if last_mined_blocks.len() <= 1 {
            // always mine if we've not mined a block for this epoch yet, or
            // if we've mined just one attempt, unconditionally try again (so we
            // can use `subsequent_miner_time_ms` in this attempt)
            if last_mined_blocks.len() == 1 {
                debug!("Have only attempted one block; unconditionally trying again");
            }
            last_mined_blocks.len() as u64 + 1
        } else {
            let mut best_attempt = 0;
            debug!(
                "Consider {} in-flight Stacks tip(s)",
                &last_mined_blocks.len()
            );
            for prev_block in last_mined_blocks.iter() {
                debug!(
                    "Consider in-flight block {} on Stacks tip {}/{} in {} with {} txs",
                    &prev_block.anchored_block.block_hash(),
                    &prev_block.parent_consensus_hash,
                    &prev_block.anchored_block.header.parent_block,
                    &prev_block.my_burn_hash,
                    &prev_block.anchored_block.txs.len()
                );

                if prev_block.anchored_block.txs.len() == 1 && prev_block.attempt == 1 {
                    // Don't let the fact that we've built an empty block during this sortition
                    // prevent us from trying again.
                    best_attempt = 1;
                    continue;
                }
                if prev_block.parent_consensus_hash == parent_consensus_hash
                    && prev_block.my_burn_hash == burn_block.burn_header_hash
                    && prev_block.anchored_block.header.parent_block
                        == stacks_parent_header.anchored_header.block_hash()
                {
                    // the anchored chain tip hasn't changed since we attempted to build a block.
                    // But, have discovered any new microblocks worthy of being mined?
                    if let Ok(Some(stream)) =
                        StacksChainState::load_descendant_staging_microblock_stream(
                            chain_state.db(),
                            &StacksBlockHeader::make_index_block_hash(
                                &prev_block.parent_consensus_hash,
                                &stacks_parent_header.anchored_header.block_hash(),
                            ),
                            0,
                            u16::MAX,
                        )
                    {
                        if (prev_block.anchored_block.header.parent_microblock
                            == BlockHeaderHash([0u8; 32])
                            && stream.len() == 0)
                            || (prev_block.anchored_block.header.parent_microblock
                                != BlockHeaderHash([0u8; 32])
                                && stream.len()
                                    <= (prev_block.anchored_block.header.parent_microblock_sequence
                                        as usize)
                                        + 1)
                        {
                            // the chain tip hasn't changed since we attempted to build a block.  Use what we
                            // already have.
                            debug!("Stacks tip is unchanged since we last tried to mine a block off of {}/{} at height {} with {} txs, in {} at burn height {}, and no new microblocks ({} <= {})",
                                   &prev_block.parent_consensus_hash, &prev_block.anchored_block.header.parent_block, prev_block.anchored_block.header.total_work.work,
                                   prev_block.anchored_block.txs.len(), prev_block.my_burn_hash, parent_block_burn_height, stream.len(), prev_block.anchored_block.header.parent_microblock_sequence);

                            return None;
                        } else {
                            // there are new microblocks!
                            // TODO: only consider rebuilding our anchored block if we (a) have
                            // time, and (b) the new microblocks are worth more than the new BTC
                            // fee minus the old BTC fee
                            debug!("Stacks tip is unchanged since we last tried to mine a block off of {}/{} at height {} with {} txs, in {} at burn height {}, but there are new microblocks ({} > {})",
                                   &prev_block.parent_consensus_hash, &prev_block.anchored_block.header.parent_block, prev_block.anchored_block.header.total_work.work,
                                   prev_block.anchored_block.txs.len(), prev_block.my_burn_hash, parent_block_burn_height, stream.len(), prev_block.anchored_block.header.parent_microblock_sequence);

                            best_attempt = cmp::max(best_attempt, prev_block.attempt);
                        }
                    } else {
                        // no microblock stream to confirm, and the stacks tip hasn't changed
                        debug!("Stacks tip is unchanged since we last tried to mine a block off of {}/{} at height {} with {} txs, in {} at burn height {}, and no microblocks present",
                               &prev_block.parent_consensus_hash, &prev_block.anchored_block.header.parent_block, prev_block.anchored_block.header.total_work.work,
                               prev_block.anchored_block.txs.len(), prev_block.my_burn_hash, parent_block_burn_height);

                        return None;
                    }
                } else {
                    if burn_block.burn_header_hash == prev_block.my_burn_hash {
                        // only try and re-mine if there was no sortition since the last chain tip
                        debug!("Stacks tip has changed to {}/{} since we last tried to mine a block in {} at burn height {}; attempt was {} (for Stacks tip {}/{})",
                               parent_consensus_hash, stacks_parent_header.anchored_header.block_hash(), prev_block.my_burn_hash, parent_block_burn_height, prev_block.attempt, &prev_block.parent_consensus_hash, &prev_block.anchored_block.header.parent_block);
                        best_attempt = cmp::max(best_attempt, prev_block.attempt);
                    } else {
                        debug!("Burn tip has changed to {} ({}) since we last tried to mine a block in {}",
                               &burn_block.burn_header_hash, burn_block.block_height, &prev_block.my_burn_hash);
                    }
                }
            }
            best_attempt + 1
        };

        // Generates a proof out of the sortition hash provided in the params.
        let vrf_proof = match keychain.generate_proof(
            &registered_key.vrf_public_key,
            burn_block.sortition_hash.as_bytes(),
        ) {
            Some(vrfp) => vrfp,
            None => {
                // Try to recover a key registered in a former session.
                // registered_key.block_height gives us a pointer to the height of the block
                // holding the key register op, but the VRF was derived using the height of one
                // of the parents blocks.
                let _ = keychain.rotate_vrf_keypair(registered_key.block_height - 1);
                match keychain.generate_proof(
                    &registered_key.vrf_public_key,
                    burn_block.sortition_hash.as_bytes(),
                ) {
                    Some(vrfp) => vrfp,
                    None => {
                        error!(
                            "Failed to generate proof with {:?}",
                            &registered_key.vrf_public_key
                        );
                        return None;
                    }
                }
            }
        };

        debug!(
            "Generated VRF Proof: {} over {} with key {}",
            vrf_proof.to_hex(),
            &burn_block.sortition_hash,
            &registered_key.vrf_public_key.to_hex()
        );

        // Generates a new secret key for signing the trail of microblocks
        // of the upcoming tenure.
        let microblock_secret_key = if attempt > 1 {
            match keychain.get_microblock_key() {
                Some(k) => k,
                None => {
                    error!(
                        "Failed to obtain microblock key for mining attempt";
                        "attempt" => %attempt
                    );
                    return None;
                }
            }
        } else {
            keychain.rotate_microblock_keypair(burn_block.block_height)
        };
        let mblock_pubkey_hash =
            Hash160::from_node_public_key(&StacksPublicKey::from_private(&microblock_secret_key));

        let coinbase_recipient_id = get_coinbase_with_recipient(&config, stacks_epoch.epoch_id);
        if let Some(id) = coinbase_recipient_id.as_ref() {
            debug!("Send coinbase rewards to {}", &id);
        }

        let coinbase_tx = inner_generate_coinbase_tx(
            keychain,
            coinbase_nonce,
            config.is_mainnet(),
            config.burnchain.chain_id,
            coinbase_recipient_id,
        );

        // find the longest microblock tail we can build off of
        let microblock_info_opt =
            match StacksChainState::load_descendant_staging_microblock_stream_with_poison(
                chain_state.db(),
                &StacksBlockHeader::make_index_block_hash(
                    &parent_consensus_hash,
                    &stacks_parent_header.anchored_header.block_hash(),
                ),
                0,
                u16::MAX,
            ) {
                Ok(x) => {
                    let num_mblocks = x.as_ref().map(|(mblocks, ..)| mblocks.len()).unwrap_or(0);
                    debug!(
                        "Loaded {} microblocks descending from {}/{}",
                        num_mblocks,
                        &parent_consensus_hash,
                        &stacks_parent_header.anchored_header.block_hash()
                    );
                    x
                }
                Err(e) => {
                    warn!(
                        "Failed to load descendant microblock stream from {}/{}: {:?}",
                        &parent_consensus_hash,
                        &stacks_parent_header.anchored_header.block_hash(),
                        &e
                    );
                    None
                }
            };

        if let Some((ref microblocks, ref poison_opt)) = &microblock_info_opt {
            if let Some(ref tail) = microblocks.last() {
                debug!(
                    "Confirm microblock stream tailed at {} (seq {})",
                    &tail.block_hash(),
                    tail.header.sequence
                );
            }

            // try and confirm as many microblocks as we can (but note that the stream itself may
            // be too long; we'll try again if that happens).
            stacks_parent_header.microblock_tail =
                microblocks.last().clone().map(|blk| blk.header.clone());

            if let Some(poison_payload) = poison_opt {
                let poison_microblock_tx = inner_generate_poison_microblock_tx(
                    keychain,
                    coinbase_nonce + 1,
                    poison_payload.clone(),
                    config.is_mainnet(),
                    config.burnchain.chain_id,
                );

                // submit the poison payload, privately, so we'll mine it when building the
                // anchored block.
                if let Err(e) = mem_pool.submit(
                    chain_state,
                    &parent_consensus_hash,
                    &stacks_parent_header.anchored_header.block_hash(),
                    &poison_microblock_tx,
                    Some(event_dispatcher),
                    &stacks_epoch.block_limit,
                    &stacks_epoch.epoch_id,
                ) {
                    warn!(
                        "Detected but failed to mine poison-microblock transaction: {:?}",
                        &e
                    );
                }
            }
        }

        let (anchored_block, _, _) = match StacksBlockBuilder::build_anchored_block(
            chain_state,
            &burn_db.index_conn(),
            mem_pool,
            &stacks_parent_header,
            parent_block_total_burn,
            vrf_proof.clone(),
            mblock_pubkey_hash,
            &coinbase_tx,
            config.make_block_builder_settings((last_mined_blocks.len() + 1) as u64, false),
            Some(event_dispatcher),
        ) {
            Ok(block) => block,
            Err(ChainstateError::InvalidStacksMicroblock(msg, mblock_header_hash)) => {
                // part of the parent microblock stream is invalid, so try again
                info!("Parent microblock stream is invalid; trying again without the offender {} (msg: {})", &mblock_header_hash, &msg);

                // truncate the stream
                stacks_parent_header.microblock_tail = match microblock_info_opt {
                    Some((microblocks, _)) => {
                        let mut tail = None;
                        for mblock in microblocks.into_iter() {
                            if mblock.block_hash() == mblock_header_hash {
                                break;
                            }
                            tail = Some(mblock);
                        }
                        if let Some(ref t) = &tail {
                            debug!(
                                "New parent microblock stream tail is {} (seq {})",
                                t.block_hash(),
                                t.header.sequence
                            );
                        }
                        tail.map(|t| t.header)
                    }
                    None => None,
                };

                // try again
                match StacksBlockBuilder::build_anchored_block(
                    chain_state,
                    &burn_db.index_conn(),
                    mem_pool,
                    &stacks_parent_header,
                    parent_block_total_burn,
                    vrf_proof.clone(),
                    mblock_pubkey_hash,
                    &coinbase_tx,
                    config.make_block_builder_settings((last_mined_blocks.len() + 1) as u64, false),
                    Some(event_dispatcher),
                ) {
                    Ok(block) => block,
                    Err(e) => {
                        error!("Failure mining anchor block even after removing offending microblock {}: {}", &mblock_header_hash, &e);
                        return None;
                    }
                }
            }
            Err(e) => {
                error!("Failure mining anchored block: {}", e);
                return None;
            }
        };
        let block_height = anchored_block.header.total_work.work;
        info!(
            "Succeeded assembling {} block #{}: {}, with {} txs, attempt {}",
            if parent_block_total_burn == 0 {
                "Genesis"
            } else {
                "Stacks"
            },
            block_height,
            anchored_block.block_hash(),
            anchored_block.txs.len(),
            attempt
        );

        // let's figure out the recipient set!
        let recipients = match get_next_recipients(
            &burn_block,
            chain_state,
            burn_db,
            burnchain,
            &OnChainRewardSetProvider(),
        ) {
            Ok(x) => x,
            Err(e) => {
                error!("Failure fetching recipient set: {:?}", e);
                return None;
            }
        };

        let commit_outs = if !burnchain.is_in_prepare_phase(burn_block.block_height + 1) {
            RewardSetInfo::into_commit_outs(recipients, config.is_mainnet())
        } else {
            vec![StacksAddress::burn_address(config.is_mainnet())]
        };

        // let's commit
        let op = inner_generate_block_commit_op(
            keychain.get_burnchain_signer(),
            anchored_block.block_hash(),
            burn_fee_cap,
            &registered_key,
            parent_block_burn_height
                .try_into()
                .expect("Could not convert parent block height into u32"),
            parent_winning_vtxindex,
            VRFSeed::from_proof(&vrf_proof),
            commit_outs,
            burn_block.block_height,
        );

        let cur_burn_chain_tip = SortitionDB::get_canonical_burn_chain_tip(burn_db.conn())
            .expect("FATAL: failed to query sortition DB for canonical burn chain tip");

        // last chance -- confirm that the stacks tip and burnchain tip are unchanged (since it could have taken long
        // enough to build this block that another block could have arrived).
        if let Some(stacks_tip) = chain_state
            .get_stacks_chain_tip(burn_db)
            .expect("FATAL: could not query chain tip")
        {
            if stacks_tip.anchored_block_hash != anchored_block.header.parent_block
                || parent_consensus_hash != stacks_tip.consensus_hash
                || cur_burn_chain_tip.sortition_id != burn_block.sortition_id
            {
                debug!(
                    "Cancel block-commit; chain tip(s) have changed";
                    "block_hash" => %anchored_block.block_hash(),
                    "tx_count" => anchored_block.txs.len(),
                    "target_height" => %anchored_block.header.total_work.work,
                    "parent_consensus_hash" => %parent_consensus_hash,
                    "parent_block_hash" => %anchored_block.header.parent_block,
                    "parent_microblock_hash" => %anchored_block.header.parent_microblock,
                    "parent_microblock_seq" => anchored_block.header.parent_microblock_sequence,
                    "old_tip_burn_block_hash" => %burn_block.burn_header_hash,
                    "old_tip_burn_block_height" => burn_block.block_height,
                    "old_tip_burn_block_sortition_id" => %burn_block.sortition_id,
                    "attempt" => attempt,
                    "new_stacks_tip_block_hash" => %stacks_tip.anchored_block_hash,
                    "new_stacks_tip_consensus_hash" => %stacks_tip.consensus_hash,
                    "new_tip_burn_block_height" => cur_burn_chain_tip.block_height,
                    "new_tip_burn_block_sortition_id" => %cur_burn_chain_tip.sortition_id,
                    "new_burn_block_sortition_id" => %cur_burn_chain_tip.sortition_id
                );
                return None;
            }
        }

        let mut op_signer = keychain.generate_op_signer();
        debug!(
            "Submit block-commit";
            "block_hash" => %anchored_block.block_hash(),
            "tx_count" => anchored_block.txs.len(),
            "target_height" => anchored_block.header.total_work.work,
            "parent_consensus_hash" => %parent_consensus_hash,
            "parent_block_hash" => %anchored_block.header.parent_block,
            "parent_microblock_hash" => %anchored_block.header.parent_microblock,
            "parent_microblock_seq" => anchored_block.header.parent_microblock_sequence,
            "tip_burn_block_hash" => %burn_block.burn_header_hash,
            "tip_burn_block_height" => burn_block.block_height,
            "tip_burn_block_sortition_id" => %burn_block.sortition_id,
            "attempt" => attempt
        );

        let send_tx = fault_injection_delay_transactions(
            bitcoin_controller,
            cur_burn_chain_tip.block_height,
            burn_block.block_height,
            &op,
            &mut op_signer,
            attempt,
        );
        if send_tx {
            let res = bitcoin_controller.submit_operation(op, &mut op_signer, attempt);
            if !res {
                if !config.node.mock_mining {
                    warn!("Failed to submit Bitcoin transaction");
                    return None;
                } else {
                    debug!("Mock-mining enabled; not sending Bitcoin transaction");
                }
            }
        }

        Some((
            AssembledAnchorBlock {
                parent_consensus_hash: parent_consensus_hash,
                my_burn_hash: burn_block.burn_header_hash,
                anchored_block,
                attempt,
            },
            microblock_secret_key,
        ))
    }

    /// Process a state coming from the burnchain, by extracting the validated KeyRegisterOp
    /// and inspecting if a sortition was won.
    /// `ibd`: boolean indicating whether or not we are in the initial block download
    pub fn process_burnchain_state(
        &mut self,
        sortdb: &SortitionDB,
        sort_id: &SortitionId,
        ibd: bool,
    ) -> Option<BlockSnapshot> {
        let mut last_sortitioned_block = None;

        let ic = sortdb.index_conn();

        let block_snapshot = SortitionDB::get_block_snapshot(&ic, sort_id)
            .expect("Failed to obtain block snapshot for processed burn block.")
            .expect("Failed to obtain block snapshot for processed burn block.");
        let block_height = block_snapshot.block_height;

        let block_commits =
            SortitionDB::get_block_commits_by_block(&ic, &block_snapshot.sortition_id)
                .expect("Unexpected SortitionDB error fetching block commits");

        update_active_miners_count_gauge(block_commits.len() as i64);

        let (_, network) = self.config.burnchain.get_bitcoin_network();

        for op in block_commits.into_iter() {
            if op.txid == block_snapshot.winning_block_txid {
                info!(
                    "Received burnchain block #{} including block_commit_op (winning) - {} ({})",
                    block_height,
                    op.apparent_sender.to_bitcoin_address(network),
                    &op.block_header_hash
                );
                last_sortitioned_block = Some((block_snapshot.clone(), op.vtxindex));
            } else {
                if self.is_miner {
                    info!(
                        "Received burnchain block #{} including block_commit_op - {} ({})",
                        block_height,
                        op.apparent_sender.to_bitcoin_address(network),
                        &op.block_header_hash
                    );
                }
            }
        }

        let key_registers =
            SortitionDB::get_leader_keys_by_block(&ic, &block_snapshot.sortition_id)
                .expect("Unexpected SortitionDB error fetching key registers");

        let node_address = Keychain::address_from_burnchain_signer(
            &self.burnchain_signer,
            self.config.is_mainnet(),
        );

        for op in key_registers.into_iter() {
            if op.address == node_address {
                if self.is_miner {
                    info!(
                        "Received burnchain block #{} including key_register_op - {}",
                        block_height, op.address
                    );
                }
                if !ibd {
                    // not in initial block download, so we're not just replaying an old key.
                    // Registered key has been mined
                    if let LeaderKeyRegistrationState::Pending = self.leader_key_registration_state
                    {
                        self.leader_key_registration_state =
                            LeaderKeyRegistrationState::Active(RegisteredKey {
                                vrf_public_key: op.public_key,
                                block_height: op.block_height as u64,
                                op_vtxindex: op.vtxindex as u32,
                            });
                    }
                }
            }
        }

        // no-op on UserBurnSupport ops are not supported / produced at this point.

        set_last_sortition(&mut self.last_sortition, block_snapshot);
        last_sortitioned_block.map(|x| x.0)
    }

    pub fn join(self) {
        self.relayer_thread_handle.join().unwrap();
        self.p2p_thread_handle.join().unwrap();
    }
}
