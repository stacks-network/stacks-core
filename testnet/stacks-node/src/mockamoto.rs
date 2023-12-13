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
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::thread::{sleep, JoinHandle};
use std::time::Duration;

use clarity::vm::ast::ASTRules;
use clarity::vm::Value as ClarityValue;
use lazy_static::lazy_static;
use stacks::burnchains::bitcoin::address::{
    BitcoinAddress, LegacyBitcoinAddress, LegacyBitcoinAddressType,
};
use stacks::burnchains::bitcoin::{
    BitcoinBlock, BitcoinInputType, BitcoinNetworkType, BitcoinTransaction,
    BitcoinTxInputStructured, BitcoinTxOutput,
};
use stacks::burnchains::db::{BurnchainDB, BurnchainHeaderReader};
use stacks::burnchains::{
    BurnchainBlock, BurnchainBlockHeader, BurnchainSigner, Error as BurnchainError, Txid,
};
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::burn::operations::leader_block_commit::BURN_BLOCK_MINED_AT_MODULUS;
use stacks::chainstate::burn::operations::{
    BlockstackOperationType, LeaderBlockCommitOp, LeaderKeyRegisterOp,
};
use stacks::chainstate::burn::BlockSnapshot;
use stacks::chainstate::coordinator::comm::CoordinatorReceivers;
use stacks::chainstate::coordinator::{
    ChainsCoordinator, ChainsCoordinatorConfig, CoordinatorCommunication,
};
use stacks::chainstate::nakamoto::{
    NakamotoBlock, NakamotoBlockHeader, NakamotoChainState, SetupBlockResult,
};
use stacks::chainstate::stacks::address::PoxAddress;
use stacks::chainstate::stacks::db::{ChainStateBootData, ClarityTx, StacksChainState};
use stacks::chainstate::stacks::miner::{
    BlockBuilder, BlockBuilderSettings, BlockLimitFunction, MinerStatus, TransactionResult,
};
use stacks::chainstate::stacks::{
    CoinbasePayload, Error as ChainstateError, StacksBlockBuilder, StacksTransaction,
    StacksTransactionSigner, TenureChangeCause, TenureChangePayload, ThresholdSignature,
    TransactionAuth, TransactionContractCall, TransactionPayload, TransactionVersion,
    MAX_EPOCH_SIZE, MINER_BLOCK_CONSENSUS_HASH, MINER_BLOCK_HEADER_HASH,
};
use stacks::core::mempool::MemPoolWalkSettings;
use stacks::core::{
    MemPoolDB, StacksEpoch, BLOCK_LIMIT_MAINNET_10, HELIUM_BLOCK_LIMIT_20, PEER_VERSION_EPOCH_1_0,
    PEER_VERSION_EPOCH_2_0, PEER_VERSION_EPOCH_2_05, PEER_VERSION_EPOCH_2_1,
    PEER_VERSION_EPOCH_2_2, PEER_VERSION_EPOCH_2_3, PEER_VERSION_EPOCH_2_4, PEER_VERSION_EPOCH_2_5,
    PEER_VERSION_EPOCH_3_0, STACKS_EPOCH_3_0_MARKER, TX_BLOCK_LIMIT_PROPORTION_HEURISTIC,
};
use stacks::net::atlas::{AtlasConfig, AtlasDB};
use stacks::net::relay::Relayer;
use stacks::net::stackerdb::StackerDBs;
use stacks::util_lib::db::Error as DBError;
use stacks_common::address::{AddressHashMode, C32_ADDRESS_VERSION_TESTNET_SINGLESIG};
use stacks_common::codec::StacksMessageCodec;
use stacks_common::consts::{
    FIRST_BURNCHAIN_CONSENSUS_HASH, FIRST_STACKS_BLOCK_HASH, STACKS_EPOCH_MAX,
};
use stacks_common::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, ConsensusHash, StacksAddress, StacksBlockId,
    StacksPrivateKey, VRFSeed,
};
use stacks_common::types::{PrivateKey, StacksEpochId};
use stacks_common::util::hash::{Hash160, MerkleTree, Sha512Trunc256Sum};
use stacks_common::util::secp256k1::{MessageSignature, Secp256k1PublicKey};
use stacks_common::util::vrf::{VRFPrivateKey, VRFProof, VRFPublicKey, VRF};

use self::signer::SelfSigner;
use crate::globals::{NeonGlobals as Globals, RelayerDirective};
use crate::neon::Counters;
use crate::neon_node::{PeerThread, StacksNode, BLOCK_PROCESSOR_STACK_SIZE};
use crate::syncctl::PoxSyncWatchdogComms;
use crate::{Config, EventDispatcher};

pub mod signer;
#[cfg(test)]
mod tests;

lazy_static! {
    pub static ref STACKS_EPOCHS_MOCKAMOTO: [StacksEpoch; 9] = [
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch10,
            start_height: 0,
            end_height: 0,
            block_limit: BLOCK_LIMIT_MAINNET_10.clone(),
            network_epoch: PEER_VERSION_EPOCH_1_0
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch20,
            start_height: 0,
            end_height: 1,
            block_limit: HELIUM_BLOCK_LIMIT_20.clone(),
            network_epoch: PEER_VERSION_EPOCH_2_0
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch2_05,
            start_height: 1,
            end_height: 2,
            block_limit: HELIUM_BLOCK_LIMIT_20.clone(),
            network_epoch: PEER_VERSION_EPOCH_2_05
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch21,
            start_height: 2,
            end_height: 3,
            block_limit: HELIUM_BLOCK_LIMIT_20.clone(),
            network_epoch: PEER_VERSION_EPOCH_2_1
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch22,
            start_height: 3,
            end_height: 4,
            block_limit: HELIUM_BLOCK_LIMIT_20.clone(),
            network_epoch: PEER_VERSION_EPOCH_2_2
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch23,
            start_height: 4,
            end_height: 5,
            block_limit: HELIUM_BLOCK_LIMIT_20.clone(),
            network_epoch: PEER_VERSION_EPOCH_2_3
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch24,
            start_height: 5,
            end_height: 6,
            block_limit: HELIUM_BLOCK_LIMIT_20.clone(),
            network_epoch: PEER_VERSION_EPOCH_2_4
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch25,
            start_height: 6,
            end_height: 7,
            block_limit: HELIUM_BLOCK_LIMIT_20.clone(),
            network_epoch: PEER_VERSION_EPOCH_2_5
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch30,
            start_height: 7,
            end_height: STACKS_EPOCH_MAX,
            block_limit: HELIUM_BLOCK_LIMIT_20.clone(),
            network_epoch: PEER_VERSION_EPOCH_3_0
        },
    ];
}

/// Produce a mock bitcoin block that is descended from `parent_snapshot` and includes
/// `ops`. This method uses `miner_pkh` to set the inputs and outputs of any supplied
/// block commits or leader key registrations
fn make_burn_block(
    parent_snapshot: &BlockSnapshot,
    miner_pkh: &Hash160,
    ops: Vec<BlockstackOperationType>,
) -> Result<BitcoinBlock, BurnchainError> {
    let block_height = parent_snapshot.block_height + 1;
    let mut mock_burn_hash_contents = [0u8; 32];
    mock_burn_hash_contents[0..8].copy_from_slice((block_height + 1).to_be_bytes().as_ref());

    let txs = ops.into_iter().map(|op| {
        let mut data = match &op {
            BlockstackOperationType::LeaderKeyRegister(op) => op.serialize_to_vec(),
            BlockstackOperationType::LeaderBlockCommit(op) => op.serialize_to_vec(),
            _ => panic!("Attempted to mock unexpected blockstack operation."),
        };

        data.remove(0);

        let (inputs, outputs) = if let BlockstackOperationType::LeaderBlockCommit(ref op) = op {
            let burn_output = BitcoinTxOutput {
                units: op.burn_fee,
                address: BitcoinAddress::Legacy(LegacyBitcoinAddress {
                    addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                    network_id: BitcoinNetworkType::Testnet,
                    bytes: Hash160([0; 20]),
                }),
            };

            let change_output = BitcoinTxOutput {
                units: 1_000_000_000_000,
                address: BitcoinAddress::Legacy(LegacyBitcoinAddress {
                    addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                    network_id: BitcoinNetworkType::Testnet,
                    bytes: miner_pkh.clone(),
                }),
            };

            let tx_ref = (parent_snapshot.winning_block_txid.clone(), 3);

            let input = BitcoinTxInputStructured {
                keys: vec![],
                num_required: 0,
                in_type: BitcoinInputType::Standard,
                tx_ref,
            };

            (
                vec![input.into()],
                vec![burn_output.clone(), burn_output, change_output],
            )
        } else {
            (
                vec![BitcoinTxInputStructured {
                    keys: vec![],
                    num_required: 0,
                    in_type: BitcoinInputType::Standard,
                    tx_ref: (Txid([0; 32]), 0),
                }
                .into()],
                vec![BitcoinTxOutput {
                    units: 1_000_000_000_000,
                    address: BitcoinAddress::Legacy(LegacyBitcoinAddress {
                        addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Testnet,
                        bytes: miner_pkh.clone(),
                    }),
                }],
            )
        };

        BitcoinTransaction {
            txid: op.txid(),
            vtxindex: op.vtxindex(),
            opcode: op.opcode() as u8,
            data,
            data_amt: 0,
            inputs,
            outputs,
        }
    });

    Ok(BitcoinBlock {
        block_height,
        block_hash: BurnchainHeaderHash(mock_burn_hash_contents),
        parent_block_hash: parent_snapshot.burn_header_hash.clone(),
        txs: txs.collect(),
        timestamp: 100 * u64::from(block_height + 1),
    })
}

/// This struct wraps all the state required for operating a
/// stacks-node in `mockamoto` mode.
///
/// This mode of operation is a single-node network in which bitcoin
/// blocks are simulated: no `bitcoind` is communicated with (either
/// operating as regtest, testnet or mainnet). This operation mode
/// is useful for testing the stacks-only operation of Nakamoto.
///
/// During operation, the mockamoto node issues `stack-stx` and
/// `stack-extend` contract-calls to ensure that the miner is a member
/// of the current stacking set. This ensures nakamoto blocks can be
/// produced with tenure change txs.
///
pub struct MockamotoNode {
    sortdb: SortitionDB,
    mempool: MemPoolDB,
    chainstate: StacksChainState,
    self_signer: SelfSigner,
    miner_key: StacksPrivateKey,
    vrf_key: VRFPrivateKey,
    relay_rcv: Option<Receiver<RelayerDirective>>,
    coord_rcv: Option<CoordinatorReceivers>,
    dispatcher: EventDispatcher,
    pub globals: Globals,
    config: Config,
}

struct MockamotoBlockBuilder {
    txs: Vec<StacksTransaction>,
    bytes_so_far: u64,
}

/// This struct is used by mockamoto to pass the burnchain indexer
///  parameter to the `ChainsCoordinator`. It errors on every
///  invocation except `read_burnchain_headers`.
///
/// The `ChainsCoordinator` only uses this indexer for evaluating
///  affirmation maps, which should never be evaluated in mockamoto.
/// This is passed to the Burnchain DB block processor, though, which
///  requires `read_burnchain_headers` (to generate affirmation maps)
struct MockBurnchainIndexer(BurnchainDB);

impl BurnchainHeaderReader for MockBurnchainIndexer {
    fn read_burnchain_headers(
        &self,
        start_height: u64,
        end_height: u64,
    ) -> Result<Vec<BurnchainBlockHeader>, DBError> {
        let mut output = vec![];
        for i in start_height..end_height {
            let header = BurnchainDB::get_burnchain_header(self.0.conn(), i)
                .map_err(|e| DBError::Other(e.to_string()))?
                .ok_or_else(|| DBError::NotFoundError)?;
            output.push(header);
        }
        Ok(output)
    }
    fn get_burnchain_headers_height(&self) -> Result<u64, DBError> {
        Err(DBError::NoDBError)
    }
    fn find_burnchain_header_height(
        &self,
        _header_hash: &BurnchainHeaderHash,
    ) -> Result<Option<u64>, DBError> {
        Err(DBError::NoDBError)
    }
}

impl BlockBuilder for MockamotoBlockBuilder {
    fn try_mine_tx_with_len(
        &mut self,
        clarity_tx: &mut ClarityTx,
        tx: &StacksTransaction,
        tx_len: u64,
        limit_behavior: &BlockLimitFunction,
        ast_rules: ASTRules,
    ) -> TransactionResult {
        if self.bytes_so_far + tx_len >= MAX_EPOCH_SIZE.into() {
            return TransactionResult::skipped(tx, "BlockSizeLimit".into());
        }

        if BlockLimitFunction::NO_LIMIT_HIT != *limit_behavior {
            return TransactionResult::skipped(tx, "LimitReached".into());
        }

        let (fee, receipt) = match StacksChainState::process_transaction(
            clarity_tx, tx, true, ast_rules,
        ) {
            Ok(x) => x,
            Err(ChainstateError::CostOverflowError(cost_before, cost_after, total_budget)) => {
                clarity_tx.reset_cost(cost_before.clone());
                if total_budget.proportion_largest_dimension(&cost_before)
                    < TX_BLOCK_LIMIT_PROPORTION_HEURISTIC
                {
                    warn!(
                        "Transaction {} consumed over {}% of block budget, marking as invalid; budget was {}",
                        tx.txid(),
                        100 - TX_BLOCK_LIMIT_PROPORTION_HEURISTIC,
                        &total_budget
                    );
                    return TransactionResult::error(&tx, ChainstateError::TransactionTooBigError);
                } else {
                    warn!(
                        "Transaction {} reached block cost {}; budget was {}",
                        tx.txid(),
                        &cost_after,
                        &total_budget
                    );
                    return TransactionResult::skipped_due_to_error(
                        &tx,
                        ChainstateError::BlockTooBigError,
                    );
                }
            }
            Err(e) => return TransactionResult::error(&tx, e),
        };

        info!("Include tx";
              "tx" => %tx.txid(),
              "payload" => tx.payload.name(),
              "origin" => %tx.origin_address());

        self.txs.push(tx.clone());
        self.bytes_so_far += tx_len;

        TransactionResult::success(tx, fee, receipt)
    }
}

impl MockamotoNode {
    pub fn new(config: &Config) -> Result<MockamotoNode, String> {
        let miner_key = config
            .miner
            .mining_key
            .clone()
            .ok_or("Mockamoto node must be configured with `miner.mining_key`")?;
        let vrf_key = VRFPrivateKey::new();

        let stacker_pk = Secp256k1PublicKey::from_private(&miner_key);
        let stacker_pk_hash = Hash160::from_node_public_key(&stacker_pk);

        let stacker = StacksAddress {
            version: C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
            bytes: stacker_pk_hash,
        };

        let burnchain = config.get_burnchain();
        let (sortdb, _burndb) = burnchain
            .connect_db(
                true,
                BurnchainHeaderHash([0; 32]),
                100,
                STACKS_EPOCHS_MOCKAMOTO.to_vec(),
            )
            .map_err(|e| e.to_string())?;

        let mut initial_balances: Vec<_> = config
            .initial_balances
            .iter()
            .map(|balance| (balance.address.clone(), balance.amount))
            .collect();

        initial_balances.push((stacker.into(), 100_000_000_000_000));

        let mut boot_data = ChainStateBootData::new(&burnchain, initial_balances, None);
        let (chainstate, boot_receipts) = StacksChainState::open_and_exec(
            config.is_mainnet(),
            config.burnchain.chain_id,
            &config.get_chainstate_path_str(),
            Some(&mut boot_data),
            Some(config.node.get_marf_opts()),
        )
        .unwrap();
        let mempool = PeerThread::connect_mempool_db(config);

        let (coord_rcv, coord_comms) = CoordinatorCommunication::instantiate();
        let miner_status = Arc::new(Mutex::new(MinerStatus::make_ready(100)));
        let (relay_send, relay_rcv) = sync_channel(10);
        let counters = Counters::new();
        let should_keep_running = Arc::new(AtomicBool::new(true));
        let sync_comms = PoxSyncWatchdogComms::new(should_keep_running.clone());

        let globals = Globals::new(
            coord_comms,
            miner_status,
            relay_send,
            counters,
            sync_comms,
            should_keep_running,
        );

        let mut event_dispatcher = EventDispatcher::new();
        for observer in config.events_observers.iter() {
            event_dispatcher.register_observer(observer);
        }

        crate::run_loop::announce_boot_receipts(
            &mut event_dispatcher,
            &chainstate,
            &burnchain.pox_constants,
            &boot_receipts,
        );

        Ok(MockamotoNode {
            sortdb,
            self_signer: SelfSigner::single_signer(),
            chainstate,
            miner_key,
            vrf_key,
            relay_rcv: Some(relay_rcv),
            coord_rcv: Some(coord_rcv),
            dispatcher: event_dispatcher,
            mempool,
            globals,
            config: config.clone(),
        })
    }

    fn spawn_chains_coordinator(&mut self) -> JoinHandle<()> {
        let config = self.config.clone();
        let atlas_config = AtlasConfig::new(false);

        let (chainstate, _) = self.chainstate.reopen().unwrap();
        let coord_config = ChainsCoordinatorConfig {
            always_use_affirmation_maps: false,
            require_affirmed_anchor_blocks: false,
            ..ChainsCoordinatorConfig::new()
        };
        let mut dispatcher = self.dispatcher.clone();
        let burnchain = self.config.get_burnchain();
        let burndb = burnchain.open_burnchain_db(true).unwrap();
        let coordinator_indexer = MockBurnchainIndexer(burndb);
        let atlas_db = AtlasDB::connect(
            atlas_config.clone(),
            &self.config.get_atlas_db_file_path(),
            true,
        )
        .unwrap();
        let miner_status = Arc::new(Mutex::new(MinerStatus::make_ready(100)));
        let coordinator_receivers = self.coord_rcv.take().unwrap();

        thread::Builder::new()
            .name(format!("chains-coordinator-{}", &config.node.rpc_bind))
            .stack_size(BLOCK_PROCESSOR_STACK_SIZE)
            .spawn(move || {
                debug!(
                    "chains-coordinator thread ID is {:?}",
                    thread::current().id()
                );
                ChainsCoordinator::run(
                    coord_config,
                    chainstate,
                    burnchain,
                    &mut dispatcher,
                    coordinator_receivers,
                    atlas_config,
                    Some(&mut ()),
                    Some(&mut ()),
                    miner_status,
                    coordinator_indexer,
                    atlas_db,
                );
            })
            .expect("FATAL: failed to start chains coordinator thread")
    }

    pub fn run(&mut self) {
        info!("Starting the mockamoto node by issuing initial empty mock burn blocks");
        let coordinator = self.spawn_chains_coordinator();

        self.produce_burnchain_block(true).unwrap();
        self.produce_burnchain_block(true).unwrap();
        self.produce_burnchain_block(true).unwrap();
        self.produce_burnchain_block(true).unwrap();
        self.produce_burnchain_block(true).unwrap();
        self.produce_burnchain_block(true).unwrap();

        let mut p2p_net = StacksNode::setup_peer_network(
            &self.config,
            &self.config.atlas,
            self.config.get_burnchain(),
        );

        let stackerdbs = StackerDBs::connect(&self.config.get_stacker_db_file_path(), true)
            .expect("FATAL: failed to connect to stacker DB");

        let _relayer = Relayer::from_p2p(&mut p2p_net, stackerdbs);

        let relayer_rcv = self.relay_rcv.take().unwrap();
        let relayer_globals = self.globals.clone();
        let mock_relayer_thread = thread::Builder::new()
            .name("mock-relayer".into())
            .spawn(move || {
                while relayer_globals.keep_running() {
                    match relayer_rcv.recv_timeout(Duration::from_millis(500)) {
                        Ok(dir) => {
                            if let RelayerDirective::Exit = dir {
                                break;
                            }
                        }
                        Err(RecvTimeoutError::Timeout) => continue,
                        Err(e) => {
                            warn!("Error accepting relayer directive: {e:?}");
                            break;
                        }
                    }
                }
            })
            .expect("FATAL: failed to start mock relayer thread");

        let peer_thread = PeerThread::new_all(
            self.globals.clone(),
            &self.config,
            self.config.get_burnchain().pox_constants,
            p2p_net,
        );

        let ev_dispatcher = self.dispatcher.clone();
        let peer_thread = thread::Builder::new()
            .stack_size(BLOCK_PROCESSOR_STACK_SIZE)
            .name("p2p".into())
            .spawn(move || {
                StacksNode::p2p_main(peer_thread, ev_dispatcher);
            })
            .expect("FATAL: failed to start p2p thread");

        while self.globals.keep_running() {
            self.produce_burnchain_block(false).unwrap();
            let expected_chain_length = self.mine_and_stage_block().unwrap();
            self.globals.coord().announce_new_stacks_block();
            let _ = self.wait_for_stacks_block(expected_chain_length);
            sleep(Duration::from_millis(self.config.node.mockamoto_time_ms));
        }

        self.globals.coord().stop_chains_coordinator();

        if let Err(e) = coordinator.join() {
            warn!("Error joining coordinator thread during shutdown: {e:?}");
        }
        if let Err(e) = mock_relayer_thread.join() {
            warn!("Error joining coordinator thread during shutdown: {e:?}");
        }
        if let Err(e) = peer_thread.join() {
            warn!("Error joining p2p thread during shutdown: {e:?}");
        }
    }

    fn wait_for_stacks_block(&mut self, expected_length: u64) -> Result<(), ChainstateError> {
        while self.globals.keep_running() {
            let chain_length = match NakamotoChainState::get_canonical_block_header(
                self.chainstate.db(),
                &self.sortdb,
            ) {
                Ok(Some(chain_tip)) => chain_tip.stacks_block_height,
                Ok(None) | Err(ChainstateError::NoSuchBlockError) => 0,
                Err(e) => return Err(e),
            };
            if chain_length >= expected_length {
                return Ok(());
            }
            sleep(Duration::from_millis(100));
        }
        Err(ChainstateError::NoSuchBlockError)
    }

    fn produce_burnchain_block(&mut self, initializing: bool) -> Result<(), BurnchainError> {
        let miner_pk = Secp256k1PublicKey::from_private(&self.miner_key);
        let miner_pk_hash = Hash160::from_node_public_key(&miner_pk);

        let parent_snapshot = SortitionDB::get_canonical_burn_chain_tip(&self.sortdb.conn())?;
        info!("Mocking bitcoin block"; "parent_height" => parent_snapshot.block_height);
        let burn_height = parent_snapshot.block_height + 1;

        let mut ops = vec![];

        if burn_height == 1 {
            let mut txid = [2u8; 32];
            txid[0..8].copy_from_slice((burn_height + 1).to_be_bytes().as_ref());
            let key_register = LeaderKeyRegisterOp {
                consensus_hash: ConsensusHash([0; 20]),
                public_key: VRFPublicKey::from_private(&self.vrf_key),
                memo: miner_pk_hash.as_bytes().to_vec(),
                txid: Txid(txid),
                vtxindex: 0,
                block_height: burn_height,
                burn_header_hash: BurnchainHeaderHash([0; 32]),
            };
            ops.push(BlockstackOperationType::LeaderKeyRegister(key_register));
        } else if !initializing {
            let mut txid = [1u8; 32];
            txid[0..8].copy_from_slice((burn_height + 1).to_be_bytes().as_ref());
            txid[8..16].copy_from_slice((0u64).to_be_bytes().as_ref());

            let (parent_block_ptr, parent_vtxindex) =
                if parent_snapshot.winning_block_txid.as_bytes() == &[0; 32] {
                    (0, 0)
                } else {
                    (parent_snapshot.block_height.try_into().unwrap(), 0)
                };

            let parent_vrf_proof = NakamotoChainState::get_block_vrf_proof(
                self.chainstate.db(),
                &parent_snapshot.consensus_hash,
            )
            .map_err(|_e| BurnchainError::MissingParentBlock)?
            .unwrap_or_else(|| VRFProof::empty());

            let vrf_seed = VRFSeed::from_proof(&parent_vrf_proof);
            let parent_block_id = parent_snapshot.get_canonical_stacks_block_id();

            let block_commit = LeaderBlockCommitOp {
                block_header_hash: BlockHeaderHash(parent_block_id.0),
                new_seed: vrf_seed,
                parent_block_ptr,
                parent_vtxindex,
                key_block_ptr: 1,
                key_vtxindex: 0,
                memo: vec![STACKS_EPOCH_3_0_MARKER],
                burn_fee: 5000,
                input: (parent_snapshot.winning_block_txid.clone(), 3),
                burn_parent_modulus: u8::try_from(
                    parent_snapshot.block_height % BURN_BLOCK_MINED_AT_MODULUS,
                )
                .unwrap(),
                apparent_sender: BurnchainSigner(miner_pk_hash.to_string()),
                commit_outs: vec![
                    PoxAddress::Standard(StacksAddress::burn_address(false), None),
                    PoxAddress::Standard(StacksAddress::burn_address(false), None),
                ],
                sunset_burn: 0,
                txid: Txid(txid),
                vtxindex: 0,
                block_height: burn_height,
                burn_header_hash: BurnchainHeaderHash([0; 32]),
            };
            ops.push(BlockstackOperationType::LeaderBlockCommit(block_commit))
        }

        let new_burn_block = make_burn_block(&parent_snapshot, &miner_pk_hash, ops)?;

        let burnchain = self.config.get_burnchain();
        let burndb = burnchain.open_burnchain_db(true).unwrap();
        let indexer = MockBurnchainIndexer(burndb);
        let mut burndb = burnchain.open_burnchain_db(true).unwrap();

        burndb.store_new_burnchain_block(
            &burnchain,
            &indexer,
            &BurnchainBlock::Bitcoin(new_burn_block),
            StacksEpochId::Epoch30,
        )?;

        self.globals.coord().announce_new_burn_block();
        let mut cur_snapshot = SortitionDB::get_canonical_burn_chain_tip(&self.sortdb.conn())?;
        while cur_snapshot.burn_header_hash == parent_snapshot.burn_header_hash {
            thread::sleep(Duration::from_millis(100));
            cur_snapshot = SortitionDB::get_canonical_burn_chain_tip(&self.sortdb.conn())?;
        }

        Ok(())
    }

    fn mine_stacks_block(&mut self) -> Result<NakamotoBlock, ChainstateError> {
        let miner_principal = StacksAddress::from_public_keys(
            C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
            &AddressHashMode::SerializeP2PKH,
            1,
            &vec![Secp256k1PublicKey::from_private(&self.miner_key)],
        )
        .unwrap()
        .into();
        let sortition_tip = SortitionDB::get_canonical_burn_chain_tip(self.sortdb.conn())?;
        let chain_id = self.chainstate.chain_id;
        let (mut chainstate_tx, clarity_instance) = self.chainstate.chainstate_tx_begin().unwrap();

        let (is_genesis, chain_tip_bh, chain_tip_ch) =
            match NakamotoChainState::get_canonical_block_header(&chainstate_tx, &self.sortdb) {
                Ok(Some(chain_tip)) => (
                    false,
                    chain_tip.anchored_header.block_hash(),
                    chain_tip.consensus_hash,
                ),
                Ok(None) | Err(ChainstateError::NoSuchBlockError) =>
                // No stacks tip yet, parent should be genesis
                {
                    (
                        true,
                        FIRST_STACKS_BLOCK_HASH,
                        FIRST_BURNCHAIN_CONSENSUS_HASH,
                    )
                }
                Err(e) => return Err(e),
            };

        let parent_block_id = StacksBlockId::new(&chain_tip_ch, &chain_tip_bh);

        let (parent_chain_length, parent_burn_height) = if is_genesis {
            (0, 0)
        } else {
            let tip_info = NakamotoChainState::get_block_header(&chainstate_tx, &parent_block_id)?
                .ok_or(ChainstateError::NoSuchBlockError)?;
            (tip_info.stacks_block_height, tip_info.burn_header_height)
        };

        let miner_nonce = if is_genesis {
            0
        } else {
            let sortdb_conn = self.sortdb.index_conn();
            let mut clarity_conn = clarity_instance.read_only_connection_checked(
                &parent_block_id,
                &chainstate_tx,
                &sortdb_conn,
            )?;
            StacksChainState::get_nonce(&mut clarity_conn, &miner_principal)
        };

        info!(
            "Mining block"; "parent_chain_length" => parent_chain_length, "chain_tip_bh" => %chain_tip_bh,
            "chain_tip_ch" => %chain_tip_ch, "miner_account" => %miner_principal, "miner_nonce" => %miner_nonce,
        );

        let vrf_proof = VRF::prove(&self.vrf_key, sortition_tip.sortition_hash.as_bytes());
        let coinbase_tx_payload =
            TransactionPayload::Coinbase(CoinbasePayload([1; 32]), None, Some(vrf_proof));
        let mut coinbase_tx = StacksTransaction::new(
            TransactionVersion::Testnet,
            TransactionAuth::from_p2pkh(&self.miner_key).unwrap(),
            coinbase_tx_payload,
        );
        coinbase_tx.chain_id = chain_id;
        coinbase_tx.set_origin_nonce(miner_nonce + 1);
        let mut coinbase_tx_signer = StacksTransactionSigner::new(&coinbase_tx);
        coinbase_tx_signer.sign_origin(&self.miner_key).unwrap();
        let coinbase_tx = coinbase_tx_signer.get_tx().unwrap();

        let miner_pk = Secp256k1PublicKey::from_private(&self.miner_key);
        let miner_pk_hash = Hash160::from_node_public_key(&miner_pk);

        // Add a tenure change transaction to the block:
        //  as of now every mockamoto block is a tenure-change.
        // If mockamoto mode changes to support non-tenure-changing blocks, this will have
        //  to be gated.
        let tenure_change_tx_payload = TransactionPayload::TenureChange(TenureChangePayload {
            tenure_consensus_hash: sortition_tip.consensus_hash.clone(),
            prev_tenure_consensus_hash: chain_tip_ch.clone(),
            burn_view_consensus_hash: sortition_tip.consensus_hash,
            previous_tenure_end: parent_block_id,
            previous_tenure_blocks: 1,
            cause: TenureChangeCause::BlockFound,
            pubkey_hash: miner_pk_hash,
            signature: ThresholdSignature::mock(),
            signers: vec![],
        });
        let mut tenure_tx = StacksTransaction::new(
            TransactionVersion::Testnet,
            TransactionAuth::from_p2pkh(&self.miner_key).unwrap(),
            tenure_change_tx_payload,
        );
        tenure_tx.chain_id = chain_id;
        tenure_tx.set_origin_nonce(miner_nonce);
        let mut tenure_tx_signer = StacksTransactionSigner::new(&tenure_tx);
        tenure_tx_signer.sign_origin(&self.miner_key).unwrap();
        let tenure_tx = tenure_tx_signer.get_tx().unwrap();

        let pox_address = PoxAddress::Standard(
            StacksAddress::burn_address(false),
            Some(AddressHashMode::SerializeP2PKH),
        );

        let stack_stx_payload = if parent_chain_length < 2 {
            TransactionPayload::ContractCall(TransactionContractCall {
                address: StacksAddress::burn_address(false),
                contract_name: "pox-4".try_into().unwrap(),
                function_name: "stack-stx".try_into().unwrap(),
                function_args: vec![
                    ClarityValue::UInt(99_000_000_000_000),
                    pox_address.as_clarity_tuple().unwrap().into(),
                    ClarityValue::UInt(u128::from(parent_burn_height)),
                    ClarityValue::UInt(12),
                ],
            })
        } else {
            // NOTE: stack-extend doesn't currently work, because the PoX-4 lockup
            //  special functions have not been implemented.
            TransactionPayload::ContractCall(TransactionContractCall {
                address: StacksAddress::burn_address(false),
                contract_name: "pox-4".try_into().unwrap(),
                function_name: "stack-extend".try_into().unwrap(),
                function_args: vec![
                    ClarityValue::UInt(5),
                    pox_address.as_clarity_tuple().unwrap().into(),
                ],
            })
        };
        let mut stack_stx_tx = StacksTransaction::new(
            TransactionVersion::Testnet,
            TransactionAuth::from_p2pkh(&self.miner_key).unwrap(),
            stack_stx_payload,
        );
        stack_stx_tx.chain_id = chain_id;
        stack_stx_tx.set_origin_nonce(miner_nonce + 2);
        let mut stack_stx_tx_signer = StacksTransactionSigner::new(&stack_stx_tx);
        stack_stx_tx_signer.sign_origin(&self.miner_key).unwrap();
        let stacks_stx_tx = stack_stx_tx_signer.get_tx().unwrap();

        let sortdb_handle = self.sortdb.index_conn();
        let SetupBlockResult {
            mut clarity_tx,
            matured_miner_rewards_opt,
            ..
        } = NakamotoChainState::setup_block(
            &mut chainstate_tx,
            clarity_instance,
            &sortdb_handle,
            &self.sortdb.pox_constants,
            chain_tip_ch.clone(),
            chain_tip_bh.clone(),
            parent_chain_length,
            parent_burn_height,
            sortition_tip.burn_header_hash.clone(),
            sortition_tip.block_height.try_into().map_err(|_| {
                ChainstateError::InvalidStacksBlock("Burn block height exceeded u32".into())
            })?,
            true,
            parent_chain_length + 1,
            false,
        )?;

        let txs = vec![tenure_tx, coinbase_tx, stacks_stx_tx];

        let _ = match StacksChainState::process_block_transactions(
            &mut clarity_tx,
            &txs,
            0,
            ASTRules::PrecheckSize,
        ) {
            Err(e) => {
                let msg = format!("Mined invalid stacks block {e:?}");
                warn!("{msg}");

                clarity_tx.rollback_block();
                return Err(ChainstateError::InvalidStacksBlock(msg));
            }
            Ok((block_fees, _block_burns, txs_receipts)) => (block_fees, txs_receipts),
        };

        let bytes_so_far = txs.iter().map(|tx| tx.tx_len()).sum();
        let mut builder = MockamotoBlockBuilder { txs, bytes_so_far };
        let _ = match StacksBlockBuilder::select_and_apply_transactions(
            &mut clarity_tx,
            &mut builder,
            &mut self.mempool,
            parent_chain_length,
            &[],
            BlockBuilderSettings {
                max_miner_time_ms: 15_000,
                mempool_settings: MemPoolWalkSettings::default(),
                miner_status: Arc::new(Mutex::new(MinerStatus::make_ready(10000))),
            },
            None,
            ASTRules::PrecheckSize,
        ) {
            Ok(x) => x,
            Err(e) => {
                let msg = format!("Mined invalid stacks block {e:?}");
                warn!("{msg}");

                clarity_tx.rollback_block();
                return Err(ChainstateError::InvalidStacksBlock(msg));
            }
        };

        let _lockup_events = match NakamotoChainState::finish_block(
            &mut clarity_tx,
            matured_miner_rewards_opt.as_ref(),
        ) {
            Err(ChainstateError::InvalidStacksBlock(e)) => {
                clarity_tx.rollback_block();
                return Err(ChainstateError::InvalidStacksBlock(e));
            }
            Err(e) => return Err(e),
            Ok(lockup_events) => lockup_events,
        };

        let state_index_root = clarity_tx.seal();
        let tx_merkle_tree: MerkleTree<Sha512Trunc256Sum> = builder.txs.iter().collect();
        clarity_tx.commit_mined_block(&StacksBlockId::new(
            &MINER_BLOCK_CONSENSUS_HASH,
            &MINER_BLOCK_HEADER_HASH,
        ));
        chainstate_tx.commit().unwrap();

        let mut block = NakamotoBlock {
            header: NakamotoBlockHeader {
                version: 100,
                chain_length: parent_chain_length + 1,
                burn_spent: sortition_tip.total_burn,
                tx_merkle_root: tx_merkle_tree.root(),
                state_index_root,
                signer_signature: ThresholdSignature::mock(),
                miner_signature: MessageSignature::empty(),
                consensus_hash: sortition_tip.consensus_hash.clone(),
                parent_block_id: StacksBlockId::new(&chain_tip_ch, &chain_tip_bh),
            },
            txs: builder.txs,
        };

        let miner_signature = self
            .miner_key
            .sign(block.header.signature_hash().unwrap().as_bytes())
            .unwrap();

        block.header.miner_signature = miner_signature;

        Ok(block)
    }

    fn mine_and_stage_block(&mut self) -> Result<u64, ChainstateError> {
        let mut block = self.mine_stacks_block()?;
        let config = self.chainstate.config();
        let chain_length = block.header.chain_length;
        let mut sortition_handle = self.sortdb.index_handle_at_tip();
        let aggregate_public_key = self.self_signer.aggregate_public_key;
        self.self_signer.sign_nakamoto_block(&mut block);
        let staging_tx = self.chainstate.staging_db_tx_begin()?;
        NakamotoChainState::accept_block(
            &config,
            block,
            &mut sortition_handle,
            &staging_tx,
            &aggregate_public_key,
        )?;
        staging_tx.commit()?;
        Ok(chain_length)
    }
}
