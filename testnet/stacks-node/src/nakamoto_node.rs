// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
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
use std::collections::HashMap;
use std::convert::TryFrom;
use std::net::SocketAddr;
use std::sync::mpsc::Receiver;
use std::thread;
use std::thread::JoinHandle;

use super::{Config, EventDispatcher, Keychain};
use crate::burnchains::bitcoin_regtest_controller::addr2str;
use crate::globals::Globals;
use crate::globals::RelayerDirective;
use crate::neon_node::LeaderKeyRegistrationState;
use crate::run_loop::nakamoto::RunLoop;
use crate::run_loop::RegisteredKey;
use clarity::vm::ast::ASTRules;
use clarity::vm::types::QualifiedContractIdentifier;
use stacks::burnchains::{Burnchain, BurnchainSigner, Txid};
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::burn::BlockSnapshot;
use stacks::chainstate::stacks::db::StacksChainState;
use stacks::chainstate::stacks::Error as ChainstateError;
use stacks::core::mempool::MemPoolDB;
use stacks::cost_estimates::metrics::UnitMetric;
use stacks::cost_estimates::UnitEstimator;
use stacks::monitoring;
use stacks::monitoring::update_active_miners_count_gauge;
use stacks::net::atlas::{AtlasConfig, AtlasDB};
use stacks::net::db::PeerDB;
use stacks::net::p2p::PeerNetwork;
use stacks::net::relay::Relayer;
use stacks::net::stackerdb::{StackerDBConfig, StackerDBSync, StackerDBs};
use stacks::net::{Error as NetError, PeerNetworkComms, ServiceFlags};
use stacks::util_lib::strings::{UrlString, VecDisplay};
use stacks_common::types::chainstate::SortitionId;
use stacks_common::types::net::PeerAddress;
use stacks_common::types::StacksEpochId;
use stacks_common::util::get_epoch_time_secs;
use stacks_common::util::secp256k1::Secp256k1PrivateKey;

pub mod miner;
pub mod peer;
pub mod relayer;

use self::peer::PeerThread;
use self::relayer::RelayerThread;

pub const RELAYER_MAX_BUFFER: usize = 100;
const VRF_MOCK_MINER_KEY: u64 = 1;

pub const BLOCK_PROCESSOR_STACK_SIZE: usize = 32 * 1024 * 1024; // 32 MB

pub type BlockCommits = HashMap<Txid, ()>;

/// Node implementation for both miners and followers.
/// This struct is used to set up the node proper and launch the p2p thread and relayer thread.
/// It is further used by the main thread to communicate with these two threads.
pub struct StacksNode {
    /// Atlas network configuration
    pub atlas_config: AtlasConfig,
    /// Global inter-thread communication handle
    pub globals: Globals,
    /// True if we're a miner
    is_miner: bool,
    /// handle to the p2p thread
    pub p2p_thread_handle: JoinHandle<()>,
    /// handle to the relayer thread
    pub relayer_thread_handle: JoinHandle<()>,
}

/// Fault injection logic to artificially increase the length of a tenure.
/// Only used in testing
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
                stacks_common::util::sleep_ms(tenure_time);
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

/// Fault injection to skip mining in this bitcoin block height
/// Only used in testing
#[cfg(test)]
fn fault_injection_skip_mining(rpc_bind: &str, target_burn_height: u64) -> bool {
    match std::env::var("STACKS_DISABLE_MINER") {
        Ok(disable_heights) => {
            let disable_schedule: serde_json::Value =
                serde_json::from_str(&disable_heights).unwrap();
            let disable_schedule = disable_schedule.as_array().unwrap();
            for disabled in disable_schedule {
                let target_miner_rpc_bind = disabled
                    .get("rpc_bind")
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_string();
                if target_miner_rpc_bind != rpc_bind {
                    continue;
                }
                let target_block_heights = disabled.get("blocks").unwrap().as_array().unwrap();
                for target_block_value in target_block_heights {
                    let target_block = target_block_value.as_i64().unwrap() as u64;
                    if target_block == target_burn_height {
                        return true;
                    }
                }
            }
            return false;
        }
        Err(_) => {
            return false;
        }
    }
}

#[cfg(not(test))]
fn fault_injection_skip_mining(_rpc_bind: &str, _target_burn_height: u64) -> bool {
    false
}

/// Open the chainstate, and inject faults from the config file
pub(crate) fn open_chainstate_with_faults(
    config: &Config,
) -> Result<StacksChainState, ChainstateError> {
    let stacks_chainstate_path = config.get_chainstate_path_str();
    let (mut chainstate, _) = StacksChainState::open(
        config.is_mainnet(),
        config.burnchain.chain_id,
        &stacks_chainstate_path,
        Some(config.node.get_marf_opts()),
    )?;

    chainstate.fault_injection.hide_blocks = config.node.fault_injection_hide_blocks;
    Ok(chainstate)
}

/// Types of errors that can arise during mining
#[derive(Debug)]
enum Error {
    /// Can't find the block sortition snapshot for the chain tip
    SnapshotNotFoundForChainTip,
    /// The burnchain tip changed while this operation was in progress
    BurnchainTipChanged,
    SpawnError(std::io::Error),
    FaultInjection,
    MissedMiningOpportunity,
    /// Attempted to mine while there was no active VRF key
    NoVRFKeyActive,
    /// The parent block or tenure could not be found
    ParentNotFound,
    /// Something unexpected happened (e.g., hash mismatches)
    UnexpectedChainState,
    /// A burnchain operation failed when submitting it to the burnchain
    BurnchainSubmissionFailed,
    NewParentDiscovered,
}

impl StacksNode {
    /// Set up the AST size-precheck height, if configured
    fn setup_ast_size_precheck(config: &Config, sortdb: &mut SortitionDB) {
        if let Some(ast_precheck_size_height) = config.burnchain.ast_precheck_size_height {
            info!(
                "Override burnchain height of {:?} to {}",
                ASTRules::PrecheckSize,
                ast_precheck_size_height
            );
            let mut tx = sortdb
                .tx_begin()
                .expect("FATAL: failed to begin tx on sortition DB");
            SortitionDB::override_ast_rule_height(
                &mut tx,
                ASTRules::PrecheckSize,
                ast_precheck_size_height,
            )
            .expect("FATAL: failed to override AST PrecheckSize rule height");
            tx.commit()
                .expect("FATAL: failed to commit sortition DB transaction");
        }
    }

    /// Set up the mempool DB by making sure it exists.
    /// Panics on failure.
    fn setup_mempool_db(config: &Config) -> MemPoolDB {
        // force early mempool instantiation
        let cost_estimator = config
            .make_cost_estimator()
            .unwrap_or_else(|| Box::new(UnitEstimator));
        let metric = config
            .make_cost_metric()
            .unwrap_or_else(|| Box::new(UnitMetric));

        let mempool = MemPoolDB::open(
            config.is_mainnet(),
            config.burnchain.chain_id,
            &config.get_chainstate_path_str(),
            cost_estimator,
            metric,
        )
        .expect("BUG: failed to instantiate mempool");

        mempool
    }

    /// Set up the Peer DB and update any soft state from the config file.  This includes:
    /// * blacklisted/whitelisted nodes
    /// * node keys
    /// * bootstrap nodes
    /// Returns the instantiated PeerDB
    /// Panics on failure.
    fn setup_peer_db(
        config: &Config,
        burnchain: &Burnchain,
        stackerdb_contract_ids: &[QualifiedContractIdentifier],
    ) -> PeerDB {
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
        let p2p_addr: SocketAddr = config.node.p2p_address.parse().expect(&format!(
            "Failed to parse socket: {}",
            &config.node.p2p_address
        ));
        let node_privkey = Secp256k1PrivateKey::from_seed(&config.node.local_peer_seed);

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
            &[],
            Some(&initial_neighbors),
            stackerdb_contract_ids,
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

        // allow all bootstrap nodes
        {
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

        // deny all config-denied peers
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

        peerdb
    }

    /// Set up the PeerNetwork, but do not bind it.
    pub fn setup_peer_network(
        config: &Config,
        atlas_config: &AtlasConfig,
        burnchain: Burnchain,
    ) -> PeerNetwork {
        let sortdb = SortitionDB::open(
            &config.get_burn_db_file_path(),
            true,
            burnchain.pox_constants.clone(),
        )
        .expect("Error while instantiating sor/tition db");

        let epochs = SortitionDB::get_stacks_epochs(sortdb.conn())
            .expect("Error while loading stacks epochs");

        let view = {
            let sortition_tip = SortitionDB::get_canonical_burn_chain_tip(&sortdb.conn())
                .expect("Failed to get sortition tip");
            SortitionDB::get_burnchain_view(&sortdb.index_conn(), &burnchain, &sortition_tip)
                .unwrap()
        };

        let atlasdb =
            AtlasDB::connect(atlas_config.clone(), &config.get_atlas_db_file_path(), true).unwrap();

        let stackerdbs = StackerDBs::connect(&config.get_stacker_db_file_path(), true).unwrap();

        let mut chainstate =
            open_chainstate_with_faults(config).expect("FATAL: could not open chainstate DB");

        let mut stackerdb_machines = HashMap::new();
        for stackerdb_contract_id in config.node.stacker_dbs.iter() {
            // attempt to load the config
            let (instantiate, stacker_db_config) = match StackerDBConfig::from_smart_contract(
                &mut chainstate,
                &sortdb,
                stackerdb_contract_id,
            ) {
                Ok(c) => (true, c),
                Err(e) => {
                    warn!(
                        "Failed to load StackerDB config for {}: {:?}",
                        stackerdb_contract_id, &e
                    );
                    (false, StackerDBConfig::noop())
                }
            };
            let mut stackerdbs =
                StackerDBs::connect(&config.get_stacker_db_file_path(), true).unwrap();

            if instantiate {
                match stackerdbs.get_stackerdb_id(stackerdb_contract_id) {
                    Ok(..) => {
                        // reconfigure
                        let tx = stackerdbs.tx_begin(stacker_db_config.clone()).unwrap();
                        tx.reconfigure_stackerdb(stackerdb_contract_id, &stacker_db_config.signers)
                            .expect(&format!(
                                "FATAL: failed to reconfigure StackerDB replica {}",
                                stackerdb_contract_id
                            ));
                        tx.commit().unwrap();
                    }
                    Err(NetError::NoSuchStackerDB(..)) => {
                        // instantiate replica
                        let tx = stackerdbs.tx_begin(stacker_db_config.clone()).unwrap();
                        tx.create_stackerdb(stackerdb_contract_id, &stacker_db_config.signers)
                            .expect(&format!(
                                "FATAL: failed to instantiate StackerDB replica {}",
                                stackerdb_contract_id
                            ));
                        tx.commit().unwrap();
                    }
                    Err(e) => {
                        panic!("FATAL: failed to query StackerDB state: {:?}", &e);
                    }
                }
            }
            let stacker_db_sync = match StackerDBSync::new(
                stackerdb_contract_id.clone(),
                &stacker_db_config,
                PeerNetworkComms::new(),
                stackerdbs,
            ) {
                Ok(s) => s,
                Err(e) => {
                    warn!(
                        "Failed to instantiate StackerDB sync machine for {}: {:?}",
                        stackerdb_contract_id, &e
                    );
                    continue;
                }
            };

            stackerdb_machines.insert(
                stackerdb_contract_id.clone(),
                (stacker_db_config, stacker_db_sync),
            );
        }

        let stackerdb_contract_ids: Vec<_> =
            stackerdb_machines.keys().map(|sc| sc.clone()).collect();
        let peerdb = Self::setup_peer_db(config, &burnchain, &stackerdb_contract_ids);

        let local_peer = match PeerDB::get_local_peer(peerdb.conn()) {
            Ok(local_peer) => local_peer,
            _ => panic!("Unable to retrieve local peer"),
        };

        let p2p_net = PeerNetwork::new(
            peerdb,
            atlasdb,
            stackerdbs,
            local_peer,
            config.burnchain.peer_version,
            burnchain,
            view,
            config.connection_options.clone(),
            stackerdb_machines,
            epochs,
        );

        p2p_net
    }

    /// This function sets the global var `GLOBAL_BURNCHAIN_SIGNER`.
    ///
    /// This variable is used for prometheus monitoring (which only
    /// runs when the feature flag `monitoring_prom` is activated).
    /// The address is set using the single-signature BTC address
    /// associated with `keychain`'s public key. This address always
    /// assumes Epoch-2.1 rules for the miner address: if the
    /// node is configured for segwit, then the miner address generated
    /// is a segwit address, otherwise it is a p2pkh.
    ///
    fn set_monitoring_miner_address(keychain: &Keychain, relayer_thread: &RelayerThread) {
        let public_key = keychain.get_pub_key();
        let miner_addr = relayer_thread
            .bitcoin_controller
            .get_miner_address(StacksEpochId::Epoch21, &public_key);
        let miner_addr_str = addr2str(&miner_addr);
        let _ = monitoring::set_burnchain_signer(BurnchainSigner(miner_addr_str)).map_err(|e| {
            warn!("Failed to set global burnchain signer: {:?}", &e);
            e
        });
    }

    pub fn spawn(
        runloop: &RunLoop,
        globals: Globals,
        // relay receiver endpoint for the p2p thread, so the relayer can feed it data to push
        relay_recv: Receiver<RelayerDirective>,
    ) -> StacksNode {
        let config = runloop.config().clone();
        let is_miner = runloop.is_miner();
        let burnchain = runloop.get_burnchain();
        let atlas_config = config.atlas.clone();
        let keychain = Keychain::default(config.node.seed.clone());

        // we can call _open_ here rather than _connect_, since connect is first called in
        //   make_genesis_block
        let mut sortdb = SortitionDB::open(
            &config.get_burn_db_file_path(),
            true,
            burnchain.pox_constants.clone(),
        )
        .expect("Error while instantiating sortition db");

        Self::setup_ast_size_precheck(&config, &mut sortdb);

        let _ = Self::setup_mempool_db(&config);

        let mut p2p_net = Self::setup_peer_network(&config, &atlas_config, burnchain.clone());

        let stackerdbs = StackerDBs::connect(&config.get_stacker_db_file_path(), true)
            .expect("FATAL: failed to connect to stacker DB");

        let relayer = Relayer::from_p2p(&mut p2p_net, stackerdbs);

        let local_peer = p2p_net.local_peer.clone();

        // setup initial key registration
        let leader_key_registration_state = if config.node.mock_mining {
            // mock mining, pretend to have a registered key
            let (vrf_public_key, _) = keychain.make_vrf_keypair(VRF_MOCK_MINER_KEY);
            LeaderKeyRegistrationState::Active(RegisteredKey {
                target_block_height: VRF_MOCK_MINER_KEY,
                block_height: 1,
                op_vtxindex: 1,
                vrf_public_key,
            })
        } else {
            LeaderKeyRegistrationState::Inactive
        };
        globals.set_initial_leader_key_registration_state(leader_key_registration_state);

        let relayer_thread = RelayerThread::new(runloop, local_peer.clone(), relayer);

        StacksNode::set_monitoring_miner_address(&keychain, &relayer_thread);

        let relayer_thread_handle = thread::Builder::new()
            .name(format!("relayer-{}", &local_peer.data_url))
            .stack_size(BLOCK_PROCESSOR_STACK_SIZE)
            .spawn(move || {
                relayer_thread.main(relay_recv);
            })
            .expect("FATAL: failed to start relayer thread");

        let p2p_event_dispatcher = runloop.get_event_dispatcher();
        let p2p_thread = PeerThread::new(runloop, p2p_net);
        let p2p_thread_handle = thread::Builder::new()
            .stack_size(BLOCK_PROCESSOR_STACK_SIZE)
            .name(format!(
                "p2p-({},{})",
                &config.node.p2p_bind, &config.node.rpc_bind
            ))
            .spawn(move || {
                p2p_thread.main(p2p_event_dispatcher);
            })
            .expect("FATAL: failed to start p2p thread");

        info!("Start HTTP server on: {}", &config.node.rpc_bind);
        info!("Start P2P server on: {}", &config.node.p2p_bind);

        StacksNode {
            atlas_config,
            globals,
            is_miner,
            p2p_thread_handle,
            relayer_thread_handle,
        }
    }

    /// Notify the relayer that a new burn block has been processed by the sortition db,
    ///  telling it to process the block and begin mining if this miner won.
    /// returns _false_ if the relayer hung up the channel.
    /// Called from the main thread.
    pub fn relayer_burnchain_notify(&self) -> bool {
        if !self.is_miner {
            // node is a follower, don't try to process my own tenure.
            return true;
        }

        let Some(snapshot) = self.globals.get_last_sortition() else {
            debug!("Tenure: Notify sortition! No last burn block");
            return true;
        };

        debug!(
            "Tenure: Notify sortition!";
            "consensus_hash" => %snapshot.consensus_hash,
            "burn_block_hash" => %snapshot.burn_header_hash,
            "winning_stacks_block_hash" => %snapshot.winning_stacks_block_hash,
            "burn_block_height" => &snapshot.block_height,
            "sortition_id" => %snapshot.sortition_id
        );

        // unlike in neon_node, the nakamoto node should *always* notify the relayer of
        //  a new burnchain block

        return self
            .globals
            .relay_send
            .send(RelayerDirective::ProcessTenure(
                snapshot.consensus_hash.clone(),
                snapshot.parent_burn_header_hash.clone(),
                snapshot.winning_stacks_block_hash.clone(),
            ))
            .is_ok();
    }

    /// Process a state coming from the burnchain, by extracting the validated KeyRegisterOp
    /// and inspecting if a sortition was won.
    /// `ibd`: boolean indicating whether or not we are in the initial block download
    /// Called from the main thread.
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

        let num_block_commits = block_commits.len();

        update_active_miners_count_gauge(block_commits.len() as i64);

        for op in block_commits.into_iter() {
            if op.txid == block_snapshot.winning_block_txid {
                info!(
                    "Received burnchain block #{} including block_commit_op (winning) - {} ({})",
                    block_height, op.apparent_sender, &op.block_header_hash
                );
                last_sortitioned_block = Some((block_snapshot.clone(), op.vtxindex));
            } else {
                if self.is_miner {
                    info!(
                        "Received burnchain block #{} including block_commit_op - {} ({})",
                        block_height, op.apparent_sender, &op.block_header_hash
                    );
                }
            }
        }

        let key_registers =
            SortitionDB::get_leader_keys_by_block(&ic, &block_snapshot.sortition_id)
                .expect("Unexpected SortitionDB error fetching key registers");

        let num_key_registers = key_registers.len();

        self.globals
            .try_activate_leader_key_registration(block_height, key_registers);

        debug!(
            "Processed burnchain state";
            "burn_height" => block_height,
            "leader_keys_count" => num_key_registers,
            "block_commits_count" => num_block_commits,
            "in_initial_block_download?" => ibd,
        );

        self.globals.set_last_sortition(block_snapshot);
        last_sortitioned_block.map(|x| x.0)
    }

    /// Join all inner threads
    pub fn join(self) {
        self.relayer_thread_handle.join().unwrap();
        self.p2p_thread_handle.join().unwrap();
    }
}
