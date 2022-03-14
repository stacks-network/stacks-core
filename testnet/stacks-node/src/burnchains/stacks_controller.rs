// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2021 Stacks Open Internet Foundation
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
use std::net::TcpStream;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Instant;

use super::super::operations::BurnchainOpSigner;
use super::super::Config;
use super::{BurnchainController, BurnchainTip, Error};

use stacks::burnchains::db::BurnchainDB;
use stacks::burnchains::indexer::BurnchainIndexer;
use stacks::burnchains::stacks::AppChainClient;
use stacks::burnchains::Burnchain;
use stacks::burnchains::BurnchainSigner;
use stacks::burnchains::Error as burnchain_error;
use stacks::burnchains::Txid;
use stacks::chainstate::stacks::C32_ADDRESS_VERSION_MAINNET_SINGLESIG;
use stacks::chainstate::stacks::C32_ADDRESS_VERSION_TESTNET_SINGLESIG;
use stacks::core::{StacksEpoch, CHAIN_ID_MAINNET, CHAIN_ID_TESTNET, STACKS_EPOCH_2_05_MARKER};

use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::burn::ConsensusHash;
use stacks::chainstate::coordinator::comm::CoordinatorChannels;

use stacks::chainstate::burn::operations::{
    BlockstackOperationType, LeaderBlockCommitOp, LeaderKeyRegisterOp,
};

use stacks::chainstate::stacks::{
    FungibleConditionCode, PostConditionPrincipal, StacksPrivateKey, StacksPublicKey,
    StacksTransaction, StacksTransactionSigner, TransactionAnchorMode, TransactionAuth,
    TransactionContractCall, TransactionPayload, TransactionPostCondition,
    TransactionPostConditionMode, TransactionVersion,
};
use stacks::types::chainstate::StacksAddress;

use stacks::chainstate::stacks::db::StacksAccount;

use stacks::codec::StacksMessageCodec;
use stacks::util::sleep_ms;
use stacks::util::vrf::VRFPublicKey;

use stacks::types::chainstate::{BlockHeaderHash, BurnchainHeaderHash, VRFSeed};

use stacks::address::AddressHashMode;

use stacks::vm::types::Value;

/// Driver for talking to an instance of the Stacks network for mining
pub struct StacksController {
    /// Inner appchain client
    pub client: AppChainClient,
    /// Has the system been booted?
    booted: bool,
    /// System config copy
    config: Config,
    /// Burnchain config
    burnchain: Burnchain,
    /// Link to chains coordinator communication channels
    coordinator_comms: Option<CoordinatorChannels>,
    /// Link to global flag to keep processing data
    should_keep_running: Option<Arc<AtomicBool>>,
    /// Cached chain tip that was last seen
    chain_tip: Option<BurnchainTip>,
    db: Option<SortitionDB>,
    burnchain_db: Option<BurnchainDB>,
    /// Minimum uSTX fee to pay to mine
    base_fee: u64,
    /// If true, then this struct must only be used to submit transactions to the host chain.
    /// Don't use it for downloading blocks and headers
    submit_only: bool,
    /// Per-host-block miner state.  Gets refreshed in-between mining.
    miner_account: Option<StacksAccount>,
}

impl StacksController {
    /// Make a new Stacks controller.  Succeeds only if the config is an appchain config -- i.e. it
    /// must have .burnchain.appchain_runtime set to Some(..).
    fn inner_new(
        config: Config,
        coordinator_comms: Option<CoordinatorChannels>,
        should_keep_running: Option<Arc<AtomicBool>>,
        submit_only: bool,
    ) -> Result<StacksController, Error> {
        // right now, you can only instantiate an app chain on top of the main stacks chain (or its
        // testnet).  This is for safety reasons -- there's no replay protection between appchains
        // that have the same chain ID.  We need to build out a designated registry smart contract
        // for this purpose.
        if let Some(appchain_runtime) = config.burnchain.appchain_runtime.as_ref() {
            let mainnet = config.is_mainnet();
            let parent_chain_id = if mainnet {
                CHAIN_ID_MAINNET
            } else {
                CHAIN_ID_TESTNET
            };

            let headers_path = config.get_spv_headers_file_path();
            let parent_chain_peer = (
                &config.burnchain.peer_host.clone(),
                config.burnchain.rpc_port,
            );
            let contract_id = appchain_runtime.config.mining_contract_id();
            let magic_bytes = config.burnchain.magic_bytes.clone();
            let base_fee = config.miner.min_tx_fee;
            let genesis_hash = config.burnchain.genesis_hash.clone();

            let working_dir = config.get_burn_db_path();
            let burnchain = Burnchain::new_appchain(&appchain_runtime.config, &working_dir)
                .expect("BUG: instantiating a burnchain from an appchain config should never fail");

            let client = AppChainClient::new(
                mainnet,
                &headers_path,
                parent_chain_id,
                (&parent_chain_peer.0, parent_chain_peer.1),
                contract_id,
                magic_bytes,
                genesis_hash,
                None,
            );

            Ok(StacksController {
                client,
                booted: false,
                config,
                burnchain,
                coordinator_comms,
                should_keep_running,
                chain_tip: None,
                db: None,
                burnchain_db: None,
                base_fee,
                miner_account: None,
                submit_only: submit_only,
            })
        } else {
            return Err(Error::IndexerError(burnchain_error::UnsupportedBurnchain));
        }
    }

    /// Make a new Stacks controller for downloading headers and blocks
    pub fn new(
        config: Config,
        coordinator_comms: CoordinatorChannels,
        should_keep_running: Arc<AtomicBool>,
    ) -> Result<StacksController, Error> {
        StacksController::inner_new(
            config,
            Some(coordinator_comms),
            Some(should_keep_running),
            false,
        )
    }

    /// Make a new Stacks controller for submitting transactions (i.e. mining).  The given config
    /// must refer to Stacks header chainstate -- i.e. there must be some other Stacks controller
    /// instance already created and running that has booted up the appchain.
    pub fn new_submitter(config: Config) -> Result<StacksController, Error> {
        let mut controller = StacksController::inner_new(config, None, None, true)?;
        controller.client.refresh_root_to_block_map()?;

        Ok(controller)
    }

    fn should_keep_running(&self) -> bool {
        match self.should_keep_running {
            Some(ref should_keep_running) => should_keep_running.load(Ordering::SeqCst),
            _ => true,
        }
    }

    /// Clear cached miner data and set the new chain tip
    fn invalidate_tip(&mut self, new_tip: BurnchainTip) {
        if let Some(old_tip) = self.chain_tip.as_ref() {
            if old_tip.block_snapshot.burn_header_hash != new_tip.block_snapshot.burn_header_hash {
                // invalidate cached state
                self.miner_account = None;
            }
        }

        self.chain_tip = Some(new_tip);
    }

    /// Go download blocks, possibly waiting for new blocks to arrive, and stop once a target
    /// height is reached.
    fn receive_blocks(
        &mut self,
        block_for_sortitions: bool,
        target_block_height: u64,
    ) -> Result<(BurnchainTip, u64), Error> {
        assert!(
            !self.submit_only,
            "BUG: tried to use a submit-only apphchain client to receive blocks"
        );
        let (block_snapshot, burnchain_height, state_transition) = loop {
            let mut burnchain = self.get_burnchain();
            if !self.should_keep_running() {
                return Err(Error::CoordinatorClosed);
            }
            match burnchain.sync_with_indexer(
                &mut self.client,
                self.coordinator_comms.clone(),
                Some(target_block_height),
                Some(self.burnchain.pox_constants.reward_cycle_length as u64),
                self.should_keep_running.clone(),
            ) {
                Ok(x) => {
                    // initialize the dbs...
                    self.sortdb_mut();

                    // wait for the chains coordinator to catch up with us
                    if block_for_sortitions {
                        self.wait_for_sortitions(Some(x.block_height))?;
                    }

                    // NOTE: This is the latest _sortition_ on the canonical sortition history, not the latest burnchain block!
                    let sort_tip =
                        SortitionDB::get_canonical_burn_chain_tip(self.sortdb_ref().conn())
                            .expect("Sortition DB error.");

                    let (snapshot, state_transition) = self
                        .sortdb_ref()
                        .get_sortition_result(&sort_tip.sortition_id)
                        .expect("Sortition DB error.")
                        .expect("BUG: no data for the canonical chain tip");

                    let burnchain_height = self.client.get_highest_header_height()?;

                    break (snapshot, burnchain_height, state_transition);
                }
                Err(e) => {
                    // keep trying
                    error!("Unable to sync with burnchain: {}", e);
                    match e {
                        burnchain_error::CoordinatorClosed => return Err(Error::CoordinatorClosed),
                        burnchain_error::TrySyncAgain => {
                            // try again immediately
                            continue;
                        }
                        burnchain_error::BurnchainPeerBroken => {
                            // remote burnchain peer broke, and produced a shorter blockchain fork.
                            // just keep trying
                            sleep_ms(5000);
                            continue;
                        }
                        _ => {
                            // delay and try again
                            sleep_ms(5000);
                            continue;
                        }
                    }
                }
            }
        };

        let burnchain_tip = BurnchainTip {
            block_snapshot: block_snapshot,
            state_transition: state_transition,
            received_at: Instant::now(),
        };

        self.invalidate_tip(burnchain_tip.clone());

        debug!("Done receiving blocks");

        Ok((burnchain_tip, burnchain_height))
    }

    /// Make a VRF key registration transaction for the host chain
    fn make_appchain_vrf_key_tx(
        &self,
        privk: &StacksPrivateKey,
        nonce: u64,
        fee: u64,
        pubk: &VRFPublicKey,
    ) -> StacksTransaction {
        let leader_key_op = LeaderKeyRegisterOp {
            public_key: pubk.clone(),
            memo: vec![],
            address: self.get_privk_addr(privk),
            consensus_hash: ConsensusHash([0x01; 20]),

            // ignored
            vtxindex: 0,
            txid: Txid([0x00; 32]),
            block_height: 0,
            burn_header_hash: BurnchainHeaderHash::zero(),
        };

        let op_bytes = {
            let mut buffer = vec![];
            let mut magic_bytes = self.client.magic_bytes.as_bytes().to_vec();
            buffer.append(&mut magic_bytes);
            leader_key_op
                .consensus_serialize(&mut buffer)
                .expect("FATAL: invalid operation");
            buffer
        };

        let mut tx = StacksTransaction::new(
            if self.client.mainnet {
                TransactionVersion::Mainnet
            } else {
                TransactionVersion::Testnet
            },
            TransactionAuth::from_p2pkh(&privk).expect(
                "BUG: failed to create a single-sig transaction auth from a valid private key",
            ),
            TransactionPayload::ContractCall(TransactionContractCall {
                address: self.client.contract_id.issuer.clone().into(),
                contract_name: self.client.contract_id.name.clone(),
                function_name: "register-vrf-key".into(),
                function_args: vec![
                    Value::buff_from(op_bytes).expect("BUG: failed to construct a (buff 80)")
                ],
            }),
        );

        tx.chain_id = self.client.parent_chain_id;
        tx.anchor_mode = TransactionAnchorMode::OnChainOnly;
        tx.post_condition_mode = TransactionPostConditionMode::Deny;
        tx.auth.set_origin_nonce(nonce);
        tx.set_tx_fee(fee);

        let mut tx_signer = StacksTransactionSigner::new(&tx);
        tx_signer
            .sign_origin(&privk)
            .expect("BUG: failed to sign transaction single-sig origin with private key");
        tx_signer
            .get_tx()
            .expect("BUG: failed to complete a transaction after one signature")
    }

    /// Make a block-commit transaction for the host chain
    fn make_appchain_block_commit_tx(
        &self,
        privk: &StacksPrivateKey,
        nonce: u64,
        fee: u64,
        block_hash: BlockHeaderHash,
        vrf_seed: VRFSeed,
        height_mod: u8,
        parent: (u32, u16),
        key: (u32, u16),
        sunset_burn: u64,
        recipients: Vec<StacksAddress>,
        total_payout: u64,
    ) -> StacksTransaction {
        let num_recipients = recipients.len();
        let recipient_payout = total_payout / (num_recipients as u64);

        let block_commit_op = LeaderBlockCommitOp {
            block_header_hash: block_hash,
            burn_fee: total_payout,
            sunset_burn: sunset_burn,
            parent_block_ptr: parent.0,
            parent_vtxindex: parent.1,
            key_block_ptr: key.0,
            key_vtxindex: key.1,
            new_seed: vrf_seed,

            // ignored
            input: (Txid([0; 32]), 0),
            apparent_sender: BurnchainSigner {
                public_keys: vec![StacksPublicKey::from_hex(
                    "02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0",
                )
                .unwrap()],
                num_sigs: 1,
                hash_mode: AddressHashMode::SerializeP2PKH,
            },
            memo: vec![STACKS_EPOCH_2_05_MARKER],

            // filled in late
            commit_outs: vec![],
            txid: Txid([0x00; 32]),
            vtxindex: 444,
            block_height: 125,
            burn_parent_modulus: height_mod,
            burn_header_hash: BurnchainHeaderHash([0x00; 32]),
        };

        let op_bytes = {
            let mut buffer = vec![];
            let mut magic_bytes = self.client.magic_bytes.as_bytes().to_vec();
            buffer.append(&mut magic_bytes);
            block_commit_op
                .consensus_serialize(&mut buffer)
                .expect("FATAL: invalid operation");
            buffer
        };

        let mut tx = StacksTransaction::new(
            if self.client.mainnet {
                TransactionVersion::Mainnet
            } else {
                TransactionVersion::Testnet
            },
            TransactionAuth::from_p2pkh(&privk)
                .expect("BUG: failed to build single-sig transaction auth from single private key"),
            TransactionPayload::ContractCall(TransactionContractCall {
                address: self.client.contract_id.issuer.clone().into(),
                contract_name: self.client.contract_id.name.clone(),
                function_name: "mine-block".into(),
                function_args: vec![
                    Value::buff_from(op_bytes).expect("BUG: failed to construct a (buff 80)"),
                    Value::UInt(sunset_burn as u128),
                    Value::list_from(
                        recipients
                            .into_iter()
                            .map(|addr| Value::Principal(addr.into()))
                            .collect(),
                    )
                    .expect("BUG: failed to construct a (list 2 principal)"),
                    Value::UInt(recipient_payout as u128),
                ],
            }),
        );

        tx.chain_id = self.client.parent_chain_id;
        tx.anchor_mode = TransactionAnchorMode::OnChainOnly;
        tx.post_condition_mode = TransactionPostConditionMode::Deny;
        tx.post_conditions = vec![TransactionPostCondition::STX(
            PostConditionPrincipal::Origin,
            FungibleConditionCode::SentEq,
            sunset_burn + recipient_payout * (num_recipients as u64),
        )];
        tx.auth.set_origin_nonce(nonce);
        tx.set_tx_fee(fee);

        let mut tx_signer = StacksTransactionSigner::new(&tx);
        tx_signer
            .sign_origin(&privk)
            .expect("BUG: failed to sign transaction single-sig origin with private key");
        tx_signer
            .get_tx()
            .expect("BUG: failed to complete a transaction after one signature")
    }

    /// Get the address of a private key
    fn get_privk_addr(&self, privk: &StacksPrivateKey) -> StacksAddress {
        StacksAddress::from_public_keys(
            if self.client.mainnet {
                C32_ADDRESS_VERSION_MAINNET_SINGLESIG
            } else {
                C32_ADDRESS_VERSION_TESTNET_SINGLESIG
            },
            &AddressHashMode::SerializeP2PKH,
            1,
            &vec![StacksPublicKey::from_private(privk)],
        )
        .expect("BUG: failed to build address from valid private key")
    }

    /// Open a socket to the remote host chain peer
    fn open_socket(&mut self) -> Result<TcpStream, Error> {
        let peer_host = self.client.peer.0.clone();
        let peer = (peer_host.as_str(), self.client.peer.1);
        let (socket, _) = self
            .client
            .try_open_session(peer, self.client.parent_chain_id)?;
        Ok(socket)
    }

    /// Get this node's miner account -- particularly its nonce.
    fn get_miner_account(
        &mut self,
        miner_address: &StacksAddress,
        force: bool,
    ) -> Result<StacksAccount, Error> {
        if force {
            self.miner_account = None;
        }

        match self.miner_account.as_ref() {
            Some(acct) => Ok(acct.clone()),
            None => {
                let mut socket = self.open_socket()?;
                let acct = self
                    .client
                    .download_account(miner_address.clone(), &mut socket)?;
                Ok(acct)
            }
        }
    }

    /// Do the client bootup, so we can have a complete config
    pub fn bootup(&mut self) -> Result<(), Error> {
        if let Some(appchain_runtime) = self.config.burnchain.appchain_runtime.as_ref() {
            let mut available_bootcode = HashMap::new();
            for (code_name, code_body) in appchain_runtime.boot_code.iter() {
                available_bootcode.insert(code_name.clone(), code_body.clone());
            }
            self.client.bootup(&available_bootcode)?;
            self.booted = true;
            Ok(())
        } else {
            panic!("BUG: config does not contain any appchain state");
        }
    }
}

impl BurnchainController for StacksController {
    fn start(
        &mut self,
        target_block_height_opt: Option<u64>,
    ) -> Result<(BurnchainTip, u64), Error> {
        if !self.booted {
            self.bootup()?;
        }

        let target_block_height = target_block_height_opt.unwrap_or(1);
        self.receive_blocks(false, target_block_height)
    }

    fn sync(&mut self, target_block_height_opt: Option<u64>) -> Result<(BurnchainTip, u64), Error> {
        let (burnchain_tip, burnchain_height) =
            self.receive_blocks(true, target_block_height_opt.unwrap_or(1))?;

        // Evaluate process_exit_at_block_height setting
        if let Some(cap) = self.config.burnchain.process_exit_at_block_height {
            if burnchain_tip.block_snapshot.block_height >= cap {
                info!(
                    "Node succesfully reached the end of the ongoing {} blocks epoch!",
                    cap
                );
                info!("This process will automatically terminate in 30s, restart your node for participating in the next epoch.");
                sleep_ms(30000);
                std::process::exit(0);
            }
        }
        Ok((burnchain_tip, burnchain_height))
    }

    /// This is always true because you can add STX to your miner at any time, without having to do
    /// an extra query step like we do in Bitcoin.
    fn can_mine(&self) -> bool {
        true
    }

    fn get_burnchain(&self) -> Burnchain {
        self.burnchain.clone()
    }

    fn sortdb_ref(&self) -> &SortitionDB {
        self.db
            .as_ref()
            .expect("BUG: did not instantiate the burn DB")
    }

    fn sortdb_mut(&mut self) -> &mut SortitionDB {
        let burnchain = self.get_burnchain();

        let (db, burnchain_db) = burnchain.open_db(true).unwrap();
        self.db = Some(db);
        self.burnchain_db = Some(burnchain_db);

        match self.db {
            Some(ref mut sortdb) => sortdb,
            None => unreachable!(),
        }
    }

    fn get_chain_tip(&self) -> BurnchainTip {
        match &self.chain_tip {
            Some(chain_tip) => chain_tip.clone(),
            None => {
                unreachable!();
            }
        }
    }

    fn connect_dbs(&mut self) -> Result<(), Error> {
        self.burnchain.connect_db(
            &self.client,
            true,
            self.client.get_first_block_header_hash()?,
            self.client.get_first_block_header_timestamp()?,
        )?;
        Ok(())
    }

    fn get_stacks_epochs(&self) -> Vec<StacksEpoch> {
        self.client.get_stacks_epochs()
    }

    fn get_headers_height(&self) -> u64 {
        self.client.get_highest_header_height()
            .unwrap_or(0)
    }

    /// wait until the ChainsCoordinator has processed sortitions up to the
    ///   canonical chain tip, or has processed up to height_to_wait
    fn wait_for_sortitions(&self, height_to_wait: Option<u64>) -> Result<BurnchainTip, Error> {
        assert!(
            !self.submit_only,
            "BUG: tried to use a submit-only apphchain client to sync the chain"
        );
        debug!("Wait for sortitions up to {:?}", &height_to_wait);
        loop {
            let canonical_burnchain_tip = self
                .burnchain_db
                .as_ref()
                .expect("BurnchainDB not opened")
                .get_canonical_chain_tip()
                .unwrap();
            let canonical_sortition_tip =
                SortitionDB::get_canonical_burn_chain_tip(self.sortdb_ref().conn()).unwrap();
            if canonical_burnchain_tip.block_height >= canonical_sortition_tip.block_height {
                let (_, state_transition) = self
                    .sortdb_ref()
                    .get_sortition_result(&canonical_sortition_tip.sortition_id)
                    .expect("Sortition DB error.")
                    .expect("BUG: no data for the canonical chain tip");
                debug!(
                    "Done waiting for sortitions -- reached height {}",
                    canonical_burnchain_tip.block_height
                );
                return Ok(BurnchainTip {
                    block_snapshot: canonical_sortition_tip,
                    received_at: Instant::now(),
                    state_transition,
                });
            } else if let Some(height_to_wait) = height_to_wait {
                if canonical_sortition_tip.block_height >= height_to_wait {
                    let (_, state_transition) = self
                        .sortdb_ref()
                        .get_sortition_result(&canonical_sortition_tip.sortition_id)
                        .expect("Sortition DB error.")
                        .expect("BUG: no data for the canonical chain tip");

                    debug!(
                        "Done waiting for sortitions -- reached height {}",
                        canonical_sortition_tip.block_height
                    );
                    return Ok(BurnchainTip {
                        block_snapshot: canonical_sortition_tip,
                        received_at: Instant::now(),
                        state_transition,
                    });
                }
            }
            if !self.should_keep_running() {
                return Err(Error::CoordinatorClosed);
            }
            // yield some time
            sleep_ms(100);
        }
    }

    fn submit_operation(
        &mut self,
        operation: BlockstackOperationType,
        op_signer: &mut BurnchainOpSigner,
        mut attempt: u64,
    ) -> bool {
        let privk = op_signer.get_private_key();
        let addr = self.get_privk_addr(&privk);

        if self.submit_only {
            // we don't have the latest root-to-block map loaded, so do so explicitly
            // (if we are sync'ing the chain, we'll have it automatically)
            if let Err(e) = self.client.refresh_root_to_block_map() {
                warn!("Failed to refresh root-to-block map: {:?}", &e);
                return false;
            }
        }

        let acct = match self.get_miner_account(&addr, true) {
            Ok(acct) => acct,
            Err(e) => {
                warn!("Failed to get miner account {}: {:?}", &addr, &e);
                return false;
            }
        };

        loop {
            let fee_with_rbf = self.base_fee + attempt * self.config.burnchain.rbf_fee_increment;

            if fee_with_rbf > self.base_fee * self.config.burnchain.max_rbf {
                warn!(
                    "Maximum RBF reached at attempt {}: {} > {} * {}",
                    attempt, fee_with_rbf, self.base_fee, self.config.burnchain.max_rbf
                );
                return false;
            }

            let tx = match &operation {
                BlockstackOperationType::LeaderKeyRegister(ref data) => self
                    .make_appchain_vrf_key_tx(&privk, acct.nonce, fee_with_rbf, &data.public_key),
                BlockstackOperationType::LeaderBlockCommit(ref data) => self
                    .make_appchain_block_commit_tx(
                        &privk,
                        acct.nonce,
                        fee_with_rbf,
                        data.block_header_hash,
                        data.new_seed,
                        data.burn_parent_modulus,
                        (data.parent_block_ptr, data.parent_vtxindex),
                        (data.key_block_ptr, data.key_vtxindex),
                        data.sunset_burn,
                        data.commit_outs.clone(),
                        data.burn_fee,
                    ),
                _ => {
                    warn!("Operation {:?} not supported yet", &operation);
                    return false;
                }
            };

            let mut socket = match self.open_socket() {
                Ok(s) => s,
                Err(e) => {
                    warn!("Failed to open socket to remote burnchain peer: {:?}", &e);
                    return false;
                }
            };

            match AppChainClient::send_transaction(&mut socket, tx.clone(), None) {
                Ok(_) => {
                    return true;
                }
                Err(e) => {
                    warn!("Failed to send transaction {:?}: {:?}", &tx, &e);
                    if format!("{:?}", &e)
                        .find("ConflictingNonceInMempool")
                        .is_some()
                    {
                        warn!("Failure appears to require RBF; attempting to do so");
                        attempt += 1;
                        continue;
                    } else {
                        return false;
                    }
                }
            }
        }
    }

    #[cfg(test)]
    fn bootstrap_chain(&mut self, _num_blocks: u64) {}
}
