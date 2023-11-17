use std::sync::atomic::AtomicBool;
use std::sync::mpsc::sync_channel;
use std::sync::mpsc::Receiver;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::thread::sleep;
use std::time::Duration;

use clarity::vm::ast::ASTRules;
use stacks::burnchains::BurnchainSigner;
use stacks::burnchains::Txid;
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::burn::operations::BlockstackOperationType;
use stacks::chainstate::burn::operations::LeaderBlockCommitOp;
use stacks::chainstate::burn::operations::LeaderKeyRegisterOp;
use stacks::chainstate::burn::BlockSnapshot;
use stacks::chainstate::burn::OpsHash;
use stacks::chainstate::burn::SortitionHash;
use stacks::chainstate::coordinator::comm::CoordinatorReceivers;
use stacks::chainstate::coordinator::CoordinatorCommunication;
use stacks::chainstate::nakamoto::NakamotoBlock;
use stacks::chainstate::nakamoto::NakamotoBlockHeader;
use stacks::chainstate::nakamoto::NakamotoChainState;
use stacks::chainstate::nakamoto::SetupBlockResult;
use stacks::chainstate::stacks::address::PoxAddress;
use stacks::chainstate::stacks::db::blocks::DummyEventDispatcher;
use stacks::chainstate::stacks::db::ChainStateBootData;
use stacks::chainstate::stacks::db::ClarityTx;
use stacks::chainstate::stacks::db::StacksChainState;
use stacks::chainstate::stacks::miner::BlockBuilder;
use stacks::chainstate::stacks::miner::BlockBuilderSettings;
use stacks::chainstate::stacks::miner::BlockLimitFunction;
use stacks::chainstate::stacks::miner::MinerStatus;
use stacks::chainstate::stacks::miner::TransactionResult;
use stacks::chainstate::stacks::CoinbasePayload;
use stacks::chainstate::stacks::Error as ChainstateError;
use stacks::chainstate::stacks::SchnorrThresholdSignature;
use stacks::chainstate::stacks::StacksBlockBuilder;
use stacks::chainstate::stacks::StacksTransaction;
use stacks::chainstate::stacks::StacksTransactionSigner;
use stacks::chainstate::stacks::TenureChangeCause;
use stacks::chainstate::stacks::TenureChangePayload;
use stacks::chainstate::stacks::TransactionAuth;
use stacks::chainstate::stacks::TransactionPayload;
use stacks::chainstate::stacks::TransactionVersion;
use stacks::chainstate::stacks::MAX_EPOCH_SIZE;
use stacks::chainstate::stacks::MINER_BLOCK_CONSENSUS_HASH;
use stacks::chainstate::stacks::MINER_BLOCK_HEADER_HASH;
use stacks::clarity_vm::database::SortitionDBRef;
use stacks::core::mempool::MemPoolWalkSettings;
use stacks::core::MemPoolDB;
use stacks::core::StacksEpoch;
use stacks::core::BLOCK_LIMIT_MAINNET_10;
use stacks::core::HELIUM_BLOCK_LIMIT_20;
use stacks::core::PEER_VERSION_EPOCH_1_0;
use stacks::core::PEER_VERSION_EPOCH_2_0;
use stacks::core::PEER_VERSION_EPOCH_2_05;
use stacks::core::PEER_VERSION_EPOCH_2_1;
use stacks::core::PEER_VERSION_EPOCH_2_2;
use stacks::core::PEER_VERSION_EPOCH_2_3;
use stacks::core::PEER_VERSION_EPOCH_2_4;
use stacks::core::PEER_VERSION_EPOCH_2_5;
use stacks::core::PEER_VERSION_EPOCH_3_0;
use stacks::core::TX_BLOCK_LIMIT_PROPORTION_HEURISTIC;
use stacks::net::relay::Relayer;
use stacks::net::stackerdb::StackerDBs;
use stacks_common::consts::FIRST_BURNCHAIN_CONSENSUS_HASH;
use stacks_common::consts::FIRST_STACKS_BLOCK_HASH;
use stacks_common::consts::STACKS_EPOCH_MAX;
use stacks_common::types::chainstate::BlockHeaderHash;
use stacks_common::types::chainstate::BurnchainHeaderHash;
use stacks_common::types::chainstate::ConsensusHash;
use stacks_common::types::chainstate::PoxId;
use stacks_common::types::chainstate::SortitionId;
use stacks_common::types::chainstate::StacksAddress;
use stacks_common::types::chainstate::StacksBlockId;
use stacks_common::types::chainstate::StacksPrivateKey;
use stacks_common::types::chainstate::TrieHash;
use stacks_common::types::chainstate::VRFSeed;
use stacks_common::types::PrivateKey;
use stacks_common::types::StacksEpochId;
use stacks_common::util::hash::Hash160;
use stacks_common::util::hash::MerkleTree;
use stacks_common::util::hash::Sha512Trunc256Sum;
use stacks_common::util::secp256k1::MessageSignature;
use stacks_common::util::secp256k1::Secp256k1PublicKey;
use stacks_common::util::vrf::VRFPrivateKey;
use stacks_common::util::vrf::VRFProof;
use stacks_common::util::vrf::VRFPublicKey;
use stacks_common::util::vrf::VRF;

use crate::neon::Counters;
use crate::neon_node::Globals;
use crate::neon_node::PeerThread;
use crate::neon_node::RelayerDirective;
use crate::neon_node::StacksNode;
use crate::neon_node::BLOCK_PROCESSOR_STACK_SIZE;
use crate::syncctl::PoxSyncWatchdogComms;
use crate::Config;
use crate::EventDispatcher;
use lazy_static::lazy_static;

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

fn make_snapshot(
    parent_snapshot: &BlockSnapshot,
    miner_pkh: &Hash160,
    initializing: bool,
) -> Result<BlockSnapshot, ChainstateError> {
    let burn_height = parent_snapshot.block_height + 1;
    let mut mock_burn_hash_contents = [0u8; 32];
    mock_burn_hash_contents[0..8].copy_from_slice((burn_height + 1).to_be_bytes().as_ref());
    let mut mock_consensus_hash_contents = [0u8; 20];
    mock_consensus_hash_contents[0..8].copy_from_slice((burn_height + 1).to_be_bytes().as_ref());

    let new_bhh = BurnchainHeaderHash(mock_burn_hash_contents);
    let new_ch = ConsensusHash(mock_consensus_hash_contents);
    let mut new_sh = SortitionHash([3; 32]);
    new_sh.0[0..8].copy_from_slice((burn_height + 1).to_be_bytes().as_ref());

    let winning_block_txid = if initializing {
        Txid([0; 32])
    } else {
        let mut winning_block_txid = [1u8; 32];
        winning_block_txid[0..8].copy_from_slice((burn_height + 1).to_be_bytes().as_ref());
        Txid(winning_block_txid)
    };

    let new_snapshot = BlockSnapshot {
        block_height: burn_height,
        burn_header_timestamp: 100 * u64::from(burn_height + 1),
        burn_header_hash: new_bhh.clone(),
        parent_burn_header_hash: parent_snapshot.burn_header_hash.clone(),
        consensus_hash: new_ch.clone(),
        ops_hash: OpsHash([0; 32]),
        total_burn: 10,
        sortition: true,
        sortition_hash: new_sh,
        winning_block_txid,
        winning_stacks_block_hash: BlockHeaderHash([0; 32]),
        index_root: TrieHash([0; 32]),
        num_sortitions: parent_snapshot.num_sortitions + 1,
        stacks_block_accepted: true,
        stacks_block_height: 1,
        arrival_index: parent_snapshot.arrival_index + 1,
        canonical_stacks_tip_height: 1,
        canonical_stacks_tip_hash: BlockHeaderHash([0; 32]),
        canonical_stacks_tip_consensus_hash: new_ch.clone(),
        sortition_id: SortitionId::new(&new_bhh.clone(), &PoxId::new(vec![true])),
        parent_sortition_id: parent_snapshot.sortition_id.clone(),
        pox_valid: true,
        accumulated_coinbase_ustx: 0,
        miner_pk_hash: Some(miner_pkh.clone()),
    };
    Ok(new_snapshot)
}

/// This struct wraps all the state required for operating a
/// stacks-node in `mockamoto` mode.
///
/// This mode of operation is a single-node network in which bitcoin
/// blocks are simulated: no `bitcoind` is communicated with (either
/// operating as regtest, testnet or mainnet). This operation mode
/// is useful for testing the stacks-only operation of Nakamoto.
///
/// The current implementation of the mockamoto node simply produces
/// Nakamoto blocks containing *only* coinbase and tenure-change
/// transactions. As the implementation of Nakamoto progresses, and
/// the mockamoto mode merges with changes to the chains coordinator,
/// the mockamoto node will support mining of transactions and event
/// emission.
///
pub struct MockamotoNode {
    sortdb: SortitionDB,
    mempool: MemPoolDB,
    chainstate: StacksChainState,
    miner_key: StacksPrivateKey,
    vrf_key: VRFPrivateKey,
    relay_rcv: Receiver<RelayerDirective>,
    coord_rcv: CoordinatorReceivers,
    globals: Globals,
    config: Config,
}

struct MockamotoBlockBuilder {
    txs: Vec<StacksTransaction>,
    bytes_so_far: u64,
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

        let burnchain = config.get_burnchain();
        let (sortdb, _burndb) = burnchain
            .connect_db(
                true,
                BurnchainHeaderHash([0; 32]),
                100,
                STACKS_EPOCHS_MOCKAMOTO.to_vec(),
            )
            .map_err(|e| e.to_string())?;

        let initial_balances: Vec<_> = config
            .initial_balances
            .iter()
            .map(|balance| (balance.address.clone(), balance.amount))
            .collect();
        let mut boot_data = ChainStateBootData::new(&burnchain, initial_balances, None);
        let (chainstate, _) = StacksChainState::open_and_exec(
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

        Ok(MockamotoNode {
            sortdb,
            chainstate,
            miner_key,
            vrf_key,
            relay_rcv,
            coord_rcv,
            mempool,
            globals,
            config: config.clone(),
        })
    }

    pub fn run(&mut self) {
        info!("Starting a burn cycle");
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

        let relayer = Relayer::from_p2p(&mut p2p_net, stackerdbs);

        let peer_thread = PeerThread::new_all(
            self.globals.clone(),
            &self.config,
            self.config.get_burnchain().pox_constants,
            p2p_net,
        );
        let ev_dispatcher = EventDispatcher::new();

        let _peer_thread = thread::Builder::new()
            .stack_size(BLOCK_PROCESSOR_STACK_SIZE)
            .name("p2p".into())
            .spawn(move || {
                StacksNode::p2p_main(peer_thread, ev_dispatcher);
            })
            .expect("FATAL: failed to start p2p thread");

        loop {
            info!("Starting a burn cycle");
            self.produce_burnchain_block(false).unwrap();
            info!("Produced a burn block");
            sleep(Duration::from_millis(100));
            info!("Mining a staging block");
            self.mine_and_stage_block().unwrap();
            info!("Processing a staging block");
            self.process_staging_block().unwrap();
            info!("Cycle done");
            sleep(Duration::from_secs(5));
        }
    }

    fn produce_burnchain_block(&mut self, initializing: bool) -> Result<(), ChainstateError> {
        let miner_pk = Secp256k1PublicKey::from_private(&self.miner_key);
        let miner_pk_hash = Hash160::from_node_public_key(&miner_pk);

        let parent_snapshot = SortitionDB::get_canonical_burn_chain_tip(&self.sortdb.conn())?;
        info!("Mocking bitcoin block"; "parent_height" => parent_snapshot.block_height);
        let new_snapshot = make_snapshot(&parent_snapshot, &miner_pk_hash, initializing)?;
        let mut sortdb_tx = self.sortdb.tx_handle_begin(&parent_snapshot.sortition_id)?;
        let burn_height = new_snapshot.block_height;

        let mut ops = vec![];

        if burn_height == 1 {
            let mut txid = [2u8; 32];
            txid[0..8].copy_from_slice((burn_height + 1).to_be_bytes().as_ref());
            let key_register = LeaderKeyRegisterOp {
                consensus_hash: new_snapshot.consensus_hash,
                public_key: VRFPublicKey::from_private(&self.vrf_key),
                memo: miner_pk_hash.as_bytes().to_vec(),
                txid: Txid(txid),
                vtxindex: 0,
                block_height: new_snapshot.block_height,
                burn_header_hash: new_snapshot.burn_header_hash,
            };
            ops.push(BlockstackOperationType::LeaderKeyRegister(key_register));
        } else if !initializing {
            let (parent_block_ptr, parent_vtxindex) =
                if parent_snapshot.winning_block_txid.as_bytes() == &[0; 32] {
                    (0, 0)
                } else {
                    (parent_snapshot.block_height.try_into().unwrap(), 0)
                };

            let parent_vrf_proof = NakamotoChainState::get_block_vrf_proof(
                self.chainstate.db(),
                &parent_snapshot.consensus_hash,
            )?
            .unwrap_or_else(|| VRFProof::empty());

            let vrf_seed = VRFSeed::from_proof(&parent_vrf_proof);

            let block_commit = LeaderBlockCommitOp {
                block_header_hash: BlockHeaderHash([0; 32]),
                new_seed: vrf_seed,
                parent_block_ptr,
                parent_vtxindex,
                key_block_ptr: 1,
                key_vtxindex: 0,
                memo: vec![],
                burn_fee: 5000,
                input: (parent_snapshot.winning_block_txid.clone(), 3),
                burn_parent_modulus: u8::try_from(burn_height % 5).unwrap(),
                apparent_sender: BurnchainSigner(miner_pk_hash.to_string()),
                commit_outs: vec![
                    PoxAddress::Standard(StacksAddress::burn_address(false), None),
                    PoxAddress::Standard(StacksAddress::burn_address(false), None),
                ],
                sunset_burn: 0,
                txid: new_snapshot.winning_block_txid.clone(),
                vtxindex: 0,
                block_height: new_snapshot.block_height,
                burn_header_hash: new_snapshot.burn_header_hash,
            };
            ops.push(BlockstackOperationType::LeaderBlockCommit(block_commit))
        }

        sortdb_tx.append_chain_tip_snapshot(
            &parent_snapshot,
            &new_snapshot,
            &ops,
            &vec![],
            None,
            None,
            None,
        )?;

        sortdb_tx.commit()?;

        let staging_db_tx = self.chainstate.db_tx_begin()?;
        NakamotoChainState::set_burn_block_processed(&staging_db_tx, &new_snapshot.consensus_hash)?;
        staging_db_tx.commit()?;

        Ok(())
    }

    fn mine_stacks_block(&mut self) -> Result<NakamotoBlock, ChainstateError> {
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

        let (parent_chain_length, parent_burn_height) = if is_genesis {
            (0, 0)
        } else {
            let tip_block_id = StacksBlockId::new(&chain_tip_ch, &chain_tip_bh);
            let tip_info = NakamotoChainState::get_block_header(&chainstate_tx, &tip_block_id)?
                .ok_or(ChainstateError::NoSuchBlockError)?;
            (tip_info.stacks_block_height, tip_info.burn_header_height)
        };

        info!("Mining block"; "parent_chain_length" => parent_chain_length, "chain_tip_bh" => %chain_tip_bh, "chain_tip_ch" => %chain_tip_ch);
        let miner_nonce = 2 * parent_chain_length;

        // TODO: VRF proof cannot be None in Nakamoto rules
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

        let parent_block_id = StacksBlockId::new(&chain_tip_ch, &chain_tip_bh);
        // Add a tenure change transaction to the block:
        //  as of now every mockamoto block is a tenure-change.
        // If mockamoto mode changes to support non-tenure-changing blocks, this will have
        //  to be gated.
        let tenure_change_tx_payload = TransactionPayload::TenureChange(TenureChangePayload {
            previous_tenure_end: parent_block_id,
            previous_tenure_blocks: 1,
            cause: TenureChangeCause::BlockFound,
            pubkey_hash: Hash160([0; 20]),
            signature: SchnorrThresholdSignature {},
            signers: vec![],
        });
        let mut tenure_tx = StacksTransaction::new(
            TransactionVersion::Testnet,
            TransactionAuth::from_p2pkh(&self.miner_key).unwrap(),
            tenure_change_tx_payload,
        );
        tenure_tx.chain_id = chain_id;
        tenure_tx.set_origin_nonce(miner_nonce);
        let txid = tenure_tx.txid();
        let mut tenure_tx_signer = StacksTransactionSigner::new(&tenure_tx);
        tenure_tx_signer.sign_origin(&self.miner_key).unwrap();
        let tenure_tx = tenure_tx_signer.get_tx().unwrap();

        let sortdb_handle = self.sortdb.index_conn();
        let SetupBlockResult {
            mut clarity_tx,
            mut tx_receipts,
            matured_miner_rewards_opt,
            evaluated_epoch,
            applied_epoch_transition,
            burn_stack_stx_ops,
            burn_transfer_stx_ops,
            mut auto_unlock_events,
            burn_delegate_stx_ops,
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
            false,
            true,
            parent_chain_length + 1,
        )?;

        let txs = vec![tenure_tx, coinbase_tx];

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
            None,
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

        let mut lockup_events = match NakamotoChainState::finish_block(
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
        chainstate_tx.commit();

        let mut block = NakamotoBlock {
            header: NakamotoBlockHeader {
                version: 100,
                chain_length: parent_chain_length + 1,
                burn_spent: 10,
                tx_merkle_root: tx_merkle_tree.root(),
                state_index_root,
                stacker_signature: MessageSignature([0; 65]),
                miner_signature: MessageSignature([0; 65]),
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

    fn mine_and_stage_block(&mut self) -> Result<(), ChainstateError> {
        let block = self.mine_stacks_block()?;
        let config = self.chainstate.config();
        let chainstate_tx = self.chainstate.db_tx_begin()?;
        let sortition_handle = self.sortdb.index_handle_at_tip();
        NakamotoChainState::accept_block(&config, block, &sortition_handle, &chainstate_tx)?;
        chainstate_tx.commit()?;
        Ok(())
    }

    fn process_staging_block(&mut self) -> Result<bool, ChainstateError> {
        info!("Processing a staging block!");
        let mut sortdb_tx = self.sortdb.tx_begin_at_tip();
        let result = NakamotoChainState::process_next_nakamoto_block::<DummyEventDispatcher>(
            &mut self.chainstate,
            &mut sortdb_tx,
            None,
        )
        .unwrap();
        sortdb_tx.commit().unwrap();
        if result.is_none() {
            return Ok(false);
        } else {
            info!("Processed a staging block!");
            return Ok(true);
        }
    }
}
