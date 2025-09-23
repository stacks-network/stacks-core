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
use crate::util_lib::db::Error as db_error;

pub trait ChainstateDB {
    fn backup(backup_path: &str) -> Result<(), db_error>;
}

// needs to come _after_ the macro def above, since they both use this macro
pub mod burn;
pub mod coordinator;
pub mod nakamoto;
pub mod stacks;

#[cfg(test)]
pub mod test {
    use std::collections::HashSet;
    use std::fs;

    use clarity::types::chainstate::{BlockHeaderHash, BurnchainHeaderHash, StacksBlockId};
    use clarity::types::sqlite::NO_PARAMS;
    use clarity::vm::ast::parser::v1::CONTRACT_MAX_NAME_LENGTH;
    use clarity::vm::database::STXBalance;
    use clarity::vm::types::*;
    use clarity::vm::ContractName;
    use rand;
    use rand::{thread_rng, Rng};
    use stacks_common::address::*;
    use stacks_common::deps_common::bitcoin::network::serialize::BitcoinHash;
    use stacks_common::types::StacksEpochId;
    use stacks_common::util::hash::*;
    use stacks_common::util::vrf::*;

    use self::nakamoto::test_signers::TestSigners;
    use super::*;
    use crate::burnchains::bitcoin::indexer::BitcoinIndexer;
    use crate::burnchains::db::{BurnchainDB, BurnchainHeaderReader};
    use crate::burnchains::tests::*;
    use crate::burnchains::*;
    use crate::chainstate::burn::db::sortdb::*;
    use crate::chainstate::burn::operations::*;
    use crate::chainstate::burn::*;
    use crate::chainstate::coordinator::tests::*;
    use crate::chainstate::coordinator::{Error as coordinator_error, *};
    use crate::chainstate::nakamoto::tests::node::TestStacker;
    use crate::chainstate::nakamoto::{NakamotoBlock, NakamotoChainState};
    use crate::chainstate::stacks::address::PoxAddress;
    use crate::chainstate::stacks::boot::test::get_parent_tip;
    use crate::chainstate::stacks::db::{StacksChainState, *};
    use crate::chainstate::stacks::tests::chain_histories::mine_smart_contract_block_contract_call_microblock;
    use crate::chainstate::stacks::tests::*;
    use crate::chainstate::stacks::{StacksMicroblockHeader, *};
    use crate::core::{EpochList, StacksEpoch, StacksEpochExtension};
    use crate::net::relay::*;
    use crate::net::test::{TestEventObserver, TestPeerConfig};
    use crate::net::Error as net_error;
    use crate::util_lib::boot::{boot_code_test_addr, boot_code_tx_auth};
    use crate::util_lib::strings::*;

    // describes a chainstate's initial configuration
    #[derive(Debug, Clone)]
    pub struct TestChainstateConfig {
        pub network_id: u32,
        pub current_block: u64,
        pub burnchain: Burnchain,
        pub test_name: String,
        pub initial_balances: Vec<(PrincipalData, u64)>,
        pub initial_lockups: Vec<ChainstateAccountLockup>,
        pub spending_account: TestMiner,
        pub setup_code: String,
        pub epochs: Option<EpochList>,
        pub test_stackers: Option<Vec<TestStacker>>,
        pub test_signers: Option<TestSigners>,
        /// aggregate public key to use
        /// (NOTE: will be used post-Nakamoto)
        pub aggregate_public_key: Option<Vec<u8>>,
        pub txindex: bool,
    }

    impl Default for TestChainstateConfig {
        fn default() -> Self {
            let peer_config = TestPeerConfig::default();
            Self::from(peer_config)
        }
    }
    impl TestChainstateConfig {
        pub fn new(test_name: &str) -> Self {
            Self {
                test_name: test_name.into(),
                ..Self::default()
            }
        }
    }
    pub struct TestChainstate<'a> {
        pub config: TestChainstateConfig,
        pub sortdb: Option<SortitionDB>,
        pub miner: TestMiner,
        pub stacks_node: Option<TestStacksNode>,
        pub chainstate_path: String,
        pub indexer: Option<BitcoinIndexer>,
        pub coord: ChainsCoordinator<
            'a,
            TestEventObserver,
            (),
            OnChainRewardSetProvider<'a, TestEventObserver>,
            (),
            (),
            BitcoinIndexer,
        >,
        pub nakamoto_parent_tenure_opt: Option<Vec<NakamotoBlock>>,
        /// list of malleablized blocks produced when mining.
        pub malleablized_blocks: Vec<NakamotoBlock>,
        pub mine_malleablized_blocks: bool,
    }

    impl From<TestPeerConfig> for TestChainstateConfig {
        fn from(peer_config: TestPeerConfig) -> Self {
            Self {
                network_id: peer_config.network_id,
                current_block: peer_config.current_block,
                burnchain: peer_config.burnchain,
                test_name: peer_config.test_name,
                initial_balances: peer_config.initial_balances,
                initial_lockups: peer_config.initial_lockups,
                spending_account: peer_config.spending_account,
                setup_code: peer_config.setup_code,
                epochs: peer_config.epochs,
                test_stackers: peer_config.test_stackers,
                test_signers: peer_config.test_signers,
                aggregate_public_key: peer_config.aggregate_public_key,
                txindex: peer_config.txindex,
            }
        }
    }
    impl<'a> TestChainstate<'a> {
        pub fn new(config: TestChainstateConfig) -> TestChainstate<'a> {
            Self::new_with_observer(config, None)
        }

        pub fn test_path(config: &TestChainstateConfig) -> String {
            let random = thread_rng().gen::<u64>();
            let random_bytes = to_hex(&random.to_be_bytes());
            let cleaned_config_test_name = config.test_name.replace("::", "_");
            format!(
                "/tmp/stacks-node-tests/units-test-consensus/{cleaned_config_test_name}-{random_bytes}"
            )
        }

        pub fn make_test_path(config: &TestChainstateConfig) -> String {
            let test_path = Self::test_path(config);
            if fs::metadata(&test_path).is_ok() {
                fs::remove_dir_all(&test_path).unwrap();
            };

            fs::create_dir_all(&test_path).unwrap();
            test_path
        }

        pub fn new_with_observer(
            mut config: TestChainstateConfig,
            observer: Option<&'a TestEventObserver>,
        ) -> TestChainstate<'a> {
            let test_path = Self::test_path(&config);
            let chainstate_path = get_chainstate_path_str(&test_path);
            let mut miner_factory = TestMinerFactory::new();
            miner_factory.chain_id = config.network_id;
            let mut miner = miner_factory.next_miner(
                config.burnchain.clone(),
                1,
                1,
                AddressHashMode::SerializeP2PKH,
            );
            // manually set fees
            miner.test_with_tx_fees = false;

            config.burnchain.working_dir = get_burnchain(&test_path, None).working_dir;

            let epochs = config.epochs.clone().unwrap_or_else(|| {
                StacksEpoch::unit_test_pre_2_05(config.burnchain.first_block_height)
            });

            let mut sortdb = SortitionDB::connect(
                &config.burnchain.get_db_path(),
                config.burnchain.first_block_height,
                &config.burnchain.first_block_hash,
                0,
                &epochs,
                config.burnchain.pox_constants.clone(),
                None,
                true,
            )
            .unwrap();

            let first_burnchain_block_height = config.burnchain.first_block_height;
            let first_burnchain_block_hash = config.burnchain.first_block_hash.clone();

            let _burnchain_blocks_db = BurnchainDB::connect(
                &config.burnchain.get_burnchaindb_path(),
                &config.burnchain,
                true,
            )
            .unwrap();

            let agg_pub_key_opt = config.aggregate_public_key.clone();

            let conf = config.clone();
            let post_flight_callback = move |clarity_tx: &mut ClarityTx| {
                let mut receipts = vec![];

                if let Some(agg_pub_key) = agg_pub_key_opt {
                    debug!("Setting aggregate public key to {}", &to_hex(&agg_pub_key));
                    NakamotoChainState::aggregate_public_key_bootcode(clarity_tx, agg_pub_key);
                } else {
                    debug!("Not setting aggregate public key");
                }
                // add test-specific boot code
                if !conf.setup_code.is_empty() {
                    let receipt = clarity_tx.connection().as_transaction(|clarity| {
                        let boot_code_addr = boot_code_test_addr();
                        let boot_code_account = StacksAccount {
                            principal: boot_code_addr.to_account_principal(),
                            nonce: 0,
                            stx_balance: STXBalance::zero(),
                        };

                        let boot_code_auth = boot_code_tx_auth(boot_code_addr.clone());

                        debug!(
                            "Instantiate test-specific boot code contract '{}.{}' ({} bytes)...",
                            &boot_code_addr.to_string(),
                            &conf.test_name,
                            conf.setup_code.len()
                        );

                        let smart_contract = TransactionPayload::SmartContract(
                            TransactionSmartContract {
                                name: ContractName::try_from(
                                    conf.test_name
                                        .replace("::", "-")
                                        .chars()
                                        .skip(
                                            conf.test_name
                                                .len()
                                                .saturating_sub(CONTRACT_MAX_NAME_LENGTH),
                                        )
                                        .collect::<String>()
                                        .trim_start_matches(|c: char| !c.is_alphabetic())
                                        .to_string(),
                                )
                                .expect("FATAL: invalid boot-code contract name"),
                                code_body: StacksString::from_str(&conf.setup_code)
                                    .expect("FATAL: invalid boot code body"),
                            },
                            None,
                        );

                        let boot_code_smart_contract = StacksTransaction::new(
                            TransactionVersion::Testnet,
                            boot_code_auth,
                            smart_contract,
                        );
                        StacksChainState::process_transaction_payload(
                            clarity,
                            &boot_code_smart_contract,
                            &boot_code_account,
                            None,
                        )
                        .unwrap()
                    });
                    receipts.push(receipt);
                }
                debug!("Bootup receipts: {receipts:?}");
            };

            let mut boot_data = ChainStateBootData::new(
                &config.burnchain,
                config.initial_balances.clone(),
                Some(Box::new(post_flight_callback)),
            );

            if !config.initial_lockups.is_empty() {
                let lockups = config.initial_lockups.clone();
                boot_data.get_bulk_initial_lockups =
                    Some(Box::new(move || Box::new(lockups.into_iter())));
            }

            let (chainstate, _) = StacksChainState::open_and_exec(
                false,
                config.network_id,
                &chainstate_path,
                Some(&mut boot_data),
                None,
            )
            .unwrap();

            let indexer = BitcoinIndexer::new_unit_test(&config.burnchain.working_dir);
            let mut coord = ChainsCoordinator::test_new_full(
                &config.burnchain,
                config.network_id,
                &test_path,
                OnChainRewardSetProvider(observer),
                observer,
                indexer,
                None,
                config.txindex,
            );
            coord.handle_new_burnchain_block().unwrap();

            let mut stacks_node = TestStacksNode::from_chainstate(chainstate);

            {
                // pre-populate burnchain, if running on bitcoin
                let prev_snapshot = SortitionDB::get_first_block_snapshot(sortdb.conn()).unwrap();
                let mut fork = TestBurnchainFork::new(
                    prev_snapshot.block_height,
                    &prev_snapshot.burn_header_hash,
                    &prev_snapshot.index_root,
                    0,
                );
                for i in prev_snapshot.block_height..config.current_block {
                    let burn_block = {
                        let ic = sortdb.index_conn();
                        let mut burn_block = fork.next_block(&ic);
                        stacks_node.add_key_register(&mut burn_block, &mut miner);
                        burn_block
                    };
                    fork.append_block(burn_block);

                    fork.mine_pending_blocks_pox(&mut sortdb, &config.burnchain, &mut coord);
                }
            }

            let indexer = BitcoinIndexer::new_unit_test(&config.burnchain.working_dir);

            TestChainstate {
                config,
                sortdb: Some(sortdb),
                miner,
                stacks_node: Some(stacks_node),
                chainstate_path,
                coord,
                indexer: Some(indexer),
                nakamoto_parent_tenure_opt: None,
                malleablized_blocks: vec![],
                mine_malleablized_blocks: true,
            }
        }

        pub fn get_burnchain_db(&self, readwrite: bool) -> BurnchainDB {
            let burnchain_db =
                BurnchainDB::open(&self.config.burnchain.get_burnchaindb_path(), readwrite)
                    .unwrap();
            burnchain_db
        }

        pub fn get_sortition_at_height(&self, height: u64) -> Option<BlockSnapshot> {
            let sortdb = self.sortdb.as_ref().unwrap();
            let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
            let sort_handle = sortdb.index_handle(&tip.sortition_id);
            sort_handle.get_block_snapshot_by_height(height).unwrap()
        }

        pub fn get_burnchain_block_ops(
            &self,
            burn_block_hash: &BurnchainHeaderHash,
        ) -> Vec<BlockstackOperationType> {
            let burnchain_db =
                BurnchainDB::open(&self.config.burnchain.get_burnchaindb_path(), false).unwrap();
            burnchain_db
                .get_burnchain_block_ops(burn_block_hash)
                .unwrap()
        }

        pub fn get_burnchain_block_ops_at_height(
            &self,
            height: u64,
        ) -> Option<Vec<BlockstackOperationType>> {
            let sortdb = self.sortdb.as_ref().unwrap();
            let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
            let sort_handle = sortdb.index_handle(&tip.sortition_id);
            let Some(sn) = sort_handle.get_block_snapshot_by_height(height).unwrap() else {
                return None;
            };
            Some(self.get_burnchain_block_ops(&sn.burn_header_hash))
        }

        pub fn next_burnchain_block(
            &mut self,
            blockstack_ops: Vec<BlockstackOperationType>,
        ) -> (u64, BurnchainHeaderHash, ConsensusHash) {
            let x = self.inner_next_burnchain_block(blockstack_ops, true, true, true, false);
            (x.0, x.1, x.2)
        }

        pub fn next_burnchain_block_diverge(
            &mut self,
            blockstack_ops: Vec<BlockstackOperationType>,
        ) -> (u64, BurnchainHeaderHash, ConsensusHash) {
            let x = self.inner_next_burnchain_block(blockstack_ops, true, true, true, true);
            (x.0, x.1, x.2)
        }

        pub fn next_burnchain_block_and_missing_pox_anchor(
            &mut self,
            blockstack_ops: Vec<BlockstackOperationType>,
        ) -> (
            u64,
            BurnchainHeaderHash,
            ConsensusHash,
            Option<BlockHeaderHash>,
        ) {
            self.inner_next_burnchain_block(blockstack_ops, true, true, true, false)
        }

        pub fn next_burnchain_block_raw(
            &mut self,
            blockstack_ops: Vec<BlockstackOperationType>,
        ) -> (u64, BurnchainHeaderHash, ConsensusHash) {
            let x = self.inner_next_burnchain_block(blockstack_ops, false, false, true, false);
            (x.0, x.1, x.2)
        }

        pub fn next_burnchain_block_raw_sortition_only(
            &mut self,
            blockstack_ops: Vec<BlockstackOperationType>,
        ) -> (u64, BurnchainHeaderHash, ConsensusHash) {
            let x = self.inner_next_burnchain_block(blockstack_ops, false, false, false, false);
            (x.0, x.1, x.2)
        }

        pub fn next_burnchain_block_raw_and_missing_pox_anchor(
            &mut self,
            blockstack_ops: Vec<BlockstackOperationType>,
        ) -> (
            u64,
            BurnchainHeaderHash,
            ConsensusHash,
            Option<BlockHeaderHash>,
        ) {
            self.inner_next_burnchain_block(blockstack_ops, false, false, true, false)
        }

        pub fn set_ops_consensus_hash(
            blockstack_ops: &mut Vec<BlockstackOperationType>,
            ch: &ConsensusHash,
        ) {
            for op in blockstack_ops.iter_mut() {
                if let BlockstackOperationType::LeaderKeyRegister(ref mut data) = op {
                    data.consensus_hash = (*ch).clone();
                }
            }
        }

        pub fn set_ops_burn_header_hash(
            blockstack_ops: &mut Vec<BlockstackOperationType>,
            bhh: &BurnchainHeaderHash,
        ) {
            for op in blockstack_ops.iter_mut() {
                op.set_burn_header_hash(bhh.clone());
            }
        }

        pub fn make_next_burnchain_block(
            burnchain: &Burnchain,
            tip_block_height: u64,
            tip_block_hash: &BurnchainHeaderHash,
            num_ops: u64,
            ops_determine_block_header: bool,
        ) -> BurnchainBlockHeader {
            test_debug!(
                "make_next_burnchain_block: tip_block_height={tip_block_height} tip_block_hash={tip_block_hash} num_ops={num_ops}"
            );
            let indexer = BitcoinIndexer::new_unit_test(&burnchain.working_dir);
            let parent_hdr = indexer
                .read_burnchain_header(tip_block_height)
                .unwrap()
                .unwrap();

            test_debug!("parent hdr ({tip_block_height}): {parent_hdr:?}");
            assert_eq!(&parent_hdr.block_hash, tip_block_hash);

            let now = BURNCHAIN_TEST_BLOCK_TIME;
            let block_header_hash = BurnchainHeaderHash::from_bitcoin_hash(
                &BitcoinIndexer::mock_bitcoin_header(
                    &parent_hdr.block_hash,
                    (now as u32)
                        + if ops_determine_block_header {
                            num_ops as u32
                        } else {
                            0
                        },
                )
                .bitcoin_hash(),
            );
            test_debug!(
                "Block header hash at {} is {block_header_hash}",
                tip_block_height + 1
            );

            BurnchainBlockHeader {
                block_height: tip_block_height + 1,
                block_hash: block_header_hash.clone(),
                parent_block_hash: parent_hdr.block_hash.clone(),
                num_txs: num_ops,
                timestamp: now,
            }
        }

        pub fn add_burnchain_block(
            burnchain: &Burnchain,
            block_header: &BurnchainBlockHeader,
            blockstack_ops: Vec<BlockstackOperationType>,
        ) {
            let mut burnchain_db =
                BurnchainDB::open(&burnchain.get_burnchaindb_path(), true).unwrap();

            let mut indexer = BitcoinIndexer::new_unit_test(&burnchain.working_dir);

            test_debug!(
                "Store header and block ops for {}-{} ({})",
                &block_header.block_hash,
                &block_header.parent_block_hash,
                block_header.block_height
            );
            indexer.raw_store_header(block_header.clone()).unwrap();
            burnchain_db
                .raw_store_burnchain_block(
                    burnchain,
                    &indexer,
                    block_header.clone(),
                    blockstack_ops,
                )
                .unwrap();
        }

        /// Generate and commit the next burnchain block with the given block operations.
        /// * if `set_consensus_hash` is true, then each op's consensus_hash field will be set to
        /// that of the resulting block snapshot.
        /// * if `set_burn_hash` is true, then each op's burnchain header hash field will be set to
        /// that of the resulting block snapshot.
        ///
        /// Returns (
        ///     burnchain tip block height,
        ///     burnchain tip block hash,
        ///     burnchain tip consensus hash,
        ///     Option<missing PoX anchor block hash>
        /// )
        fn inner_next_burnchain_block(
            &mut self,
            mut blockstack_ops: Vec<BlockstackOperationType>,
            set_consensus_hash: bool,
            set_burn_hash: bool,
            update_burnchain: bool,
            ops_determine_block_header: bool,
        ) -> (
            u64,
            BurnchainHeaderHash,
            ConsensusHash,
            Option<BlockHeaderHash>,
        ) {
            let sortdb = self.sortdb.take().unwrap();
            let (block_height, block_hash, epoch_id) = {
                let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
                let epoch_id = SortitionDB::get_stacks_epoch(sortdb.conn(), tip.block_height + 1)
                    .unwrap()
                    .unwrap()
                    .epoch_id;

                if set_consensus_hash {
                    Self::set_ops_consensus_hash(&mut blockstack_ops, &tip.consensus_hash);
                }

                let block_header = Self::make_next_burnchain_block(
                    &self.config.burnchain,
                    tip.block_height,
                    &tip.burn_header_hash,
                    blockstack_ops.len() as u64,
                    ops_determine_block_header,
                );

                if set_burn_hash {
                    Self::set_ops_burn_header_hash(&mut blockstack_ops, &block_header.block_hash);
                }

                if update_burnchain {
                    Self::add_burnchain_block(
                        &self.config.burnchain,
                        &block_header,
                        blockstack_ops.clone(),
                    );
                }
                (block_header.block_height, block_header.block_hash, epoch_id)
            };

            let missing_pox_anchor_block_hash_opt = if epoch_id < StacksEpochId::Epoch30 {
                self.coord
                    .handle_new_burnchain_block()
                    .unwrap()
                    .into_missing_block_hash()
            } else if self.coord.handle_new_nakamoto_burnchain_block().unwrap() {
                None
            } else {
                Some(BlockHeaderHash([0x00; 32]))
            };

            let pox_id = {
                let ic = sortdb.index_conn();
                let tip_sort_id = SortitionDB::get_canonical_sortition_tip(sortdb.conn()).unwrap();
                let sortdb_reader = SortitionHandleConn::open_reader(&ic, &tip_sort_id).unwrap();
                sortdb_reader.get_pox_id().unwrap()
            };

            test_debug!("\n\nafter burn block {block_hash:?}, tip PoX ID is {pox_id:?}\n\n");

            let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
            self.sortdb = Some(sortdb);
            (
                block_height,
                block_hash,
                tip.consensus_hash,
                missing_pox_anchor_block_hash_opt,
            )
        }

        /// Pre-process an epoch 2.x Stacks block.
        /// Validate it and store it to staging.
        pub fn preprocess_stacks_block(&mut self, block: &StacksBlock) -> Result<bool, String> {
            let sortdb = self.sortdb.take().unwrap();
            let mut node = self.stacks_node.take().unwrap();
            let res = {
                let sn = {
                    let ic = sortdb.index_conn();
                    let tip = SortitionDB::get_canonical_burn_chain_tip(&ic).unwrap();
                    let sn_opt = SortitionDB::get_block_snapshot_for_winning_stacks_block(
                        &ic,
                        &tip.sortition_id,
                        &block.block_hash(),
                    )
                    .unwrap();
                    if sn_opt.is_none() {
                        return Err(format!(
                            "No such block in canonical burn fork: {}",
                            block.block_hash()
                        ));
                    }
                    sn_opt.unwrap()
                };

                let parent_sn = {
                    let db_handle = sortdb.index_handle(&sn.sortition_id);
                    let parent_sn = db_handle
                        .get_block_snapshot(&sn.parent_burn_header_hash)
                        .unwrap();
                    parent_sn.unwrap()
                };

                let ic = sortdb.index_conn();
                node.chainstate
                    .preprocess_anchored_block(
                        &ic,
                        &sn.consensus_hash,
                        block,
                        &parent_sn.consensus_hash,
                        5,
                    )
                    .map_err(|e| format!("Failed to preprocess anchored block: {e:?}"))
            };
            if res.is_ok() {
                let pox_id = {
                    let ic = sortdb.index_conn();
                    let tip_sort_id =
                        SortitionDB::get_canonical_sortition_tip(sortdb.conn()).unwrap();
                    let sortdb_reader =
                        SortitionHandleConn::open_reader(&ic, &tip_sort_id).unwrap();
                    sortdb_reader.get_pox_id().unwrap()
                };
                test_debug!(
                    "\n\nafter stacks block {:?}, tip PoX ID is {pox_id:?}\n\n",
                    block.block_hash()
                );
                self.coord.handle_new_stacks_block().unwrap();
            }

            self.sortdb = Some(sortdb);
            self.stacks_node = Some(node);
            res
        }

        /// Preprocess epoch 2.x microblocks.
        /// Validate them and store them to staging.
        pub fn preprocess_stacks_microblocks(
            &mut self,
            microblocks: &[StacksMicroblock],
        ) -> Result<bool, String> {
            assert!(!microblocks.is_empty());
            let sortdb = self.sortdb.take().unwrap();
            let mut node = self.stacks_node.take().unwrap();
            let res = {
                let anchor_block_hash = microblocks[0].header.prev_block.clone();
                let sn = {
                    let ic = sortdb.index_conn();
                    let tip = SortitionDB::get_canonical_burn_chain_tip(&ic).unwrap();
                    let sn_opt = SortitionDB::get_block_snapshot_for_winning_stacks_block(
                        &ic,
                        &tip.sortition_id,
                        &anchor_block_hash,
                    )
                    .unwrap();
                    if sn_opt.is_none() {
                        return Err(format!(
                            "No such block in canonical burn fork: {anchor_block_hash}"
                        ));
                    }
                    sn_opt.unwrap()
                };

                let mut res = Ok(true);
                for mblock in microblocks.iter() {
                    res = node
                        .chainstate
                        .preprocess_streamed_microblock(
                            &sn.consensus_hash,
                            &anchor_block_hash,
                            mblock,
                        )
                        .map_err(|e| format!("Failed to preprocess microblock: {e:?}"));

                    if res.is_err() {
                        break;
                    }
                }
                res
            };

            self.sortdb = Some(sortdb);
            self.stacks_node = Some(node);
            res
        }

        /// Store the given epoch 2.x Stacks block and microblock to staging, and then try and
        /// process them.
        pub fn process_stacks_epoch_at_tip(
            &mut self,
            block: &StacksBlock,
            microblocks: &[StacksMicroblock],
        ) {
            let sortdb = self.sortdb.take().unwrap();
            let mut node = self.stacks_node.take().unwrap();
            {
                let ic = sortdb.index_conn();
                let tip = SortitionDB::get_canonical_burn_chain_tip(&ic).unwrap();
                node.chainstate
                    .preprocess_stacks_epoch(&ic, &tip, block, microblocks)
                    .unwrap();
            }
            self.coord.handle_new_stacks_block().unwrap();

            let pox_id = {
                let ic = sortdb.index_conn();
                let tip_sort_id = SortitionDB::get_canonical_sortition_tip(sortdb.conn()).unwrap();
                let sortdb_reader = SortitionHandleConn::open_reader(&ic, &tip_sort_id).unwrap();
                sortdb_reader.get_pox_id().unwrap()
            };
            test_debug!(
                "\n\nafter stacks block {:?}, tip PoX ID is {pox_id:?}\n\n",
                block.block_hash()
            );

            self.sortdb = Some(sortdb);
            self.stacks_node = Some(node);
        }

        /// Store the given epoch 2.x Stacks block and microblock to the given node's staging,
        /// using the given sortition DB as well, and then try and process them.
        fn inner_process_stacks_epoch_at_tip(
            &mut self,
            sortdb: &SortitionDB,
            node: &mut TestStacksNode,
            block: &StacksBlock,
            microblocks: &[StacksMicroblock],
        ) -> Result<(), coordinator_error> {
            {
                let ic = sortdb.index_conn();
                let tip = SortitionDB::get_canonical_burn_chain_tip(&ic)?;
                node.chainstate
                    .preprocess_stacks_epoch(&ic, &tip, block, microblocks)?;
            }
            self.coord.handle_new_stacks_block()?;

            let pox_id = {
                let ic = sortdb.index_conn();
                let tip_sort_id = SortitionDB::get_canonical_sortition_tip(sortdb.conn())?;
                let sortdb_reader = SortitionHandleConn::open_reader(&ic, &tip_sort_id)?;
                sortdb_reader.get_pox_id()?
            };
            test_debug!(
                "\n\nafter stacks block {:?}, tip PoX ID is {pox_id:?}\n\n",
                block.block_hash()
            );
            Ok(())
        }

        /// Store the given epoch 2.x Stacks block and microblock to the given node's staging,
        /// and then try and process them.
        pub fn process_stacks_epoch_at_tip_checked(
            &mut self,
            block: &StacksBlock,
            microblocks: &[StacksMicroblock],
        ) -> Result<(), coordinator_error> {
            let sortdb = self.sortdb.take().unwrap();
            let mut node = self.stacks_node.take().unwrap();
            let res =
                self.inner_process_stacks_epoch_at_tip(&sortdb, &mut node, block, microblocks);
            self.sortdb = Some(sortdb);
            self.stacks_node = Some(node);
            res
        }

        /// Accept a new Stacks block and microblocks via the relayer, and then try to process
        /// them.
        pub fn process_stacks_epoch(
            &mut self,
            block: &StacksBlock,
            consensus_hash: &ConsensusHash,
            microblocks: &[StacksMicroblock],
        ) {
            let sortdb = self.sortdb.take().unwrap();
            let mut node = self.stacks_node.take().unwrap();
            {
                let ic = sortdb.index_conn();
                Relayer::process_new_anchored_block(
                    &ic,
                    &mut node.chainstate,
                    consensus_hash,
                    block,
                    0,
                )
                .unwrap();

                let block_hash = block.block_hash();
                for mblock in microblocks.iter() {
                    node.chainstate
                        .preprocess_streamed_microblock(consensus_hash, &block_hash, mblock)
                        .unwrap();
                }
            }
            self.coord.handle_new_stacks_block().unwrap();

            let pox_id = {
                let ic = sortdb.index_conn();
                let tip_sort_id = SortitionDB::get_canonical_sortition_tip(sortdb.conn()).unwrap();
                let sortdb_reader = SortitionHandleConn::open_reader(&ic, &tip_sort_id).unwrap();
                sortdb_reader.get_pox_id().unwrap()
            };

            test_debug!(
                "\n\nafter stacks block {:?}, tip PoX ID is {pox_id:?}\n\n",
                block.block_hash()
            );

            self.sortdb = Some(sortdb);
            self.stacks_node = Some(node);
        }

        pub fn add_empty_burnchain_block(&mut self) -> (u64, BurnchainHeaderHash, ConsensusHash) {
            self.next_burnchain_block(vec![])
        }

        pub fn mine_empty_tenure(&mut self) -> (u64, BurnchainHeaderHash, ConsensusHash) {
            let (burn_ops, ..) = self.begin_nakamoto_tenure(TenureChangeCause::BlockFound);
            let result = self.next_burnchain_block(burn_ops);
            // remove the last block commit so that the testpeer doesn't try to build off of this tenure
            self.miner.block_commits.pop();
            result
        }

        pub fn chainstate(&mut self) -> &mut StacksChainState {
            &mut self.stacks_node.as_mut().unwrap().chainstate
        }

        pub fn chainstate_ref(&self) -> &StacksChainState {
            &self.stacks_node.as_ref().unwrap().chainstate
        }

        pub fn sortdb(&mut self) -> &mut SortitionDB {
            self.sortdb.as_mut().unwrap()
        }

        pub fn sortdb_ref(&mut self) -> &SortitionDB {
            self.sortdb.as_ref().unwrap()
        }

        pub fn with_mining_state<F, R>(&mut self, f: F) -> Result<R, net_error>
        where
            F: FnOnce(
                &mut SortitionDB,
                &mut TestMiner,
                &mut TestMiner,
                &mut TestStacksNode,
            ) -> Result<R, net_error>,
        {
            let mut stacks_node = self.stacks_node.take().unwrap();
            let mut sortdb = self.sortdb.take().unwrap();
            let res = f(
                &mut sortdb,
                &mut self.miner,
                &mut self.config.spending_account,
                &mut stacks_node,
            );
            self.sortdb = Some(sortdb);
            self.stacks_node = Some(stacks_node);
            res
        }

        /// Make a tenure with the given transactions. Creates a coinbase tx with the given nonce, and then increments
        /// the provided reference.
        pub fn tenure_with_txs(
            &mut self,
            txs: &[StacksTransaction],
            coinbase_nonce: &mut usize,
        ) -> StacksBlockId {
            let microblock_privkey = self.miner.next_microblock_privkey();
            let microblock_pubkeyhash =
                Hash160::from_node_public_key(&StacksPublicKey::from_private(&microblock_privkey));
            let tip =
                SortitionDB::get_canonical_burn_chain_tip(self.sortdb.as_ref().unwrap().conn())
                    .unwrap();
            let burnchain = self.config.burnchain.clone();

            let (burn_ops, stacks_block, microblocks) = self.make_tenure(
                |ref mut miner,
                 ref mut sortdb,
                 ref mut chainstate,
                 vrf_proof,
                 ref parent_opt,
                 ref parent_microblock_header_opt| {
                    let parent_tip = get_parent_tip(parent_opt, chainstate, sortdb);
                    let coinbase_tx = make_coinbase(miner, *coinbase_nonce);

                    let mut block_txs = vec![coinbase_tx];
                    block_txs.extend_from_slice(txs);

                    let block_builder = StacksBlockBuilder::make_regtest_block_builder(
                        &burnchain,
                        &parent_tip,
                        vrf_proof,
                        tip.total_burn,
                        &microblock_pubkeyhash,
                    )
                    .unwrap();
                    let (anchored_block, _size, _cost) =
                        StacksBlockBuilder::make_anchored_block_from_txs(
                            block_builder,
                            chainstate,
                            &sortdb.index_handle(&tip.sortition_id),
                            block_txs,
                        )
                        .unwrap();
                    (anchored_block, vec![])
                },
            );

            let (_, _, consensus_hash) = self.next_burnchain_block(burn_ops);
            self.process_stacks_epoch_at_tip(&stacks_block, &microblocks);

            *coinbase_nonce += 1;

            let tip_id = StacksBlockId::new(&consensus_hash, &stacks_block.block_hash());
            tip_id
        }

        /// Make a tenure, using `tenure_builder` to generate a Stacks block and a list of
        /// microblocks.
        pub fn make_tenure<F>(
            &mut self,
            mut tenure_builder: F,
        ) -> (
            Vec<BlockstackOperationType>,
            StacksBlock,
            Vec<StacksMicroblock>,
        )
        where
            F: FnMut(
                &mut TestMiner,
                &mut SortitionDB,
                &mut StacksChainState,
                &VRFProof,
                Option<&StacksBlock>,
                Option<&StacksMicroblockHeader>,
            ) -> (StacksBlock, Vec<StacksMicroblock>),
        {
            let mut sortdb = self.sortdb.take().unwrap();
            let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();

            let mut burn_block = TestBurnchainBlock::new(&tip, 0);
            let mut stacks_node = self.stacks_node.take().unwrap();

            let parent_block_opt = stacks_node.get_last_anchored_block(&self.miner);
            let parent_sortition_opt = parent_block_opt.as_ref().and_then(|parent_block| {
                let ic = sortdb.index_conn();
                SortitionDB::get_block_snapshot_for_winning_stacks_block(
                    &ic,
                    &tip.sortition_id,
                    &parent_block.block_hash(),
                )
                .unwrap()
            });

            let parent_microblock_header_opt =
                get_last_microblock_header(&stacks_node, &self.miner, parent_block_opt.as_ref());
            let last_key = stacks_node.get_last_key(&self.miner);

            let network_id = self.config.network_id;
            let chainstate_path = self.chainstate_path.clone();
            let burn_block_height = burn_block.block_height;

            let proof = self
                .miner
                .make_proof(
                    &last_key.public_key,
                    &burn_block.parent_snapshot.sortition_hash,
                )
                .unwrap_or_else(|| panic!("FATAL: no private key for {:?}", last_key.public_key));

            let (stacks_block, microblocks) = tenure_builder(
                &mut self.miner,
                &mut sortdb,
                &mut stacks_node.chainstate,
                &proof,
                parent_block_opt.as_ref(),
                parent_microblock_header_opt.as_ref(),
            );

            let mut block_commit_op = stacks_node.make_tenure_commitment(
                &sortdb,
                &mut burn_block,
                &mut self.miner,
                &stacks_block,
                microblocks.clone(),
                1000,
                &last_key,
                parent_sortition_opt.as_ref(),
            );

            // patch up block-commit -- these blocks all mine off of genesis
            if stacks_block.header.parent_block == BlockHeaderHash([0u8; 32]) {
                block_commit_op.parent_block_ptr = 0;
                block_commit_op.parent_vtxindex = 0;
            }

            let leader_key_op = stacks_node.add_key_register(&mut burn_block, &mut self.miner);

            // patch in reward set info
            let recipients = get_next_recipients(
                &tip,
                &mut stacks_node.chainstate,
                &mut sortdb,
                &self.config.burnchain,
                &OnChainRewardSetProvider::new(),
            )
            .unwrap_or_else(|e| panic!("Failure fetching recipient set: {e:?}"));
            block_commit_op.commit_outs = match recipients {
                Some(info) => {
                    let mut recipients = info
                        .recipients
                        .into_iter()
                        .map(|x| x.0)
                        .collect::<Vec<PoxAddress>>();
                    if recipients.len() == 1 {
                        recipients.push(PoxAddress::standard_burn_address(false));
                    }
                    recipients
                }
                None => {
                    if self
                        .config
                        .burnchain
                        .is_in_prepare_phase(burn_block.block_height)
                    {
                        vec![PoxAddress::standard_burn_address(false)]
                    } else {
                        vec![
                            PoxAddress::standard_burn_address(false),
                            PoxAddress::standard_burn_address(false),
                        ]
                    }
                }
            };
            test_debug!(
                "Block commit at height {} has {} recipients: {:?}",
                block_commit_op.block_height,
                block_commit_op.commit_outs.len(),
                &block_commit_op.commit_outs
            );

            self.stacks_node = Some(stacks_node);
            self.sortdb = Some(sortdb);
            (
                vec![
                    BlockstackOperationType::LeaderKeyRegister(leader_key_op),
                    BlockstackOperationType::LeaderBlockCommit(block_commit_op),
                ],
                stacks_block,
                microblocks,
            )
        }

        /// Produce a default, non-empty tenure for epoch 2.x
        pub fn make_default_tenure(
            &mut self,
        ) -> (
            Vec<BlockstackOperationType>,
            StacksBlock,
            Vec<StacksMicroblock>,
        ) {
            let sortdb = self.sortdb.take().unwrap();
            let mut burn_block = {
                let sn = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
                TestBurnchainBlock::new(&sn, 0)
            };

            let mut stacks_node = self.stacks_node.take().unwrap();

            let parent_block_opt = stacks_node.get_last_anchored_block(&self.miner);
            let parent_microblock_header_opt =
                get_last_microblock_header(&stacks_node, &self.miner, parent_block_opt.as_ref());
            let last_key = stacks_node.get_last_key(&self.miner);

            let network_id = self.config.network_id;
            let chainstate_path = self.chainstate_path.clone();
            let burn_block_height = burn_block.block_height;

            let (stacks_block, microblocks, block_commit_op) = stacks_node.mine_stacks_block(
                &sortdb,
                &mut self.miner,
                &mut burn_block,
                &last_key,
                parent_block_opt.as_ref(),
                1000,
                |mut builder, ref mut miner, sortdb| {
                    let (mut miner_chainstate, _) =
                        StacksChainState::open(false, network_id, &chainstate_path, None).unwrap();
                    let sort_iconn = sortdb.index_handle_at_tip();

                    let mut miner_epoch_info = builder
                        .pre_epoch_begin(&mut miner_chainstate, &sort_iconn, true)
                        .unwrap();
                    let mut epoch = builder
                        .epoch_begin(&sort_iconn, &mut miner_epoch_info)
                        .unwrap()
                        .0;

                    let (stacks_block, microblocks) =
                        mine_smart_contract_block_contract_call_microblock(
                            &mut epoch,
                            &mut builder,
                            miner,
                            burn_block_height as usize,
                            parent_microblock_header_opt.as_ref(),
                        );

                    builder.epoch_finish(epoch).unwrap();
                    (stacks_block, microblocks)
                },
            );

            let leader_key_op = stacks_node.add_key_register(&mut burn_block, &mut self.miner);

            self.stacks_node = Some(stacks_node);
            self.sortdb = Some(sortdb);
            (
                vec![
                    BlockstackOperationType::LeaderKeyRegister(leader_key_op),
                    BlockstackOperationType::LeaderBlockCommit(block_commit_op),
                ],
                stacks_block,
                microblocks,
            )
        }

        pub fn get_burnchain_view(&mut self) -> Result<BurnchainView, db_error> {
            let sortdb = self.sortdb.take().unwrap();
            let view_res = {
                let chaintip =
                    SortitionDB::get_canonical_burn_chain_tip(&sortdb.index_conn()).unwrap();
                SortitionDB::get_burnchain_view(
                    &sortdb.index_conn(),
                    &self.config.burnchain,
                    &chaintip,
                )
            };
            self.sortdb = Some(sortdb);
            view_res
        }

        pub fn get_burn_block_height(&self) -> u64 {
            SortitionDB::get_canonical_burn_chain_tip(
                self.sortdb.as_ref().expect("Failed to get sortdb").conn(),
            )
            .expect("Failed to get canonical burn chain tip")
            .block_height
        }

        pub fn get_reward_cycle(&self) -> u64 {
            let block_height = self.get_burn_block_height();
            self.config
                .burnchain
                .block_height_to_reward_cycle(block_height)
                .unwrap_or_else(|| {
                    panic!("Failed to get reward cycle for block height {block_height}")
                })
        }

        /// Verify that the sortition DB migration into Nakamoto worked correctly.
        pub fn check_nakamoto_migration(&mut self) {
            let mut sortdb = self.sortdb.take().unwrap();
            let mut node = self.stacks_node.take().unwrap();
            let chainstate = &mut node.chainstate;

            let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
            let epochs = SortitionDB::get_stacks_epochs(sortdb.conn()).unwrap();
            let epoch_3 = epochs.get(StacksEpochId::Epoch30).unwrap().clone();

            let mut all_chain_tips = sortdb.get_all_stacks_chain_tips().unwrap();
            let mut all_preprocessed_reward_sets =
                SortitionDB::get_all_preprocessed_reward_sets(sortdb.conn()).unwrap();

            // see that we can reconstruct the canonical chain tips for epoch 2.5 and earlier
            // NOTE: the migration logic DOES NOT WORK and IS NOT MEANT TO WORK with Nakamoto blocks,
            // so test this only with epoch 2 blocks before the epoch2-3 transition.
            let epoch2_sns: Vec<_> = sortdb
                .get_all_snapshots()
                .unwrap()
                .into_iter()
                .filter(|sn| sn.block_height + 1 < epoch_3.start_height)
                .collect();

            let epoch2_chs: HashSet<_> = epoch2_sns
                .iter()
                .map(|sn| sn.consensus_hash.clone())
                .collect();

            let expected_epoch2_chain_tips: Vec<_> = all_chain_tips
                .clone()
                .into_iter()
                .filter(|tip| epoch2_chs.contains(&tip.1))
                .collect();

            let tx = sortdb.tx_begin().unwrap();
            tx.execute(
                "CREATE TABLE stacks_chain_tips_backup AS SELECT * FROM stacks_chain_tips;",
                NO_PARAMS,
            )
            .unwrap();
            tx.execute("DELETE FROM stacks_chain_tips;", NO_PARAMS)
                .unwrap();
            tx.commit().unwrap();

            // NOTE: this considers each and every snapshot, but we only care about epoch2.x
            sortdb.apply_schema_8_stacks_chain_tips(&tip).unwrap();
            let migrated_epoch2_chain_tips: Vec<_> = sortdb
                .get_all_stacks_chain_tips()
                .unwrap()
                .into_iter()
                .filter(|tip| epoch2_chs.contains(&tip.1))
                .collect();

            // what matters is that the last tip is the same, and that each sortition has a chain tip.
            // depending on block arrival order, different sortitions might have witnessed different
            // stacks blocks as their chain tips, however.
            assert_eq!(
                migrated_epoch2_chain_tips.last().unwrap(),
                expected_epoch2_chain_tips.last().unwrap()
            );
            assert_eq!(
                migrated_epoch2_chain_tips.len(),
                expected_epoch2_chain_tips.len()
            );

            // restore
            let tx = sortdb.tx_begin().unwrap();
            tx.execute("DROP TABLE stacks_chain_tips;", NO_PARAMS)
                .unwrap();
            tx.execute(
                "ALTER TABLE stacks_chain_tips_backup RENAME TO stacks_chain_tips;",
                NO_PARAMS,
            )
            .unwrap();
            tx.commit().unwrap();

            // see that we calculate all the prior reward set infos
            let mut expected_epoch2_reward_sets: Vec<_> =
                SortitionDB::get_all_preprocessed_reward_sets(sortdb.conn())
                    .unwrap()
                    .into_iter()
                    .filter(|(sort_id, rc_info)| {
                        let sn = SortitionDB::get_block_snapshot(sortdb.conn(), sort_id)
                            .unwrap()
                            .unwrap();
                        let rc_sn = sortdb
                            .pox_constants
                            .block_height_to_reward_cycle(
                                sortdb.first_block_height,
                                sn.block_height,
                            )
                            .unwrap();
                        let rc_height = sortdb
                            .pox_constants
                            .reward_cycle_to_block_height(sortdb.first_block_height, rc_sn + 1);
                        sn.block_height <= epoch_3.start_height && sn.block_height < rc_height
                    })
                    .collect();

            let tx = sortdb.tx_begin().unwrap();
            tx.execute("CREATE TABLE preprocessed_reward_sets_backup AS SELECT * FROM preprocessed_reward_sets;", NO_PARAMS).unwrap();
            tx.execute("DELETE FROM preprocessed_reward_sets;", NO_PARAMS)
                .unwrap();
            tx.commit().unwrap();

            let migrator = SortitionDBMigrator::new(
                self.config.burnchain.clone(),
                &self.chainstate_path,
                None,
            )
            .unwrap();
            sortdb
                .apply_schema_8_preprocessed_reward_sets(&tip, migrator)
                .unwrap();

            let mut migrated_epoch2_reward_sets: Vec<_> =
                SortitionDB::get_all_preprocessed_reward_sets(sortdb.conn())
                    .unwrap()
                    .into_iter()
                    .filter(|(sort_id, rc_info)| {
                        let sn = SortitionDB::get_block_snapshot(sortdb.conn(), sort_id)
                            .unwrap()
                            .unwrap();
                        sn.block_height < epoch_3.start_height
                    })
                    .collect();

            expected_epoch2_reward_sets.sort_by(|a, b| a.0.cmp(&b.0));
            migrated_epoch2_reward_sets.sort_by(|a, b| a.0.cmp(&b.0));

            assert_eq!(expected_epoch2_reward_sets, migrated_epoch2_reward_sets);

            let tx = sortdb.tx_begin().unwrap();
            tx.execute("DROP TABLE preprocessed_reward_sets;", NO_PARAMS)
                .unwrap();
            tx.execute(
                "ALTER TABLE preprocessed_reward_sets_backup RENAME TO preprocessed_reward_sets;",
                NO_PARAMS,
            )
            .unwrap();
            tx.commit().unwrap();

            // sanity check -- restored tables are the same
            let mut restored_chain_tips = sortdb.get_all_stacks_chain_tips().unwrap();
            let mut restored_reward_sets =
                SortitionDB::get_all_preprocessed_reward_sets(sortdb.conn()).unwrap();

            all_chain_tips.sort_by(|a, b| a.0.cmp(&b.0));
            restored_chain_tips.sort_by(|a, b| a.0.cmp(&b.0));

            all_preprocessed_reward_sets.sort_by(|a, b| a.0.cmp(&b.0));
            restored_reward_sets.sort_by(|a, b| a.0.cmp(&b.0));

            assert_eq!(restored_chain_tips, all_chain_tips);
            assert_eq!(restored_reward_sets, all_preprocessed_reward_sets);

            self.sortdb = Some(sortdb);
            self.stacks_node = Some(node);
        }

        /// Verify that all malleablized blocks are duly processed
        pub fn check_malleablized_blocks(
            &self,
            all_blocks: Vec<NakamotoBlock>,
            expected_siblings: usize,
        ) {
            if !self.mine_malleablized_blocks {
                return;
            }
            for block in all_blocks.iter() {
                let sighash = block.header.signer_signature_hash();
                let siblings = self
                    .chainstate_ref()
                    .nakamoto_blocks_db()
                    .get_blocks_at_height(block.header.chain_length);

                debug!("Expect {expected_siblings} siblings: {siblings:?}");
                assert_eq!(siblings.len(), expected_siblings);

                for sibling in siblings {
                    let (processed, orphaned) = NakamotoChainState::get_nakamoto_block_status(
                        self.chainstate_ref().nakamoto_blocks_db(),
                        self.chainstate_ref().db(),
                        &sibling.header.consensus_hash,
                        &sibling.header.block_hash(),
                    )
                    .unwrap()
                    .unwrap();
                    assert!(processed);
                    assert!(!orphaned);
                }
            }
        }

        /// Set the nakamoto tenure to mine on
        pub fn mine_nakamoto_on(&mut self, parent_tenure: Vec<NakamotoBlock>) {
            self.nakamoto_parent_tenure_opt = Some(parent_tenure);
        }

        /// Clear the tenure to mine on. This causes the miner to build on the canonical tip
        pub fn mine_nakamoto_on_canonical_tip(&mut self) {
            self.nakamoto_parent_tenure_opt = None;
        }

        /// Get an account off of a tip
        pub fn get_account(
            &mut self,
            tip: &StacksBlockId,
            account: &PrincipalData,
        ) -> StacksAccount {
            let sortdb = self.sortdb.take().expect("FATAL: sortdb not restored");
            let mut node = self
                .stacks_node
                .take()
                .expect("FATAL: chainstate not restored");

            let acct = node
                .chainstate
                .maybe_read_only_clarity_tx(
                    &sortdb.index_handle_at_block(&node.chainstate, tip).unwrap(),
                    tip,
                    |clarity_tx| StacksChainState::get_account(clarity_tx, account),
                )
                .unwrap()
                .unwrap();

            self.sortdb = Some(sortdb);
            self.stacks_node = Some(node);
            acct
        }
    }
}
