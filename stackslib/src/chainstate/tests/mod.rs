// Copyright (C) 2025 Stacks Open Internet Foundation
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
pub mod consensus;

use std::fs;

use clarity::types::chainstate::{BlockHeaderHash, BurnchainHeaderHash, StacksBlockId};
use clarity::vm::ast::parser::v1::CONTRACT_MAX_NAME_LENGTH;
use clarity::vm::costs::ExecutionCost;
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
use crate::chainstate::coordinator::*;
use crate::chainstate::nakamoto::coordinator::get_nakamoto_next_recipients;
use crate::chainstate::nakamoto::tests::get_account;
use crate::chainstate::nakamoto::tests::node::{get_nakamoto_parent, TestStacker};
use crate::chainstate::nakamoto::{NakamotoBlock, NakamotoChainState, StacksDBIndexed};
use crate::chainstate::stacks::address::PoxAddress;
use crate::chainstate::stacks::boot::test::get_parent_tip;
use crate::chainstate::stacks::db::{StacksChainState, *};
use crate::chainstate::stacks::tests::*;
use crate::chainstate::stacks::{Error as ChainstateError, StacksMicroblockHeader, *};
use crate::core::{EpochList, StacksEpoch, StacksEpochExtension, BOOT_BLOCK_HASH};
use crate::net::test::{TestEventObserver, TestPeerConfig};
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
        let chain_config = TestPeerConfig::default();
        Self::from(chain_config)
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
    fn from(chain_config: TestPeerConfig) -> Self {
        Self {
            network_id: chain_config.network_id,
            current_block: chain_config.current_block,
            burnchain: chain_config.burnchain,
            test_name: chain_config.test_name,
            initial_balances: chain_config.initial_balances,
            initial_lockups: chain_config.initial_lockups,
            spending_account: chain_config.spending_account,
            setup_code: chain_config.setup_code,
            epochs: chain_config.epochs,
            test_stackers: chain_config.test_stackers,
            test_signers: chain_config.test_signers,
            aggregate_public_key: chain_config.aggregate_public_key,
            txindex: chain_config.txindex,
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

    pub fn next_burnchain_block(
        &mut self,
        blockstack_ops: Vec<BlockstackOperationType>,
    ) -> (u64, BurnchainHeaderHash, ConsensusHash) {
        let x = self.inner_next_burnchain_block(blockstack_ops, true, true, true, false);
        (x.0, x.1, x.2)
    }

    pub fn set_ops_consensus_hash(
        blockstack_ops: &mut [BlockstackOperationType],
        ch: &ConsensusHash,
    ) {
        for op in blockstack_ops.iter_mut() {
            if let BlockstackOperationType::LeaderKeyRegister(ref mut data) = op {
                data.consensus_hash = (*ch).clone();
            }
        }
    }

    pub fn set_ops_burn_header_hash(
        blockstack_ops: &mut [BlockstackOperationType],
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
        let mut burnchain_db = BurnchainDB::open(&burnchain.get_burnchaindb_path(), true).unwrap();

        let mut indexer = BitcoinIndexer::new_unit_test(&burnchain.working_dir);

        test_debug!(
            "Store header and block ops for {}-{} ({})",
            &block_header.block_hash,
            &block_header.parent_block_hash,
            block_header.block_height
        );
        indexer.raw_store_header(block_header.clone()).unwrap();
        burnchain_db
            .raw_store_burnchain_block(burnchain, &indexer, block_header.clone(), blockstack_ops)
            .unwrap();
    }

    /// Generate and commit the next burnchain block with the given block operations.
    /// * if `set_consensus_hash` is true, then each op's consensus_hash field will be set to
    ///   that of the resulting block snapshot.
    /// * if `set_burn_hash` is true, then each op's burnchain header hash field will be set to
    ///   that of the resulting block snapshot.
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

    pub fn sortdb(&mut self) -> &mut SortitionDB {
        self.sortdb.as_mut().unwrap()
    }

    pub fn sortdb_ref(&self) -> &SortitionDB {
        self.sortdb.as_ref().unwrap()
    }

    pub fn stacks_node(&mut self) -> &mut TestStacksNode {
        self.stacks_node.as_mut().unwrap()
    }

    pub fn stacks_node_ref(&self) -> &TestStacksNode {
        self.stacks_node.as_ref().unwrap()
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
        let tip = SortitionDB::get_canonical_burn_chain_tip(self.sortdb.as_ref().unwrap().conn())
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

        StacksBlockId::new(&consensus_hash, &stacks_block.block_hash())
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
            .unwrap_or_else(|| panic!("Failed to get reward cycle for block height {block_height}"))
    }

    /// Start the next Nakamoto tenure.
    /// This generates the VRF key and block-commit txs, as well as the TenureChange and
    /// leader key this commit references
    pub fn begin_nakamoto_tenure(
        &mut self,
        tenure_change_cause: TenureChangeCause,
    ) -> (
        Vec<BlockstackOperationType>,
        TenureChangePayload,
        LeaderKeyRegisterOp,
    ) {
        let mut sortdb = self.sortdb.take().unwrap();
        let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();

        let mut burn_block = TestBurnchainBlock::new(&tip, 0);
        let mut stacks_node = self.stacks_node.take().unwrap();

        let (last_tenure_id, parent_block_opt, parent_tenure_opt) =
            if let Some(nakamoto_parent_tenure) = self.nakamoto_parent_tenure_opt.as_ref() {
                (
                    nakamoto_parent_tenure.first().as_ref().unwrap().block_id(),
                    None,
                    Some(nakamoto_parent_tenure.clone()),
                )
            } else {
                get_nakamoto_parent(&self.miner, &stacks_node, &sortdb)
            };

        // find the VRF leader key register tx to use.
        // it's the one pointed to by the parent tenure
        let parent_consensus_hash_and_tenure_start_id_opt =
            if let Some(parent_tenure) = parent_tenure_opt.as_ref() {
                let tenure_start_block = parent_tenure.first().unwrap();
                Some((
                    tenure_start_block.header.consensus_hash.clone(),
                    tenure_start_block.block_id(),
                ))
            } else if let Some(parent_block) = parent_block_opt.as_ref() {
                let parent_header_info =
                    StacksChainState::get_stacks_block_header_info_by_index_block_hash(
                        stacks_node.chainstate.db(),
                        &last_tenure_id,
                    )
                    .unwrap()
                    .unwrap();
                Some((
                    parent_header_info.consensus_hash.clone(),
                    parent_header_info.index_block_hash(),
                ))
            } else {
                None
            };

        let (ch, parent_tenure_start_block_id) = parent_consensus_hash_and_tenure_start_id_opt
            .clone()
            .expect("No leader key");
        // it's possible that the parent was a shadow block.
        // if so, find the highest non-shadow ancestor's block-commit, so we can
        let mut cursor = ch;
        let (tenure_sn, tenure_block_commit) = loop {
            let tenure_sn = SortitionDB::get_block_snapshot_consensus(sortdb.conn(), &cursor)
                .unwrap()
                .unwrap();

            let Some(tenure_block_commit) = get_block_commit_by_txid(
                sortdb.conn(),
                &tenure_sn.sortition_id,
                &tenure_sn.winning_block_txid,
            )
            .unwrap() else {
                // parent must be a shadow block
                let header = NakamotoChainState::get_block_header_nakamoto(
                    stacks_node.chainstate.db(),
                    &parent_tenure_start_block_id,
                )
                .unwrap()
                .unwrap()
                .anchored_header
                .as_stacks_nakamoto()
                .cloned()
                .unwrap();

                assert!(header.is_shadow_block(), "Parent tenure start block ID {parent_tenure_start_block_id} has no block-commit and is not a shadow block");

                cursor = stacks_node
                    .chainstate
                    .index_conn()
                    .get_parent_tenure_consensus_hash(&parent_tenure_start_block_id, &cursor)
                    .unwrap()
                    .unwrap();

                continue;
            };
            break (tenure_sn, tenure_block_commit);
        };

        let last_key = SortitionDB::get_leader_key_at(
            &sortdb.index_conn(),
            tenure_block_commit.key_block_ptr.into(),
            tenure_block_commit.key_vtxindex.into(),
            &tenure_sn.sortition_id,
        )
        .unwrap()
        .unwrap();

        let network_id = self.config.network_id;
        let chainstate_path = self.chainstate_path.clone();
        let burn_block_height = burn_block.block_height;

        let (mut block_commit_op, tenure_change_payload) = stacks_node.begin_nakamoto_tenure(
            &sortdb,
            &mut self.miner,
            &mut burn_block,
            &last_key,
            parent_block_opt.as_ref(),
            parent_tenure_opt.as_deref(),
            1000,
            tenure_change_cause,
        );

        // patch up block-commit -- these blocks all mine off of genesis
        if last_tenure_id == StacksBlockId(BOOT_BLOCK_HASH.0) {
            block_commit_op.parent_block_ptr = 0;
            block_commit_op.parent_vtxindex = 0;
        }

        let mut burn_ops = vec![];
        if self.miner.last_VRF_public_key().is_none() {
            let leader_key_op = stacks_node.add_key_register(&mut burn_block, &mut self.miner);
            burn_ops.push(BlockstackOperationType::LeaderKeyRegister(leader_key_op));
        }

        // patch in reward set info
        let recipients = get_nakamoto_next_recipients(
            &tip,
            &mut sortdb,
            &mut stacks_node.chainstate,
            &tenure_change_payload.previous_tenure_end,
            &self.config.burnchain,
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

        burn_ops.push(BlockstackOperationType::LeaderBlockCommit(block_commit_op));

        // prepare to mine
        let miner_addr = self.miner.origin_address().unwrap();
        let miner_account = get_account(&mut stacks_node.chainstate, &sortdb, &miner_addr);
        self.miner.set_nonce(miner_account.nonce);

        self.stacks_node = Some(stacks_node);
        self.sortdb = Some(sortdb);
        (burn_ops, tenure_change_payload, last_key)
    }

    /// Make the VRF proof for this tenure.
    /// Call after processing the block-commit
    pub fn make_nakamoto_vrf_proof(&mut self, miner_key: LeaderKeyRegisterOp) -> VRFProof {
        let sortdb = self.sortdb.take().unwrap();
        let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
        let proof = self
            .miner
            .make_proof(&miner_key.public_key, &tip.sortition_hash)
            .unwrap_or_else(|| panic!("FATAL: no private key for {:?}", miner_key.public_key));
        self.sortdb = Some(sortdb);
        debug!(
            "VRF proof made from {:?} over {}: {proof:?}",
            miner_key.public_key, &tip.sortition_hash
        );
        proof
    }

    /// Produce and process a Nakamoto tenure, after processing the block-commit from
    /// begin_nakamoto_tenure().  You'd process the burnchain ops from begin_nakamoto_tenure(),
    /// take the consensus hash, and feed it in here.
    ///
    /// Returns the blocks, their sizes, and runtime costs
    pub fn make_nakamoto_tenure(
        &mut self,
        tenure_change: StacksTransaction,
        coinbase: StacksTransaction,
        timestamp: Option<u64>,
    ) -> Result<Vec<(NakamotoBlock, u64, ExecutionCost)>, ChainstateError> {
        let cycle = self.get_reward_cycle();
        let mut signers = self.config.test_signers.clone().unwrap_or_default();
        signers.generate_aggregate_key(cycle);

        let mut sortdb = self.sortdb.take().unwrap();
        let mut stacks_node = self.stacks_node.take().unwrap();
        let blocks = TestStacksNode::make_nakamoto_tenure_blocks(
            &mut stacks_node.chainstate,
            &mut sortdb,
            &mut self.miner,
            &mut signers,
            &tenure_change
                .try_as_tenure_change()
                .unwrap()
                .tenure_consensus_hash
                .clone(),
            Some(tenure_change),
            Some(coinbase),
            &mut self.coord,
            |_| {},
            |_, _, _, _| vec![],
            |_| true,
            self.mine_malleablized_blocks,
            self.nakamoto_parent_tenure_opt.is_none(),
            timestamp,
        )?;

        let just_blocks = blocks
            .clone()
            .into_iter()
            .map(|(block, _, _, _)| block)
            .collect();

        stacks_node.add_nakamoto_tenure_blocks(just_blocks);

        let mut malleablized_blocks: Vec<NakamotoBlock> = blocks
            .clone()
            .into_iter()
            .flat_map(|(_, _, _, malleablized)| malleablized)
            .collect();

        self.malleablized_blocks.append(&mut malleablized_blocks);

        let block_data = blocks
            .into_iter()
            .map(|(blk, sz, cost, _)| (blk, sz, cost))
            .collect();

        self.sortdb = Some(sortdb);
        self.stacks_node = Some(stacks_node);
        Ok(block_data)
    }
}
