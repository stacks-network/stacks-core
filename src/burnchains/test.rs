use std::collections::HashMap;

use address::*;
use burnchains::db::*;
use burnchains::Burnchain;
use burnchains::*;
use chainstate::burn::db::sortdb::*;
use chainstate::burn::operations::BlockstackOperationType;
use chainstate::burn::operations::*;
use chainstate::burn::*;
use chainstate::coordinator::comm::*;
use chainstate::coordinator::*;
use chainstate::stacks::*;
use util::get_epoch_time_secs;
use util::hash::*;
use util::secp256k1::*;
use util::vrf::*;
use util_lib::db::*;

use crate::burnchains::events::ContractEvent;
use crate::burnchains::events::NewBlock;
use crate::burnchains::events::NewBlockTxEvent;
use crate::burnchains::events::TxEventType;
use crate::types::chainstate::{BlockHeaderHash, SortitionId, VRFSeed};
use crate::vm::execute;
use crate::vm::types::QualifiedContractIdentifier;
use crate::vm::types::StandardPrincipalData;

use super::*;

impl Txid {
    pub fn from_test_data(
        block_height: u64,
        vtxindex: u32,
        burn_header_hash: &BurnchainHeaderHash,
        noise: u64,
    ) -> Txid {
        let mut bytes = vec![];
        bytes.extend_from_slice(&block_height.to_be_bytes());
        bytes.extend_from_slice(&vtxindex.to_be_bytes());
        bytes.extend_from_slice(burn_header_hash.as_bytes());
        bytes.extend_from_slice(&noise.to_be_bytes());
        let h = DoubleSha256::from_data(&bytes[..]);
        let mut hb = [0u8; 32];
        hb.copy_from_slice(h.as_bytes());

        Txid(hb)
    }
}

pub fn bhh_from_test_data(
    block_height: u64,
    index_root: &TrieHash,
    noise: u64,
) -> BurnchainHeaderHash {
    let mut bytes = vec![];
    bytes.extend_from_slice(&block_height.to_be_bytes());
    bytes.extend_from_slice(index_root.as_bytes());
    bytes.extend_from_slice(&noise.to_be_bytes());
    let h = DoubleSha256::from_data(&bytes[..]);
    let mut hb = [0u8; 32];
    hb.copy_from_slice(h.as_bytes());

    BurnchainHeaderHash(hb)
}

impl BurnchainBlockHeader {
    pub fn from_parent_snapshot(
        parent_sn: &BlockSnapshot,
        block_hash: BurnchainHeaderHash,
        num_txs: u64,
    ) -> BurnchainBlockHeader {
        BurnchainBlockHeader {
            block_height: parent_sn.block_height + 1,
            block_hash: block_hash,
            parent_block_hash: parent_sn.burn_header_hash.clone(),
            num_txs: num_txs,
            timestamp: get_epoch_time_secs(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TestBurnchainBlock {
    pub block_height: u64,
    pub parent_snapshot: BlockSnapshot,
    pub txs: Vec<BlockstackOperationType>,
    pub fork_id: u64,
    pub timestamp: u64,
}

#[derive(Debug, Clone)]
pub struct TestBurnchainFork {
    pub start_height: u64,
    pub mined: u64,
    pub tip_index_root: TrieHash,
    pub tip_header_hash: BurnchainHeaderHash,
    pub tip_sortition_id: SortitionId,
    pub pending_blocks: Vec<TestBurnchainBlock>,
    pub blocks: Vec<TestBurnchainBlock>,
    pub fork_id: u64,
}

pub struct TestBurnchainNode {
    pub sortdb: SortitionDB,
    pub dirty: bool,
    pub burnchain: Burnchain,
}

#[derive(Debug, Clone)]
pub struct TestMiner {
    pub burnchain: Burnchain,
    pub privks: Vec<StacksPrivateKey>,
    pub num_sigs: u16,
    pub hash_mode: AddressHashMode,
    pub microblock_privks: Vec<StacksPrivateKey>,
    pub vrf_keys: Vec<VRFPrivateKey>,
    pub vrf_key_map: HashMap<VRFPublicKey, VRFPrivateKey>,
    pub block_commits: Vec<LeaderBlockCommitOp>,
    pub id: usize,
    pub nonce: u64,
    pub spent_at_nonce: HashMap<u64, u128>, // how much uSTX this miner paid in a given tx's nonce
    pub test_with_tx_fees: bool, // set to true to make certain helper methods attach a pre-defined tx fee
}

pub struct TestMinerFactory {
    pub key_seed: [u8; 32],
    pub next_miner_id: usize,
}

impl TestMiner {
    pub fn new(
        burnchain: &Burnchain,
        privks: &Vec<StacksPrivateKey>,
        num_sigs: u16,
        hash_mode: &AddressHashMode,
    ) -> TestMiner {
        TestMiner {
            burnchain: burnchain.clone(),
            privks: privks.clone(),
            num_sigs,
            hash_mode: hash_mode.clone(),
            microblock_privks: vec![],
            vrf_keys: vec![],
            vrf_key_map: HashMap::new(),
            block_commits: vec![],
            id: 0,
            nonce: 0,
            spent_at_nonce: HashMap::new(),
            test_with_tx_fees: true,
        }
    }

    pub fn last_VRF_public_key(&self) -> Option<VRFPublicKey> {
        match self.vrf_keys.len() {
            0 => None,
            x => Some(VRFPublicKey::from_private(&self.vrf_keys[x - 1])),
        }
    }

    pub fn last_block_commit(&self) -> Option<LeaderBlockCommitOp> {
        match self.block_commits.len() {
            0 => None,
            x => Some(self.block_commits[x - 1].clone()),
        }
    }

    pub fn next_VRF_key(&mut self) -> VRFPrivateKey {
        let pk = if self.vrf_keys.len() == 0 {
            // first key is simply the 32-byte hash of the secret state
            let mut buf: Vec<u8> = vec![];
            for i in 0..self.privks.len() {
                buf.extend_from_slice(&self.privks[i].to_bytes()[..]);
            }
            buf.extend_from_slice(&[
                (self.num_sigs >> 8) as u8,
                (self.num_sigs & 0xff) as u8,
                self.hash_mode as u8,
            ]);
            let h = Sha256Sum::from_data(&buf[..]);
            VRFPrivateKey::from_bytes(h.as_bytes()).unwrap()
        } else {
            // next key is just the hash of the last
            let h = Sha256Sum::from_data(self.vrf_keys[self.vrf_keys.len() - 1].as_bytes());
            VRFPrivateKey::from_bytes(h.as_bytes()).unwrap()
        };

        self.vrf_keys.push(pk.clone());
        self.vrf_key_map
            .insert(VRFPublicKey::from_private(&pk), pk.clone());
        pk
    }

    pub fn next_microblock_privkey(&mut self) -> StacksPrivateKey {
        let pk = if self.microblock_privks.len() == 0 {
            // first key is simply the 32-byte hash of the secret state
            let mut buf: Vec<u8> = vec![];
            for i in 0..self.privks.len() {
                buf.extend_from_slice(&self.privks[i].to_bytes()[..]);
            }
            buf.extend_from_slice(&[
                (self.num_sigs >> 8) as u8,
                (self.num_sigs & 0xff) as u8,
                self.hash_mode as u8,
            ]);
            let h = Sha256Sum::from_data(&buf[..]);
            StacksPrivateKey::from_slice(h.as_bytes()).unwrap()
        } else {
            // next key is the hash of the last
            let h = Sha256Sum::from_data(
                &self.microblock_privks[self.microblock_privks.len() - 1].to_bytes(),
            );
            StacksPrivateKey::from_slice(h.as_bytes()).unwrap()
        };

        self.microblock_privks.push(pk.clone());
        pk
    }

    pub fn make_proof(
        &self,
        vrf_pubkey: &VRFPublicKey,
        last_sortition_hash: &SortitionHash,
    ) -> Option<VRFProof> {
        test_debug!(
            "Make proof from {} over {}",
            vrf_pubkey.to_hex(),
            last_sortition_hash
        );
        match self.vrf_key_map.get(vrf_pubkey) {
            Some(ref prover_key) => {
                let proof = VRF::prove(prover_key, &last_sortition_hash.as_bytes().to_vec());
                let valid =
                    match VRF::verify(vrf_pubkey, &proof, &last_sortition_hash.as_bytes().to_vec())
                    {
                        Ok(v) => v,
                        Err(e) => false,
                    };
                assert!(valid);
                Some(proof)
            }
            None => None,
        }
    }

    pub fn as_transaction_auth(&self) -> Option<TransactionAuth> {
        match self.hash_mode {
            AddressHashMode::SerializeP2PKH => TransactionAuth::from_p2pkh(&self.privks[0]),
            AddressHashMode::SerializeP2SH => {
                TransactionAuth::from_p2sh(&self.privks, self.num_sigs)
            }
            AddressHashMode::SerializeP2WPKH => TransactionAuth::from_p2wpkh(&self.privks[0]),
            AddressHashMode::SerializeP2WSH => {
                TransactionAuth::from_p2wsh(&self.privks, self.num_sigs)
            }
        }
    }

    pub fn origin_address(&self) -> Option<StacksAddress> {
        match self.as_transaction_auth() {
            Some(auth) => Some(auth.origin().address_testnet()),
            None => None,
        }
    }

    pub fn get_nonce(&self) -> u64 {
        self.nonce
    }

    pub fn set_nonce(&mut self, n: u64) -> () {
        self.nonce = n;
    }

    pub fn sign_as_origin(&mut self, tx_signer: &mut StacksTransactionSigner) -> () {
        let num_keys = if self.privks.len() < self.num_sigs as usize {
            self.privks.len()
        } else {
            self.num_sigs as usize
        };

        for i in 0..num_keys {
            tx_signer.sign_origin(&self.privks[i]).unwrap();
        }

        self.nonce += 1
    }

    pub fn sign_as_sponsor(&mut self, tx_signer: &mut StacksTransactionSigner) -> () {
        let num_keys = if self.privks.len() < self.num_sigs as usize {
            self.privks.len()
        } else {
            self.num_sigs as usize
        };

        for i in 0..num_keys {
            tx_signer.sign_sponsor(&self.privks[i]).unwrap();
        }

        self.nonce += 1
    }
}

// creates miners deterministically
impl TestMinerFactory {
    pub fn new() -> TestMinerFactory {
        TestMinerFactory {
            key_seed: [0u8; 32],
            next_miner_id: 1,
        }
    }

    pub fn from_u16(seed: u16) -> TestMinerFactory {
        let mut bytes = [0u8; 32];
        (&mut bytes[0..2]).copy_from_slice(&seed.to_be_bytes());
        TestMinerFactory {
            key_seed: bytes,
            next_miner_id: seed as usize,
        }
    }

    pub fn next_private_key(&mut self) -> StacksPrivateKey {
        let h = Sha256Sum::from_data(&self.key_seed);
        self.key_seed.copy_from_slice(h.as_bytes());

        StacksPrivateKey::from_slice(h.as_bytes()).unwrap()
    }

    pub fn next_miner(
        &mut self,
        burnchain: &Burnchain,
        num_keys: u16,
        num_sigs: u16,
        hash_mode: AddressHashMode,
    ) -> TestMiner {
        let mut keys = vec![];
        for i in 0..num_keys {
            keys.push(self.next_private_key());
        }

        test_debug!("New miner: {:?} {}:{:?}", &hash_mode, num_sigs, &keys);
        let mut m = TestMiner::new(burnchain, &keys, num_sigs, &hash_mode);
        m.id = self.next_miner_id;
        self.next_miner_id += 1;
        m
    }
}

impl TestBurnchainBlock {
    pub fn new(parent_snapshot: &BlockSnapshot, fork_id: u64) -> TestBurnchainBlock {
        TestBurnchainBlock {
            parent_snapshot: parent_snapshot.clone(),
            block_height: parent_snapshot.block_height + 1,
            txs: vec![],
            fork_id: fork_id,
            timestamp: get_epoch_time_secs(),
        }
    }

    pub fn add_leader_block_commit(
        &mut self,
        ic: &SortitionDBConn,
        miner: &mut TestMiner,
        block_hash: &BlockHeaderHash,
        burn_fee: u64,
        fork_snapshot: Option<&BlockSnapshot>,
        parent_block_snapshot: Option<&BlockSnapshot>,
    ) -> LeaderBlockCommitOp {
        let input = (Txid([0; 32]), 0);
        let pubks = miner
            .privks
            .iter()
            .map(|ref pk| StacksPublicKey::from_private(pk))
            .collect();
        let apparent_sender = BurnchainSigner {
            hash_mode: miner.hash_mode.clone(),
            num_sigs: miner.num_sigs as usize,
            public_keys: pubks,
        };

        let last_snapshot = match fork_snapshot {
            Some(sn) => sn.clone(),
            None => SortitionDB::get_canonical_burn_chain_tip(ic).unwrap(),
        };

        let last_snapshot_with_sortition = match parent_block_snapshot {
            Some(sn) => sn.clone(),
            None => SortitionDB::get_first_block_snapshot(ic).unwrap(),
        };

        let get_commit_res = SortitionDB::get_block_commit(
            ic.conn(),
            &last_snapshot_with_sortition.winning_block_txid,
            &last_snapshot_with_sortition.sortition_id,
        )
        .expect("FATAL: failed to read block commit");
        let mut txop = match get_commit_res {
            Some(parent) => LeaderBlockCommitOp::new(block_hash),
            None => LeaderBlockCommitOp::initial(block_hash),
        };

        txop.burn_header_hash = bhh_from_test_data(
            self.block_height,
            &self.parent_snapshot.index_root,
            self.fork_id,
        ); // NOTE: override this if you intend to insert into the sortdb!
        txop.txid = Txid::from_test_data(self.block_height, 0, &txop.burn_header_hash, 0);

        let epoch = SortitionDB::get_stacks_epoch(ic, self.block_height)
            .unwrap()
            .expect(&format!("BUG: no epoch for height {}", &self.block_height));

        self.txs
            .push(BlockstackOperationType::LeaderBlockCommit(txop.clone()));

        miner.block_commits.push(txop.clone());
        txop
    }

    // TODO: user burn support

    pub fn patch_from_chain_tip(&mut self, parent_snapshot: &BlockSnapshot) -> () {
        assert_eq!(parent_snapshot.block_height + 1, self.block_height);
    }

    pub fn mine(&self, db: &mut SortitionDB, burnchain: &Burnchain) -> BlockSnapshot {
        let block_hash = bhh_from_test_data(
            self.block_height,
            &self.parent_snapshot.index_root,
            self.fork_id,
        );
        let mock_bitcoin_block = StacksHyperBlock {
            current_block: StacksBlockId(block_hash.0.clone()),
            parent_block: StacksBlockId(self.parent_snapshot.burn_header_hash.0.clone()),
            ops: vec![],
            block_height: self.block_height,
        };
        let block = BurnchainBlock::StacksHyperBlock(mock_bitcoin_block);

        // this is basically lifted verbatum from Burnchain::process_block_ops()

        test_debug!(
            "Process block {} {}",
            block.block_height(),
            &block.block_hash()
        );

        let header = block.header();
        let sort_id = SortitionId::new(&header.parent_block_hash);
        let mut sortition_db_handle = SortitionHandleTx::begin(db, &sort_id).unwrap();

        let parent_snapshot = sortition_db_handle
            .get_block_snapshot(&header.parent_block_hash, &sort_id)
            .unwrap()
            .expect("FATAL: failed to get burnchain linkage info");

        let blockstack_txs = self.txs.clone();

        let new_snapshot = sortition_db_handle
            .process_block_txs(
                &parent_snapshot,
                &header,
                burnchain,
                blockstack_txs,
                None,
                None,
                0,
            )
            .unwrap();
        sortition_db_handle.commit().unwrap();

        new_snapshot.0
    }

    pub fn mine_pox<'a, T: BlockEventDispatcher, N: CoordinatorNotices, R: RewardSetProvider>(
        &self,
        db: &mut SortitionDB,
        burnchain: &Burnchain,
        coord: &mut ChainsCoordinator<'a, T, N, R, (), ()>,
    ) -> BlockSnapshot {
        let block_hash = bhh_from_test_data(
            self.block_height,
            &self.parent_snapshot.index_root,
            self.fork_id,
        );
        let mock_bitcoin_block = StacksHyperBlock {
            current_block: StacksBlockId(block_hash.0.clone()),
            parent_block: StacksBlockId(self.parent_snapshot.burn_header_hash.0.clone()),
            ops: vec![],
            block_height: self.block_height,
        };
        let block = BurnchainBlock::StacksHyperBlock(mock_bitcoin_block);

        test_debug!(
            "Process PoX block {} {}",
            block.block_height(),
            &block.block_hash()
        );

        let header = block.header();

        let mut burnchain_db = BurnchainDB::open(&burnchain.get_burnchaindb_path(), true).unwrap();
        burnchain_db
            .raw_store_burnchain_block(header.clone(), self.txs.clone())
            .unwrap();

        coord.handle_new_burnchain_block().unwrap();

        let snapshot = SortitionDB::get_canonical_burn_chain_tip(db.conn()).unwrap();
        snapshot
    }
}

impl TestBurnchainFork {
    pub fn new(
        start_height: u64,
        start_header_hash: &BurnchainHeaderHash,
        start_index_root: &TrieHash,
        fork_id: u64,
    ) -> TestBurnchainFork {
        TestBurnchainFork {
            start_height,
            mined: 0,
            tip_header_hash: start_header_hash.clone(),
            tip_sortition_id: SortitionId([0x00; 32]),
            tip_index_root: start_index_root.clone(),
            blocks: vec![],
            pending_blocks: vec![],
            fork_id: fork_id,
        }
    }

    pub fn fork(&self) -> TestBurnchainFork {
        let mut new_fork = (*self).clone();
        new_fork.fork_id += 1;
        new_fork
    }

    pub fn append_block(&mut self, b: TestBurnchainBlock) -> () {
        self.pending_blocks.push(b);
    }

    pub fn get_tip(&mut self, ic: &SortitionDBConn) -> BlockSnapshot {
        test_debug!(
            "Get tip snapshot at {} (sortition ID {})",
            &self.tip_header_hash,
            &self.tip_sortition_id
        );
        SortitionDB::get_block_snapshot(ic, &self.tip_sortition_id)
            .unwrap()
            .unwrap()
    }

    pub fn next_block(&mut self, ic: &SortitionDBConn) -> TestBurnchainBlock {
        let fork_tip = self.get_tip(ic);
        TestBurnchainBlock::new(&fork_tip, self.fork_id)
    }

    pub fn mine_pending_blocks(
        &mut self,
        db: &mut SortitionDB,
        burnchain: &Burnchain,
    ) -> BlockSnapshot {
        let mut snapshot = {
            let ic = db.index_conn();
            self.get_tip(&ic)
        };

        for mut block in self.pending_blocks.drain(..) {
            // fill in consensus hash and block hash, which we may not have known at the call
            // to next_block (since we can call next_block() many times without mining blocks)
            block.patch_from_chain_tip(&snapshot);

            snapshot = block.mine(db, burnchain);

            self.blocks.push(block);
            self.mined += 1;
            self.tip_index_root = snapshot.index_root;
            self.tip_header_hash = snapshot.burn_header_hash;
            self.tip_sortition_id = snapshot.sortition_id;
        }

        // give back the new chain tip
        snapshot
    }

    pub fn mine_pending_blocks_pox<
        'a,
        T: BlockEventDispatcher,
        N: CoordinatorNotices,
        R: RewardSetProvider,
    >(
        &mut self,
        db: &mut SortitionDB,
        burnchain: &Burnchain,
        coord: &mut ChainsCoordinator<'a, T, N, R, (), ()>,
    ) -> BlockSnapshot {
        let mut snapshot = {
            let ic = db.index_conn();
            self.get_tip(&ic)
        };

        for mut block in self.pending_blocks.drain(..) {
            // fill in consensus hash and block hash, which we may not have known at the call
            // to next_block (since we can call next_block() many times without mining blocks)
            block.patch_from_chain_tip(&snapshot);

            snapshot = block.mine_pox(db, burnchain, coord);

            self.blocks.push(block);
            self.mined += 1;
            self.tip_index_root = snapshot.index_root;
            self.tip_header_hash = snapshot.burn_header_hash;
            self.tip_sortition_id = snapshot.sortition_id;
        }

        // give back the new chain tip
        snapshot
    }
}

impl TestBurnchainNode {
    pub fn new() -> TestBurnchainNode {
        let first_block_height = 100;
        let first_block_hash = BurnchainHeaderHash([0u8; 32]);
        let db = SortitionDB::connect_test(first_block_height, &first_block_hash).unwrap();
        TestBurnchainNode {
            sortdb: db,
            dirty: false,
            burnchain: Burnchain::default_unittest(first_block_height, &first_block_hash),
        }
    }

    pub fn mine_fork(&mut self, fork: &mut TestBurnchainFork) -> BlockSnapshot {
        fork.mine_pending_blocks(&mut self.sortdb, &self.burnchain)
    }
}

fn process_next_sortition(
    node: &mut TestBurnchainNode,
    fork: &mut TestBurnchainFork,
    miners: &mut Vec<TestMiner>,
    block_hashes: &Vec<BlockHeaderHash>,
) -> (
    BlockSnapshot,
    Vec<LeaderBlockCommitOp>,
    Vec<UserBurnSupportOp>,
) {
    assert_eq!(miners.len(), block_hashes.len());

    let mut block = {
        let ic = node.sortdb.index_conn();
        fork.next_block(&ic)
    };

    let mut next_commits = vec![];

    if miners.len() > 0 {
        // make a Stacks block (hash) for each of the prior block's keys
        for j in 0..1 {
            let block_commit_op = {
                let ic = node.sortdb.index_conn();
                let hash = block_hashes[j].clone();
                block.add_leader_block_commit(
                    &ic,
                    &mut miners[j],
                    &hash,
                    ((j + 1) as u64) * 1000,
                    None,
                    None,
                )
            };
            next_commits.push(block_commit_op);
        }
    }

    test_debug!("Mine {} transactions", block.txs.len());

    fork.append_block(block);
    let tip_snapshot = node.mine_fork(fork);

    // TODO: user burn support
    (tip_snapshot, next_commits, vec![])
}

fn verify_commits_accepted(
    node: &TestBurnchainNode,
    next_block_commits: &Vec<LeaderBlockCommitOp>,
) -> () {
    // all commits accepted
    for commit in next_block_commits.iter() {
        let tx_opt =
            SortitionDB::get_burnchain_transaction(node.sortdb.conn(), &commit.txid).unwrap();
        assert!(tx_opt.is_some());

        let tx = tx_opt.unwrap();
        match tx {
            BlockstackOperationType::LeaderBlockCommit(ref op) => {
                assert_eq!(*op, *commit);
            }
            _ => {
                assert!(false);
            }
        }
    }
}

#[test]
fn mine_10_stacks_blocks_1_fork() {
    let mut node = TestBurnchainNode::new();
    let mut miner_factory = TestMinerFactory::new();

    let mut miners = vec![];
    for i in 0..10 {
        miners.push(miner_factory.next_miner(
            &node.burnchain,
            1,
            1,
            AddressHashMode::SerializeP2PKH,
        ));
    }

    let first_snapshot = SortitionDB::get_first_block_snapshot(node.sortdb.conn()).unwrap();
    let mut fork = TestBurnchainFork::new(
        first_snapshot.block_height,
        &first_snapshot.burn_header_hash,
        &first_snapshot.index_root,
        0,
    );

    for i in 0..10 {
        let mut next_block_hashes = vec![];
        for j in 0..miners.len() {
            let hash = BlockHeaderHash([(i * 10 + j + miners.len()) as u8; 32]);
            next_block_hashes.push(hash);
        }

        let (next_snapshot, next_block_commits, next_user_burns) =
            process_next_sortition(&mut node, &mut fork, &mut miners, &next_block_hashes);

        verify_commits_accepted(&mut node, &next_block_commits);
    }
}

#[test]
fn mine_10_stacks_blocks_2_forks_disjoint() {
    let mut node = TestBurnchainNode::new();
    let mut miner_factory = TestMinerFactory::new();

    let mut miners = vec![];
    for i in 0..10 {
        miners.push(miner_factory.next_miner(
            &node.burnchain,
            1,
            1,
            AddressHashMode::SerializeP2PKH,
        ));
    }

    let first_snapshot = SortitionDB::get_first_block_snapshot(node.sortdb.conn()).unwrap();
    let mut fork_1 = TestBurnchainFork::new(
        first_snapshot.block_height,
        &first_snapshot.burn_header_hash,
        &first_snapshot.index_root,
        0,
    );

    // one fork for 5 blocks...
    for i in 0..5 {
        let mut next_block_hashes = vec![];
        for j in 0..miners.len() {
            let hash = BlockHeaderHash([(i * 10 + j + miners.len()) as u8; 32]);
            next_block_hashes.push(hash);
        }

        let (next_snapshot, next_block_commits, next_user_burns) =
            process_next_sortition(&mut node, &mut fork_1, &mut miners, &next_block_hashes);

        verify_commits_accepted(&mut node, &next_block_commits);
    }

    let mut fork_2 = fork_1.fork();

    let mut miners_1 = vec![];
    let mut miners_2 = vec![];

    let mut miners_drain = miners.drain(..);
    for i in 0..5 {
        let m = miners_drain.next().unwrap();
        miners_1.push(m);
    }
    for i in 0..5 {
        let m = miners_drain.next().unwrap();
        miners_2.push(m);
    }

    // two disjoint forks for 5 blocks...
    for i in 5..10 {
        let mut next_block_hashes_1 = vec![];
        for j in 0..miners_1.len() {
            let hash = BlockHeaderHash(
                [(i * (miners_1.len() + miners_2.len()) + j + miners_1.len() + miners_2.len())
                    as u8; 32],
            );
            next_block_hashes_1.push(hash);
        }

        let mut next_block_hashes_2 = vec![];
        for j in 0..miners_2.len() {
            let hash = BlockHeaderHash(
                [(i * (miners_1.len() + miners_2.len()) + (5 + j) + miners_1.len() + miners_2.len())
                    as u8; 32],
            );
            next_block_hashes_2.push(hash);
        }

        let (next_snapshot_1, next_block_commits_1, next_user_burns_1) =
            process_next_sortition(&mut node, &mut fork_1, &mut miners_1, &next_block_hashes_1);
        let (next_snapshot_2, next_block_commits_2, next_user_burns_2) =
            process_next_sortition(&mut node, &mut fork_2, &mut miners_2, &next_block_hashes_2);

        assert!(next_snapshot_1.burn_header_hash != next_snapshot_2.burn_header_hash);

        verify_commits_accepted(&mut node, &next_block_commits_1);

        verify_commits_accepted(&mut node, &next_block_commits_2);
    }
}

#[test]
fn mine_10_stacks_blocks_2_forks_disjoint_same_blocks() {
    let mut node = TestBurnchainNode::new();
    let mut miner_factory = TestMinerFactory::new();

    let mut miners = vec![];
    for i in 0..10 {
        miners.push(miner_factory.next_miner(
            &node.burnchain,
            1,
            1,
            AddressHashMode::SerializeP2PKH,
        ));
    }

    let first_snapshot = SortitionDB::get_first_block_snapshot(node.sortdb.conn()).unwrap();
    let mut fork_1 = TestBurnchainFork::new(
        first_snapshot.block_height,
        &first_snapshot.burn_header_hash,
        &first_snapshot.index_root,
        0,
    );

    // one fork for 5 blocks...
    for i in 0..5 {
        let mut next_block_hashes = vec![];
        for j in 0..miners.len() {
            let hash = BlockHeaderHash([(i * 10 + j + miners.len()) as u8; 32]);
            next_block_hashes.push(hash);
        }

        let (snapshot, next_block_commits, next_user_burns) =
            process_next_sortition(&mut node, &mut fork_1, &mut miners, &next_block_hashes);

        verify_commits_accepted(&mut node, &next_block_commits);
    }

    let mut fork_2 = fork_1.fork();

    let mut miners_1 = vec![];
    let mut miners_2 = vec![];

    let mut miners_drain = miners.drain(..);
    for i in 0..5 {
        let m = miners_drain.next().unwrap();
        miners_1.push(m);
    }
    for i in 0..5 {
        let m = miners_drain.next().unwrap();
        miners_2.push(m);
    }

    // two disjoint forks for 5 blocks, but miners in each fork mine the same blocks.
    // This tests that we can accept two burnchain forks that each contain the same stacks
    // block history.
    for i in 5..10 {
        let mut next_block_hashes_1 = vec![];
        for j in 0..miners_1.len() {
            let hash = BlockHeaderHash(
                [(i * (miners_1.len() + miners_2.len()) + j + miners_1.len() + miners_2.len())
                    as u8; 32],
            );
            next_block_hashes_1.push(hash);
        }

        let mut next_block_hashes_2 = vec![];
        for j in 0..miners_2.len() {
            let hash = BlockHeaderHash(
                [(i * (miners_1.len() + miners_2.len()) + j + miners_1.len() + miners_2.len())
                    as u8; 32],
            );
            next_block_hashes_2.push(hash);
        }

        let (snapshot_1, next_block_commits_1, next_user_burns_1) =
            process_next_sortition(&mut node, &mut fork_1, &mut miners_1, &next_block_hashes_1);
        let (snapshot_2, next_block_commits_2, next_user_burns_2) =
            process_next_sortition(&mut node, &mut fork_2, &mut miners_2, &next_block_hashes_2);

        assert!(snapshot_1.burn_header_hash != snapshot_2.burn_header_hash);
        assert!(snapshot_1.consensus_hash != snapshot_2.consensus_hash);

        // same blocks mined in both forks
        assert_eq!(next_block_commits_1.len(), next_block_commits_2.len());
        for i in 0..next_block_commits_1.len() {
            assert_eq!(
                next_block_commits_1[i].block_header_hash,
                next_block_commits_2[i].block_header_hash
            );
        }

        verify_commits_accepted(&mut node, &next_block_commits_1);

        verify_commits_accepted(&mut node, &next_block_commits_2);
    }
}

#[test]
fn general_parsing() {
    let test_events = include_str!("./test_events_sample.jsons").lines();
    for test_event in test_events {
        let _new_block: NewBlock =
            serde_json::from_str(test_event).expect("Failed to parse events JSON");
    }
}

#[test]
fn create_stacks_events_failures_general() {
    let inputs = [
        ("1", "Expected Clarity type to be tuple"),
        (
            r#"{ block-commit: 0x1234567890123456789012345678901212345678901234567890123456789012 }"#,
            "No 'event' field",
        ),
        (r#"{ event: 1 }"#, "Expected 'event' type to be string"),
        (r#"{ event: "unknown-event" }"#, "Unexpected 'event' string"),
    ];

    for (test_input, expected_err) in inputs.iter() {
        let value = execute(test_input).unwrap().unwrap();
        let err_str =
            StacksHyperOp::try_from_clar_value(value, Txid([0; 32]), 0, &StacksBlockId([0; 32]))
                .unwrap_err();
        assert!(
            err_str.starts_with(expected_err),
            "{} starts_with? {}",
            err_str,
            expected_err
        );
    }
}

#[test]
fn create_stacks_events_failures_block_commit() {
    let inputs = [
        (r#"{ event: "block-commit" }"#, "No 'block-commit' field"),
        (
            r#"{ event: "block-commit", block-commit: 1 }"#,
            "Expected 'block-commit' type to be buffer",
        ),
        (
            r#"{ event: "block-commit", block-commit: 0x12 }"#,
            "Expected 'block-commit' type to be length 32",
        ),
    ];

    for (test_input, expected_err) in inputs.iter() {
        let value = execute(test_input).unwrap().unwrap();
        let err_str =
            StacksHyperOp::try_from_clar_value(value, Txid([0; 32]), 0, &StacksBlockId([0; 32]))
                .unwrap_err();
        assert!(
            err_str.starts_with(expected_err),
            "{} starts_with? {}",
            err_str,
            expected_err
        );
    }
}

#[test]
fn create_stacks_events_failures_deposit_ft() {
    let inputs = [
        (
            r#"{ event: "deposit-ft", l1-contract-id: 'ST000000000000000000002AMW42H.simple-ft, ft-name: "simple-ft",
            hc-contract-id: 'STTHM8422MZMP02R6KHPSCBAHKDTZZ6Y4FRH7CSH.simple-ft, sender: 'ST000000000000000000002AMW42H, hc-function-name: "hyperchain-deposit-simple-ft"   }"#,
            "No 'ft-amount' field in Clarity tuple",
        ),
        (
            r#"{ event: "deposit-ft", ft-amount: u100, l1-contract-id: 'ST000000000000000000002AMW42H.simple-ft,
            hc-contract-id: 'STTHM8422MZMP02R6KHPSCBAHKDTZZ6Y4FRH7CSH.simple-ft, sender: 'ST000000000000000000002AMW42H, hc-function-name: "hyperchain-deposit-simple-ft"  }"#,
            "No 'ft-name' field in Clarity tuple",
        ),
        (
            r#"{ event: "deposit-ft", ft-amount: u100, l1-contract-id: 'ST000000000000000000002AMW42H.simple-ft,
            ft-name: "simple-ft", hc-contract-id: 'STTHM8422MZMP02R6KHPSCBAHKDTZZ6Y4FRH7CSH.simple-ft, hc-function-name: "hyperchain-deposit-simple-ft" }"#,
            "No 'sender' field in Clarity tuple",
        ),
        (
            r#"{ event: "deposit-ft", ft-amount: u100, ft-name: "simple-ft",
            hc-contract-id: 'STTHM8422MZMP02R6KHPSCBAHKDTZZ6Y4FRH7CSH.simple-ft, sender: 'ST000000000000000000002AMW42H,
            hc-function-name: "hyperchain-deposit-simple-ft"  }"#,
            "No 'l1-contract-id' field in Clarity tuple",
        ),
        (
            r#"{ event: "deposit-ft", ft-amount: u100, l1-contract-id: 'ST000000000000000000002AMW42H, ft-name: "simple-ft",
            hc-contract-id: 'ST000000000000000000002AMW42H.simple-ft, sender: 'ST000000000000000000002AMW42H, hc-function-name: "hyperchain-deposit-simple-ft"  }"#,
            "Expected 'l1-contract-id' to be a contract principal",
        ),
        (
            r#"{ event: "deposit-ft", ft-amount: u100, l1-contract-id: 'ST000000000000000000002AMW42H.simple-ft,
            ft-name: "simple-ft", sender: 'ST000000000000000000002AMW42H, hc-function-name: "hyperchain-deposit-simple-ft"  }"#,
            "No 'hc-contract-id' field in Clarity tuple",
        ),
        (
            r#"{ event: "deposit-ft", ft-amount: u100, l1-contract-id: 'ST000000000000000000002AMW42H.simple-ft,
            ft-name: "simple-ft", hc-contract-id: 'STTHM8422MZMP02R6KHPSCBAHKDTZZ6Y4FRH7CSH, sender: 'ST000000000000000000002AMW42H,
            hc-function-name: "hyperchain-deposit-simple-ft"  }"#,
            "Expected 'hc-contract-id' to be a contract principal",
        ),
        (
            r#"{ event: "deposit-ft", ft-amount: u100, l1-contract-id: 'ST000000000000000000002AMW42H.simple-ft, ft-name: "simple-ft", hc-contract-id: 'ST000000000000000000002AMW42H.simple-ft, sender: 'ST000000000000000000002AMW42H  }"#,
            "No 'hc-function-name' field in Clarity tuple",
        ),
    ];

    for (test_input, expected_err) in inputs.iter() {
        let value = execute(test_input).unwrap().unwrap();
        let err_str =
            StacksHyperOp::try_from_clar_value(value, Txid([0; 32]), 0, &StacksBlockId([0; 32]))
                .unwrap_err();
        assert!(
            err_str.starts_with(expected_err),
            "{} starts_with? {}",
            err_str,
            expected_err
        );
    }
}

#[test]
fn create_stacks_events_failures_deposit_nft() {
    let inputs = [
        (
            r#"{ event: "deposit-nft", l1-contract-id: 'ST000000000000000000002AMW42H.simple-ft,
            hc-contract-id: 'STTHM8422MZMP02R6KHPSCBAHKDTZZ6Y4FRH7CSH.simple-ft, sender: 'ST000000000000000000002AMW42H,
            hc-function-name: "hyperchain-deposit-simple-nft"  }"#,
            "No 'nft-id' field in Clarity tuple",
        ),
        (
            r#"{ event: "deposit-nft", nft-id: u100, l1-contract-id: 'ST000000000000000000002AMW42H.simple-ft,
            hc-contract-id: 'STTHM8422MZMP02R6KHPSCBAHKDTZZ6Y4FRH7CSH.simple-ft, hc-function-name: "hyperchain-deposit-simple-nft" }"#,
            "No 'sender' field in Clarity tuple",
        ),
        (
            r#"{ event: "deposit-nft", nft-id: u100, hc-contract-id: 'STTHM8422MZMP02R6KHPSCBAHKDTZZ6Y4FRH7CSH.simple-ft,
            sender: 'ST000000000000000000002AMW42H, hc-function-name: "hyperchain-deposit-simple-nft"  }"#,
            "No 'l1-contract-id' field in Clarity tuple",
        ),
        (
            r#"{ event: "deposit-nft", nft-id: u100, l1-contract-id: 'ST000000000000000000002AMW42H,
            hc-contract-id: 'ST000000000000000000002AMW42H.simple-ft, sender: 'ST000000000000000000002AMW42H,
            hc-function-name: "hyperchain-deposit-simple-nft"  }"#,
            "Expected 'l1-contract-id' to be a contract principal",
        ),
        (
            r#"{ event: "deposit-nft", nft-id: u100, l1-contract-id: 'ST000000000000000000002AMW42H.simple-ft,
            sender: 'ST000000000000000000002AMW42H, hc-function-name: "hyperchain-deposit-simple-nft"  }"#,
            "No 'hc-contract-id' field in Clarity tuple",
        ),
        (
            r#"{ event: "deposit-nft", nft-id: u100, l1-contract-id: 'ST000000000000000000002AMW42H.simple-ft,
            hc-contract-id: 'STTHM8422MZMP02R6KHPSCBAHKDTZZ6Y4FRH7CSH, sender: 'ST000000000000000000002AMW42H,
            hc-function-name: "hyperchain-deposit-simple-nft"  }"#,
            "Expected 'hc-contract-id' to be a contract principal",
        ),
        (
            r#"{ event: "deposit-nft", nft-id: u100, l1-contract-id: 'ST000000000000000000002AMW42H.simple-ft, hc-contract-id: 'STTHM8422MZMP02R6KHPSCBAHKDTZZ6Y4FRH7CSH.simple-ft, sender: 'ST000000000000000000002AMW42H  }"#,
            "No 'hc-function-name' field in Clarity tuple",
        ),
    ];

    for (test_input, expected_err) in inputs.iter() {
        let value = execute(test_input).unwrap().unwrap();
        let err_str =
            StacksHyperOp::try_from_clar_value(value, Txid([0; 32]), 0, &StacksBlockId([0; 32]))
                .unwrap_err();
        assert!(
            err_str.starts_with(expected_err),
            "{} starts_with? {}",
            err_str,
            expected_err
        );
    }
}

#[test]
fn create_stacks_events_failures_withdraw_ft() {
    let inputs = [
        (
            r#"{ event: "withdraw-ft", l1-contract-id: 'ST000000000000000000002AMW42H.simple-ft,
            ft-name: "simple-ft", hc-contract-id: 'STTHM8422MZMP02R6KHPSCBAHKDTZZ6Y4FRH7CSH.simple-ft,
            recipient: 'ST000000000000000000002AMW42H, hc-function-name: "hyperchain-withdraw-simple-ft"  }"#,
            "No 'ft-amount' field in Clarity tuple",
        ),
        (
            r#"{ event: "withdraw-ft", ft-amount: u100, l1-contract-id: 'ST000000000000000000002AMW42H.simple-ft,
            hc-contract-id: 'STTHM8422MZMP02R6KHPSCBAHKDTZZ6Y4FRH7CSH.simple-ft, recipient: 'ST000000000000000000002AMW42H,
            hc-function-name: "hyperchain-withdraw-simple-ft"  }"#,
            "No 'ft-name' field in Clarity tuple",
        ),
        (
            r#"{ event: "withdraw-ft", ft-amount: u100, l1-contract-id: 'ST000000000000000000002AMW42H.simple-ft,
            ft-name: "simple-ft", hc-contract-id: 'STTHM8422MZMP02R6KHPSCBAHKDTZZ6Y4FRH7CSH.simple-ft,
            hc-function-name: "hyperchain-withdraw-simple-ft" }"#,
            "No 'recipient' field in Clarity tuple",
        ),
        (
            r#"{ event: "withdraw-ft", ft-amount: u100, ft-name: "simple-ft", hc-contract-id: 'STTHM8422MZMP02R6KHPSCBAHKDTZZ6Y4FRH7CSH.simple-ft,
            recipient: 'ST000000000000000000002AMW42H, hc-function-name: "hyperchain-withdraw-simple-ft"  }"#,
            "No 'l1-contract-id' field in Clarity tuple",
        ),
        (
            r#"{ event: "withdraw-ft", ft-amount: u100, l1-contract-id: 'ST000000000000000000002AMW42H,
            ft-name: "simple-ft", hc-contract-id: 'ST000000000000000000002AMW42H.simple-ft, recipient: 'ST000000000000000000002AMW42H,
            hc-function-name: "hyperchain-withdraw-simple-ft"  }"#,
            "Expected 'l1-contract-id' to be a contract principal",
        ),
        (
            r#"{ event: "withdraw-ft", ft-amount: u100, l1-contract-id: 'ST000000000000000000002AMW42H.simple-ft,
            ft-name: "simple-ft", recipient: 'ST000000000000000000002AMW42H, hc-function-name: "hyperchain-withdraw-simple-ft"  }"#,
            "No 'hc-contract-id' field in Clarity tuple",
        ),
        (
            r#"{ event: "withdraw-ft", ft-amount: u100, l1-contract-id: 'ST000000000000000000002AMW42H.simple-ft,
            ft-name: "simple-ft", hc-contract-id: 'STTHM8422MZMP02R6KHPSCBAHKDTZZ6Y4FRH7CSH, recipient: 'ST000000000000000000002AMW42H,
            hc-function-name: "hyperchain-withdraw-simple-ft"  }"#,
            "Expected 'hc-contract-id' to be a contract principal",
        ),
        (
            r#"{ event: "withdraw-ft", ft-amount: u100, l1-contract-id: 'ST000000000000000000002AMW42H.simple-ft,
            ft-name: "simple-ft", hc-contract-id: 'STTHM8422MZMP02R6KHPSCBAHKDTZZ6Y4FRH7CSH.simple-ft,
            recipient: 'ST000000000000000000002AMW42H  }"#,
            "No 'hc-function-name' field in Clarity tuple",
        ),
    ];

    for (test_input, expected_err) in inputs.iter() {
        let value = execute(test_input).unwrap().unwrap();
        let err_str =
            StacksHyperOp::try_from_clar_value(value, Txid([0; 32]), 0, &StacksBlockId([0; 32]))
                .unwrap_err();
        assert!(
            err_str.starts_with(expected_err),
            "{} starts_with? {}",
            err_str,
            expected_err
        );
    }
}

#[test]
fn create_stacks_events_failures_withdraw_nft() {
    let inputs = [
        (
            r#"{ event: "withdraw-nft", l1-contract-id: 'ST000000000000000000002AMW42H.simple-ft,
            hc-contract-id: 'STTHM8422MZMP02R6KHPSCBAHKDTZZ6Y4FRH7CSH.simple-ft, recipient: 'ST000000000000000000002AMW42H,
            hc-function-name: "hyperchain-withdraw-simple-nft"  }"#,
            "No 'nft-id' field in Clarity tuple",
        ),
        (
            r#"{ event: "withdraw-nft", nft-id: u100, l1-contract-id: 'ST000000000000000000002AMW42H.simple-ft,
            hc-contract-id: 'STTHM8422MZMP02R6KHPSCBAHKDTZZ6Y4FRH7CSH.simple-ft, hc-function-name: "hyperchain-withdraw-simple-nft" }"#,
            "No 'recipient' field in Clarity tuple",
        ),
        (
            r#"{ event: "withdraw-nft", nft-id: u100, hc-contract-id: 'STTHM8422MZMP02R6KHPSCBAHKDTZZ6Y4FRH7CSH.simple-ft,
            recipient: 'ST000000000000000000002AMW42H, hc-function-name: "hyperchain-withdraw-simple-nft"  }"#,
            "No 'l1-contract-id' field in Clarity tuple",
        ),
        (
            r#"{ event: "withdraw-nft", nft-id: u100, l1-contract-id: 'ST000000000000000000002AMW42H,
            hc-contract-id: 'ST000000000000000000002AMW42H.simple-ft, recipient: 'ST000000000000000000002AMW42H,
            hc-function-name: "hyperchain-withdraw-simple-nft"  }"#,
            "Expected 'l1-contract-id' to be a contract principal",
        ),
        (
            r#"{ event: "withdraw-nft", nft-id: u100, l1-contract-id: 'ST000000000000000000002AMW42H.simple-ft,
            recipient: 'ST000000000000000000002AMW42H, hc-function-name: "hyperchain-withdraw-simple-nft"  }"#,
            "No 'hc-contract-id' field in Clarity tuple",
        ),
        (
            r#"{ event: "withdraw-nft", nft-id: u100, l1-contract-id: 'ST000000000000000000002AMW42H.simple-ft,
            hc-contract-id: 'STTHM8422MZMP02R6KHPSCBAHKDTZZ6Y4FRH7CSH, recipient: 'ST000000000000000000002AMW42H,
            hc-function-name: "hyperchain-withdraw-simple-nft"  }"#,
            "Expected 'hc-contract-id' to be a contract principal",
        ),
        (
            r#"{ event: "withdraw-nft", nft-id: u100, l1-contract-id: 'ST000000000000000000002AMW42H.simple-ft,
            hc-contract-id: 'STTHM8422MZMP02R6KHPSCBAHKDTZZ6Y4FRH7CSH.simple-ft, recipient: 'ST000000000000000000002AMW42H  }"#,
            "No 'hc-function-name' field in Clarity tuple",
        ),
    ];

    for (test_input, expected_err) in inputs.iter() {
        let value = execute(test_input).unwrap().unwrap();
        let err_str =
            StacksHyperOp::try_from_clar_value(value, Txid([0; 32]), 0, &StacksBlockId([0; 32]))
                .unwrap_err();
        assert!(
            err_str.starts_with(expected_err),
            "{} starts_with? {}",
            err_str,
            expected_err
        );
    }
}

#[test]
fn create_stacks_event_block_for_block_commit() {
    let watched_contract =
        QualifiedContractIdentifier::new(StandardPrincipalData(1, [3; 20]), "hc-contract-1".into());

    let ignored_contract =
        QualifiedContractIdentifier::new(StandardPrincipalData(1, [2; 20]), "hc-contract-2".into());

    // include one "good" event in the block, and two skipped events
    let input = NewBlock {
        block_height: 1,
        burn_block_time: 0,
        index_block_hash: StacksBlockId([1; 32]),
        parent_index_block_hash: StacksBlockId([0; 32]),
        events: vec![
            // Valid transaction
            NewBlockTxEvent {
                txid: Txid([0; 32]),
                event_index: 0,
                committed: true,
                event_type: TxEventType::ContractEvent,
                contract_event: Some(
                    ContractEvent {
                        contract_identifier: watched_contract.clone(),
                        topic: "print".into(),
                        value: execute(r#"{ event: "block-commit", block-commit: 0x1234567890123456789012345678901212345678901234567890123456789012 }"#)
                            .unwrap().unwrap(),
                    }
                )
            },
            // Invalid since committed = false
            NewBlockTxEvent {
                txid: Txid([1; 32]),
                event_index: 1,
                committed: false,
                event_type: TxEventType::ContractEvent,
                contract_event: Some(
                    ContractEvent {
                        contract_identifier: watched_contract.clone(),
                        topic: "print".into(),
                        value: execute(r#"{ event: "block-commit", block-commit: 0x12345678901234567890123456789012 }"#)
                            .unwrap().unwrap(),
                    }
                )
            },
            // Invalid since this event is from `ignored_contract`
            NewBlockTxEvent {
                txid: Txid([2; 32]),
                event_index: 2,
                committed: true,
                event_type: TxEventType::ContractEvent,
                contract_event: Some(
                    ContractEvent {
                        contract_identifier: ignored_contract.clone(),
                        topic: "print".into(),
                        value: execute(r#"{ event: "block-commit", block-commit: 0x12345678901234567890123456789012 }"#)
                            .unwrap().unwrap(),
                    }
                )
            },
        ],
    };

    let stacks_event_block = StacksHyperBlock::from_new_block_event(&watched_contract, input);

    assert_eq!(stacks_event_block.block_height, 1);
    assert_eq!(stacks_event_block.current_block, StacksBlockId([1; 32]));
    assert_eq!(stacks_event_block.parent_block, StacksBlockId([0; 32]));
    assert_eq!(
        stacks_event_block.ops.len(),
        1,
        "Only one event from the watched contract committed"
    );
    assert_eq!(stacks_event_block.ops[0].event_index, 2);
}

#[test]
fn create_stacks_event_block_for_deposit_ft() {
    let watched_contract =
        QualifiedContractIdentifier::new(StandardPrincipalData(1, [3; 20]), "hc-contract-1".into());

    let ignored_contract =
        QualifiedContractIdentifier::new(StandardPrincipalData(1, [2; 20]), "hc-contract-2".into());

    // include one "good" event in the block, and three skipped events
    let input = NewBlock {
        block_height: 1,
        burn_block_time: 0,
        index_block_hash: StacksBlockId([1; 32]),
        parent_index_block_hash: StacksBlockId([0; 32]),
        events: vec![
            // Invalid since this event is badly formed
            NewBlockTxEvent {
                txid: Txid([0; 32]),
                event_index: 0,
                committed: true,
                event_type: TxEventType::ContractEvent,
                contract_event: Some(
                    ContractEvent {
                        contract_identifier: watched_contract.clone(),
                        topic: "print".into(),
                        value: execute(r#"{ event: "deposit-ft", ft-amount: u100, ft-name: "simple-ft", hc-contract-id: 'ST000000000000000000002AMW42H.simple-ft, sender: 'ST000000000000000000002AMW42H  }"#,)
                            .unwrap().unwrap(),
                    }
                )
            },
            // Invalid since committed=false
            NewBlockTxEvent {
                txid: Txid([1; 32]),
                event_index: 1,
                committed: false,
                event_type: TxEventType::ContractEvent,
                contract_event: Some(
                    ContractEvent {
                        contract_identifier: watched_contract.clone(),
                        topic: "print".into(),
                        value: execute(r#"{ event: "deposit-ft", ft-amount: u100, l1-contract-id: 'ST000000000000000000002AMW42H.simple-ft, ft-name: "simple-ft", hc-contract-id: 'ST000000000000000000002AMW42H.simple-ft, sender: 'ST000000000000000000002AMW42H, hc-function-name: "hyperchain-deposit-simple-ft" }"#,)
                            .unwrap().unwrap(),
                    }
                )
            },
            // Valid transaction
            NewBlockTxEvent {
                txid: Txid([1; 32]),
                event_index: 2,
                committed: true,
                event_type: TxEventType::ContractEvent,
                contract_event: Some(
                    ContractEvent {
                        contract_identifier: watched_contract.clone(),
                        topic: "print".into(),
                        value: execute(r#"{ event: "deposit-ft", ft-amount: u100, l1-contract-id: 'ST000000000000000000002AMW42H.simple-ft, ft-name: "simple-ft", hc-contract-id: 'ST000000000000000000002AMW42H.simple-ft, sender: 'ST000000000000000000002AMW42H, hc-function-name: "hyperchain-deposit-simple-ft"  }"#,)
                            .unwrap().unwrap(),
                    }
                )
            },
            // Invalid since this event is from `ignored_contract`
            NewBlockTxEvent {
                txid: Txid([2; 32]),
                event_index: 3,
                committed: true,
                event_type: TxEventType::ContractEvent,
                contract_event: Some(
                    ContractEvent {
                        contract_identifier: ignored_contract.clone(),
                        topic: "print".into(),
                        value: execute(r#"{ event: "deposit-ft", ft-amount: u100, l1-contract-id: 'ST000000000000000000002AMW42H.simple-ft, ft-name: "simple-ft", hc-contract-id: 'ST000000000000000000002AMW42H.simple-ft, sender: 'ST000000000000000000002AMW42H, hc-function-name: "hyperchain-deposit-simple-ft" }"#)
                            .unwrap().unwrap(),
                    }
                )
            },
        ],
    };

    let stacks_event_block = StacksHyperBlock::from_new_block_event(&watched_contract, input);

    assert_eq!(stacks_event_block.block_height, 1);
    assert_eq!(stacks_event_block.current_block, StacksBlockId([1; 32]));
    assert_eq!(stacks_event_block.parent_block, StacksBlockId([0; 32]));
    assert_eq!(
        stacks_event_block.ops.len(),
        1,
        "Only one event from the watched contract committed"
    );
    assert_eq!(stacks_event_block.ops[0].event_index, 2);
}

#[test]
fn create_stacks_event_block_for_deposit_nft() {
    let watched_contract =
        QualifiedContractIdentifier::new(StandardPrincipalData(1, [3; 20]), "hc-contract-1".into());

    let ignored_contract =
        QualifiedContractIdentifier::new(StandardPrincipalData(1, [2; 20]), "hc-contract-2".into());

    // include one "good" event in the block, and three skipped events
    let input = NewBlock {
        block_height: 1,
        burn_block_time: 0,
        index_block_hash: StacksBlockId([1; 32]),
        parent_index_block_hash: StacksBlockId([0; 32]),
        events: vec![
            // Invalid since this event is badly formed
            NewBlockTxEvent {
                txid: Txid([0; 32]),
                event_index: 0,
                committed: true,
                event_type: TxEventType::ContractEvent,
                contract_event: Some(
                    ContractEvent {
                        contract_identifier: watched_contract.clone(),
                        topic: "print".into(),
                        value: execute(r#"{ event: "deposit-nft", nft-id: u100, hc-contract-id: 'ST000000000000000000002AMW42H.simple-ft, sender: 'ST000000000000000000002AMW42H  }"#,)
                            .unwrap().unwrap(),
                    }
                )
            },
            // Invalid since committed=false
            NewBlockTxEvent {
                txid: Txid([1; 32]),
                event_index: 1,
                committed: false,
                event_type: TxEventType::ContractEvent,
                contract_event: Some(
                    ContractEvent {
                        contract_identifier: watched_contract.clone(),
                        topic: "print".into(),
                        value: execute(r#"{ event: "deposit-nft", nft-id: u100, l1-contract-id: 'ST000000000000000000002AMW42H.simple-ft,
                                hc-contract-id: 'ST000000000000000000002AMW42H.simple-ft, sender: 'ST000000000000000000002AMW42H, hc-function-name: "hyperchain-deposit-simple-nft"  }"#,)
                            .unwrap().unwrap(),
                    }
                )
            },
            // Valid transaction
            NewBlockTxEvent {
                txid: Txid([1; 32]),
                event_index: 2,
                committed: true,
                event_type: TxEventType::ContractEvent,
                contract_event: Some(
                    ContractEvent {
                        contract_identifier: watched_contract.clone(),
                        topic: "print".into(),
                        value: execute(r#"{ event: "deposit-nft", nft-id: u100, l1-contract-id: 'ST000000000000000000002AMW42H.simple-ft,
                                hc-contract-id: 'ST000000000000000000002AMW42H.simple-ft, sender: 'ST000000000000000000002AMW42H, hc-function-name: "hyperchain-deposit-simple-nft"  }"#,)
                            .unwrap().unwrap(),
                    }
                )
            },
            // Invalid since this event is from `ignored_contract`
            NewBlockTxEvent {
                txid: Txid([2; 32]),
                event_index: 3,
                committed: true,
                event_type: TxEventType::ContractEvent,
                contract_event: Some(
                    ContractEvent {
                        contract_identifier: ignored_contract.clone(),
                        topic: "print".into(),
                        value: execute(r#"{ event: "deposit-nft", nft-id: u100, l1-contract-id: 'ST000000000000000000002AMW42H.simple-ft,
                                hc-contract-id: 'ST000000000000000000002AMW42H.simple-ft, sender: 'ST000000000000000000002AMW42H, hc-function-name: "hyperchain-deposit-simple-nft"  }"#)
                            .unwrap().unwrap(),
                    }
                )
            },
        ],
    };

    let stacks_event_block = StacksHyperBlock::from_new_block_event(&watched_contract, input);

    assert_eq!(stacks_event_block.block_height, 1);
    assert_eq!(stacks_event_block.current_block, StacksBlockId([1; 32]));
    assert_eq!(stacks_event_block.parent_block, StacksBlockId([0; 32]));
    assert_eq!(
        stacks_event_block.ops.len(),
        1,
        "Only one event from the watched contract committed"
    );
    assert_eq!(stacks_event_block.ops[0].event_index, 2);
}

#[test]
fn create_stacks_event_block_for_withdraw_ft() {
    let watched_contract =
        QualifiedContractIdentifier::new(StandardPrincipalData(1, [3; 20]), "hc-contract-1".into());

    let ignored_contract =
        QualifiedContractIdentifier::new(StandardPrincipalData(1, [2; 20]), "hc-contract-2".into());

    // include one "good" event in the block, and three skipped events
    let input = NewBlock {
        block_height: 1,
        burn_block_time: 0,
        index_block_hash: StacksBlockId([1; 32]),
        parent_index_block_hash: StacksBlockId([0; 32]),
        events: vec![
            // Invalid since this event is badly formed
            NewBlockTxEvent {
                txid: Txid([0; 32]),
                event_index: 0,
                committed: true,
                event_type: TxEventType::ContractEvent,
                contract_event: Some(
                    ContractEvent {
                        contract_identifier: watched_contract.clone(),
                        topic: "print".into(),
                        value: execute(r#"{ event: "withdraw-ft", ft-amount: u100, ft-name: "simple-ft",
                                hc-contract-id: 'ST000000000000000000002AMW42H.simple-ft, recipient: 'ST000000000000000000002AMW42H, hc-function-name: "hyperchain-withdraw-simple-ft"  }"#,)
                            .unwrap().unwrap(),
                    }
                )
            },
            // Invalid since committed=false
            NewBlockTxEvent {
                txid: Txid([1; 32]),
                event_index: 1,
                committed: false,
                event_type: TxEventType::ContractEvent,
                contract_event: Some(
                    ContractEvent {
                        contract_identifier: watched_contract.clone(),
                        topic: "print".into(),
                        value: execute(r#"{ event: "withdraw-ft", ft-amount: u100, l1-contract-id: 'ST000000000000000000002AMW42H.simple-ft,
                                ft-name: "simple-ft", hc-contract-id: 'ST000000000000000000002AMW42H.simple-ft, recipient: 'ST000000000000000000002AMW42H, hc-function-name: "hyperchain-withdraw-simple-ft"  }"#,)
                            .unwrap().unwrap(),
                    }
                )
            },
            // Valid transaction
            NewBlockTxEvent {
                txid: Txid([1; 32]),
                event_index: 2,
                committed: true,
                event_type: TxEventType::ContractEvent,
                contract_event: Some(
                    ContractEvent {
                        contract_identifier: watched_contract.clone(),
                        topic: "print".into(),
                        value: execute(r#"{ event: "withdraw-ft", ft-amount: u100, l1-contract-id: 'ST000000000000000000002AMW42H.simple-ft,
                                ft-name: "simple-ft", hc-contract-id: 'ST000000000000000000002AMW42H.simple-ft, recipient: 'ST000000000000000000002AMW42H, hc-function-name: "hyperchain-withdraw-simple-ft"  }"#,)
                            .unwrap().unwrap(),
                    }
                )
            },
            // Invalid since this event is from `ignored_contract`
            NewBlockTxEvent {
                txid: Txid([2; 32]),
                event_index: 3,
                committed: true,
                event_type: TxEventType::ContractEvent,
                contract_event: Some(
                    ContractEvent {
                        contract_identifier: ignored_contract.clone(),
                        topic: "print".into(),
                        value: execute(r#"{ event: "withdraw-ft", ft-amount: u100, l1-contract-id: 'ST000000000000000000002AMW42H.simple-ft,
                                ft-name: "simple-ft", hc-contract-id: 'ST000000000000000000002AMW42H.simple-ft, recipient: 'ST000000000000000000002AMW42H, hc-function-name: "hyperchain-withdraw-simple-ft"  }"#)
                            .unwrap().unwrap(),
                    }
                )
            },
        ],
    };

    let stacks_event_block = StacksHyperBlock::from_new_block_event(&watched_contract, input);

    assert_eq!(stacks_event_block.block_height, 1);
    assert_eq!(stacks_event_block.current_block, StacksBlockId([1; 32]));
    assert_eq!(stacks_event_block.parent_block, StacksBlockId([0; 32]));
    assert_eq!(
        stacks_event_block.ops.len(),
        1,
        "Only one event from the watched contract committed"
    );
    assert_eq!(stacks_event_block.ops[0].event_index, 2);
}

#[test]
fn create_stacks_event_block_for_withdraw_nft() {
    let watched_contract =
        QualifiedContractIdentifier::new(StandardPrincipalData(1, [3; 20]), "hc-contract-1".into());

    let ignored_contract =
        QualifiedContractIdentifier::new(StandardPrincipalData(1, [2; 20]), "hc-contract-2".into());

    // include one "good" event in the block, and three skipped events
    let input = NewBlock {
        block_height: 1,
        burn_block_time: 0,
        index_block_hash: StacksBlockId([1; 32]),
        parent_index_block_hash: StacksBlockId([0; 32]),
        events: vec![
            // Invalid since this event is badly formed
            NewBlockTxEvent {
                txid: Txid([0; 32]),
                event_index: 0,
                committed: true,
                event_type: TxEventType::ContractEvent,
                contract_event: Some(
                    ContractEvent {
                        contract_identifier: watched_contract.clone(),
                        topic: "print".into(),
                        value: execute(r#"{ event: "withdraw-nft", nft-id: u100, hc-contract-id: 'ST000000000000000000002AMW42H.simple-ft,
                                recipient: 'ST000000000000000000002AMW42H, hc-function-name: "hyperchain-withdraw-simple-nft"  }"#, )
                            .unwrap().unwrap(),
                    }
                )
            },
            // Invalid since committed=false
            NewBlockTxEvent {
                txid: Txid([1; 32]),
                event_index: 1,
                committed: false,
                event_type: TxEventType::ContractEvent,
                contract_event: Some(
                    ContractEvent {
                        contract_identifier: watched_contract.clone(),
                        topic: "print".into(),
                        value: execute(r#"{ event: "withdraw-nft", nft-id: u100, l1-contract-id: 'ST000000000000000000002AMW42H.simple-ft,
                                hc-contract-id: 'ST000000000000000000002AMW42H.simple-ft, recipient: 'ST000000000000000000002AMW42H, hc-function-name: "hyperchain-withdraw-simple-nft"  }"#, )
                            .unwrap().unwrap(),
                    }
                )
            },
            // Valid transaction
            NewBlockTxEvent {
                txid: Txid([1; 32]),
                event_index: 2,
                committed: true,
                event_type: TxEventType::ContractEvent,
                contract_event: Some(
                    ContractEvent {
                        contract_identifier: watched_contract.clone(),
                        topic: "print".into(),
                        value: execute(r#"{ event: "withdraw-nft", nft-id: u100, l1-contract-id: 'ST000000000000000000002AMW42H.simple-ft,
                                hc-contract-id: 'ST000000000000000000002AMW42H.simple-ft, recipient: 'ST000000000000000000002AMW42H, hc-function-name: "hyperchain-withdraw-simple-nft"  }"#, )
                            .unwrap().unwrap(),
                    }
                )
            },
            // Invalid since this event is from `ignored_contract`
            NewBlockTxEvent {
                txid: Txid([2; 32]),
                event_index: 3,
                committed: true,
                event_type: TxEventType::ContractEvent,
                contract_event: Some(
                    ContractEvent {
                        contract_identifier: ignored_contract.clone(),
                        topic: "print".into(),
                        value: execute(r#"{ event: "withdraw-nft", nft-id: u100, l1-contract-id: 'ST000000000000000000002AMW42H.simple-ft,
                                hc-contract-id: 'ST000000000000000000002AMW42H.simple-ft, recipient: 'ST000000000000000000002AMW42H, hc-function-name: "hyperchain-withdraw-simple-nft"  }"#)
                            .unwrap().unwrap(),
                    }
                )
            },
        ],
    };

    let stacks_event_block = StacksHyperBlock::from_new_block_event(&watched_contract, input);

    assert_eq!(stacks_event_block.block_height, 1);
    assert_eq!(stacks_event_block.current_block, StacksBlockId([1; 32]));
    assert_eq!(stacks_event_block.parent_block, StacksBlockId([0; 32]));
    assert_eq!(
        stacks_event_block.ops.len(),
        1,
        "Only one event from the watched contract committed"
    );
    assert_eq!(stacks_event_block.ops[0].event_index, 2);
}

#[test]
fn test_num_sync_cycles_to_height() {
    // target_height == 0
    assert_eq!(1, PoxConstants::num_sync_cycles_to_height_internal(0, 1));
    assert_eq!(1, PoxConstants::num_sync_cycles_to_height_internal(0, 2));

    // target height < cycle_length
    assert_eq!(1, PoxConstants::num_sync_cycles_to_height_internal(1, 2));
    assert_eq!(1, PoxConstants::num_sync_cycles_to_height_internal(1, 3));

    // target_height == cycle_length
    assert_eq!(2, PoxConstants::num_sync_cycles_to_height_internal(1, 1));
    assert_eq!(2, PoxConstants::num_sync_cycles_to_height_internal(2, 2));

    // target_height is even multiples of cycle_length
    assert_eq!(3, PoxConstants::num_sync_cycles_to_height_internal(4, 2));
    assert_eq!(4, PoxConstants::num_sync_cycles_to_height_internal(6, 2));

    // target_height is not even multiples of cycle_length
    assert_eq!(3, PoxConstants::num_sync_cycles_to_height_internal(5, 2));
    assert_eq!(4, PoxConstants::num_sync_cycles_to_height_internal(7, 2));
}
