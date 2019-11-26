/*
 copyright: (c) 2013-2019 by Blockstack PBC, a public benefit corporation.

 This file is part of Blockstack.

 Blockstack is free software. You may redistribute or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License or
 (at your option) any later version.

 Blockstack is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY, including without the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with Blockstack. If not, see <http://www.gnu.org/licenses/>.
*/

use std::fs;
use chainstate::stacks::Error;
use chainstate::stacks::*;
use chainstate::stacks::db::{
    ClarityTx,
    StacksChainState
};
use chainstate::stacks::index::TrieHash;

use chainstate::burn::BlockHeaderHash;

use net::StacksMessageCodec;
use net::Error as net_error;
use net::codec::{read_next, write_next};

use util::hash::MerkleTree;
use util::hash::Sha512Trunc256Sum;
use util::secp256k1::MessageSignature;

use net::StacksPublicKeyBuffer;

use chainstate::burn::*;
use chainstate::burn::operations::*;

use burnchains::BurnchainHeaderHash;
use burnchains::PrivateKey;
use burnchains::PublicKey;

use util::vrf::*;

impl StacksBlockBuilder {
    pub fn from_parent(parent_chain_tip: &StacksHeaderInfo, total_work: &StacksWorkScore, proof: &VRFProof, microblock_privkey: &StacksPrivateKey) -> StacksBlockBuilder {
        let pubk = StacksPublicKey::from_private(microblock_privkey);
        let pubkh = Hash160::from_data(&pubk.to_bytes());
        let header = StacksBlockHeader::from_parent_empty(&parent_chain_tip.anchored_header, parent_chain_tip.microblock_tail.as_ref(), total_work, proof, &pubkh);
        let bytes_so_far = header.serialize().len() as u64;
        
        StacksBlockBuilder {
            chain_tip: parent_chain_tip.clone(),
            header: header,
            txs: vec![],
            micro_txs: vec![],
            bytes_so_far: bytes_so_far,
            anchored_done: false,
            prev_microblock_header: StacksMicroblockHeader::first_unsigned(&BlockHeaderHash([0u8; 32]), &Sha512Trunc256Sum([0u8; 32])),       // will be updated
            miner_privkey: microblock_privkey.clone(),
            miner_payouts: None
        }
    }
    
    pub fn first(genesis_burn_header_hash: &BurnchainHeaderHash, proof: &VRFProof, microblock_privkey: &StacksPrivateKey) -> StacksBlockBuilder {
        let genesis_chain_tip = StacksHeaderInfo {
            anchored_header: StacksBlockHeader::genesis(),
            microblock_tail: None,
            block_height: 0,
            index_root: TrieHash([0u8; 32]),
            burn_header_hash: genesis_burn_header_hash.clone()
        };

        let mut builder = StacksBlockBuilder::from_parent(&genesis_chain_tip, &StacksWorkScore::initial(), proof, microblock_privkey);
        builder.header.parent_block = BlockHeaderHash([0u8; 32]);
        builder
    }

    /// Append a transaction if doing so won't exceed the epoch data size.
    pub fn try_mine_tx<'a>(&mut self, clarity_tx: &mut ClarityTx<'a>, tx: &StacksTransaction) -> Result<(), Error> {
        let tx_len = tx.serialize().len() as u64;
        if self.bytes_so_far + tx_len >= MAX_EPOCH_SIZE.into() {
            return Err(Error::BlockTooBigError);
        }

        if !self.anchored_done {
            // building up the anchored blocks
            if tx.anchor_mode != TransactionAnchorMode::OnChainOnly && tx.anchor_mode != TransactionAnchorMode::Any {
                return Err(Error::InvalidStacksTransaction("Invalid transaction anchor mode for anchored data".to_string()));
            }

            StacksChainState::process_transaction(clarity_tx, tx)?;

            // save
            self.txs.push(tx.clone());
        }
        else {
            // building up the anchored blocks
            if tx.anchor_mode != TransactionAnchorMode::OffChainOnly && tx.anchor_mode != TransactionAnchorMode::Any {
                return Err(Error::InvalidStacksTransaction("Invalid transaction anchor mode for streamed data".to_string()));
            }
            
            StacksChainState::process_transaction(clarity_tx, tx)?;

            self.micro_txs.push(tx.clone());
        }

        self.bytes_so_far += tx_len;
        Ok(())
    }

    /// Finish building the anchored block.
    pub fn mine_anchored_block<'a>(&mut self, clarity_tx: &mut ClarityTx<'a>) -> StacksBlock {
        assert!(!self.anchored_done);

        // add miner payments
        if let Some(ref mature_miner_rewards) = self.miner_payouts {
            // grant in order by miner, then users
            StacksChainState::process_matured_miner_rewards(clarity_tx, mature_miner_rewards)
                .expect("FATAL: failed to process miner rewards");
        }

        let txid_vecs = self.txs
            .iter()
            .map(|tx| tx.txid().as_bytes().to_vec())
            .collect();

        let merkle_tree = MerkleTree::<Sha512Trunc256Sum>::new(&txid_vecs);
        let tx_merkle_root = merkle_tree.root();
        let state_root_hash = clarity_tx.get_root_hash();

        self.header.tx_merkle_root = tx_merkle_root;
        self.header.state_index_root = state_root_hash;
        
        let block = StacksBlock {
            header: self.header.clone(),
            txs: self.txs.clone()
        };

        self.prev_microblock_header = StacksMicroblockHeader::first_unsigned(&block.block_hash(), &Sha512Trunc256Sum([0u8; 32]));

        self.prev_microblock_header.prev_block = block.block_hash();
        self.anchored_done = true;

        block
    }

    /// Cut the next microblock.
    pub fn mine_next_microblock<'a>(&mut self) -> Result<StacksMicroblock, Error> {
        let txid_vecs = self.micro_txs
            .iter()
            .map(|tx| tx.txid().as_bytes().to_vec())
            .collect();

        let merkle_tree = MerkleTree::<Sha512Trunc256Sum>::new(&txid_vecs);
        let tx_merkle_root = merkle_tree.root();
        let mut next_microblock_header =
            if self.prev_microblock_header.sequence == 0 {
                StacksMicroblockHeader::first_unsigned(&self.prev_microblock_header.block_hash(), &tx_merkle_root)
            }
            else {
                StacksMicroblockHeader::from_parent_unsigned(&self.prev_microblock_header, &tx_merkle_root)
                    .ok_or(Error::MicroblockStreamTooLongError)?
            };

        next_microblock_header.sign(&self.miner_privkey).unwrap();
        self.prev_microblock_header = next_microblock_header.clone();

        let microblock = StacksMicroblock {
            header: next_microblock_header,
            txs: self.micro_txs.clone()
        };

        self.micro_txs.clear();
        Ok(microblock)
    }

    /// Begin mining an epoch's transactions.
    /// NOTE: even though we don't yet know the block hash, the Clarity VM ensures that a
    /// transaction can't query information about the _current_ block (i.e. information that is not
    /// yet known).
    pub fn epoch_begin_empty<'a>(&mut self, chainstate: &'a mut StacksChainState) -> Result<ClarityTx<'a>, Error> {
        // find matured miner rewards, so we can grant them within the Clarity DB tx.
        let matured_miner_rewards_opt = {
            let mut tx = chainstate.headers_tx_begin()?;
            StacksChainState::find_mature_miner_rewards(&mut tx, &self.chain_tip)?
        };

        self.miner_payouts = matured_miner_rewards_opt;

        // there's no way the miner can learn either the burn block hash or the stacks block hash,
        // so use a sentinel hash value for each that will never occur in practice.
        let new_burn_hash = BurnchainHeaderHash([1u8; 32]);
        let new_block_hash = BlockHeaderHash([1u8; 32]);

        debug!("Miner epoch begin off of {}/{}", self.chain_tip.burn_header_hash.to_hex(), self.header.parent_block.to_hex());
        let tx = chainstate.block_begin(&self.chain_tip.burn_header_hash, &self.header.parent_block, &new_burn_hash, &new_block_hash);
        Ok(tx)
    }

    pub fn epoch_begin<'a>(&mut self, chainstate: &'a mut StacksChainState, coinbase: &StacksTransaction) -> Result<ClarityTx<'a>, Error> {
        let mut tx = self.epoch_begin_empty(chainstate)?;
        self.try_mine_tx(&mut tx, coinbase)?;
        Ok(tx)
    }

    /// Finish up mining an epoch's transactions
    pub fn epoch_finish<'a>(&self, mut tx: ClarityTx<'a>) {
        let new_burn_hash = BurnchainHeaderHash([1u8; 32]);
        let new_block_hash = BlockHeaderHash([1u8; 32]);
        let index_block_hash = StacksBlockHeader::make_index_block_hash(&new_burn_hash, &new_block_hash);

        // clear out the block trie we just created, so the block validator logic doesn't step all
        // over it.
        let block_pathbuf = tx.get_block_path(&new_burn_hash, &new_block_hash);
        let mut mined_block_pathbuf = block_pathbuf.clone();
        mined_block_pathbuf.set_file_name(format!("{}.last-mined", index_block_hash.to_hex()));

        // write out the trie...
        tx.commit_block();

        // ...and move it (possibly overwriting)
        fs::rename(&block_pathbuf, &mined_block_pathbuf)
            .expect(&format!("FATAL: failed to rename {:?} to {:?}", &block_pathbuf, &mined_block_pathbuf));

        debug!("Finished mining child of {}/{}. Trie is in {:?}", self.chain_tip.burn_header_hash.to_hex(), self.chain_tip.anchored_header.block_hash().to_hex(), &mined_block_pathbuf);
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use std::collections::HashMap;
    use address::*;
    use chainstate::stacks::*;
    use chainstate::stacks::db::*;
    use chainstate::stacks::db::test::*;
    use chainstate::burn::*;
    use chainstate::burn::db::burndb::*;
    use chainstate::burn::operations::*;

    use burnchains::*;
    use burnchains::test::*;

    use util::vrf::*;

    use vm::types::*;

    pub struct TestStacksNode {
        pub burn: TestBurnchainNode,
        pub chainstate: StacksChainState,
        pub prev_keys: Vec<LeaderKeyRegisterOp>,        // _all_ keys generated
        pub key_ops: HashMap<VRFPublicKey, usize>,      // map VRF public keys to their locations in the prev_keys array
        pub anchored_blocks: Vec<StacksBlock>,
        pub microblocks: Vec<Vec<StacksMicroblock>>,
        pub commit_ops: HashMap<BlockHeaderHash, usize>
    }

    impl TestStacksNode {
        pub fn new(mainnet: bool, chain_id: u32, test_name: &str) -> TestStacksNode {
            let chainstate = instantiate_chainstate(mainnet, chain_id, test_name);
            TestStacksNode {
                burn: TestBurnchainNode::new(),
                chainstate: chainstate,
                prev_keys: vec![],
                key_ops: HashMap::new(),
                anchored_blocks: vec![],
                microblocks: vec![],
                commit_ops: HashMap::new()
            }
        }

        pub fn next_burn_block(&mut self, fork: &mut TestBurnchainFork) -> TestBurnchainBlock {
            let burn_block = {
                let mut tx = self.burn.burndb.tx_begin().unwrap();
                fork.next_block(&mut tx)
            };
            burn_block
        }

        pub fn add_key_register(&mut self, block: &mut TestBurnchainBlock, miner: &mut TestMiner) -> LeaderKeyRegisterOp {
            let key_register_op = block.add_leader_key_register(miner);
            self.prev_keys.push(key_register_op.clone());
            self.key_ops.insert(key_register_op.public_key.clone(), self.prev_keys.len()-1);
            key_register_op
        }

        pub fn add_block_commit(&mut self, burn_block: &mut TestBurnchainBlock, miner: &mut TestMiner, block_hash: &BlockHeaderHash, burn_amount: u64, key_op: &LeaderKeyRegisterOp, parent_block_snapshot: Option<&BlockSnapshot>) -> LeaderBlockCommitOp {
            let block_commit_op = {
                let mut tx = self.burn.burndb.tx_begin().unwrap();
                let parent_snapshot = burn_block.parent_snapshot.clone();
                burn_block.add_leader_block_commit(&mut tx, miner, block_hash, burn_amount, key_op, Some(&parent_snapshot), parent_block_snapshot)
            };
            block_commit_op
        }

        pub fn get_last_key(&self, miner: &TestMiner) -> LeaderKeyRegisterOp {
            let last_vrf_pubkey = miner.last_VRF_public_key().unwrap();
            let idx = *self.key_ops.get(&last_vrf_pubkey).unwrap();
            self.prev_keys[idx].clone()
        }

        pub fn get_last_anchored_block(&self, miner: &TestMiner) -> Option<StacksBlock> {
            match miner.last_block_commit() {
                None => None,
                Some(block_commit_op) => match self.commit_ops.get(&block_commit_op.block_header_hash) {
                    None => None,
                    Some(idx) => Some(self.anchored_blocks[*idx].clone())
                }
            }
        }

        pub fn get_anchored_block(&self, miner: &TestMiner, block_hash: &BlockHeaderHash) -> Option<StacksBlock> {
            match self.commit_ops.get(block_hash) {
                None => None,
                Some(idx) => Some(self.anchored_blocks[*idx].clone())
            }
        }

        pub fn get_last_winning_snapshot<'a>(tx: &mut BurnDBTx<'a>, fork_tip: &BlockSnapshot, miner: &TestMiner) -> Option<BlockSnapshot> {
            for commit_op in miner.block_commits.iter().rev() {
                match BurnDB::get_block_snapshot_for_winning_stacks_block(tx, &fork_tip.burn_header_hash, &commit_op.block_header_hash).unwrap() {
                    Some(sn) => {
                        return Some(sn);
                    }
                    None => {}
                }
            }
            return None;
        }

        pub fn get_miner_status<'a>(clarity_tx: &mut ClarityTx<'a>, addr: &StacksAddress) -> Option<(bool, u128)> {
            let boot_code_address = StacksAddress::from_string(&STACKS_BOOT_CODE_CONTRACT_ADDRESS.to_string()).unwrap();
            let miner_contract_id = QualifiedContractIdentifier::new(StandardPrincipalData::from(boot_code_address.clone()), ContractName::try_from(BOOT_CODE_MINER_CONTRACT_NAME.to_string()).unwrap());
            
            let miner_participant_principal = ClarityName::try_from(BOOT_CODE_MINER_REWARDS_PARTICIPANT.to_string()).unwrap();
            let miner_available_name = ClarityName::try_from(BOOT_CODE_MINER_REWARDS_AVAILABLE.to_string()).unwrap();
            let miner_authorized_name = ClarityName::try_from(BOOT_CODE_MINER_REWARDS_AUTHORIZED.to_string()).unwrap();
            
            let miner_principal = Value::Tuple(TupleData::from_data(vec![
                    (miner_participant_principal, Value::Principal(PrincipalData::Standard(StandardPrincipalData::from(addr.clone()))))])
                .expect("FATAL: failed to construct miner principal key"));

            let miner_status = clarity_tx.connection().with_clarity_db_readonly(|ref mut db| {
                let miner_status_opt = db.fetch_entry(&miner_contract_id, BOOT_CODE_MINER_REWARDS_MAP, &miner_principal)?;
                let miner_status = match miner_status_opt {
                    Value::Optional(ref optional_data) => {
                        match optional_data.data {
                            None => None,
                            Some(ref miner_status) => {
                                match **miner_status {
                                    Value::Tuple(ref tuple) => {
                                        let authorized = match tuple.get(&miner_authorized_name).expect("FATAL: no miner authorized in tuple") {
                                            Value::Bool(ref authorized) => *authorized,
                                            _ => {
                                                panic!("FATAL: miner reward data map is malformed");
                                            }
                                        };

                                        let available = match tuple.get(&miner_available_name).expect("FATAL: no miner available in tuple") {
                                            Value::UInt(ref available) => *available,
                                            _ => {
                                                panic!("FATAL: miner reward data map is malformed");
                                            }
                                        };
                                        
                                        Some((authorized, available))
                                    },
                                    ref x => {
                                        panic!("FATAL: miner status is not a tuple: {:?}", &x);
                                    }
                                }
                            }
                        }
                    },
                    ref x => {
                        panic!("FATAL: fetched miner status it not an optional: {:?}", &x);
                    }
                };
            
                Ok(miner_status)
            }).unwrap();

            miner_status
        }

        fn mine_stacks_block<F>(&mut self,
                                miner: &mut TestMiner, 
                                burn_block: &mut TestBurnchainBlock, 
                                miner_key: &LeaderKeyRegisterOp, 
                                parent_stacks_block: Option<&StacksBlock>, 
                                burn_amount: u64,
                                block_assembler: F) -> (StacksBlock, Vec<StacksMicroblock>, LeaderBlockCommitOp) 
        where
            F: FnOnce(&mut StacksBlockBuilder, &mut TestMiner) -> (StacksBlock, Vec<StacksMicroblock>)
        {
            let proof = miner.make_proof(&miner_key.public_key, &burn_block.parent_snapshot.sortition_hash).unwrap();

            let (mut builder, parent_block_snapshot_opt) = match parent_stacks_block {
                None => {
                    // first stacks block
                    let builder = StacksBlockBuilder::first(&burn_block.parent_snapshot.burn_header_hash, &proof, &miner.next_microblock_privkey());
                    (builder, None)
                },
                Some(parent_stacks_block) => {
                    // building off an existing stacks block
                    let parent_stacks_block_snapshot = {
                        let mut tx = self.burn.burndb.tx_begin().unwrap();
                        let parent_stacks_block_snapshot = BurnDB::get_block_snapshot_for_winning_stacks_block(&mut tx, &burn_block.parent_snapshot.burn_header_hash, &parent_stacks_block.block_hash()).unwrap().unwrap();
                        let burned_last = BurnDB::get_block_burn_amount(&mut tx, burn_block.parent_snapshot.block_height, &burn_block.parent_snapshot.burn_header_hash).unwrap();
                        parent_stacks_block_snapshot
                    };

                    let parent_chain_tip = StacksChainState::get_anchored_block_header_info(&self.chainstate.headers_db, &parent_stacks_block_snapshot.burn_header_hash, &parent_stacks_block.header.block_hash()).unwrap().unwrap();

                    let new_work = StacksWorkScore {
                        burn: parent_stacks_block_snapshot.total_burn,
                        work: 0
                    };

                    test_debug!("Burned in {} {}: {}", burn_block.block_height, burn_block.parent_snapshot.burn_header_hash.to_hex(), new_work.burn);
                    let builder = StacksBlockBuilder::from_parent(&parent_chain_tip, &new_work, &proof, &miner.next_microblock_privkey());
                    (builder, Some(parent_stacks_block_snapshot))
                }
            };

            test_debug!("Assemble stacks block");

            let (stacks_block, microblocks) = block_assembler(&mut builder, miner);
            self.anchored_blocks.push(stacks_block.clone());
            self.microblocks.push(microblocks.clone());
            
            test_debug!("Commit to stacks block {}", stacks_block.block_hash());

            // send block commit for this block (block i)
            let block_commit_op = self.add_block_commit(burn_block, miner, &stacks_block.block_hash(), burn_amount, miner_key, parent_block_snapshot_opt.as_ref());
            self.commit_ops.insert(block_commit_op.block_header_hash.clone(), self.anchored_blocks.len()-1);

            (stacks_block, microblocks, block_commit_op)
        }
    }

    /// Return Some(bool) to indicate whether or not the block was accepted into the queue.
    /// Return None if the block was not submitted at all.
    fn preprocess_stacks_block_data(node: &mut TestStacksNode, fork_snapshot: &BlockSnapshot, stacks_block: &StacksBlock, stacks_microblocks: &Vec<StacksMicroblock>, block_commit_op: &LeaderBlockCommitOp) -> Option<bool> {
        let block_hash = stacks_block.block_hash();

        let mut tx = node.burn.burndb.tx_begin().unwrap();
        let parent_block_burn_header_hash = match BurnDB::get_block_commit_parent(&mut tx, block_commit_op.parent_block_ptr.into(), block_commit_op.parent_vtxindex.into(), &fork_snapshot.burn_header_hash).unwrap() {
            Some(parent_commit) => parent_commit.burn_header_hash.clone(),
            None => {
                // only allowed if this is the first-ever block in the stacks fork
                assert_eq!(block_commit_op.parent_block_ptr, 0);
                assert_eq!(block_commit_op.parent_vtxindex, 0);
                assert!(stacks_block.header.is_genesis());

                BurnchainHeaderHash([0u8; 32])
            }
        };
    
        let commit_snapshot = match BurnDB::get_block_snapshot_for_winning_stacks_block(&mut tx, &fork_snapshot.burn_header_hash, &block_hash).unwrap() {
            Some(sn) => sn,
            None => {
                test_debug!("Block commit did not win sorition: {:?}", block_commit_op);
                return None;
            }
        };

        test_debug!("Preprocess Stacks block {}/{}", &commit_snapshot.burn_header_hash.to_hex(), &block_hash.to_hex());

        // "discover" this stacks block
        let res = node.chainstate.preprocess_anchored_block(&mut tx, &commit_snapshot.burn_header_hash, &stacks_block, &parent_block_burn_header_hash).unwrap();
        if !res {
            return Some(res)
        }

        // "discover" this stacks microblock stream
        for mblock in stacks_microblocks.iter() {
            let res = node.chainstate.preprocess_streamed_microblock(&mut tx, &commit_snapshot.burn_header_hash, &stacks_block.block_hash(), mblock).unwrap();
            if !res {
                return Some(res)
            }
        }

        Some(true)
    }
    
    /// Verify that the stacks block's state root matches the state root in the chain state
    fn check_block_state_index_root(chainstate: &mut StacksChainState, burn_header_hash: &BurnchainHeaderHash, stacks_header: &StacksBlockHeader) -> bool {
        let index_block_hash = StacksBlockHeader::make_index_block_hash(burn_header_hash, &stacks_header.block_hash());
        let state_root = chainstate.clarity_state_index.borrow_storage_backend().read_block_root_hash(&index_block_hash).unwrap();
        state_root == stacks_header.state_index_root
    }

    /// Verify that the miner got the expected block reward
    fn check_mining_reward<'a>(clarity_tx: &mut ClarityTx<'a>, miner: &mut TestMiner, expected_block_value: u128) -> bool {
        let miner_status_opt = TestStacksNode::get_miner_status(clarity_tx, &miner.origin_address().unwrap());
        match miner_status_opt {
            None => {
                return miner.expected_mining_rewards + expected_block_value == 0;
            },
            Some((authorized, amount)) => {
                if amount != miner.expected_mining_rewards + expected_block_value {
                    return false;
                }
                miner.expected_mining_rewards += expected_block_value;
                return true;
            }
        }
    }

    /// Simplest end-to-end test: create 1 fork of 10 Stacks blocks, mined on 1 burn chain fork,
    /// all comprising of empty blocks (i.e. just a coinbase) and no streamed blocks.
    #[test]
    fn mine_anchored_empty_blocks() {
        let mut node = TestStacksNode::new(false, 0x80000000, "mine_anchored_empty_blocks");
        let mut miner_factory = TestMinerFactory::new();
        let mut miner = miner_factory.next_miner(&node.burn.burnchain, 1, 1, AddressHashMode::SerializeP2PKH); 

        let first_snapshot = BurnDB::get_first_block_snapshot(node.burn.burndb.conn()).unwrap();
        let mut fork = TestBurnchainFork::new(first_snapshot.block_height, &first_snapshot.burn_header_hash, &first_snapshot.index_root, 0);
        
        let mut first_burn_block = node.next_burn_block(&mut fork);

        let mut miner_keys_1 = vec![];

        // first, register a VRF key
        let k1 = node.add_key_register(&mut first_burn_block, &mut miner);
        miner_keys_1.push(k1);

        test_debug!("Mine {} initial transactions", first_burn_block.txs.len());

        fork.append_block(first_burn_block);
        node.burn.mine_fork(&mut fork);

        // next, build up some stacks blocks
        for i in 0..10 {
            let mut burn_block = {
                let mut tx = node.burn.burndb.tx_begin().unwrap();
                fork.next_block(&mut tx)
            };
            
            let last_key = node.get_last_key(&miner);
            let parent_block_opt = node.get_last_anchored_block(&miner);

            // send next key (key for block i+1)
            let k = node.add_key_register(&mut burn_block, &mut miner);
            miner_keys_1.push(k);

            let (stacks_block, microblocks, block_commit_op) = node.mine_stacks_block(&mut miner, &mut burn_block, &last_key, parent_block_opt.as_ref(), 1000, |ref mut builder, ref mut miner| {
                // make a coinbase for this miner
                let mut tx_coinbase = StacksTransaction::new(TransactionVersion::Testnet, miner.as_transaction_auth().unwrap(), TransactionPayload::Coinbase(CoinbasePayload([i as u8; 32])));
                tx_coinbase.chain_id = 0x80000000;
                tx_coinbase.anchor_mode = TransactionAnchorMode::OnChainOnly;
                let mut tx_signer = StacksTransactionSigner::new(&tx_coinbase);

                miner.sign_as_origin(&mut tx_signer);
                let tx_coinbase_signed = tx_signer.get_tx().unwrap();

                test_debug!("Produce anchored stacks block");

                let (stacks_block, microblocks) = {
                    let mut miner_chainstate = open_chainstate(false, 0x80000000, "mine_anchored_empty_blocks");
                    
                    let mut epoch = builder.epoch_begin(&mut miner_chainstate, &tx_coinbase_signed).unwrap();
                    let anchored_block = builder.mine_anchored_block(&mut epoch);

                    // make sure the coinbase is right
                    if i <= MINER_REWARD_MATURITY + MINER_REWARD_WINDOW {
                        assert!(check_mining_reward(&mut epoch, miner, 0));
                    }
                    else {
                        // matured!
                        assert!(check_mining_reward(&mut epoch, miner, 500000000));
                    }

                    builder.epoch_finish(epoch);

                    (anchored_block, vec![])
                };
                (stacks_block, microblocks)
            });

            // process burn chain
            fork.append_block(burn_block);
            let fork_snapshot = node.burn.mine_fork(&mut fork);

            // "discover" the stacks block
            preprocess_stacks_block_data(&mut node, &fork_snapshot, &stacks_block, &microblocks, &block_commit_op);

            // process all blocks
            test_debug!("Process Stacks block {}", &stacks_block.block_hash().to_hex());
            let tip_info_list = node.chainstate.process_blocks(node.burn.burndb.conn(), 1).unwrap();

            // processed _this_ block
            assert_eq!(tip_info_list.len(), 1);
            let (chain_tip_opt, poison_opt) = tip_info_list[0].clone();

            assert!(chain_tip_opt.is_some());
            assert!(poison_opt.is_none());

            let chain_tip = chain_tip_opt.unwrap();

            assert_eq!(chain_tip.anchored_header.block_hash(), stacks_block.block_hash());
            assert_eq!(chain_tip.burn_header_hash, fork_snapshot.burn_header_hash);

            // MARF trie exists for the block header's chain state, so we can make merkle proofs on it
            assert!(check_block_state_index_root(&mut node.chainstate, &fork_snapshot.burn_header_hash, &chain_tip.anchored_header));
        }
    }

    /// mine 10 empty stacks blocks, but fork the stacks blockchain at height 5
    #[test]
    fn mine_anchored_empty_blocks_stacks_fork() {
        let mut node = TestStacksNode::new(false, 0x80000000, "mine_anchored_empty_blocks_stacks_fork");
        let mut miner_factory = TestMinerFactory::new();
        let mut miner_1 = miner_factory.next_miner(&node.burn.burnchain, 1, 1, AddressHashMode::SerializeP2PKH); 
        let mut miner_2 = miner_factory.next_miner(&node.burn.burnchain, 1, 1, AddressHashMode::SerializeP2PKH); 

        let first_snapshot = BurnDB::get_first_block_snapshot(node.burn.burndb.conn()).unwrap();
        let mut fork = TestBurnchainFork::new(first_snapshot.block_height, &first_snapshot.burn_header_hash, &first_snapshot.index_root, 0);
        
        let mut first_burn_block = node.next_burn_block(&mut fork);

        // first, register a VRF key
         node.add_key_register(&mut first_burn_block, &mut miner_1);

        test_debug!("Mine {} initial transactions", first_burn_block.txs.len());

        fork.append_block(first_burn_block);
        node.burn.mine_fork(&mut fork);

        // next, build up some stacks blocks
        for i in 0..5 {
            let mut burn_block = {
                let mut tx = node.burn.burndb.tx_begin().unwrap();
                fork.next_block(&mut tx)
            };
            
            let last_key = node.get_last_key(&miner_1);
            let parent_block_opt = node.get_last_anchored_block(&miner_1);

            // send next key (key for block i+1)
            node.add_key_register(&mut burn_block, &mut miner_1);
            node.add_key_register(&mut burn_block, &mut miner_2);

            let (stacks_block, microblocks, block_commit_op) = node.mine_stacks_block(&mut miner_1, &mut burn_block, &last_key, parent_block_opt.as_ref(), 1000, |ref mut builder, ref mut miner| {
                // make a coinbase for this miner
                let mut tx_coinbase = StacksTransaction::new(TransactionVersion::Testnet, miner.as_transaction_auth().unwrap(), TransactionPayload::Coinbase(CoinbasePayload([i as u8; 32])));
                tx_coinbase.chain_id = 0x80000000;
                tx_coinbase.anchor_mode = TransactionAnchorMode::OnChainOnly;
                let mut tx_signer = StacksTransactionSigner::new(&tx_coinbase);

                miner.sign_as_origin(&mut tx_signer);
                let tx_coinbase_signed = tx_signer.get_tx().unwrap();

                test_debug!("Produce anchored stacks block");

                let (stacks_block, microblocks) = {
                    let mut miner_chainstate = open_chainstate(false, 0x80000000, "mine_anchored_empty_blocks_stacks_fork");
                    
                    let mut epoch = builder.epoch_begin(&mut miner_chainstate, &tx_coinbase_signed).unwrap();
                    let anchored_block = builder.mine_anchored_block(&mut epoch);
                    builder.epoch_finish(epoch);

                    (anchored_block, vec![])
                };
                (stacks_block, microblocks)
            });

            // process burn chain
            fork.append_block(burn_block);
            let fork_snapshot = node.burn.mine_fork(&mut fork);

            // "discover" the stacks block
            preprocess_stacks_block_data(&mut node, &fork_snapshot, &stacks_block, &microblocks, &block_commit_op);

            // process all blocks
            test_debug!("Process Stacks block {}", &stacks_block.block_hash().to_hex());
            let tip_info_list = node.chainstate.process_blocks(node.burn.burndb.conn(), 1).unwrap();

            // processed _this_ block
            assert_eq!(tip_info_list.len(), 1);
            let (chain_tip_opt, poison_opt) = tip_info_list[0].clone();

            assert!(chain_tip_opt.is_some());
            assert!(poison_opt.is_none());

            let chain_tip = chain_tip_opt.unwrap();

            assert_eq!(chain_tip.anchored_header.block_hash(), stacks_block.block_hash());
            assert_eq!(chain_tip.burn_header_hash, fork_snapshot.burn_header_hash);
            
            // MARF trie exists for the block header's chain state, so we can make merkle proofs on it
            assert!(check_block_state_index_root(&mut node.chainstate, &fork_snapshot.burn_header_hash, &chain_tip.anchored_header));
        }

        test_debug!("\n\n\nBegin fork\n\n");

        for i in 0..5 {
            let mut burn_block = {
                let mut tx = node.burn.burndb.tx_begin().unwrap();
                fork.next_block(&mut tx)
            };
            
            let last_key_1 = node.get_last_key(&miner_1);
            let last_key_2 = node.get_last_key(&miner_2);

            let (block_1_snapshot_opt, block_2_snapshot_opt) = {
                let mut tx = node.burn.burndb.tx_begin().unwrap();
                let chain_tip = fork.get_tip(&mut tx);
                let block_1_snapshot_opt = TestStacksNode::get_last_winning_snapshot(&mut tx, &chain_tip, &miner_1);
                let block_2_snapshot_opt = TestStacksNode::get_last_winning_snapshot(&mut tx, &chain_tip, &miner_2);
                (block_1_snapshot_opt, block_2_snapshot_opt)
            };

            let parent_block_opt_1 = match block_1_snapshot_opt {
                Some(sn) => node.get_anchored_block(&miner_1, &sn.winning_stacks_block_hash),
                None => None
            };
            
            let parent_block_opt_2 = match block_2_snapshot_opt {
                Some(sn) => node.get_anchored_block(&miner_2, &sn.winning_stacks_block_hash),
                None => parent_block_opt_1.clone()
            };

            // send next key (key for block i+1)
            node.add_key_register(&mut burn_block, &mut miner_1);
            node.add_key_register(&mut burn_block, &mut miner_2);

            let (stacks_block_1, microblocks_1, block_commit_op_1) = node.mine_stacks_block(&mut miner_1, &mut burn_block, &last_key_1, parent_block_opt_1.as_ref(), 1000, |ref mut builder, ref mut miner| {
                // make a coinbase for this miner
                let mut tx_coinbase = StacksTransaction::new(TransactionVersion::Testnet, miner.as_transaction_auth().unwrap(), TransactionPayload::Coinbase(CoinbasePayload([i as u8; 32])));
                tx_coinbase.chain_id = 0x80000000;
                tx_coinbase.anchor_mode = TransactionAnchorMode::OnChainOnly;
                let mut tx_signer = StacksTransactionSigner::new(&tx_coinbase);

                miner.sign_as_origin(&mut tx_signer);
                let tx_coinbase_signed = tx_signer.get_tx().unwrap();

                test_debug!("Produce anchored stacks block 1");

                let (stacks_block, microblocks) = {
                    let mut miner_chainstate = open_chainstate(false, 0x80000000, "mine_anchored_empty_blocks_stacks_fork");
                    
                    let mut epoch = builder.epoch_begin(&mut miner_chainstate, &tx_coinbase_signed).unwrap();
                    let anchored_block = builder.mine_anchored_block(&mut epoch);
                    builder.epoch_finish(epoch);

                    (anchored_block, vec![])
                };
                
                test_debug!("Finished producing anchored stacks block 1");
                (stacks_block, microblocks)
            });
            
            let (stacks_block_2, microblocks_2, block_commit_op_2) = node.mine_stacks_block(&mut miner_2, &mut burn_block, &last_key_2, parent_block_opt_2.as_ref(), 1000, |ref mut builder, ref mut miner| {
                // make a coinbase for this miner
                let mut tx_coinbase = StacksTransaction::new(TransactionVersion::Testnet, miner.as_transaction_auth().unwrap(), TransactionPayload::Coinbase(CoinbasePayload([i as u8; 32])));
                tx_coinbase.chain_id = 0x80000000;
                tx_coinbase.anchor_mode = TransactionAnchorMode::OnChainOnly;
                let mut tx_signer = StacksTransactionSigner::new(&tx_coinbase);

                miner.sign_as_origin(&mut tx_signer);
                let tx_coinbase_signed = tx_signer.get_tx().unwrap();

                test_debug!("Produce anchored stacks block 2");

                let (stacks_block, microblocks) = {
                    let mut miner_chainstate = open_chainstate(false, 0x80000000, "mine_anchored_empty_blocks_stacks_fork");
                    
                    let mut epoch = builder.epoch_begin(&mut miner_chainstate, &tx_coinbase_signed).unwrap();
                    let anchored_block = builder.mine_anchored_block(&mut epoch);
                    builder.epoch_finish(epoch);

                    (anchored_block, vec![])
                };

                test_debug!("Finished producing anchored stacks block 2");
                (stacks_block, microblocks)
            });

            // process burn chain
            fork.append_block(burn_block);
            let fork_snapshot = node.burn.mine_fork(&mut fork);

            // "discover" the stacks blocks
            let res_1 = preprocess_stacks_block_data(&mut node, &fork_snapshot, &stacks_block_1, &microblocks_1, &block_commit_op_1);
            let res_2 = preprocess_stacks_block_data(&mut node, &fork_snapshot, &stacks_block_2, &microblocks_2, &block_commit_op_2);

            // exactly one stacks block will have been queued up, since sortition picks only one.
            match (res_1, res_2) {
                (Some(res), None) => assert!(res),
                (None, Some(res)) => assert!(res),
                (_, _) => assert!(false)
            }

            // process all blocks
            test_debug!("Process Stacks block {}", &fork_snapshot.winning_stacks_block_hash.to_hex());
            let tip_info_list = node.chainstate.process_blocks(node.burn.burndb.conn(), 2).unwrap();

            // processed exactly one block, but got back two tip-infos
            assert_eq!(tip_info_list.len(), 1);
            let (chain_tip_opt, poison_opt) = tip_info_list[0].clone();

            assert!(chain_tip_opt.is_some());
            assert!(poison_opt.is_none());

            let chain_tip = chain_tip_opt.unwrap();

            // selected block is the sortition-winning block
            assert_eq!(chain_tip.anchored_header.block_hash(), fork_snapshot.winning_stacks_block_hash);
            assert_eq!(chain_tip.burn_header_hash, fork_snapshot.burn_header_hash);
            
            if fork_snapshot.winning_stacks_block_hash == stacks_block_1.block_hash() {
                test_debug!("\n\nMiner 1 won sortition\n");

                // MARF trie exists for the block header's chain state, so we can make merkle proofs on it
                assert!(check_block_state_index_root(&mut node.chainstate, &fork_snapshot.burn_header_hash, &stacks_block_1.header));
            }
            else {
                test_debug!("\n\nMiner 2 won sortition\n");
                
                // MARF trie exists for the block header's chain state, so we can make merkle proofs on it
                assert!(check_block_state_index_root(&mut node.chainstate, &fork_snapshot.burn_header_hash, &stacks_block_2.header));
            }
        }
    }
   
    /// Mine 10 empty stacks blocks, but fork the underlying burn chain after the 5th block.
    #[test]
    fn mine_anchored_empty_blocks_burnchain_fork() {
        let mut node = TestStacksNode::new(false, 0x80000000, "mine_anchored_empty_blocks_burnchain_fork");
        let mut miner_factory = TestMinerFactory::new();
        let mut miner_1 = miner_factory.next_miner(&node.burn.burnchain, 1, 1, AddressHashMode::SerializeP2PKH); 
        let mut miner_2 = miner_factory.next_miner(&node.burn.burnchain, 1, 1, AddressHashMode::SerializeP2PKH); 

        let first_snapshot = BurnDB::get_first_block_snapshot(node.burn.burndb.conn()).unwrap();
        let mut fork_1 = TestBurnchainFork::new(first_snapshot.block_height, &first_snapshot.burn_header_hash, &first_snapshot.index_root, 0);
        
        let mut first_burn_block = node.next_burn_block(&mut fork_1);

        // first, register a VRF key
        node.add_key_register(&mut first_burn_block, &mut miner_1);

        test_debug!("Mine {} initial transactions", first_burn_block.txs.len());

        fork_1.append_block(first_burn_block);
        node.burn.mine_fork(&mut fork_1);

        // next, build up some stacks blocks
        for i in 0..5 {
            let mut burn_block = {
                let mut tx = node.burn.burndb.tx_begin().unwrap();
                fork_1.next_block(&mut tx)
            };
            
            let last_key = node.get_last_key(&miner_1);
            let parent_block_opt = node.get_last_anchored_block(&miner_1);

            // send next key (key for block i+1)
            node.add_key_register(&mut burn_block, &mut miner_1);
            node.add_key_register(&mut burn_block, &mut miner_2);

            let (stacks_block, microblocks, block_commit_op) = node.mine_stacks_block(&mut miner_1, &mut burn_block, &last_key, parent_block_opt.as_ref(), 1000, |ref mut builder, ref mut miner| {
                // make a coinbase for this miner
                let mut tx_coinbase = StacksTransaction::new(TransactionVersion::Testnet, miner.as_transaction_auth().unwrap(), TransactionPayload::Coinbase(CoinbasePayload([i as u8; 32])));
                tx_coinbase.chain_id = 0x80000000;
                tx_coinbase.anchor_mode = TransactionAnchorMode::OnChainOnly;
                let mut tx_signer = StacksTransactionSigner::new(&tx_coinbase);

                miner.sign_as_origin(&mut tx_signer);
                let tx_coinbase_signed = tx_signer.get_tx().unwrap();

                test_debug!("Produce anchored stacks block");

                let (stacks_block, microblocks) = {
                    let mut miner_chainstate = open_chainstate(false, 0x80000000, "mine_anchored_empty_blocks_burnchain_fork");
                    
                    let mut epoch = builder.epoch_begin(&mut miner_chainstate, &tx_coinbase_signed).unwrap();
                    let anchored_block = builder.mine_anchored_block(&mut epoch);
                    builder.epoch_finish(epoch);

                    (anchored_block, vec![])
                };
                (stacks_block, microblocks)
            });

            // process burn chain
            fork_1.append_block(burn_block);
            let fork_snapshot = node.burn.mine_fork(&mut fork_1);

            // "discover" the stacks block
            preprocess_stacks_block_data(&mut node, &fork_snapshot, &stacks_block, &microblocks, &block_commit_op);

            // process all blocks
            test_debug!("Process Stacks block {}", &stacks_block.block_hash().to_hex());
            let tip_info_list = node.chainstate.process_blocks(node.burn.burndb.conn(), 1).unwrap();

            // processed _this_ block
            assert_eq!(tip_info_list.len(), 1);
            let (chain_tip_opt, poison_opt) = tip_info_list[0].clone();

            assert!(chain_tip_opt.is_some());
            assert!(poison_opt.is_none());

            let chain_tip = chain_tip_opt.unwrap();

            assert_eq!(chain_tip.anchored_header.block_hash(), stacks_block.block_hash());
            assert_eq!(chain_tip.burn_header_hash, fork_snapshot.burn_header_hash);
            
            // MARF trie exists for the block header's chain state, so we can make merkle proofs on it
            assert!(check_block_state_index_root(&mut node.chainstate, &fork_snapshot.burn_header_hash, &chain_tip.anchored_header));
        }

        let mut fork_2 = fork_1.fork();

        test_debug!("\n\n\nbegin burnchain fork\n\n");

        // next, build up some stacks blocks on two separate burnchain forks.
        // send the same leader key register transactions to both forks.
        for i in 0..5 {
            let mut burn_block_1 = {
                let mut tx = node.burn.burndb.tx_begin().unwrap();
                fork_1.next_block(&mut tx)
            };
            let mut burn_block_2 = {
                let mut tx = node.burn.burndb.tx_begin().unwrap();
                fork_2.next_block(&mut tx)
            };
            
            let last_key_1 = node.get_last_key(&miner_1);
            let last_key_2 = node.get_last_key(&miner_2);
            let parent_block_opt_1 = node.get_last_anchored_block(&miner_1);
            let parent_block_opt_2 = match node.get_last_anchored_block(&miner_2) {
                Some(bbl) => Some(bbl),
                None => {
                    // beginning of fork --- this miner hasn't produced any blocks yet
                    parent_block_opt_1.clone()
                }
            };

            // send next key (key for block i+1)
            node.add_key_register(&mut burn_block_1, &mut miner_1);
            node.add_key_register(&mut burn_block_2, &mut miner_2);

            let (stacks_block_1, microblocks_1, block_commit_op_1) = node.mine_stacks_block(&mut miner_1, &mut burn_block_1, &last_key_1, parent_block_opt_1.as_ref(), 1000, |ref mut builder, ref mut miner| {
                // make a coinbase for this miner
                let mut tx_coinbase = StacksTransaction::new(TransactionVersion::Testnet, miner.as_transaction_auth().unwrap(), TransactionPayload::Coinbase(CoinbasePayload([i as u8; 32])));
                tx_coinbase.chain_id = 0x80000000;
                tx_coinbase.anchor_mode = TransactionAnchorMode::OnChainOnly;
                let mut tx_signer = StacksTransactionSigner::new(&tx_coinbase);

                miner.sign_as_origin(&mut tx_signer);
                let tx_coinbase_signed = tx_signer.get_tx().unwrap();
                
                test_debug!("Produce anchored stacks block 1");

                let (stacks_block, microblocks) = {
                    let mut miner_chainstate = open_chainstate(false, 0x80000000, "mine_anchored_empty_blocks_burnchain_fork");
                    
                    let mut epoch = builder.epoch_begin(&mut miner_chainstate, &tx_coinbase_signed).unwrap();
                    let anchored_block = builder.mine_anchored_block(&mut epoch);
                    builder.epoch_finish(epoch);

                    (anchored_block, vec![])
                };
                (stacks_block, microblocks)
            });
            
            let (stacks_block_2, microblocks_2, block_commit_op_2) = node.mine_stacks_block(&mut miner_2, &mut burn_block_2, &last_key_2, parent_block_opt_2.as_ref(), 1000, |ref mut builder, ref mut miner| {
                // make a coinbase for this miner
                let mut tx_coinbase = StacksTransaction::new(TransactionVersion::Testnet, miner.as_transaction_auth().unwrap(), TransactionPayload::Coinbase(CoinbasePayload([i as u8; 32])));
                tx_coinbase.chain_id = 0x80000000;
                tx_coinbase.anchor_mode = TransactionAnchorMode::OnChainOnly;
                let mut tx_signer = StacksTransactionSigner::new(&tx_coinbase);

                miner.sign_as_origin(&mut tx_signer);
                let tx_coinbase_signed = tx_signer.get_tx().unwrap();

                test_debug!("Produce anchored stacks block 2");

                let (stacks_block, microblocks) = {
                    let mut miner_chainstate = open_chainstate(false, 0x80000000, "mine_anchored_empty_blocks_burnchain_fork");
                    
                    let mut epoch = builder.epoch_begin(&mut miner_chainstate, &tx_coinbase_signed).unwrap();
                    let anchored_block = builder.mine_anchored_block(&mut epoch);
                    builder.epoch_finish(epoch);

                    (anchored_block, vec![])
                };
                (stacks_block, microblocks)
            });

            // process burn chain
            fork_1.append_block(burn_block_1);
            fork_2.append_block(burn_block_2);
            let fork_snapshot_1 = node.burn.mine_fork(&mut fork_1);
            let fork_snapshot_2 = node.burn.mine_fork(&mut fork_2);
            
            assert!(fork_snapshot_1.burn_header_hash != fork_snapshot_2.burn_header_hash);
            assert!(fork_snapshot_1.consensus_hash != fork_snapshot_2.consensus_hash);

            // "discover" the stacks block
            test_debug!("preprocess fork 1 {}", stacks_block_1.block_hash().to_hex());
            preprocess_stacks_block_data(&mut node, &fork_snapshot_1, &stacks_block_1, &microblocks_1, &block_commit_op_1);
            
            test_debug!("preprocess fork 2 {}", stacks_block_1.block_hash().to_hex());
            preprocess_stacks_block_data(&mut node, &fork_snapshot_2, &stacks_block_2, &microblocks_2, &block_commit_op_2);

            // process all blocks
            test_debug!("Process all Stacks blocks: {}, {}", &stacks_block_1.block_hash().to_hex(), &stacks_block_2.block_hash().to_hex());
            let tip_info_list = node.chainstate.process_blocks(node.burn.burndb.conn(), 2).unwrap();

            // processed all stacks blocks -- one on each burn chain fork
            assert_eq!(tip_info_list.len(), 2);

            for (ref chain_tip_opt, ref poison_opt) in tip_info_list.iter() {
                assert!(chain_tip_opt.is_some());
                assert!(poison_opt.is_none());
            }

            // fork 1?
            let mut found_fork_1 = false;
            for (ref chain_tip_opt, ref poison_opt) in tip_info_list.iter() {
                let chain_tip = chain_tip_opt.clone().unwrap();
                if chain_tip.burn_header_hash == fork_snapshot_1.burn_header_hash {
                    found_fork_1 = true;
                    assert_eq!(chain_tip.anchored_header.block_hash(), stacks_block_1.block_hash());
            
                    // MARF trie exists for the block header's chain state, so we can make merkle proofs on it
                    assert!(check_block_state_index_root(&mut node.chainstate, &fork_snapshot_1.burn_header_hash, &chain_tip.anchored_header));
                }
            }

            assert!(found_fork_1);

            let mut found_fork_2 = false;
            for (ref chain_tip_opt, ref poison_opt) in tip_info_list.iter() {
                let chain_tip = chain_tip_opt.clone().unwrap();
                if chain_tip.burn_header_hash == fork_snapshot_2.burn_header_hash {
                    found_fork_2 = true;
                    assert_eq!(chain_tip.anchored_header.block_hash(), stacks_block_2.block_hash());
                    
                    // MARF trie exists for the block header's chain state, so we can make merkle proofs on it
                    assert!(check_block_state_index_root(&mut node.chainstate, &fork_snapshot_2.burn_header_hash, &chain_tip.anchored_header));
                }
            }

            assert!(found_fork_2);
        }
    }

    // TODO: microblocks
    // TODO; skipped blocks
    // TODO: missing blocks
    // TODO: invalid blocks
    // TODO: verify that the Clarity MARF stores _only_ Clarity data
}
