use super::{MemPool, Config, Keychain, MemPoolFS, TestnetNode, LeaderConfig, TestnetBurnchainNode, TestnetMiner, BurnchainSimulator, MemPoolObserver};

use std::fs;
use std::env;
use std::process;
use std::sync::mpsc::Sender;
use net::StacksMessageCodec;
use chainstate::stacks::*;
use util::hash::hex_bytes;

use chainstate::stacks::db::{StacksChainState, StacksHeaderInfo};
use chainstate::stacks::{StacksBlock, StacksTransactionSigner, StacksMicroblock, CoinbasePayload, StacksBlockBuilder, TransactionAuth};
use address::AddressHashMode;
use burnchains::{Burnchain, BurnchainHeaderHash, Txid, PrivateKey, BurnchainBlock};
use chainstate::stacks::{StacksPrivateKey};
use chainstate::burn::operations::{BlockstackOperationType, LeaderKeyRegisterOp, LeaderBlockCommitOp};
use chainstate::burn::{ConsensusHash, SortitionHash, BlockSnapshot, VRFSeed};
use util::vrf::{VRF, VRFProof, VRFPublicKey, VRFPrivateKey};
use util::hash::Sha256Sum;
use std::collections::HashMap;
use rusqlite::{Connection, OpenFlags, NO_PARAMS};
use rand::RngCore;
use util::hash::{to_hex};
use std::{thread, time};

// struct LeaderKey {
//     vrf_public_key: VRFPublicKey,
//     key_block_height: u16,
//     key_vtxindex: u16,
// }

pub struct Leader <'a> {
    chain_state: StacksChainState,
    chain_tip: Option<StacksHeaderInfo>,
    mem_pool: MemPoolFS<'a>,
    keychain: Keychain,
    key_block_height: u16,
    key_vtxindex: u16,
    commit_block_height: u16,
    commit_vtxindex: u16,
    vtxindex: u16,
    block_time: u64,
    burchain_ops_tx: Option<Sender<BlockstackOperationType>>,
}

impl <'a> Leader <'a> {

    pub fn new(config: LeaderConfig, block_time: u64) -> Leader<'a> {
        
        let keychain = Keychain::default();

        let chain_state = StacksChainState::open(false, 0x80000000, &config.name).unwrap();

        let mem_pool = MemPoolFS::new(&config.mem_pool_path);

        Self {
            chain_state,
            chain_tip: Some(StacksHeaderInfo::genesis()),
            keychain,
            key_block_height: 0,
            key_vtxindex: 0,
            mem_pool,
            commit_block_height: 0,
            commit_vtxindex: 0,
            vtxindex: 0,
            block_time,
            burchain_ops_tx: None
        }
    }

    pub fn tear_up(&mut self, burchain_ops_tx: Sender<BlockstackOperationType>, consensus_hash: ConsensusHash) {
        
        let mut vrf_pk = self.keychain.rotate_vrf_keypair();
        let mut burn_fee = 1;

        let key_reg_op = self.generate_leader_key_register_op(vrf_pk, consensus_hash);
        burchain_ops_tx.send(key_reg_op).unwrap();
        self.burchain_ops_tx = Some(burchain_ops_tx);
    }

    fn generate_leader_key_register_op(&mut self, vrf_public_key: VRFPublicKey, consensus_hash: ConsensusHash) -> BlockstackOperationType {
        self.vtxindex += 1;

        BlockstackOperationType::LeaderKeyRegister(LeaderKeyRegisterOp {
            public_key: vrf_public_key,
            memo: vec![],
            address: self.keychain.get_address(),
            consensus_hash,
            vtxindex: self.vtxindex as u32,

            // to be filled in 
            txid: Txid([0u8; 32]),
            block_height: 0,
            burn_header_hash: BurnchainHeaderHash([0u8; 32]),
        })
    }

    fn generate_block_commitment_op(&mut self, tenure: LeaderTenure, burn_fee: u64) -> BlockstackOperationType {
        self.vtxindex += 1;

        BlockstackOperationType::LeaderBlockCommit(LeaderBlockCommitOp {
            new_seed: tenure.vrf_seed,
            key_block_ptr: self.key_block_height as u32,
            key_vtxindex: self.key_vtxindex as u16,
            parent_block_ptr: self.commit_block_height as u32, //block_height as u32 - 1,
            parent_vtxindex: self.commit_vtxindex as u16,
            memo: vec![],
            burn_fee,
            input: self.keychain.get_burnchain_signer(),
            block_header_hash: tenure.block_builder.header.block_hash(),
            vtxindex: self.vtxindex as u32,

            // to be filled in 
            txid: Txid([0u8; 32]),
            block_height: 0,
            burn_header_hash: BurnchainHeaderHash([0u8; 32]),
        })
    }

    fn initiate_new_tenure(&mut self, sortition_hash: SortitionHash) -> LeaderTenure {

        let chain_tip = match self.chain_tip {
            Some(ref b) => b.clone(),
            _ => panic!()
        };

        let vrf_proof = self.keychain.generate_proof(vrf_public_key, sortition_hash.as_bytes()).unwrap();

        let microblock_secret_key = self.keychain.rotate_microblock_keypair();

        let mut tenure = LeaderTenure::new(chain_tip, vrf_proof, microblock_secret_key);

        let coinbase_tx = {
            let tx_auth = self.keychain.get_transaction_auth().unwrap();

            let mut tx = StacksTransaction::new(
                TransactionVersion::Testnet, 
                tx_auth, 
                TransactionPayload::Coinbase(CoinbasePayload([0u8; 32])));
            tx.chain_id = 0x80000000;
            tx.anchor_mode = TransactionAnchorMode::OnChainOnly;
            let mut tx_signer = StacksTransactionSigner::new(&tx);
            self.keychain.sign_as_origin(&mut tx_signer);
            tx_signer.get_tx().unwrap()
        };

        tenure.handle_txs(vec![coinbase_tx]);

        tenure
    }
}

pub struct LeaderTenure {
    started_at: std::time::Instant,
    block_builder: StacksBlockBuilder,
    vrf_seed: VRFSeed,
    // registered_key: RegisteredKey,
}

impl LeaderTenure {

    pub fn new(parent_block: StacksHeaderInfo, vrf_proof: VRFProof, microblock_secret_key: StacksPrivateKey) -> LeaderTenure {
        let now = time::Instant::now();
        
        let ratio = StacksWorkScore {
            burn: 1, // todo(ludo): get burn from burnchain_tip.
            work: 0
        };

        let block_builder = StacksBlockBuilder::from_parent(&parent_block, &ratio, &vrf_proof, &microblock_secret_key);

        Self {
            started_at: now,
            block_builder,
            vrf_seed: VRFSeed::from_proof(&vrf_proof),
        }
    }

    pub fn handle_txs(&mut self, txs: Vec<StacksTransaction>) {
        
    }
}