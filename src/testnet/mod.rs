pub mod run_loop; 
pub mod mem_pool;
pub mod keychain;

pub use self::run_loop::{RunLoop};
pub use self::mem_pool::{MemPoolFS};
pub use self::keychain::{Keychain};

use std::fs;
use std::env;
use std::process;
use net::StacksMessageCodec;
use chainstate::stacks::*;
use util::hash::hex_bytes;

use chainstate::stacks::db::StacksChainState;
use chainstate::stacks::{StacksBlock, StacksMicroblock, CoinbasePayload};
use chainstate::burn::db::burndb::{BurnDB};
use address::AddressHashMode;
use burnchains::{Burnchain, BurnchainHeaderHash, Txid, PrivateKey};
use chainstate::stacks::{StacksPrivateKey};
use chainstate::burn::operations::{LeaderKeyRegisterOp, LeaderBlockCommitOp};
use chainstate::burn::SortitionHash;
use util::vrf::{VRF, VRFProof, VRFPublicKey, VRFPrivateKey};
use util::hash::Sha256Sum;
use std::collections::HashMap;
use rusqlite::{Connection, OpenFlags, NO_PARAMS};
use rand::RngCore;
use util::hash::{to_hex};
use std::{thread, time};

pub struct Config {
    pub name: String,
    pub db_path: String,
}

pub trait MemPool <'a> {
    fn start(&mut self);
    fn stop(&mut self);
    fn reset(&mut self);
    fn handle_incoming_tx(&mut self, tx: Txid);
    fn archive_tx(&mut self, tx: Txid);
    fn register_observer(&mut self, observer: &'a mut MemPoolObserver);
    fn unregister_observer(&mut self, observer: &'a mut MemPoolObserver);
}

pub trait MemPoolObserver {
    fn handle_received_tx(&mut self, tx: Txid);
    fn handle_archived_tx(&mut self, tx: Txid);
}

pub trait TxHandler {
    // fn configure(&mut self);
    // fn start(&mut self);
    // fn stop(&mut self);
}

pub trait Node {
    fn configure(&mut self);
    fn start(&mut self);
    fn stop(&mut self);
}

pub struct TestnetRunLoop {
}

pub struct TestnetNode {
    pub chainstate: StacksChainState,
    pub anchored_blocks: Vec<StacksBlock>,
    pub microblocks: Vec<Vec<StacksMicroblock>>,
    pub burnchain_node: TestnetBurnchainNode,
}

impl TestnetNode {

    fn new() -> Self {
        Self {
            chainstate: StacksChainState::open(false, 0x80000000, "testnet").unwrap(),
            anchored_blocks: vec![],
            microblocks: vec![],
            burnchain_node: TestnetBurnchainNode::new()
        }
    }
}

pub struct TestnetBurnchainNode {
    pub db: BurnDB,
    pub chain: Burnchain
}

impl TestnetBurnchainNode {

    fn new() -> Self {
        let first_block_height = 100;
        let first_block_hash = BurnchainHeaderHash([0u8; 32]);
        
        let mut rng = rand::thread_rng();
        let mut buf = [0u8; 32];
        rng.fill_bytes(&mut buf);
        let path = format!("/tmp/test-blockstack-burndb-{}", to_hex(&buf));

        let db = BurnDB::connect(&path, first_block_height, &first_block_hash, true).unwrap();
        let chain = Burnchain::new(&path.to_string(), &"bitcoin".to_string(), &"regtest".to_string()).unwrap();
        Self {
            db,
            chain,
        }
    }
}

pub struct TestnetMiner {
    pub burnchain: Burnchain,
    pub privks: Vec<StacksPrivateKey>,
    pub num_sigs: u16,
    pub hash_mode: AddressHashMode,
    pub microblock_privks: Vec<StacksPrivateKey>,
    pub vrf_keys: Vec<VRFPrivateKey>,
    pub vrf_key_map: HashMap<VRFPublicKey, VRFPrivateKey>,
    pub block_commits: Vec<LeaderBlockCommitOp>,
    pub expected_mining_rewards: u128
}

impl TestnetMiner {

    fn new(burnchain: &Burnchain, num_keys: u16, num_sigs: u16, hash_mode: AddressHashMode) -> Self {
        let mut key_seed = [0u8; 32];

        let mut keys = vec![];
        for i in 0..num_keys {
            let h = Sha256Sum::from_data(&key_seed);
            key_seed.copy_from_slice(h.as_bytes());
            keys.push(StacksPrivateKey::from_slice(h.as_bytes()).unwrap());
        }

        Self {
            burnchain: burnchain.clone(),
            privks: keys,
            num_sigs,
            hash_mode: hash_mode.clone(),
            microblock_privks: vec![],
            vrf_keys: vec![],
            vrf_key_map: HashMap::new(),
            block_commits: vec![],
            expected_mining_rewards: 0
        }
    }

    pub fn sign_as_origin(&self, tx_signer: &mut StacksTransactionSigner) -> () {
        let num_keys = 
            if self.privks.len() < self.num_sigs as usize {
                self.privks.len() 
            }
            else {
                self.num_sigs as usize
            };

        for i in 0..num_keys {
            tx_signer.sign_origin(&self.privks[i]).unwrap();
        }
    }

    pub fn get_address(&self) -> StacksAddress {
        let pubks = self.privks.iter().map(|ref pk| StacksPublicKey::from_private(pk)).collect();
        StacksAddress::from_public_keys(
            self.hash_mode.to_version_testnet(), 
            &self.hash_mode, 
            self.num_sigs as usize, 
            &pubks).unwrap()
    }

    pub fn make_proof(&self, vrf_pubkey: &VRFPublicKey, last_sortition_hash: &SortitionHash) -> Option<VRFProof> {
        match self.vrf_key_map.get(vrf_pubkey) {
            Some(ref prover_key) => {
                let proof = VRF::prove(prover_key, &last_sortition_hash.as_bytes().to_vec());
                let valid = match VRF::verify(vrf_pubkey, &proof, &last_sortition_hash.as_bytes().to_vec()) {
                    Ok(v) => {
                        v
                    },
                    Err(e) => {
                        false
                    }
                };
                assert!(valid);
                Some(proof)
            },
            None => {
                None
            }
        }
    }

    pub fn first_microblock_secret_key(&mut self) -> StacksPrivateKey {
        let sk = {
            // first key is simply the 32-byte hash of the secret state
            let mut buf : Vec<u8> = vec![];
            for i in 0..self.privks.len() {
                buf.extend_from_slice(&self.privks[i].to_bytes()[..]);
            }
            buf.extend_from_slice(&[(self.num_sigs >> 8) as u8, (self.num_sigs & 0xff) as u8, self.hash_mode as u8]);
            let h = Sha256Sum::from_data(&buf[..]);
            StacksPrivateKey::from_slice(h.as_bytes()).unwrap()
        };

        self.microblock_privks.push(sk.clone());
        sk
    }

    pub fn next_microblock_secret_key(&mut self) -> StacksPrivateKey {
        let sk = {
            // next key is just the hash of the last
            let h = Sha256Sum::from_data(self.vrf_keys[self.vrf_keys.len()-1].as_bytes());
            StacksPrivateKey::from_slice(h.as_bytes()).unwrap()
        };

        self.microblock_privks.push(sk.clone());
        sk
    }

    pub fn first_VRF_keypair(&mut self) -> (VRFPrivateKey, VRFPublicKey) {
        let (sk, pk) = {
            // first key is simply the 32-byte hash of the secret state
            let mut buf : Vec<u8> = vec![];
            for i in 0..self.privks.len() {
                buf.extend_from_slice(&self.privks[i].to_bytes()[..]);
            }
            buf.extend_from_slice(&[(self.num_sigs >> 8) as u8, (self.num_sigs & 0xff) as u8, self.hash_mode as u8]);
            let h = Sha256Sum::from_data(&buf[..]);
            let sk = VRFPrivateKey::from_bytes(h.as_bytes()).unwrap();
            (sk.clone(), VRFPublicKey::from_private(&sk))
        };

        self.vrf_keys.push(sk.clone());
        self.vrf_key_map.insert(VRFPublicKey::from_private(&sk), sk.clone());
        (sk, pk)
    }

    pub fn next_VRF_keypair(&mut self) -> (VRFPrivateKey, VRFPublicKey) {
        let (sk, pk) = {
            // next key is just the hash of the last
            let h = Sha256Sum::from_data(self.vrf_keys[self.vrf_keys.len()-1].as_bytes());
            let sk = VRFPrivateKey::from_bytes(h.as_bytes()).unwrap();
            (sk.clone(), VRFPublicKey::from_private(&sk))
        };

        self.vrf_keys.push(sk.clone());
        self.vrf_key_map.insert(VRFPublicKey::from_private(&sk), sk.clone());
        (sk, pk)
    }
}
