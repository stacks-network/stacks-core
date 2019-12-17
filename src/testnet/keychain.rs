use std::collections::HashMap;

use chainstate::stacks::{StacksTransactionSigner, TransactionAuth, StacksPublicKey, StacksPrivateKey, StacksAddress};
use address::AddressHashMode;
use burnchains::{BurnchainSigner, BurnchainHeaderHash, PrivateKey};
use util::vrf::{VRF, VRFProof, VRFPublicKey, VRFPrivateKey};
use util::hash::{Sha256Sum};

pub struct Keychain {
    secret_keys: Vec<StacksPrivateKey>, 
    threshold: u16,
    hash_mode: AddressHashMode,
    pub hashed_secret_state: Sha256Sum,
    microblocks_secret_keys: Vec<StacksPrivateKey>,
    vrf_secret_keys: Vec<VRFPrivateKey>,
    vrf_map: HashMap<VRFPublicKey, VRFPrivateKey>,
}

impl Keychain {

    pub fn new(secret_keys: Vec<StacksPrivateKey>, threshold: u16, hash_mode: AddressHashMode) -> Keychain {
        // Compute hashed secret state
        let hashed_secret_state = {
            let mut buf : Vec<u8> = secret_keys.iter()
                .flat_map(|sk| sk.to_bytes())
                .collect();
            buf.extend_from_slice(&[(threshold >> 8) as u8, (threshold & 0xff) as u8, hash_mode as u8]);
            Sha256Sum::from_data(&buf[..])
        };

        Self {
            hash_mode,
            hashed_secret_state,
            microblocks_secret_keys: vec![],
            secret_keys,
            threshold,
            vrf_secret_keys: vec![],
            vrf_map: HashMap::new(),
        }
    }

    pub fn default() -> Keychain {
        let seed_hashed = Sha256Sum::from_data(&[0u8; 32]);
        let secret_key = StacksPrivateKey::from_slice(seed_hashed.as_bytes()).unwrap();
        let threshold = 1;
        let hash_mode = AddressHashMode::SerializeP2PKH;

        Keychain::new(vec![secret_key], 1, hash_mode)
    }

    pub fn rotate_vrf_keypair(&mut self) -> VRFPublicKey {
        let seed = match self.vrf_secret_keys.last() {
            // First key is the hash of the secret state
            None => self.hashed_secret_state,
            // Next key is the hash of the last
            Some(last_vrf) => Sha256Sum::from_data(last_vrf.as_bytes()),  
        };
        let sk = VRFPrivateKey::from_bytes(seed.as_bytes()).unwrap();
        let pk = VRFPublicKey::from_private(&sk);

        self.vrf_secret_keys.push(sk.clone());
        self.vrf_map.insert(pk.clone(), sk.clone());

        pk
    }

    pub fn rotate_microblock_keypair(&mut self) -> StacksPrivateKey {
        let seed = match self.microblocks_secret_keys.last() {
            // First key is the hash of the secret state
            None => self.hashed_secret_state,
            // Next key is the hash of the last
            Some(last_sk) => Sha256Sum::from_data(&last_sk.to_bytes()[..]),  
        };
        let sk = StacksPrivateKey::from_slice(&seed.to_bytes()[..]).unwrap();

        self.microblocks_secret_keys.push(sk.clone());

        sk
    }

    pub fn sign_as_origin(&self, tx_signer: &mut StacksTransactionSigner) -> () {
        // todo(ludo): hmmm
        let num_keys = if self.secret_keys.len() < self.threshold as usize {
            self.secret_keys.len() 
        } else {
            self.threshold as usize
        };

        for i in 0..num_keys {
            tx_signer.sign_origin(&self.secret_keys[i]).unwrap();
        }
    }

    pub fn generate_proof(&self, vrf_pk: &VRFPublicKey, bytes: &[u8; 32]) -> Option<VRFProof> {
        let vrf_sk = match self.vrf_map.get(vrf_pk) {
            Some(vrf_pk) => vrf_pk,
            None => return None
        };

        let proof = VRF::prove(&vrf_sk, &bytes.to_vec());
        let is_valid = match VRF::verify(vrf_pk, &proof, &bytes.to_vec()) {
            Ok(v) => v,
            Err(e) => false
        };
        assert!(is_valid);
        Some(proof)
    }

    pub fn get_address(&self) -> StacksAddress {
        let public_keys = self.secret_keys.iter().map(|ref pk| StacksPublicKey::from_private(pk)).collect();
        StacksAddress::from_public_keys(
            self.hash_mode.to_version_testnet(), // todo(ludo): testnet hard-coded
            &self.hash_mode, 
            self.threshold as usize, 
            &public_keys).unwrap()
    }

    pub fn get_transaction_auth(&self) -> Option<TransactionAuth> {
        match self.hash_mode {
            AddressHashMode::SerializeP2PKH => TransactionAuth::from_p2pkh(&self.secret_keys[0]),
            AddressHashMode::SerializeP2SH => TransactionAuth::from_p2sh(&self.secret_keys, self.threshold),
            AddressHashMode::SerializeP2WPKH => TransactionAuth::from_p2wpkh(&self.secret_keys[0]),
            AddressHashMode::SerializeP2WSH => TransactionAuth::from_p2wsh(&self.secret_keys, self.threshold),
        }
    }

    pub fn get_burnchain_signer(&self) -> BurnchainSigner {
        let public_keys = self.secret_keys.iter().map(|ref pk| StacksPublicKey::from_private(pk)).collect();
        BurnchainSigner {
            hash_mode: self.hash_mode,
            num_sigs: self.threshold as usize,
            public_keys
        }
    }

    pub fn origin_address(&self) -> Option<StacksAddress> {
        match self.get_transaction_auth() {
            Some(auth) => Some(auth.origin().address_testnet()), // todo(ludo): testnet hard-coded
            None => None
        }
    }
}
