use std::collections::HashMap;

use stacks::address::AddressHashMode;
use stacks::burnchains::{BurnchainSigner, PrivateKey};
use stacks::chainstate::stacks::{
    StacksPrivateKey, StacksPublicKey, StacksTransactionSigner, TransactionAuth,
};
use stacks::types::chainstate::StacksAddress;
use stacks::util::hash::{Hash160, Sha256Sum};
use stacks::util::vrf::{VRFPrivateKey, VRFProof, VRFPublicKey, VRF};

use super::operations::BurnchainOpSigner;

#[derive(Clone)]
pub struct Keychain {
    secret_keys: Vec<StacksPrivateKey>,
    threshold: u16,
    hash_mode: AddressHashMode,
    pub hashed_secret_state: Sha256Sum,
    microblocks_secret_keys: Vec<StacksPrivateKey>,
    vrf_secret_keys: Vec<VRFPrivateKey>,
    vrf_map: HashMap<VRFPublicKey, VRFPrivateKey>,
    _rotations: u64,
}

impl Keychain {
    pub fn new(
        secret_keys: Vec<StacksPrivateKey>,
        threshold: u16,
        hash_mode: AddressHashMode,
    ) -> Keychain {
        // Compute hashed secret state
        let hashed_secret_state = {
            let mut buf: Vec<u8> = secret_keys.iter().flat_map(|sk| sk.to_bytes()).collect();
            buf.extend_from_slice(&[
                (threshold >> 8) as u8,
                (threshold & 0xff) as u8,
                hash_mode as u8,
            ]);
            Sha256Sum::from_data(&buf[..])
        };

        Self {
            hash_mode,
            hashed_secret_state,
            microblocks_secret_keys: vec![],
            secret_keys,
            threshold,
            _rotations: 0,
            vrf_secret_keys: vec![],
            vrf_map: HashMap::new(),
        }
    }

    pub fn default(seed: Vec<u8>) -> Keychain {
        let mut re_hashed_seed = seed;
        let secret_key = loop {
            match StacksPrivateKey::from_slice(&re_hashed_seed[..]) {
                Ok(sk) => break sk,
                Err(_) => {
                    re_hashed_seed = Sha256Sum::from_data(&re_hashed_seed[..])
                        .as_bytes()
                        .to_vec()
                }
            }
        };

        let threshold = 1;
        let hash_mode = AddressHashMode::SerializeP2PKH;

        Keychain::new(vec![secret_key], threshold, hash_mode)
    }

    pub fn rotate_vrf_keypair(&mut self, block_height: u64) -> VRFPublicKey {
        let mut seed = {
            let mut secret_state = self.hashed_secret_state.to_bytes().to_vec();
            secret_state.extend_from_slice(&block_height.to_be_bytes());
            Sha256Sum::from_data(&secret_state)
        };

        // Not every 256-bit number is a valid Ed25519 secret key.
        // As such, we continuously generate seeds through re-hashing until one works.
        let sk = loop {
            match VRFPrivateKey::from_bytes(seed.as_bytes()) {
                Some(sk) => break sk,
                None => seed = Sha256Sum::from_data(seed.as_bytes()),
            }
        };
        let pk = VRFPublicKey::from_private(&sk);

        self.vrf_secret_keys.push(sk.clone());
        self.vrf_map.insert(pk.clone(), sk);
        pk
    }

    pub fn rotate_microblock_keypair(&mut self, burn_block_height: u64) -> StacksPrivateKey {
        let mut secret_state = match self.microblocks_secret_keys.last() {
            // First key is the hash of the secret state
            None => self.hashed_secret_state.to_bytes().to_vec(),
            // Next key is the hash of the last
            Some(last_sk) => last_sk.to_bytes().to_vec(),
        };

        secret_state.extend_from_slice(&burn_block_height.to_be_bytes());

        let mut seed = Sha256Sum::from_data(&secret_state);

        // Not every 256-bit number is a valid secp256k1 secret key.
        // As such, we continuously generate seeds through re-hashing until one works.
        let mut sk = loop {
            match StacksPrivateKey::from_slice(&seed.to_bytes()[..]) {
                Ok(sk) => break sk,
                Err(_) => seed = Sha256Sum::from_data(seed.as_bytes()),
            }
        };
        sk.set_compress_public(true);
        self.microblocks_secret_keys.push(sk.clone());

        debug!("Microblock keypair rotated";
               "burn_block_height" => %burn_block_height,
               "pubkey_hash" => %Hash160::from_node_public_key(&StacksPublicKey::from_private(&sk)).to_string(),);

        sk
    }

    pub fn get_microblock_key(&self) -> Option<StacksPrivateKey> {
        self.microblocks_secret_keys.last().cloned()
    }

    pub fn sign_as_origin(&self, tx_signer: &mut StacksTransactionSigner) -> () {
        let num_keys = if self.secret_keys.len() < self.threshold as usize {
            self.secret_keys.len()
        } else {
            self.threshold as usize
        };

        for i in 0..num_keys {
            tx_signer.sign_origin(&self.secret_keys[i]).unwrap();
        }
    }

    /// Given a VRF public key, generates a VRF Proof
    pub fn generate_proof(&self, vrf_pk: &VRFPublicKey, bytes: &[u8; 32]) -> Option<VRFProof> {
        // Retrieve the corresponding VRF secret key
        let vrf_sk = match self.vrf_map.get(vrf_pk) {
            Some(vrf_pk) => vrf_pk,
            None => {
                warn!("No VRF secret key on file for {:?}", vrf_pk);
                return None;
            }
        };

        // Generate the proof
        let proof = VRF::prove(&vrf_sk, &bytes.to_vec());
        // Ensure that the proof is valid by verifying
        let is_valid = match VRF::verify(vrf_pk, &proof, &bytes.to_vec()) {
            Ok(v) => v,
            Err(_) => false,
        };
        assert!(is_valid);
        Some(proof)
    }

    /// Given the keychain's secret keys, computes and returns the corresponding Stack address.
    pub fn get_address(&self, is_mainnet: bool) -> StacksAddress {
        let public_keys = self
            .secret_keys
            .iter()
            .map(|ref pk| StacksPublicKey::from_private(pk))
            .collect();
        let version = if is_mainnet {
            self.hash_mode.to_version_mainnet()
        } else {
            self.hash_mode.to_version_testnet()
        };
        StacksAddress::from_public_keys(
            version,
            &self.hash_mode,
            self.threshold as usize,
            &public_keys,
        )
        .unwrap()
    }

    pub fn address_from_burnchain_signer(
        signer: &BurnchainSigner,
        is_mainnet: bool,
    ) -> StacksAddress {
        let version = if is_mainnet {
            signer.hash_mode.to_version_mainnet()
        } else {
            signer.hash_mode.to_version_testnet()
        };
        StacksAddress::from_public_keys(
            version,
            &signer.hash_mode,
            signer.num_sigs,
            &signer.public_keys,
        )
        .unwrap()
    }

    pub fn get_burnchain_signer(&self) -> BurnchainSigner {
        let public_keys = self
            .secret_keys
            .iter()
            .map(|ref pk| StacksPublicKey::from_private(pk))
            .collect();
        BurnchainSigner {
            hash_mode: self.hash_mode,
            num_sigs: self.threshold as usize,
            public_keys,
        }
    }

    pub fn get_transaction_auth(&self) -> Option<TransactionAuth> {
        match self.hash_mode {
            AddressHashMode::SerializeP2PKH => TransactionAuth::from_p2pkh(&self.secret_keys[0]),
            AddressHashMode::SerializeP2SH => {
                TransactionAuth::from_p2sh(&self.secret_keys, self.threshold)
            }
            AddressHashMode::SerializeP2WPKH => TransactionAuth::from_p2wpkh(&self.secret_keys[0]),
            AddressHashMode::SerializeP2WSH => {
                TransactionAuth::from_p2wsh(&self.secret_keys, self.threshold)
            }
        }
    }

    pub fn origin_address(&self, is_mainnet: bool) -> Option<StacksAddress> {
        match self.get_transaction_auth() {
            Some(auth) => {
                let address = if is_mainnet {
                    auth.origin().address_mainnet()
                } else {
                    auth.origin().address_testnet()
                };
                Some(address)
            }
            None => None,
        }
    }

    pub fn generate_op_signer(&self) -> BurnchainOpSigner {
        BurnchainOpSigner::new(self.secret_keys[0], false)
    }
}
