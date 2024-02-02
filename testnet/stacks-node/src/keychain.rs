use stacks::burnchains::BurnchainSigner;
use stacks::chainstate::stacks::{
    StacksPrivateKey, StacksPublicKey, StacksTransactionSigner, TransactionAuth,
};
use stacks_common::address::{
    AddressHashMode, C32_ADDRESS_VERSION_MAINNET_SINGLESIG, C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
};
use stacks_common::types::chainstate::StacksAddress;
use stacks_common::util::hash::{Hash160, Sha256Sum};
use stacks_common::util::secp256k1::{Secp256k1PrivateKey, Secp256k1PublicKey};
use stacks_common::util::vrf::{VRFPrivateKey, VRFProof, VRFPublicKey, VRF};

use super::operations::BurnchainOpSigner;

/// A wrapper around a node's seed, coupled with operations for using it
#[derive(Clone)]
pub struct Keychain {
    secret_state: Vec<u8>,
    nakamoto_mining_key: Secp256k1PrivateKey,
}

impl Keychain {
    /// Create a secret key from some state.
    /// Returns the bytes that can be fed into StacksPrivateKey
    fn make_secret_key_bytes(seed: &[u8]) -> Vec<u8> {
        let mut re_hashed_seed = seed.to_vec();
        loop {
            match StacksPrivateKey::from_slice(&re_hashed_seed[..]) {
                Ok(_sk) => {
                    break;
                }
                Err(_) => {
                    re_hashed_seed = Sha256Sum::from_data(&re_hashed_seed[..])
                        .as_bytes()
                        .to_vec()
                }
            }
        }
        re_hashed_seed
    }

    /// Create a secret key from our secret state
    fn get_secret_key(&self) -> StacksPrivateKey {
        let sk_bytes = Keychain::make_secret_key_bytes(&self.secret_state);
        StacksPrivateKey::from_slice(&sk_bytes[..]).expect("FATAL: Keychain::make_secret_key_bytes() returned bytes that could not be parsed into a secp256k1 secret key!")
    }

    /// Get the public key hash of the nakamoto mining key (i.e., Hash160(pubkey))
    pub fn get_nakamoto_pkh(&self) -> Hash160 {
        let pk = Secp256k1PublicKey::from_private(&self.nakamoto_mining_key);
        Hash160::from_node_public_key(&pk)
    }

    /// Get the secret key of the nakamoto mining key
    pub fn get_nakamoto_sk(&self) -> &Secp256k1PrivateKey {
        &self.nakamoto_mining_key
    }

    /// Set the secret key of the nakamoto mining key
    pub fn set_nakamoto_sk(&mut self, mining_key: Secp256k1PrivateKey) {
        self.nakamoto_mining_key = mining_key;
    }

    /// Create a default keychain from the seed, with a default nakamoto mining key derived
    ///  from the same seed (
    pub fn default(seed: Vec<u8>) -> Keychain {
        let secret_state = Self::make_secret_key_bytes(&seed);
        // re-hash secret_state to use as a default seed for the nakamoto mining key
        let nakamoto_mining_key =
            Secp256k1PrivateKey::from_seed(Sha256Sum::from_data(&secret_state).as_bytes());
        Keychain {
            secret_state,
            nakamoto_mining_key,
        }
    }

    /// Generate a VRF keypair for this burn block height.
    /// The keypair is unique to this burn block height.
    pub fn make_vrf_keypair(&self, block_height: u64) -> (VRFPublicKey, VRFPrivateKey) {
        let mut seed = {
            let mut secret_state = self.secret_state.clone();
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
        (pk, sk)
    }

    /// Generate a Stacks keypair for this burn block height.
    /// The keypair is unique to this burn block height.
    pub fn make_stacks_keypair(
        &self,
        block_height: u64,
        salt: &[u8],
    ) -> (StacksPublicKey, StacksPrivateKey) {
        let seed = {
            let mut secret_state = self.secret_state.clone();
            secret_state.extend_from_slice(&block_height.to_be_bytes());
            secret_state.extend_from_slice(salt);
            Sha256Sum::from_data(&secret_state)
        };

        let sk_bytes = Keychain::make_secret_key_bytes(&seed.0);
        let sk = StacksPrivateKey::from_slice(&sk_bytes[..]).expect("FATAL: Keychain::make_secret_key_bytes() returned bytes that could not be parsed into a secp256k1 secret key!");
        let pk = StacksPublicKey::from_private(&sk);

        (pk, sk)
    }

    /// Generate a VRF proof over a given byte message.
    /// `block_height` must be the _same_ block height called to make_vrf_keypair()
    pub fn generate_proof(&self, block_height: u64, bytes: &[u8; 32]) -> VRFProof {
        let (pk, sk) = self.make_vrf_keypair(block_height);
        let proof = VRF::prove(&sk, bytes.as_ref());

        // Ensure that the proof is valid by verifying
        let is_valid = match VRF::verify(&pk, &proof, bytes.as_ref()) {
            Ok(v) => v,
            Err(_) => false,
        };
        assert!(is_valid);
        proof
    }

    /// Generate a microblock signing key for this burnchain block height.
    /// `salt` can be any byte string; in practice, it's the parent Stacks block's block ID hash.
    pub fn make_microblock_secret_key(
        &mut self,
        burn_block_height: u64,
        salt: &[u8],
    ) -> StacksPrivateKey {
        let (_, mut sk) = self.make_stacks_keypair(burn_block_height, salt);
        sk.set_compress_public(true);

        debug!("Microblock keypair rotated";
               "burn_block_height" => %burn_block_height,
               "pubkey_hash" => %Hash160::from_node_public_key(&StacksPublicKey::from_private(&sk)).to_string()
        );
        sk
    }

    pub fn get_pub_key(&self) -> Secp256k1PublicKey {
        let sk = self.get_secret_key();
        StacksPublicKey::from_private(&sk)
    }

    /// Get the Stacks address for the inner secret state
    pub fn get_address(&self, is_mainnet: bool) -> StacksAddress {
        let sk = self.get_secret_key();
        let pk = StacksPublicKey::from_private(&sk);

        let version = if is_mainnet {
            C32_ADDRESS_VERSION_MAINNET_SINGLESIG
        } else {
            C32_ADDRESS_VERSION_TESTNET_SINGLESIG
        };
        StacksAddress::from_public_keys(version, &AddressHashMode::SerializeP2PKH, 1, &vec![pk])
            .expect("FATAL: could not produce address from secret key")
    }

    /// Get a BurnchainSigner representation of this keychain
    pub fn get_burnchain_signer(&self) -> BurnchainSigner {
        BurnchainSigner(format!("{}", &self.get_address(true)))
    }

    /// Convenience wrapper around make_stacks_keypair
    pub fn get_microblock_key(&self, block_height: u64) -> StacksPrivateKey {
        self.make_stacks_keypair(block_height, &[]).1
    }

    /// Sign a transaction as if we were the origin
    pub fn sign_as_origin(&self, tx_signer: &mut StacksTransactionSigner) -> () {
        let sk = self.get_secret_key();
        tx_signer
            .sign_origin(&sk)
            .expect("FATAL: failed to sign transaction origin");
    }

    /// Create a transaction authorization struct from this keychain's secret state
    pub fn get_transaction_auth(&self) -> Option<TransactionAuth> {
        TransactionAuth::from_p2pkh(&self.get_secret_key())
    }

    /// Get the origin address that this keychain represents
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

    /// Create a BurnchainOpSigner representation of this keychain
    /// (this is going to be removed in 2.1)
    pub fn generate_op_signer(&self) -> BurnchainOpSigner {
        BurnchainOpSigner::new(self.get_secret_key(), false)
    }
}

#[cfg(test)]
#[allow(dead_code)]
mod tests {
    use std::collections::HashMap;

    use stacks::burnchains::PrivateKey;
    use stacks::chainstate::stacks::{
        StacksPrivateKey, StacksPublicKey, StacksTransaction, StacksTransactionSigner,
        TokenTransferMemo, TransactionAuth, TransactionPayload, TransactionPostConditionMode,
        TransactionVersion,
    };
    use stacks_common::address::AddressHashMode;
    use stacks_common::types::chainstate::StacksAddress;
    use stacks_common::util::hash::{Hash160, Sha256Sum};
    use stacks_common::util::vrf::{VRFPrivateKey, VRFProof, VRFPublicKey, VRF};

    use super::Keychain;
    use crate::operations::BurnchainOpSigner;
    use crate::stacks_common::types::Address;

    /// Legacy implementation; kept around for testing
    #[derive(Clone)]
    pub struct KeychainOld {
        secret_keys: Vec<StacksPrivateKey>,
        threshold: u16,
        hash_mode: AddressHashMode,
        pub hashed_secret_state: Sha256Sum,
        microblocks_secret_keys: Vec<StacksPrivateKey>,
        vrf_secret_keys: Vec<VRFPrivateKey>,
        vrf_map: HashMap<VRFPublicKey, VRFPrivateKey>,
    }

    impl KeychainOld {
        pub fn new(
            secret_keys: Vec<StacksPrivateKey>,
            threshold: u16,
            hash_mode: AddressHashMode,
        ) -> KeychainOld {
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
                vrf_secret_keys: vec![],
                vrf_map: HashMap::new(),
            }
        }

        pub fn default(seed: Vec<u8>) -> KeychainOld {
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

            KeychainOld::new(vec![secret_key], threshold, hash_mode)
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
            let proof = VRF::prove(&vrf_sk, bytes.as_ref());
            // Ensure that the proof is valid by verifying
            let is_valid = match VRF::verify(vrf_pk, &proof, bytes.as_ref()) {
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

        pub fn get_transaction_auth(&self) -> Option<TransactionAuth> {
            match self.hash_mode {
                AddressHashMode::SerializeP2PKH => {
                    TransactionAuth::from_p2pkh(&self.secret_keys[0])
                }
                AddressHashMode::SerializeP2SH => {
                    TransactionAuth::from_p2sh(&self.secret_keys, self.threshold)
                }
                AddressHashMode::SerializeP2WPKH => {
                    TransactionAuth::from_p2wpkh(&self.secret_keys[0])
                }
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

    #[test]
    fn test_origin_address() {
        let seeds = [
            [0u8; 32],
            [
                0xc2, 0x7e, 0x1d, 0x7e, 0x9a, 0x0d, 0x47, 0xfa, 0xa5, 0x10, 0xbe, 0x50, 0x9b, 0xce,
                0xd4, 0x95, 0x99, 0x64, 0x40, 0x34, 0xbd, 0x5a, 0xf2, 0x2b, 0x51, 0x9c, 0x21, 0x19,
                0xbd, 0xaa, 0x5d, 0x62,
            ],
        ];

        for seed in seeds {
            let k1 = Keychain::default(seed.to_vec());
            let k2 = KeychainOld::default(seed.to_vec());

            assert_eq!(k1.origin_address(true), k2.origin_address(true));
            assert_eq!(k1.origin_address(false), k2.origin_address(false));
        }
    }

    #[test]
    fn test_get_address() {
        let seeds = [
            [0u8; 32],
            [
                0xc2, 0x7e, 0x1d, 0x7e, 0x9a, 0x0d, 0x47, 0xfa, 0xa5, 0x10, 0xbe, 0x50, 0x9b, 0xce,
                0xd4, 0x95, 0x99, 0x64, 0x40, 0x34, 0xbd, 0x5a, 0xf2, 0x2b, 0x51, 0x9c, 0x21, 0x19,
                0xbd, 0xaa, 0x5d, 0x62,
            ],
        ];

        for seed in seeds {
            let k1 = Keychain::default(seed.to_vec());
            let k2 = KeychainOld::default(seed.to_vec());

            assert_eq!(k1.get_address(true), k2.get_address(true));
            assert_eq!(k1.get_address(false), k2.get_address(false));
        }
    }

    #[test]
    fn test_get_transaction_auth() {
        let seeds = [
            [0u8; 32],
            [
                0xc2, 0x7e, 0x1d, 0x7e, 0x9a, 0x0d, 0x47, 0xfa, 0xa5, 0x10, 0xbe, 0x50, 0x9b, 0xce,
                0xd4, 0x95, 0x99, 0x64, 0x40, 0x34, 0xbd, 0x5a, 0xf2, 0x2b, 0x51, 0x9c, 0x21, 0x19,
                0xbd, 0xaa, 0x5d, 0x62,
            ],
        ];

        for seed in seeds {
            let k1 = Keychain::default(seed.to_vec());
            let k2 = KeychainOld::default(seed.to_vec());

            assert_eq!(k1.get_transaction_auth(), k2.get_transaction_auth());
        }
    }

    #[test]
    fn test_sign_as_origin() {
        let seeds = [
            [0u8; 32],
            [
                0xc2, 0x7e, 0x1d, 0x7e, 0x9a, 0x0d, 0x47, 0xfa, 0xa5, 0x10, 0xbe, 0x50, 0x9b, 0xce,
                0xd4, 0x95, 0x99, 0x64, 0x40, 0x34, 0xbd, 0x5a, 0xf2, 0x2b, 0x51, 0x9c, 0x21, 0x19,
                0xbd, 0xaa, 0x5d, 0x62,
            ],
        ];

        for seed in seeds {
            let k1 = Keychain::default(seed.to_vec());
            let k2 = KeychainOld::default(seed.to_vec());

            let recv_addr =
                StacksAddress::from_string("SP1Z4P459B2M5XC2PMM2CSCNZ6824DN5GZG2XYWFH").unwrap();

            let mut tx_stx_transfer_1 = StacksTransaction::new(
                TransactionVersion::Testnet,
                k1.get_transaction_auth().unwrap(),
                TransactionPayload::TokenTransfer(
                    recv_addr.clone().into(),
                    123,
                    TokenTransferMemo([0u8; 34]),
                ),
            );
            let mut tx_stx_transfer_2 = StacksTransaction::new(
                TransactionVersion::Testnet,
                k2.get_transaction_auth().unwrap(),
                TransactionPayload::TokenTransfer(
                    recv_addr.clone().into(),
                    123,
                    TokenTransferMemo([0u8; 34]),
                ),
            );

            tx_stx_transfer_1.chain_id = 0x80000000;
            tx_stx_transfer_1.post_condition_mode = TransactionPostConditionMode::Allow;
            tx_stx_transfer_1.set_tx_fee(0);

            tx_stx_transfer_2.chain_id = 0x80000000;
            tx_stx_transfer_2.post_condition_mode = TransactionPostConditionMode::Allow;
            tx_stx_transfer_2.set_tx_fee(0);

            let mut signer_1 = StacksTransactionSigner::new(&tx_stx_transfer_1);
            k1.sign_as_origin(&mut signer_1);
            let tx_1 = signer_1.get_tx().unwrap();

            let mut signer_2 = StacksTransactionSigner::new(&tx_stx_transfer_2);
            k2.sign_as_origin(&mut signer_2);
            let tx_2 = signer_2.get_tx().unwrap();

            assert_eq!(tx_1, tx_2);
        }
    }
}
