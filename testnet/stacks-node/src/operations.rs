use stacks::burnchains::PrivateKey;
use stacks_common::util::hash::hex_bytes;
use stacks_common::util::secp256k1::{MessageSignature, Secp256k1PrivateKey, Secp256k1PublicKey};

pub struct BurnchainOpSigner {
    secret_key: Secp256k1PrivateKey,
    is_one_off: bool,
    is_disposed: bool,
    usages: u8,
}

impl BurnchainOpSigner {
    pub fn new(secret_key: Secp256k1PrivateKey, is_one_off: bool) -> BurnchainOpSigner {
        BurnchainOpSigner {
            secret_key,
            usages: 0,
            is_one_off,
            is_disposed: false,
        }
    }

    pub fn get_sk_as_wif(&self) -> String {
        let hex_encoded = self.secret_key.to_hex();
        let mut as_bytes = hex_bytes(&hex_encoded).unwrap();
        as_bytes.insert(0, 0x80);
        stacks_common::address::b58::check_encode_slice(&as_bytes)
    }

    pub fn get_sk_as_hex(&self) -> String {
        self.secret_key.to_hex()
    }

    pub fn get_public_key(&mut self) -> Secp256k1PublicKey {
        let public_key = Secp256k1PublicKey::from_private(&self.secret_key);
        public_key
    }

    pub fn sign_message(&mut self, hash: &[u8]) -> Option<MessageSignature> {
        if self.is_disposed {
            debug!("Signer is disposed");
            return None;
        }

        let signature = match self.secret_key.sign(hash) {
            Ok(r) => r,
            Err(e) => {
                debug!("Secret key error: {:?}", &e);
                return None;
            }
        };
        self.usages += 1;

        if self.is_one_off && self.usages == 1 {
            self.is_disposed = true;
        }

        Some(signature)
    }

    pub fn dispose(&mut self) {
        self.is_disposed = true;
    }
}

#[cfg(test)]
mod test {
    use stacks_common::util::secp256k1::Secp256k1PrivateKey;

    use super::BurnchainOpSigner;

    #[test]
    fn test_wif() {
        let examples = [(
            "0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D",
            "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ",
        )];
        for (secret_key, expected_wif) in examples.iter() {
            let secp_k = Secp256k1PrivateKey::from_hex(secret_key).unwrap();
            let op_signer = BurnchainOpSigner::new(secp_k, false);
            assert_eq!(expected_wif, &op_signer.get_sk_as_wif());
        }
    }
}
