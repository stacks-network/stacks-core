use stacks::burnchains::{PrivateKey};
use stacks::util::secp256k1::{MessageSignature, Secp256k1PublicKey, Secp256k1PrivateKey};

pub struct BurnchainOpSigner {
    secret_key: Secp256k1PrivateKey,
    is_one_off: bool,
    is_disposed: bool,
    usages: u8,
}

impl BurnchainOpSigner {

    pub fn new(secret_key: Secp256k1PrivateKey, is_one_off: bool) -> BurnchainOpSigner {
        BurnchainOpSigner {
            secret_key: secret_key,
            usages: 0,
            is_one_off,
            is_disposed: false,
        }
    }

    pub fn get_public_key(&mut self) -> Secp256k1PublicKey {
        let public_key = Secp256k1PublicKey::from_private(&self.secret_key);
        public_key
    }

    pub fn sign_message(&mut self, hash: &[u8]) -> Option<MessageSignature> {
        if self.is_disposed {
            return None;
        }

        let signature = match self.secret_key.sign(hash) {
            Ok(r) => r,
            _ => return None
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
