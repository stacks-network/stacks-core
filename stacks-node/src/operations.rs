use stacks::burnchains::PrivateKey;
use stacks_common::util::hash::hex_bytes;
use stacks_common::util::secp256k1::{MessageSignature, Secp256k1PrivateKey, Secp256k1PublicKey};

/// A signer used for burnchain operations, which manages a private key and provides
/// functionality to derive public keys, sign messages, and export keys in different formats.
///
/// The signer can be "disposed" to prevent further use of the private key (e.g., for security
/// or lifecycle management).
pub struct BurnchainOpSigner {
    /// The Secp256k1 private key used for signing operations.
    secret_key: Secp256k1PrivateKey,
    /// Indicates whether the signer has been disposed and can no longer be used for signing.
    is_disposed: bool,
}

impl BurnchainOpSigner {
    /// Creates a new `BurnchainOpSigner` from the given private key.
    ///
    /// # Arguments
    ///
    /// * `secret_key` - A Secp256k1 private key used for signing.
    ///
    /// # Returns
    ///
    /// A new instance of `BurnchainOpSigner`.
    pub fn new(secret_key: Secp256k1PrivateKey) -> Self {
        BurnchainOpSigner {
            secret_key,
            is_disposed: false,
        }
    }

    /// Returns the private key encoded as a Wallet Import Format (WIF) string.
    ///
    /// This format is commonly used for exporting private keys in Bitcoin-related systems.
    ///
    /// # Returns
    ///
    /// A WIF-encoded string representation of the private key.
    pub fn get_secret_key_as_wif(&self) -> String {
        let hex_encoded = self.secret_key.to_hex();
        let mut as_bytes = hex_bytes(&hex_encoded).unwrap();
        as_bytes.insert(0, 0x80);
        stacks_common::address::b58::check_encode_slice(&as_bytes)
    }

    /// Returns the private key encoded as a hexadecimal string.
    ///
    /// # Returns
    ///
    /// A hex-encoded string representation of the private key.
    pub fn get_secret_key_as_hex(&self) -> String {
        self.secret_key.to_hex()
    }

    /// Derives and returns the public key associated with the private key.
    ///
    /// # Returns
    ///
    /// A `Secp256k1PublicKey` corresponding to the private key.
    pub fn get_public_key(&mut self) -> Secp256k1PublicKey {
        Secp256k1PublicKey::from_private(&self.secret_key)
    }

    /// Signs the given message hash using the private key.
    ///
    /// If the signer has been disposed, no signature will be produced.
    ///
    /// # Arguments
    ///
    /// * `hash` - A byte slice representing the hash of the message to sign.
    ///            This must be exactly **32 bytes** long, as required by the Secp256k1 signing algorithm.
    /// # Returns
    ///
    /// `Some(MessageSignature)` if signing was successful, or `None` if the signer
    /// is disposed or signing failed.
    pub fn sign_message(&mut self, hash: &[u8]) -> Option<MessageSignature> {
        if self.is_disposed {
            debug!("Signer is disposed");
            return None;
        }

        let signature = match self.secret_key.sign(hash) {
            Ok(r) => r,
            Err(e) => {
                debug!("Secret key error: {e:?}");
                return None;
            }
        };

        Some(signature)
    }

    /// Marks the signer as disposed, preventing any further signing operations.
    ///
    /// Once disposed, the private key can no longer be used to sign messages.
    pub fn dispose(&mut self) {
        self.is_disposed = true;
    }
}

/// Test-only utilities for `BurnchainOpSigner`
#[cfg(any(test, feature = "testing"))]
impl BurnchainOpSigner {
    /// Returns `true` if the signer has been disposed.
    ///
    /// This is useful in tests to assert that disposal behavior is working as expected.
    pub fn is_disposed(&self) -> bool {
        self.is_disposed
    }

    /// Returns a new `BurnchainOpSigner` instance using the same secret key,
    /// but with `is_disposed` set to `false` and `is_one_off` set to `false`.
    ///
    /// This is useful in testing scenarios where you need a fresh, undisposed copy
    /// of a signer without recreating the private key.
    pub fn undisposed(&self) -> Self {
        Self::new(self.secret_key.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_secret_key_as_wif() {
        let priv_key_hex = "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d";
        let expected_wif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";

        let secret = Secp256k1PrivateKey::from_hex(priv_key_hex).unwrap();
        let op_signer = BurnchainOpSigner::new(secret);
        assert_eq!(expected_wif, &op_signer.get_secret_key_as_wif());
    }

    #[test]
    fn test_get_secret_key_as_hex() {
        let priv_key_hex = "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d";
        let expected_hex = priv_key_hex;

        let secp_k = Secp256k1PrivateKey::from_hex(priv_key_hex).unwrap();
        let op_signer = BurnchainOpSigner::new(secp_k);
        assert_eq!(expected_hex, op_signer.get_secret_key_as_hex());
    }

    #[test]
    fn test_get_public_key() {
        let priv_key_hex = "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d";
        let expected_hex = "04d0de0aaeaefad02b8bdc8a01a1b8b11c696bd3d66a2c5f10780d95b7df42645cd85228a6fb29940e858e7e55842ae2bd115d1ed7cc0e82d934e929c97648cb0a";

        let secp_k = Secp256k1PrivateKey::from_hex(priv_key_hex).unwrap();
        let mut op_signer = BurnchainOpSigner::new(secp_k);
        assert_eq!(expected_hex, op_signer.get_public_key().to_hex());
    }

    #[test]
    fn test_sign_message_ok() {
        let priv_key_hex = "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d";
        let message = &[0u8; 32];
        let expected_msg_sig = "00b911e6cf9c49b738c4a0f5e33c003fa5b74a00ddc68e574e9f1c3504f6ba7e84275fd62773978cc8165f345cc3f691cf68be274213d552e79af39998df61273f";

        let secp_k = Secp256k1PrivateKey::from_hex(priv_key_hex).unwrap();
        let mut op_signer = BurnchainOpSigner::new(secp_k);

        let msg_sig = op_signer
            .sign_message(message)
            .expect("Message should be signed!");

        assert_eq!(expected_msg_sig, msg_sig.to_hex());
    }

    #[test]
    fn test_sign_message_fails_due_to_hash_length() {
        let priv_key_hex = "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d";
        let message = &[0u8; 20];

        let secp_k = Secp256k1PrivateKey::from_hex(priv_key_hex).unwrap();
        let mut op_signer = BurnchainOpSigner::new(secp_k);

        let result = op_signer.sign_message(message);
        assert!(result.is_none());
    }

    #[test]
    fn test_sign_message_fails_due_to_disposal() {
        let priv_key_hex = "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d";
        let message = &[0u8; 32];

        let secp_k = Secp256k1PrivateKey::from_hex(priv_key_hex).unwrap();
        let mut op_signer = BurnchainOpSigner::new(secp_k);

        op_signer.dispose();

        let result = op_signer.sign_message(message);
        assert!(result.is_none());
    }
}
