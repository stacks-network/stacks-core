use std::collections::VecDeque;

use blockstack_lib::util_lib::db::Error as DBError;
use rand::{CryptoRng, RngCore};
use rand_core::OsRng;
use stacks_common::util::hash::Sha512Trunc256Sum;
use wsts::curve::scalar::Scalar;
use wsts::traits::SignerState;

use crate::client::{ClientError, StackerDB};
use crate::signer::SignerSlotID;
use crate::signerdb::SignerDb;

/// The persisted signer states
pub type StoredSignerStates = VecDeque<SignerState>;

/// Load the encrypted signer state from the given storage
pub(crate) fn load_encrypted_signer_state<S: SignerStateStorage>(
    storage: S,
    id: S::IdType,
    private_key: &Scalar,
) -> Result<StoredSignerStates, PersistenceError> {
    let Some(encrypted_state) = storage.get_encrypted_signer_state(id)? else {
        return Ok(VecDeque::new());
    };
    let serialized_state = decrypt(private_key, &encrypted_state)?;

    Ok(serde_json::from_slice(&serialized_state)?)
}

/// Helper trait to support different types of storage for signer state
pub(crate) trait SignerStateStorage {
    type IdType;

    fn get_encrypted_signer_state(
        self,
        signer_config: Self::IdType,
    ) -> Result<Option<Vec<u8>>, PersistenceError>;
}

impl SignerStateStorage for &mut StackerDB {
    type IdType = SignerSlotID;

    fn get_encrypted_signer_state(
        self,
        id: Self::IdType,
    ) -> Result<Option<Vec<u8>>, PersistenceError> {
        Ok(self.get_encrypted_signer_state(id)?)
    }
}

impl SignerStateStorage for &SignerDb {
    type IdType = u64;
    fn get_encrypted_signer_state(
        self,
        id: Self::IdType,
    ) -> Result<Option<Vec<u8>>, PersistenceError> {
        Ok(self.get_encrypted_signer_state(id)?)
    }
}

pub(crate) fn encrypt(
    private_key: &Scalar,
    msg: &[u8],
    rng: &mut impl rand_core::CryptoRngCore,
) -> Result<Vec<u8>, EncryptionError> {
    wsts::util::encrypt(derive_encryption_key(private_key).as_bytes(), msg, rng)
        .map_err(|_| EncryptionError::Encrypt)
}

pub(crate) fn decrypt(
    private_key: &Scalar,
    encrypted_msg: &[u8],
) -> Result<Vec<u8>, EncryptionError> {
    wsts::util::decrypt(derive_encryption_key(private_key).as_bytes(), encrypted_msg)
        .map_err(|_| EncryptionError::Decrypt)
}

fn derive_encryption_key(private_key: &Scalar) -> Sha512Trunc256Sum {
    let mut prefixed_key = "SIGNER_STATE_ENCRYPTION_KEY/".as_bytes().to_vec();
    prefixed_key.extend_from_slice(&private_key.to_bytes());

    Sha512Trunc256Sum::from_data(&prefixed_key)
}

/// This is the RNG implementation that the signer uses when randomness is required for cryptographic operations. Currently, this is OsRng, which is also the RNG used by WSTS when initializing signer state.
pub(crate) const fn crypto_rng() -> impl CryptoRng + RngCore {
    OsRng
}

/// Error stemming from a persistence operation
#[derive(Debug, thiserror::Error)]
pub enum PersistenceError {
    /// Encryption error
    #[error("{0}")]
    Encryption(#[from] EncryptionError),
    /// Database error
    #[error("Database operation failed: {0}")]
    DBError(#[from] DBError),
    /// Serialization error
    #[error("JSON serialization failed: {0}")]
    JsonSerializationError(#[from] serde_json::Error),
    /// StackerDB client error
    #[error("StackerDB client error: {0}")]
    StackerDBClientError(#[from] ClientError),
}

/// Error stemming from a persistence operation
#[derive(Debug, thiserror::Error)]
pub enum EncryptionError {
    /// Encryption failed
    #[error("Encryption operation failed")]
    Encrypt,
    /// Decryption failed
    #[error("Encryption operation failed")]
    Decrypt,
}
