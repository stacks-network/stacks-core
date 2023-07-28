pub mod hash160;
pub mod sha256;

const SHA256_HASH_LENGTH: usize = 32;

pub struct Sha256Hash([u8; SHA256_HASH_LENGTH]);
