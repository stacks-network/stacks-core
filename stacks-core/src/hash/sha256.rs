use sha2::{Digest, Sha256};

const SHA256_LENGTH: usize = 32;
const CHECKSUM_LENGTH: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SHA256Hash([u8; SHA256_LENGTH]);

impl SHA256Hash {
    pub fn new(value: impl AsRef<[u8]>) -> Self {
        Self(Sha256::digest(value).into())
    }

    pub fn checksum(&self) -> [u8; CHECKSUM_LENGTH] {
        self.as_ref()[0..CHECKSUM_LENGTH].try_into().unwrap()
    }
}

impl AsRef<[u8]> for SHA256Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DoubleSHA256Hash([u8; SHA256_LENGTH]);

impl DoubleSHA256Hash {
    pub fn new(value: impl AsRef<[u8]>) -> Self {
        Self(
            SHA256Hash::new(SHA256Hash::new(value).as_ref())
                .as_ref()
                .try_into()
                .unwrap(),
        )
    }

    pub fn checksum(&self) -> [u8; CHECKSUM_LENGTH] {
        self.as_ref()[0..CHECKSUM_LENGTH].try_into().unwrap()
    }
}

impl AsRef<[u8]> for DoubleSHA256Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_sha256_hash_correctly() {
        let plaintext = "Hello world";
        let expected_hash_hex = "64ec88ca00b268e5ba1a35678a1b5316d212f4f366b2477232534a8aeca37f3c";

        assert_eq!(
            hex::encode(SHA256Hash::new(plaintext.as_bytes())),
            expected_hash_hex
        );
    }

    #[test]
    fn should_double_sha256_hash_correctly() {
        let plaintext = "Hello world";
        let expected_hash_hex = "f6dc724d119649460e47ce719139e521e082be8a9755c5bece181de046ee65fe";

        assert_eq!(
            hex::encode(DoubleSHA256Hash::new(plaintext.as_bytes()).as_ref()),
            expected_hash_hex
        );
    }

    #[test]
    fn should_sha256_checksum_correctly() {
        let plaintext = "Hello world";
        let expected_checksum_hex = "64ec88ca";

        assert_eq!(
            hex::encode(SHA256Hash::new(plaintext.as_bytes()).checksum()),
            expected_checksum_hex
        );
    }
}
