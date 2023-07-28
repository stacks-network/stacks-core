use ruint::aliases::U256;
use sha2::{Digest, Sha256};

const SHA256_LENGTH: usize = 32;
const CHECKSUM_LENGTH: usize = 4;

pub trait HashUtils: AsRef<[u8]> {
    fn new(value: impl AsRef<[u8]>) -> Self;
    fn zeroes() -> Self;
    fn checksum(&self) -> [u8; CHECKSUM_LENGTH];
    fn to_uint256(&self) -> U256 {
        let nontransmuted: [u8; SHA256_LENGTH] = self.as_ref().try_into().unwrap();

        #[allow(unused_assignments)]
        let mut transmuted = [0u64; SHA256_LENGTH / 8];
        transmuted = unsafe { std::mem::transmute(nontransmuted) };

        for byte in transmuted.iter_mut() {
            *byte = byte.to_le();
        }

        U256::from_limbs(transmuted)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Sha256Hash([u8; SHA256_LENGTH]);

impl HashUtils for Sha256Hash {
    fn new(value: impl AsRef<[u8]>) -> Self {
        Self(Sha256::digest(value).into())
    }

    fn zeroes() -> Self {
        Self([0; SHA256_LENGTH])
    }

    fn checksum(&self) -> [u8; CHECKSUM_LENGTH] {
        self.as_ref()[0..CHECKSUM_LENGTH].try_into().unwrap()
    }
}

impl AsRef<[u8]> for Sha256Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DoubleSha256Hash(Sha256Hash);

impl HashUtils for DoubleSha256Hash {
    fn new(value: impl AsRef<[u8]>) -> Self {
        Self(Sha256Hash::new(Sha256Hash::new(value).as_ref()))
    }

    fn zeroes() -> Self {
        Self(Sha256Hash([0; SHA256_LENGTH]))
    }

    fn checksum(&self) -> [u8; CHECKSUM_LENGTH] {
        self.0.checksum()
    }
}

impl AsRef<[u8]> for DoubleSha256Hash {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
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
            hex::encode(Sha256Hash::new(plaintext.as_bytes())),
            expected_hash_hex
        );
    }

    #[test]
    fn should_sha256_checksum_correctly() {
        let plaintext = "Hello world";
        let expected_checksum_hex = "64ec88ca";

        assert_eq!(
            hex::encode(Sha256Hash::new(plaintext.as_bytes()).checksum()),
            expected_checksum_hex
        );
    }

    #[test]
    fn should_double_sha256_hash_correctly() {
        let plaintext = "Hello world";
        let expected_hash_hex = "f6dc724d119649460e47ce719139e521e082be8a9755c5bece181de046ee65fe";

        assert_eq!(
            hex::encode(DoubleSha256Hash::new(plaintext.as_bytes()).as_ref()),
            expected_hash_hex
        );
    }

    #[test]
    fn should_double_sha256_checksum_correctly() {
        let plaintext = "Hello world";
        let expected_checksum_hex = "f6dc724d";

        assert_eq!(
            hex::encode(DoubleSha256Hash::new(plaintext.as_bytes()).checksum()),
            expected_checksum_hex
        );
    }

    #[test]
    fn should_convert_to_uint_correctly() {
        let expected_num =
            U256::from(0xDEADBEEFDEADBEEF as u64) << 64 | U256::from(0x0102030405060708 as u64);
        let num_bytes =
            hex::decode("0807060504030201efbeaddeefbeadde00000000000000000000000000000000")
                .unwrap();

        let hash = Sha256Hash(num_bytes.try_into().unwrap());

        assert_eq!(
            expected_num,
            U256::from_le_bytes::<SHA256_LENGTH>(hash.as_ref().try_into().unwrap())
        );
    }
}
