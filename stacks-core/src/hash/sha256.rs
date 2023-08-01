use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{StacksError, StacksResult};

pub(crate) const SHA256_LENGTH: usize = 32;
pub(crate) const CHECKSUM_LENGTH: usize = 4;

#[derive(Serialize, Deserialize)]
#[serde(transparent)]
struct Hex(String);

pub trait Hashing: Clone + Sized {
    const LENGTH: usize;

    fn hash(data: &[u8]) -> Self;
    fn as_bytes(&self) -> &[u8];
    fn from_bytes(bytes: &[u8]) -> StacksResult<Self>;

    fn new(value: impl AsRef<[u8]>) -> Self {
        Self::hash(value.as_ref())
    }

    fn zeroes() -> Self {
        Self::from_bytes(vec![0; Self::LENGTH].as_slice()).unwrap()
    }

    fn checksum(&self) -> [u8; CHECKSUM_LENGTH] {
        self.as_bytes()[0..CHECKSUM_LENGTH].try_into().unwrap()
    }

    fn from_hex<'a>(data: impl AsRef<str>) -> StacksResult<Self> {
        Ok(Self::from_bytes(&hex::decode(data.as_ref().as_bytes())?)?)
    }

    fn to_hex(&self) -> String {
        hex::encode(self.as_bytes())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[serde(try_from = "Hex")]
#[serde(into = "Hex")]
pub struct Hasher<T>(T)
where
    T: Hashing;

impl<T> Hashing for Hasher<T>
where
    T: Hashing,
{
    const LENGTH: usize = T::LENGTH;

    fn hash(data: &[u8]) -> Self {
        Self(T::hash(data))
    }

    fn as_bytes(&self) -> &[u8] {
        T::as_bytes(&self.0)
    }

    fn from_bytes(bytes: &[u8]) -> StacksResult<Self> {
        Ok(Self(T::from_bytes(bytes)?))
    }
}

impl<T> AsRef<[u8]> for Hasher<T>
where
    T: Hashing,
{
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<T> TryFrom<&[u8]> for Hasher<T>
where
    T: Hashing,
{
    type Error = StacksError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(value)
    }
}

impl<T> Default for Hasher<T>
where
    T: Hashing,
{
    fn default() -> Self {
        Self::zeroes()
    }
}

impl<T> Into<Hex> for Hasher<T>
where
    T: Hashing,
{
    fn into(self) -> Hex {
        Hex(hex::encode(self.as_bytes()))
    }
}

impl<T> TryFrom<Hex> for Hasher<T>
where
    T: Hashing,
{
    type Error = StacksError;

    fn try_from(value: Hex) -> Result<Self, Self::Error> {
        Ok(Self::from_bytes(&hex::decode(value.0)?)?)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[serde(try_from = "Hex")]
#[serde(into = "Hex")]
pub struct Sha256Hashing([u8; SHA256_LENGTH]);

impl Hashing for Sha256Hashing {
    const LENGTH: usize = SHA256_LENGTH;

    fn hash(data: &[u8]) -> Self {
        Self(Sha256::digest(data).into())
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    fn from_bytes(bytes: &[u8]) -> StacksResult<Self> {
        Ok(Self(bytes.try_into()?))
    }
}

impl Into<Hex> for Sha256Hashing {
    fn into(self) -> Hex {
        Hex(hex::encode(self.as_bytes()))
    }
}

impl TryFrom<Hex> for Sha256Hashing {
    type Error = StacksError;

    fn try_from(value: Hex) -> Result<Self, Self::Error> {
        Ok(Self::from_bytes(&hex::decode(value.0)?)?)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DoubleSha256Hashing(Sha256Hashing);

impl Hashing for DoubleSha256Hashing {
    const LENGTH: usize = SHA256_LENGTH;

    fn hash(data: &[u8]) -> Self {
        Self(Sha256Hashing::hash(Sha256Hashing::hash(data).as_bytes()))
    }

    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    fn from_bytes(bytes: &[u8]) -> StacksResult<Self> {
        Ok(Self(Sha256Hashing::from_bytes(bytes)?))
    }
}

impl Into<Hex> for DoubleSha256Hashing {
    fn into(self) -> Hex {
        Hex(hex::encode(self.as_bytes()))
    }
}

impl TryFrom<Hex> for DoubleSha256Hashing {
    type Error = StacksError;

    fn try_from(value: Hex) -> Result<Self, Self::Error> {
        Ok(Self::from_bytes(&hex::decode(value.0)?)?)
    }
}

pub type Sha256Hasher = Hasher<Sha256Hashing>;
pub type DoubleSha256Hasher = Hasher<DoubleSha256Hashing>;

#[cfg(test)]
mod tests {
    use crate::uint::Uint256;

    use super::*;

    #[test]
    fn should_sha256_hash_correctly() {
        let plaintext = "Hello world";
        let expected_hash_hex = "64ec88ca00b268e5ba1a35678a1b5316d212f4f366b2477232534a8aeca37f3c";

        assert_eq!(
            hex::encode(Sha256Hasher::hash(plaintext.as_bytes())),
            expected_hash_hex
        );
    }

    #[test]
    fn should_sha256_checksum_correctly() {
        let plaintext = "Hello world";
        let expected_checksum_hex = "64ec88ca";

        assert_eq!(
            hex::encode(Sha256Hasher::hash(plaintext.as_bytes()).checksum()),
            expected_checksum_hex
        );
    }

    #[test]
    fn should_double_sha256_hash_correctly() {
        let plaintext = "Hello world";
        let expected_hash_hex = "f6dc724d119649460e47ce719139e521e082be8a9755c5bece181de046ee65fe";

        assert_eq!(
            hex::encode(DoubleSha256Hasher::hash(plaintext.as_bytes()).as_bytes()),
            expected_hash_hex
        );
    }

    #[test]
    fn should_double_sha256_checksum_correctly() {
        let plaintext = "Hello world";
        let expected_checksum_hex = "f6dc724d";

        assert_eq!(
            hex::encode(DoubleSha256Hasher::hash(plaintext.as_bytes()).checksum()),
            expected_checksum_hex
        );
    }

    #[test]
    fn should_convert_to_uint_correctly() {
        let expected_num = Uint256::from(0xDEADBEEFDEADBEEF as u64) << 64
            | Uint256::from(0x0102030405060708 as u64);
        let num_bytes =
            hex::decode("0807060504030201efbeaddeefbeadde00000000000000000000000000000000")
                .unwrap();

        let hash = Sha256Hashing(num_bytes.try_into().unwrap());

        assert_eq!(
            expected_num,
            Uint256::from_le_bytes(hash.as_bytes()).unwrap()
        );
    }
}
