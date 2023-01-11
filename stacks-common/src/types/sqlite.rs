use crate::deps_common::bitcoin::util::hash::Sha256dHash;
use crate::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, ConsensusHash, SortitionId, StacksBlockId, TrieHash,
};
use crate::util::hash::{Hash160, Sha512Trunc256Sum};
use crate::util::secp256k1::MessageSignature;
use rusqlite::types::{FromSql, FromSqlError, FromSqlResult, ToSql, ToSqlOutput, ValueRef};

impl FromSql for Sha256dHash {
    fn column_result(value: ValueRef) -> FromSqlResult<Sha256dHash> {
        let hex_str = value.as_str()?;
        let hash = Sha256dHash::from_hex(hex_str).map_err(|_e| FromSqlError::InvalidType)?;
        Ok(hash)
    }
}

impl ToSql for Sha256dHash {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput> {
        let hex_str = self.be_hex_string();
        Ok(hex_str.into())
    }
}

// Implement rusqlite traits for a bunch of structs that used to be defined
//  in the chainstate code
impl_byte_array_rusqlite_only!(ConsensusHash);
impl_byte_array_rusqlite_only!(Hash160);
impl_byte_array_rusqlite_only!(BlockHeaderHash);
impl_byte_array_rusqlite_only!(BurnchainHeaderHash);
impl_byte_array_rusqlite_only!(TrieHash);
impl_byte_array_rusqlite_only!(Sha512Trunc256Sum);
impl_byte_array_rusqlite_only!(MessageSignature);
impl_byte_array_rusqlite_only!(SortitionId);
impl_byte_array_rusqlite_only!(StacksBlockId);
