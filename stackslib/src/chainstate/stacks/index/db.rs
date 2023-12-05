use std::{io::Write, cell::{RefCell, Ref}, path::{PathBuf, Path}, marker::PhantomData};

use rusqlite::{Connection, Transaction, blob::Blob};
use stacks_common::types::chainstate::TrieHash;

use super::{Error, node::{TriePtr, TrieNodeType}, MarfTrieId};

pub trait DbBackend: Sized {
    fn establish(uri: &str)-> Result<Self, DbError>;
}

pub trait TransactionalDb
where
    Self: DbBackend
{
    type TxType<'conn>: DbTransactionType<'conn> where Self: 'conn;
    
    fn transaction<'conn, 'tx, E>(
        &'conn mut self
    ) -> Result<DbTransactionGuard<Self::TxType<'conn>>, E> 
    where 
        E: From<DbError>;
}

pub trait DbTransactionType<'conn> {}

pub trait DbTransaction {
    fn commit(self) -> Result<(), DbError>;
    fn rollback(self) -> Result<(), DbError>;
}

pub struct DbTransactionGuard<'conn, TxType: DbTransactionType<'conn>> {
    tx: TxType,
    _phantom: PhantomData<&'conn ()>,
}

impl<'conn, TxType: DbTransactionType<'conn>> DbTransactionGuard<'conn, TxType> {
    pub fn new(tx: TxType) -> Self {
        Self {
            tx,
            _phantom: PhantomData,
        }
    }
}

pub enum DbError {
    Database(String),
    Other(String),
}

impl From<DbError> for Error {
    fn from(e: DbError) -> Self {
        match e {
            DbError::Database(s) => Error::DbError(s),
            DbError::Other(s) => Error::DbError(s),
        }
    }
}