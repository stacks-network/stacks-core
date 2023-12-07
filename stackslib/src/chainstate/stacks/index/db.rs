use std::{io::Write, cell::{RefCell, Ref}, path::{PathBuf, Path}, marker::PhantomData, ops::Deref};

use rusqlite::{Connection, Transaction, blob::Blob};
use stacks_common::types::chainstate::TrieHash;

use super::{Error, node::{TriePtr, TrieNodeType}, MarfTrieId};

pub trait DbConnection: Sized {
    fn establish<P: AsRef<Path>>(uri: P)-> Result<Self, DbError>;
}

pub trait TransactionalDb
where
    Self: DbConnection
{
    type TxType<'conn>: DbTransaction<'conn> where Self: 'conn;
    
    fn transaction<'conn, 'tx, E>(
        &'conn mut self
    ) -> Result<DbTransactionGuard<Self::TxType<'conn>>, E> 
    where 
        E: From<DbError>;
}

pub trait DbTransaction<'conn> {
    fn commit(self) -> Result<(), DbError>;
    fn rollback(self) -> Result<(), DbError>;
}

pub struct DbTransactionGuard<'conn, TxType>
where
    TxType: DbTransaction<'conn>,
 {
    tx: TxType,
    _phantom: PhantomData<&'conn ()>,
}

impl<'conn, TxType> DbTransactionGuard<'conn, TxType>
where
    TxType: DbTransaction<'conn>
{
    pub fn new(tx: TxType) -> Self {
        Self {
            tx,
            _phantom: PhantomData,
        }
    }
}

impl<'conn, TxType> Deref for DbTransactionGuard<'conn, TxType>
where
    TxType: DbTransaction<'conn>,
{
    type Target = TxType;

    fn deref(&self) -> &Self::Target {
        &self.tx
    }
}

impl<'conn, TxType> DbTransaction<'conn> for DbTransactionGuard<'conn, TxType> 
where
    TxType: DbTransaction<'conn>,
{
    fn commit(self) -> Result<(), DbError> {
        self.tx.commit()
    }

    fn rollback(self) -> Result<(), DbError> {
        self.tx.rollback()
    }
}

pub enum DbError {
    Database(String),
    Other(String),
}