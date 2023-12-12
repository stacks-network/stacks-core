use std::ops::Deref;

use clarity::vm::database::v2::ClarityDbKvStore;

use crate::chainstate::stacks::index::trie_db::TrieDb;

pub trait ChainStateDb
where
    Self: TrieDb + ClarityDbKvStore,
{
}

pub trait ChainStateDbTransaction<DB>
where
    DB: ChainStateDb,
    Self: Deref<Target = DB>
{
}