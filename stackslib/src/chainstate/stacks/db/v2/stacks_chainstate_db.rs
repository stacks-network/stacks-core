use crate::chainstate::stacks::index::trie_db::TrieDb;

pub trait ChainStateDb
where
    Self: TrieDb
{
}

pub trait ChainStateDbTransaction {

}