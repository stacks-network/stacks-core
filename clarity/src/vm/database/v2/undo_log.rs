
use super::{transactional::TransactionalClarityDb, blocks::ClarityDbBlocks};


pub trait UndoLog 
{
    type DB: TransactionalClarityDb + ClarityDbBlocks;

    fn nest(&mut self) -> UndoRecord;
    fn depth(&self) -> usize;
}

#[derive(Debug, Clone)]
pub struct UndoRecord {
}