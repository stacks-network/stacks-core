
use super::{transactional::TransactionalClarityDb, blocks::ClarityDbBlocks};


pub trait UndoLog 
{
    type DB: TransactionalClarityDb + ClarityDbBlocks;

    fn nest(&mut self) -> UndoRecord;
    fn depth(&self) -> usize;
    fn is_stack_empty(&self) -> bool;
}

#[derive(Debug, Clone)]
pub struct UndoRecord {
}