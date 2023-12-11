use crate::vm::database::RollbackWrapper;

use super::{ClarityDb, UndoLog};

pub trait TransactionalClarityDb 
where
    Self: ClarityDb + UndoLog<DB = Self>
{
    fn begin(&mut self);
    fn commit(&mut self);
    fn rollback(&mut self);

    fn from_rollback_wrapper(wrapper: RollbackWrapper<Self>) -> Self where Self: Sized;
}