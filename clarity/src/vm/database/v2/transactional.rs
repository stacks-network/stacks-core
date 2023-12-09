use super::ClarityDb;

pub trait TransactionalClarityDb: ClarityDb {
    fn begin(&mut self);
    fn commit(&mut self);
    fn rollback(&mut self);
}