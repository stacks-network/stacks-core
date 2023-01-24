#[derive(Debug, PartialEq)]
pub enum States {
    Init,
    DkgDistribute,
    DkgGather,
    SignGather,
    Signed,
}

pub trait StateMachine {
    fn move_to(&mut self, state: States) -> Result<(), String>;
    fn can_move_to(&self, state: &States) -> Result<(), String>;
}
