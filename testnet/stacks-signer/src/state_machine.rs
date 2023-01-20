#[derive(Debug, PartialEq)]
pub enum States {
    Init,
    DkgDistribute,
    DkgGather,
    SignGather,
    Signed,
}

pub trait StateMachine {
    fn move_to(&self, state: States) -> Result<(), String>;
}
