#[derive(Clone)]
pub enum SymbolicExpression {
    Atom(String),
    List(Box<[SymbolicExpression]>)
}

pub struct Contract {
    pub content: Box<[SymbolicExpression]>
}
