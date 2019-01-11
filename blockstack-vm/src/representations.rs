#[derive(Clone)]
pub struct SymbolicExpression {
    pub value: String,
    pub children: Option<Box<[SymbolicExpression]>>
}

pub struct Contract {
    pub content: Box<[SymbolicExpression]>
}
