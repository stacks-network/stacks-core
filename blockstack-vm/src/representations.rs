use types::{ValueType, TypeSignature};

/*
 I don't add a pair type here, since we're only using these S-Expressions to represent code, rather than
 data structures, and we don't support pair expressions directly in our lisp dialect.
 */
#[derive(Debug)]
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum SymbolicExpression {
    AtomValue(ValueType),
    Atom(String),
    List(Box<[SymbolicExpression]>),
    TypeIdentifier(TypeSignature)
}

pub struct Contract {
    pub content: Box<[SymbolicExpression]>
}
