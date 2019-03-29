use vm::types::{Value};

/*
 I don't add a pair type here, since we're only using these S-Expressions to represent code, rather than
 data structures, and we don't support pair expressions directly in our lisp dialect.
 */

#[derive(Debug)]
#[derive(Serialize, Deserialize)]
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum SymbolicExpressionType {
    AtomValue(Value),
    Atom(String),
    List(Box<[SymbolicExpression]>),
}

#[derive(Debug)]
#[derive(Serialize, Deserialize)]
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SymbolicExpression {
    pub expr: SymbolicExpressionType,
    // this id field is used by compiler passes to store information in
    //  maps.
    // first pass       -> fill out unique ids
    // ...typing passes -> store information in hashmap according to id.
    // 
    // this is a fairly standard technique in compiler passes
    pub id: u64
}

impl SymbolicExpression {
    pub fn atom_value(val: Value) -> SymbolicExpression {
        SymbolicExpression {
            id: 0,
            expr: SymbolicExpressionType::AtomValue(val)
        }
    }

    pub fn atom(val: String) -> SymbolicExpression {
        SymbolicExpression {
            id: 0,
            expr: SymbolicExpressionType::Atom(val)
        }
    }

    pub fn list(val: Box<[SymbolicExpression]>) -> SymbolicExpression {
        SymbolicExpression {
            id: 0,
            expr: SymbolicExpressionType::List(val)
        }
    }
}
