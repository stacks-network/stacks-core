use vm::representations::{SymbolicExpression};
use vm::ast::errors::{ParseResult};
use vm::types::{QualifiedContractIdentifier};

pub trait BuildASTPass {
    fn run_pass(contract_ast: &mut ContractAST) -> ParseResult<()>;
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractAST {
    pub contract_identifier: QualifiedContractIdentifier,
    pub expressions: Vec<SymbolicExpression>,
}

impl ContractAST {
    pub fn new(contract_identifier: QualifiedContractIdentifier, expressions: Vec<SymbolicExpression>) -> ContractAST {
        ContractAST {
            contract_identifier,
            expressions,
        }
    }
}

