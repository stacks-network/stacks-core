use vm::representations::{SymbolicExpression, PreSymbolicExpression};
use vm::ast::errors::{ParseResult};
use vm::types::{QualifiedContractIdentifier};

pub trait BuildASTPass {
    fn run_pass(contract_ast: &mut ContractAST) -> ParseResult<()>;
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractAST {
    pub contract_identifier: QualifiedContractIdentifier,
    pub pre_expressions: Vec<PreSymbolicExpression>,
    pub expressions: Vec<SymbolicExpression>,
}

impl ContractAST {
    pub fn new(contract_identifier: QualifiedContractIdentifier, pre_expressions: Vec<PreSymbolicExpression>) -> ContractAST {
        ContractAST {
            contract_identifier,
            pre_expressions,
            expressions: Vec::new()
        }
    }
}

