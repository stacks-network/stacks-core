pub mod parser;
pub mod expression_identifier;
pub mod sugar_expander;
pub mod types;
pub mod errors;
use vm::errors::Error;

use vm::representations::{SymbolicExpression};
use vm::types::QualifiedContractIdentifier;

use self::types::{ContractAST, BuildASTPass};
use self::errors::{ParseResult};
use self::expression_identifier::ExpressionIdentifier;
use self::sugar_expander::SugarExpander;

/// Legacy function
pub fn parse(contract_identifier: &QualifiedContractIdentifier,source_code: &str) -> Result<Vec<SymbolicExpression>, Error> {
    let ast = build_ast(contract_identifier, source_code).unwrap();
    Ok(ast.expressions)
}

pub fn build_ast(contract_identifier: &QualifiedContractIdentifier, source_code: &str) -> ParseResult<ContractAST> {
    let expressions = parser::parse(source_code)?;
    let mut contract_ast = ContractAST::new(contract_identifier.clone(), expressions);
    ExpressionIdentifier::run_pass(&mut contract_ast)?;
    SugarExpander::run_pass(&mut contract_ast)?;
    Ok(contract_ast)
}
