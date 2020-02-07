pub mod parser;
pub mod expression_identifier;
pub mod sugar_expander;
pub mod types;
pub mod errors;
use vm::errors::{Error, RuntimeErrorType};

use vm::representations::{SymbolicExpression};
use vm::types::QualifiedContractIdentifier;

pub use self::types::{ContractAST};
use self::types::{BuildASTPass};
use self::errors::{ParseResult};
use self::expression_identifier::ExpressionIdentifier;
use self::sugar_expander::SugarExpander;

/// Legacy function
pub fn parse(contract_identifier: &QualifiedContractIdentifier,source_code: &str) -> Result<Vec<SymbolicExpression>, Error> {
    let ast = build_ast(contract_identifier, source_code)
        .map_err(|e| RuntimeErrorType::ASTError(e))?;
    Ok(ast.expressions)
}

pub fn build_ast(contract_identifier: &QualifiedContractIdentifier, source_code: &str) -> ParseResult<ContractAST> {
    let pre_expressions = parser::parse(source_code)?;
    let mut contract_ast = ContractAST::new(contract_identifier.clone(), pre_expressions);
    SugarExpander::run_pass(&mut contract_ast)?;
    ExpressionIdentifier::run_pass(&mut contract_ast)?;
    Ok(contract_ast)
}
