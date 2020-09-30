use vm::ast::errors::{ParseError, ParseErrors, ParseResult};
use vm::ast::types::{BuildASTPass, ContractAST};
use vm::representations::PreSymbolicExpressionType::List;
use vm::representations::SymbolicExpressionCommon;

fn inner_relabel<T: SymbolicExpressionCommon>(args: &mut [T], index: u64) -> ParseResult<u64> {
    let mut current = index
        .checked_add(1)
        .ok_or(ParseError::new(ParseErrors::TooManyExpressions))?;
    for expression in &mut args[..] {
        expression.set_id(current);
        current = if let Some(exprs) = expression.match_list_mut() {
            inner_relabel(exprs, current)
        } else {
            current
                .checked_add(1)
                .ok_or(ParseError::new(ParseErrors::TooManyExpressions))
        }?;
    }
    Ok(current)
}

pub fn update_expression_id<T: SymbolicExpressionCommon>(exprs: &mut [T]) -> ParseResult<()> {
    inner_relabel(exprs, 0)?;
    Ok(())
}

pub struct ExpressionIdentifier;

impl ExpressionIdentifier {
    pub fn run_pre_expression_pass(contract_ast: &mut ContractAST) -> ParseResult<()> {
        update_expression_id(contract_ast.pre_expressions.as_mut_slice())?;
        Ok(())
    }
    pub fn run_expression_pass(contract_ast: &mut ContractAST) -> ParseResult<()> {
        update_expression_id(contract_ast.expressions.as_mut_slice())?;
        Ok(())
    }
}
