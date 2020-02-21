use vm::representations::{PreSymbolicExpression};
use vm::representations::PreSymbolicExpressionType::List;
use vm::ast::types::{ContractAST, BuildASTPass};
use vm::ast::errors::{ParseResult, ParseErrors, ParseError};

fn inner_relabel(args: &mut [PreSymbolicExpression], index: u64) -> ParseResult<u64> {
    let mut current = index.checked_add(1)
        .ok_or(ParseError::new(ParseErrors::TooManyExpressions))?;
    for expression in &mut args[..] {
        expression.id = current;
        current = match expression.pre_expr {
            List(ref mut exprs) => {
                inner_relabel(exprs, current)
            },
            _ => {
                current.checked_add(1)
                    .ok_or(ParseError::new(ParseErrors::TooManyExpressions))
            },
        }?;
    }
    Ok(current)
}

pub fn update_expression_id(exprs: &mut [PreSymbolicExpression]) -> ParseResult<()> {
    inner_relabel(exprs, 0)?;
    Ok(())
}

pub struct ExpressionIdentifier;

impl BuildASTPass for ExpressionIdentifier {

    fn run_pass(contract_ast: &mut ContractAST) -> ParseResult<()> {
        update_expression_id(& mut contract_ast.pre_expressions)?;
        Ok(())
    }
}
