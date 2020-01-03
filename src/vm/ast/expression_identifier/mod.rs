use vm::representations::{SymbolicExpression, SymbolicExpressionType};
use vm::ast::types::{ContractAST, BuildASTPass};
use vm::ast::errors::{ParseResult, ParseErrors, ParseError};

fn inner_relabel(args: &mut [SymbolicExpression], index: u64) -> ParseResult<u64> {
    let mut current = index.checked_add(1)
        .ok_or(ParseError::new(ParseErrors::TooManyExpressions))?;
    for expression in &mut args[..] {
        expression.id = current;
        current = match expression.expr {
            SymbolicExpressionType::AtomValue(_) | SymbolicExpressionType::LiteralValue(_) => {
                current.checked_add(1)
                    .ok_or(ParseError::new(ParseErrors::TooManyExpressions))
            },
            SymbolicExpressionType::Atom(_) => {
                current.checked_add(1)
                    .ok_or(ParseError::new(ParseErrors::TooManyExpressions))
            },
            SymbolicExpressionType::List(ref mut exprs) => {
                inner_relabel(exprs, current)
            }
        }?;
    }
    Ok(current)
}

pub fn update_expression_id(exprs: &mut [SymbolicExpression]) -> ParseResult<()> {
    inner_relabel(exprs, 0)?;
    Ok(())
}

pub struct ExpressionIdentifier;

impl BuildASTPass for ExpressionIdentifier {

    fn run_pass(contract_ast: &mut ContractAST) -> ParseResult<()> {
        update_expression_id(& mut contract_ast.expressions)?;
        Ok(())
    }
}
