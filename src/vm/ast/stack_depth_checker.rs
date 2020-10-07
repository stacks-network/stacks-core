use vm::ast::errors::{ParseError, ParseErrors, ParseResult};
use vm::ast::types::{BuildASTPass, ContractAST};
use vm::representations::PreSymbolicExpression;
use vm::representations::PreSymbolicExpressionType::List;

use vm::MAX_CALL_STACK_DEPTH;

// allow  the AST to get deeper than the max call stack depth,
//    but not much deeper (things like tuples would increase the
//    AST depth, without impacting the stack depth).
pub const AST_CALL_STACK_DEPTH_BUFFER: u64 = 5;

fn check(args: &[PreSymbolicExpression], depth: u64) -> ParseResult<()> {
    if depth >= (AST_CALL_STACK_DEPTH_BUFFER + MAX_CALL_STACK_DEPTH as u64) {
        return Err(ParseErrors::ExpressionStackDepthTooDeep.into());
    }
    for expression in args.iter() {
        match expression.pre_expr {
            List(ref exprs) => check(exprs, depth + 1),
            _ => {
                // Other symbolic expressions don't have depth
                //  impacts.
                Ok(())
            }
        }?;
    }
    Ok(())
}

pub struct StackDepthChecker;

impl BuildASTPass for StackDepthChecker {
    fn run_pass(contract_ast: &mut ContractAST) -> ParseResult<()> {
        check(&contract_ast.pre_expressions, 0)
    }
}
