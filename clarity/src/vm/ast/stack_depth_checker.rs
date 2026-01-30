// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use crate::vm::ast::errors::{ParseErrorKind, ParseResult};
use crate::vm::ast::types::{BuildASTPass, ContractAST};
use crate::vm::representations::PreSymbolicExpression;
use crate::vm::representations::PreSymbolicExpressionType::{List, Tuple};
use crate::vm::{ClarityVersion, max_call_stack_depth_for_epoch};

// allow  the AST to get deeper than the max call stack depth,
//    but not much deeper (things like tuples would increase the
//    AST depth, without impacting the stack depth).
pub const AST_CALL_STACK_DEPTH_BUFFER: u64 = 5;

pub fn max_nesting_depth(max_call_stack_depth: usize) -> u64 {
    AST_CALL_STACK_DEPTH_BUFFER + (max_call_stack_depth as u64) + 1
}

fn check(
    args: &[PreSymbolicExpression],
    depth: u64,
    max_call_stack_depth: usize,
) -> ParseResult<()> {
    if depth >= (AST_CALL_STACK_DEPTH_BUFFER + max_call_stack_depth as u64) {
        return Err(ParseErrorKind::ExpressionStackDepthTooDeep {
            max_depth: max_call_stack_depth,
        }
        .into());
    }
    for expression in args.iter() {
        match expression.pre_expr {
            List(ref exprs) => check(exprs, depth + 1, max_call_stack_depth),
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
    fn run_pass(
        contract_ast: &mut ContractAST,
        _version: ClarityVersion,
        epoch: stacks_common::types::StacksEpochId,
    ) -> ParseResult<()> {
        let max_call_stack_depth = max_call_stack_depth_for_epoch(epoch);
        check(&contract_ast.pre_expressions, 0, max_call_stack_depth)
    }
}

fn check_vary(
    args: &[PreSymbolicExpression],
    depth: u64,
    max_call_stack_depth: usize,
) -> ParseResult<()> {
    if depth >= (AST_CALL_STACK_DEPTH_BUFFER + max_call_stack_depth as u64) {
        return Err(ParseErrorKind::VaryExpressionStackDepthTooDeep {
            max_depth: max_call_stack_depth,
        }
        .into());
    }
    for expression in args.iter() {
        match expression.pre_expr {
            List(ref exprs) => check_vary(exprs, depth + 1, max_call_stack_depth),
            Tuple(ref exprs) => check_vary(exprs, depth + 1, max_call_stack_depth),
            _ => {
                // Other symbolic expressions don't have depth
                //  impacts.
                Ok(())
            }
        }?;
    }
    Ok(())
}

pub struct VaryStackDepthChecker;

impl BuildASTPass for VaryStackDepthChecker {
    fn run_pass(
        contract_ast: &mut ContractAST,
        _version: ClarityVersion,
        epoch: stacks_common::types::StacksEpochId,
    ) -> ParseResult<()> {
        let max_call_stack_depth = max_call_stack_depth_for_epoch(epoch);
        check_vary(&contract_ast.pre_expressions, 0, max_call_stack_depth)
    }
}
