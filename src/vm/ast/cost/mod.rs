// Copyright (C) 2013-2021 Blockstack PBC, a public benefit corporation
// Copyright (C) 2021 Stacks Open Internet Foundation
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

use vm::ast::errors::ParseResult;
use vm::ast::types::BuildASTPass;
use vm::ast::ContractAST;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SymbolicCostExpression {
    Var(u32), // the number represents the var name
    Number(u32),
    Sum(Box<SymbolicCostExpression>, Box<SymbolicCostExpression>),
    Mul(Box<SymbolicCostExpression>, Box<SymbolicCostExpression>),
    Max(Box<SymbolicCostExpression>, Box<SymbolicCostExpression>),
    TraitInvocation(String), // todo: how should we uniquely identify traits?
}

pub struct StaticCostAnalyzer {}

impl BuildASTPass for StaticCostAnalyzer {
    fn run_pass(_contract_ast: &mut ContractAST) -> ParseResult<()> {
        Ok(())
    }
}

impl StaticCostAnalyzer {
    fn new() -> Self {
        Self {}
    }
}
