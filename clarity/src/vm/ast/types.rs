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

use crate::vm::ast::errors::ParseResult;
use crate::vm::representations::{PreSymbolicExpression, SymbolicExpression, TraitDefinition};
use crate::vm::types::signatures::FunctionSignature;
use crate::vm::types::{QualifiedContractIdentifier, TraitIdentifier};
use crate::vm::ClarityName;
use std::collections::{HashMap, HashSet};
use std::vec::Drain;

pub trait BuildASTPass {
    fn run_pass(contract_ast: &mut ContractAST) -> ParseResult<()>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractAST {
    pub contract_identifier: QualifiedContractIdentifier,
    pub pre_expressions: Vec<PreSymbolicExpression>,
    pub expressions: Vec<SymbolicExpression>,
    pub top_level_expression_sorting: Option<Vec<usize>>,
    pub referenced_traits: HashMap<ClarityName, TraitDefinition>,
    pub implemented_traits: HashSet<TraitIdentifier>,
}

impl ContractAST {
    pub fn new(
        contract_identifier: QualifiedContractIdentifier,
        pre_expressions: Vec<PreSymbolicExpression>,
    ) -> ContractAST {
        ContractAST {
            contract_identifier,
            pre_expressions,
            expressions: Vec::new(),
            top_level_expression_sorting: Some(Vec::new()),
            referenced_traits: HashMap::new(),
            implemented_traits: HashSet::new(),
        }
    }

    pub fn pre_expressions_drain(&mut self) -> PreExpressionsDrain {
        let sorting = match self.top_level_expression_sorting {
            Some(ref exprs_ids) => Some(exprs_ids[..].to_vec()),
            None => None,
        };

        PreExpressionsDrain::new(self.pre_expressions.drain(..), sorting)
    }

    pub fn add_implemented_trait(&mut self, trait_identifier: TraitIdentifier) {
        self.implemented_traits.insert(trait_identifier);
    }

    pub fn get_referenced_trait(&self, name: &str) -> Option<&TraitDefinition> {
        self.referenced_traits.get(name)
    }
}

pub struct PreExpressionsDrain {
    pre_expressions: HashMap<usize, PreSymbolicExpression>,
    sorting: Option<Vec<usize>>,
    index: usize,
    len: usize,
}

impl PreExpressionsDrain {
    pub fn new(pre_exprs_drain: Drain<PreSymbolicExpression>, sorting: Option<Vec<usize>>) -> Self {
        let mut pre_expressions = HashMap::new();
        let mut index = 0;
        for pre_expr in pre_exprs_drain {
            pre_expressions.insert(index, pre_expr);
            index += 1;
        }

        let sorting = match sorting {
            Some(sorting) if sorting.len() > 0 => Some(sorting),
            _ => None,
        };
        let drain = PreExpressionsDrain {
            len: pre_expressions.len(),
            pre_expressions,
            sorting,
            index: 0,
        };
        drain
    }
}

impl Iterator for PreExpressionsDrain {
    type Item = PreSymbolicExpression;

    fn next(&mut self) -> Option<PreSymbolicExpression> {
        if self.index >= self.len {
            return None;
        }
        let expr_index = match self.sorting {
            Some(ref indirections) => indirections[self.index],
            None => self.index,
        };
        let result = self.pre_expressions.remove(&expr_index);
        self.index += 1;
        result
    }
}
