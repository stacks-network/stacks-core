// Copyright (C) 2025 Stacks Open Internet Foundation
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

// MAST (Merkelized Abstract Syntax Tree) implementation, used to hash a
// contract and its top-level definitions.
// Used for `contract-hash?` and `definition-hash?` Clarity functions.

use stacks_common::codec::StacksMessageCodec;
use stacks_common::util::hash::Sha512Trunc256Sum;

use crate::vm::ast::ContractAST;
use crate::vm::representations::TraitDefinition;
use crate::vm::types::TraitIdentifier;
use crate::vm::{SymbolicExpression, SymbolicExpressionType, Value};

#[cfg(test)]
mod test;

impl ContractAST {
    pub fn to_mast_hash(&self) -> [u8; 32] {
        let mut all_hashes = Vec::with_capacity(self.expressions.len() * 32);
        for expr in self.expressions.iter() {
            all_hashes.extend_from_slice(&expr.to_mast_hash());
        }
        Sha512Trunc256Sum::from_data(&all_hashes).into_bytes()
    }
}

impl SymbolicExpression {
    fn to_mast_bytes(&self) -> Vec<u8> {
        self.expr.to_mast_bytes()
    }

    fn to_mast_hash(&self) -> [u8; 32] {
        let bytes = self.to_mast_bytes();
        Sha512Trunc256Sum::from_data(&bytes).into_bytes()
    }
}

impl SymbolicExpressionType {
    fn to_mast_bytes(&self) -> Vec<u8> {
        match self {
            SymbolicExpressionType::AtomValue(value) => {
                let mut out = b"atomval".to_vec();
                value
                    .consensus_serialize(&mut out)
                    .expect("Failed to serialize atom value");
                out
            }
            SymbolicExpressionType::Atom(name) => {
                let mut out = b"atom".to_vec();
                out.extend_from_slice(name.as_bytes());
                out
            }
            SymbolicExpressionType::List(list) => {
                let mut out = b"list".to_vec();
                for item in list.iter() {
                    out.extend_from_slice(&item.to_mast_hash());
                }
                out
            }
            SymbolicExpressionType::LiteralValue(value) => {
                let mut out = b"literal".to_vec();
                value
                    .consensus_serialize(&mut out)
                    .expect("Failed to serialize literal value");
                out
            }
            SymbolicExpressionType::Field(field) => field.to_mast_bytes(),
            SymbolicExpressionType::TraitReference(name, TraitDefinition::Defined(identifier)) => {
                let mut out = b"traitref".to_vec();
                out.extend_from_slice(name.as_bytes());
                out.extend_from_slice(&identifier.to_mast_bytes());
                out
            }
            SymbolicExpressionType::TraitReference(name, TraitDefinition::Imported(identifier)) => {
                let mut out = b"traitref".to_vec();
                out.extend_from_slice(name.as_bytes());
                out.extend_from_slice(&identifier.to_mast_bytes());
                out
            }
        }
    }
}

impl TraitIdentifier {
    pub fn to_mast_bytes(&self) -> Vec<u8> {
        let mut out = b"trait".to_vec();
        let principal = Value::from(self.contract_identifier.clone());
        principal
            .consensus_serialize(&mut out)
            .expect("Failed to serialize trait contract identifier");
        out.push(0xff); // delimiter between contract and trait name
        out.extend_from_slice(self.name.as_bytes());
        out
    }
}
