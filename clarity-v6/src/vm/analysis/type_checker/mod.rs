// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2026 Stacks Open Internet Foundation
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

pub mod contexts;
pub mod v2_1;

use stacks_common::types::StacksEpochId;

use super::AnalysisDatabase;
use super::errors::StaticCheckError;
pub use super::types::{AnalysisPass, ContractAnalysis};
use crate::vm::analysis::type_checker::v2_1::FunctionTypeExtV21;
use crate::vm::costs::CostTracker;
use crate::vm::types::{FunctionType, TypeSignature};
use crate::vm::{ClarityVersion, Value};

/// Epoch-dispatching argument checks for [`FunctionType`]. Extension
/// trait: the data type lives in `clarity-kernel`, the checking rules are
/// engine business.
pub trait FunctionTypeExt {
    fn check_args<T: CostTracker>(
        &self,
        accounting: &mut T,
        args: &[TypeSignature],
        epoch: StacksEpochId,
        clarity_version: ClarityVersion,
    ) -> Result<TypeSignature, StaticCheckError>;
    fn check_args_by_allowing_trait_cast(
        &self,
        db: &mut AnalysisDatabase,
        func_args: &[Value],
        epoch: StacksEpochId,
        clarity_version: ClarityVersion,
    ) -> Result<TypeSignature, StaticCheckError>;
}

impl FunctionTypeExt for FunctionType {
    fn check_args<T: CostTracker>(
        &self,
        accounting: &mut T,
        args: &[TypeSignature],
        _epoch: StacksEpochId,
        _clarity_version: ClarityVersion,
    ) -> Result<TypeSignature, StaticCheckError> {
        self.check_args_2_1(accounting, args, ClarityVersion::Clarity6)
    }

    fn check_args_by_allowing_trait_cast(
        &self,
        db: &mut AnalysisDatabase,
        func_args: &[Value],
        _epoch: StacksEpochId,
        _clarity_version: ClarityVersion,
    ) -> Result<TypeSignature, StaticCheckError> {
        self.check_args_by_allowing_trait_cast_2_1(db, ClarityVersion::Clarity6, func_args)
    }
}

fn is_reserved_word_v3(word: &str) -> bool {
    word == "block-height"
}

/// Is this a reserved word that should trigger an analysis error for the given
/// Clarity version? Note that most of the reserved words do not trigger an
/// analysis error, but will trigger an error at runtime. This should likely be
/// changed in a future Clarity version.
pub fn is_reserved_word(word: &str, _version: ClarityVersion) -> bool {
    is_reserved_word_v3(word)
}
