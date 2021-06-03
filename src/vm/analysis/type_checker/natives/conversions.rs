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

use vm::representations::SymbolicExpression;
use vm::types::SequenceSubtype;
use vm::types::TypeSignature;

use vm::analysis::type_checker::{
    check_argument_count, CheckErrors, TypeChecker, TypeResult, TypingContext,
};
use vm::costs::runtime_cost;
use vm::costs::cost_functions::ClarityCostFunction;

pub fn check_special_buff_to_int(
    checker: &mut TypeChecker,
    args: &[SymbolicExpression],
    context: &TypingContext,
) -> TypeResult {
    check_argument_count(1, args)?;
    runtime_cost(ClarityCostFunction::BuffToInt, checker, 0)?;

    let collection_type = checker.type_check(&args[0], context)?;
    match collection_type {
        TypeSignature::SequenceType(SequenceSubtype::BufferType(u16)) => return Ok(TypeSignature::IntType),
        _ => return Err(CheckErrors::ExpectedBuffer16(collection_type).into()),
    };
}

pub fn check_special_buff_to_uint(
    checker: &mut TypeChecker,
    args: &[SymbolicExpression],
    context: &TypingContext,
) -> TypeResult {
    check_argument_count(1, args)?;
    runtime_cost(ClarityCostFunction::BuffToInt, checker, 0)?;

    let collection_type = checker.type_check(&args[0], context)?;
    match collection_type {
        TypeSignature::SequenceType(SequenceSubtype::BufferType(u16)) => return Ok(TypeSignature::UIntType),
        _ => return Err(CheckErrors::ExpectedBuffer16(collection_type).into()),
    };
}
