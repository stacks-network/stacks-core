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

pub mod v1;
pub mod v2;

use self::v1::parse as parse_v1;
use self::v2::parse as parse_v2;

use stacks_common::types::StacksEpochId;
use crate::vm::ast::errors::ParseResult;
use crate::vm::representations::PreSymbolicExpression;

/// Parse a program based on which epoch is active
pub fn parse_in_epoch(source_code: &str, epoch_id: StacksEpochId) -> ParseResult<Vec<PreSymbolicExpression>> {
    if epoch_id >= StacksEpochId::Epoch21 {
        parse_v2(source_code)
    }
    else {
        parse_v1(source_code)
    }
}

