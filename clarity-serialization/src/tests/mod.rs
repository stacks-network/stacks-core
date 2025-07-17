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

#![cfg(any(test, feature = "testing"))]

use crate::errors::CodecError;
use crate::types::Value;

impl Value {
    pub fn list_from(list_data: Vec<Value>) -> Result<Value, CodecError> {
        Value::cons_list_unsanitized(list_data)
    }
}

// Implement PartialEq for testing and simple equality checks by comparing the
// string representations of each error. This avoids requiring all wrapped
// fields (like `std::io::Error`) to implement PartialEq.
impl PartialEq for CodecError {
    fn eq(&self, other: &Self) -> bool {
        self.to_string() == other.to_string()
    }
}
