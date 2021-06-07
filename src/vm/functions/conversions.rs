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

use vm::costs::cost_functions::ClarityCostFunction;
use vm::costs::runtime_cost;
use vm::errors::{check_argument_count, CheckErrors, InterpreterResult as Result};
use vm::representations::SymbolicExpression;
use vm::types::BufferLength;
use vm::types::SequenceSubtype::{BufferType, StringType};
use vm::types::StringSubtype::ASCII;
use vm::types::TypeSignature::SequenceType;
use vm::types::{SequenceData, TypeSignature, Value};
use vm::{apply, eval, lookup_function, Environment, LocalContext};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EndianDirection {
    LittleEndian,
    BigEndian,
}

// The functions in this file support conversion from (buff 16) to either 1) int or 2) uint,
// from formats 1) big-endian and 2) little-endian.
//
// The function 'buff_to_int_generic' describes the logic common to these four functions.
// This is a generic function for conversion from a buffer to an int or uint. The four
// versions of Clarity function each call this, with different values for 'conversion_fn'.
//
// This function checks and parses the arguments, and calls 'conversion_fn' to do
// the specific form of conversion required.
pub fn buff_to_int_generic(
    value: Value,
    direction: EndianDirection,
    conversion_fn: fn([u8; 16]) -> Value,
) -> Result<Value> {
    match value {
        Value::Sequence(SequenceData::Buffer(ref sequence_data)) => {
            if sequence_data.len() > BufferLength(16) {
                return Err(CheckErrors::ExpectedBuffer16(TypeSignature::type_of(&value)).into());
            } else {
                let mut buf = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
                let mut original_slice = sequence_data.as_slice().to_vec();
                // 'conversion_fn' expects that the encoding is little-endian. So, if the input has a big-endian
                // encoding, reverse it. This means that we can start filling 'buf' from the beginning,
                // and any unused bytes at the end are considered padding.
                if direction == EndianDirection::BigEndian {
                    original_slice.reverse();
                }
                for (index, value) in original_slice.iter().enumerate() {
                    buf[index] = *value;
                }
                let value = conversion_fn(buf);
                return Ok(value);
            }
        }
        _ => return Err(CheckErrors::ExpectedBuffer16(TypeSignature::type_of(&value)).into()),
    };
}

// Converts a 16-byte array to an integer, assuming a little-endian encoding.
fn convert_to_int(buffer: [u8; 16]) -> Value {
    let value = i128::from_le_bytes(buffer);
    return Value::Int(value);
}

fn convert_to_uint(buffer: [u8; 16]) -> Value {
    let value = u128::from_le_bytes(buffer);
    return Value::UInt(value);
}

pub fn native_buff_to_int_le(value: Value) -> Result<Value> {
    return buff_to_int_generic(value, EndianDirection::LittleEndian, convert_to_int);
}

pub fn native_buff_to_uint_le(value: Value) -> Result<Value> {
    return buff_to_int_generic(value, EndianDirection::LittleEndian, convert_to_uint);
}

pub fn native_buff_to_int_be(value: Value) -> Result<Value> {
    return buff_to_int_generic(value, EndianDirection::BigEndian, convert_to_int);
}

pub fn native_buff_to_uint_be(value: Value) -> Result<Value> {
    return buff_to_int_generic(value, EndianDirection::BigEndian, convert_to_uint);
}
