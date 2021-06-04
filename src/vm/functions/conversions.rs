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
use vm::types::ASCIIData;
use vm::types::CharType;
use vm::types::{SequenceData, TypeSignature, Value};
use vm::{apply, eval, lookup_function, Environment, LocalContext};

use crate::vm::types::BufferLength;

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
    args: &[SymbolicExpression],
    env: &mut Environment,
    context: &LocalContext,
    conversion_fn: fn([u8; 16]) -> Value,
) -> Result<Value> {
    check_argument_count(1, args)?;
    runtime_cost(ClarityCostFunction::BuffToInt, env, 0)?;
    let mut sequence = eval(&args[0], env, context)?;
    match sequence {
        Value::Sequence(SequenceData::Buffer(ref mut sequence_data)) => {
            let mut buf = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            for (index, value) in sequence_data.as_slice().iter().enumerate() {
                buf[index] = *value;
            }
            if sequence_data.len() == BufferLength(16) {
                let value = conversion_fn(buf);
                return Ok(value);
            } else {
                return Err(
                    CheckErrors::ExpectedBuffer16(TypeSignature::type_of(&sequence)).into(),
                );
            }
        }
        _ => return Err(CheckErrors::ExpectedBuffer16(TypeSignature::type_of(&sequence)).into()),
    };
}

pub fn special_buff_to_int_le(
    args: &[SymbolicExpression],
    env: &mut Environment,
    context: &LocalContext,
) -> Result<Value> {
    fn convert_to_int_le(buffer: [u8; 16]) -> Value {
        let value = i128::from_le_bytes(buffer);
        return Value::Int(value);
    }
    return buff_to_int_generic(args, env, context, convert_to_int_le);
}

pub fn special_buff_to_uint_le(
    args: &[SymbolicExpression],
    env: &mut Environment,
    context: &LocalContext,
) -> Result<Value> {
    fn convert_to_uint_le(buffer: [u8; 16]) -> Value {
        let value = u128::from_le_bytes(buffer);
        return Value::UInt(value);
    }
    return buff_to_int_generic(args, env, context, convert_to_uint_le);
}

pub fn special_buff_to_int_be(
    args: &[SymbolicExpression],
    env: &mut Environment,
    context: &LocalContext,
) -> Result<Value> {
    fn convert_to_int_be(buffer: [u8; 16]) -> Value {
        let value = i128::from_be_bytes(buffer);
        return Value::Int(value);
    }
    return buff_to_int_generic(args, env, context, convert_to_int_be);
}

pub fn special_buff_to_uint_be(
    args: &[SymbolicExpression],
    env: &mut Environment,
    context: &LocalContext,
) -> Result<Value> {
    fn convert_to_uint_be(buffer: [u8; 16]) -> Value {
        let value = u128::from_be_bytes(buffer);
        return Value::UInt(value);
    }
    return buff_to_int_generic(args, env, context, convert_to_uint_be);
}

pub fn special_string_to_int(
    args: &[SymbolicExpression],
    env: &mut Environment,
    context: &LocalContext,
) -> Result<Value> {
    check_argument_count(1, args)?;
    runtime_cost(ClarityCostFunction::BuffToInt, env, 0)?;
    let mut sequence = eval(&args[0], env, context)?;
    match sequence {
        Value::Sequence(SequenceData::String(CharType::ASCII(ASCIIData { data }))) => {

            let as_string = String::from_utf8(data).unwrap();
            let possible_int = as_string.parse::<i128>();
            match possible_int {
                Ok(val) => return Ok(Value::Int(val)),
                Err(error) => return Err(CheckErrors::ValueError("int".to_string(), as_string).into()),
            }
        }
        _ => return Err(CheckErrors::ExpectedBuffer16(TypeSignature::type_of(&sequence)).into()),
    };
}

pub fn special_string_to_uint(
    args: &[SymbolicExpression],
    env: &mut Environment,
    context: &LocalContext,
) -> Result<Value> {
    check_argument_count(1, args)?;
    runtime_cost(ClarityCostFunction::BuffToInt, env, 0)?;
    let mut sequence = eval(&args[0], env, context)?;
    match sequence {
        Value::Sequence(SequenceData::String(CharType::ASCII(ASCIIData { data }))) => {

            let as_string = String::from_utf8(data).unwrap();
            let possible_int = as_string.parse::<u128>();
            match possible_int {
                Ok(val) => return Ok(Value::UInt(val)),
                Err(error) => return Err(CheckErrors::ValueError("uint".to_string(), as_string).into()),
            }
        }
        _ => return Err(CheckErrors::ExpectedBuffer16(TypeSignature::type_of(&sequence)).into()),
    };
}

pub fn special_int_to_ascii(
    args: &[SymbolicExpression],
    env: &mut Environment,
    context: &LocalContext,
) -> Result<Value> {
    check_argument_count(1, args)?;
    runtime_cost(ClarityCostFunction::BuffToInt, env, 0)?;
    let mut sequence = eval(&args[0], env, context)?;
    match sequence {
        Value::Sequence(SequenceData::String(CharType::ASCII(ASCIIData { data }))) => {

            let as_string = String::from_utf8(data).unwrap();
            let possible_int = as_string.parse::<i128>();
            match possible_int {
                Ok(val) => return Ok(Value::Int(val)),
                Err(error) => return Err(CheckErrors::ValueError("int".to_string(), as_string).into()),
            }
        }
        _ => return Err(CheckErrors::ExpectedBuffer16(TypeSignature::type_of(&sequence)).into()),
    };
}

pub fn special_int_to_utf8(
    args: &[SymbolicExpression],
    env: &mut Environment,
    context: &LocalContext,
) -> Result<Value> {
    check_argument_count(1, args)?;
    runtime_cost(ClarityCostFunction::BuffToInt, env, 0)?;
    let mut sequence = eval(&args[0], env, context)?;
    match sequence {
        Value::Sequence(SequenceData::String(CharType::ASCII(ASCIIData { data }))) => {

            let as_string = String::from_utf8(data).unwrap();
            let possible_int = as_string.parse::<i128>();
            match possible_int {
                Ok(val) => return Ok(Value::Int(val)),
                Err(error) => return Err(CheckErrors::ValueError("int".to_string(), as_string).into()),
            }
        }
        _ => return Err(CheckErrors::ExpectedBuffer16(TypeSignature::type_of(&sequence)).into()),
    };
}
