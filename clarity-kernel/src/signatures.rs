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

//! Function-type vocabulary shared across engines: these types appear in the
//! stored contract-interface metadata ([`crate::analysis`]), so their shape
//! (including serde output) is consensus-adjacent and kernel-owned.
//!
//! The *rules* for checking arguments against these types are engine
//! business: each engine version implements them as extension traits over
//! these data types.

use std::fmt;

use clarity_types::representations::ClarityName;
use clarity_types::types::TypeSignature;
use stacks_common::types::StacksEpochId;

use crate::costs::CostOverflowingMath;
use crate::errors::analysis::{CommonCheckErrorKind, StaticCheckErrorKind};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionSignature {
    pub args: Vec<TypeSignature>,
    pub returns: TypeSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixedFunction {
    pub args: Vec<FunctionArg>,
    pub returns: TypeSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FunctionArgSignature {
    Union(Vec<TypeSignature>),
    Single(TypeSignature),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FunctionReturnsSignature {
    TypeOfArgAtPosition(usize),
    Fixed(TypeSignature),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FunctionType {
    Variadic(TypeSignature, TypeSignature),
    Fixed(FixedFunction),
    // Functions where the single input is a union type, e.g., Buffer or Int
    UnionArgs(Vec<TypeSignature>, TypeSignature),
    ArithmeticVariadic,
    ArithmeticUnary,
    ArithmeticBinary,
    ArithmeticComparison,
    Binary(
        FunctionArgSignature,
        FunctionArgSignature,
        FunctionReturnsSignature,
    ),
}

impl FunctionArgSignature {
    pub fn canonicalize(&self, epoch: &StacksEpochId) -> FunctionArgSignature {
        match self {
            FunctionArgSignature::Union(arg_types) => {
                let arg_types = arg_types
                    .iter()
                    .map(|arg_type| arg_type.canonicalize(epoch))
                    .collect();
                FunctionArgSignature::Union(arg_types)
            }
            FunctionArgSignature::Single(arg_type) => {
                let arg_type = arg_type.canonicalize(epoch);
                FunctionArgSignature::Single(arg_type)
            }
        }
    }
}

impl FunctionReturnsSignature {
    pub fn canonicalize(&self, epoch: &StacksEpochId) -> FunctionReturnsSignature {
        match self {
            FunctionReturnsSignature::TypeOfArgAtPosition(_) => self.clone(),
            FunctionReturnsSignature::Fixed(return_type) => {
                let return_type = return_type.canonicalize(epoch);
                FunctionReturnsSignature::Fixed(return_type)
            }
        }
    }
}

impl FunctionType {
    pub fn canonicalize(&self, epoch: &StacksEpochId) -> FunctionType {
        match self {
            FunctionType::Variadic(arg_type, return_type) => {
                let arg_type = arg_type.canonicalize(epoch);
                let return_type = return_type.canonicalize(epoch);
                FunctionType::Variadic(arg_type, return_type)
            }
            FunctionType::Fixed(fixed_function) => {
                let args = fixed_function
                    .args
                    .iter()
                    .map(|arg| FunctionArg {
                        signature: arg.signature.canonicalize(epoch),
                        name: arg.name.clone(),
                    })
                    .collect();
                let returns = fixed_function.returns.canonicalize(epoch);
                FunctionType::Fixed(FixedFunction { args, returns })
            }
            FunctionType::UnionArgs(arg_types, return_type) => {
                let arg_types = arg_types
                    .iter()
                    .map(|arg_type: &TypeSignature| arg_type.canonicalize(epoch))
                    .collect();
                let return_type = return_type.canonicalize(epoch);
                FunctionType::UnionArgs(arg_types, return_type)
            }
            FunctionType::ArithmeticVariadic => FunctionType::ArithmeticVariadic,
            FunctionType::ArithmeticUnary => FunctionType::ArithmeticUnary,
            FunctionType::ArithmeticBinary => FunctionType::ArithmeticBinary,
            FunctionType::ArithmeticComparison => FunctionType::ArithmeticComparison,
            FunctionType::Binary(arg1, arg2, return_type) => {
                let arg1 = arg1.canonicalize(epoch);
                let arg2 = arg2.canonicalize(epoch);
                let return_type = return_type.canonicalize(epoch);
                FunctionType::Binary(arg1, arg2, return_type)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionArg {
    pub signature: TypeSignature,
    pub name: ClarityName,
}

impl From<FixedFunction> for FunctionSignature {
    fn from(data: FixedFunction) -> FunctionSignature {
        let FixedFunction { args, returns } = data;
        let args = args.into_iter().map(|x| x.signature).collect();
        FunctionSignature { args, returns }
    }
}

impl FixedFunction {
    pub fn total_type_size(&self) -> Result<u64, StaticCheckErrorKind> {
        let mut function_type_size = u64::from(self.returns.type_size()?);
        for arg in self.args.iter() {
            function_type_size =
                function_type_size.cost_overflow_add(u64::from(arg.signature.type_size()?))?;
        }
        Ok(function_type_size)
    }
}

impl FunctionSignature {
    pub fn total_type_size(&self) -> Result<u64, StaticCheckErrorKind> {
        let mut function_type_size = u64::from(self.returns.type_size()?);
        for arg in self.args.iter() {
            function_type_size = function_type_size
                .cost_overflow_add(u64::from(arg.type_size()?))
                .map_err(|_| StaticCheckErrorKind::CostOverflow)?;
        }
        Ok(function_type_size)
    }

    pub fn check_args_trait_compliance(
        &self,
        epoch: &StacksEpochId,
        args: Vec<TypeSignature>,
    ) -> Result<bool, CommonCheckErrorKind> {
        if args.len() != self.args.len() {
            return Ok(false);
        }
        let args_iter = self.args.iter().zip(args.iter());
        for (expected_arg, arg) in args_iter {
            if !arg.admits_type(epoch, expected_arg)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

impl FunctionSignature {
    pub fn canonicalize(&self, epoch: &StacksEpochId) -> FunctionSignature {
        let canonicalized_args = self
            .args
            .iter()
            .map(|arg| arg.canonicalize(epoch))
            .collect();

        FunctionSignature {
            args: canonicalized_args,
            returns: self.returns.canonicalize(epoch),
        }
    }
}

impl FunctionArg {
    pub fn new(signature: TypeSignature, name: ClarityName) -> FunctionArg {
        FunctionArg { signature, name }
    }
}

impl fmt::Display for FunctionArg {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.signature)
    }
}
