// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Epoch-free adapters over shared value and signature APIs.
//!
//! `clarity-types` and `clarity-kernel` retain epoch-shaped compatibility
//! entry points for the frozen legacy engine. Clarity 6 has one semantic
//! profile, so evaluator code uses these adapters and cannot choose another.

use std::collections::BTreeMap;

use clarity_types::ClarityTypeError;

use super::signatures::{FunctionSignature, TypeSignature, TypeSignatureExt};
use super::{SequenceData, Value};
use crate::CLARITY6_BASELINE_EPOCH;
use crate::vm::ClarityVersion;
use crate::vm::analysis::errors::CommonCheckErrorKind;
use crate::vm::costs::CostTracker;
use crate::vm::errors::SyntaxBindingErrorType;
use crate::vm::representations::{ClarityName, SymbolicExpression};

pub trait Clarity6TypeSignature {
    fn admits_clarity6(&self, value: &Value) -> Result<bool, ClarityTypeError>;
    fn admits_type_clarity6(&self, actual: &TypeSignature) -> Result<bool, ClarityTypeError>;
    fn canonicalize_clarity6(&self) -> TypeSignature;
    fn least_supertype_clarity6(
        left: &TypeSignature,
        right: &TypeSignature,
    ) -> Result<TypeSignature, ClarityTypeError>;
    fn parse_type_repr_clarity6<A: CostTracker>(
        expression: &SymbolicExpression,
        accounting: &mut A,
    ) -> Result<TypeSignature, CommonCheckErrorKind>;
    fn parse_trait_type_repr_clarity6<A: CostTracker>(
        arguments: &[SymbolicExpression],
        accounting: &mut A,
    ) -> Result<BTreeMap<ClarityName, FunctionSignature>, CommonCheckErrorKind>;
}

impl Clarity6TypeSignature for TypeSignature {
    fn admits_clarity6(&self, value: &Value) -> Result<bool, ClarityTypeError> {
        self.admits(&CLARITY6_BASELINE_EPOCH, value)
    }

    fn admits_type_clarity6(&self, actual: &TypeSignature) -> Result<bool, ClarityTypeError> {
        self.admits_type(&CLARITY6_BASELINE_EPOCH, actual)
    }

    fn canonicalize_clarity6(&self) -> TypeSignature {
        self.canonicalize_v2_1()
    }

    fn least_supertype_clarity6(
        left: &TypeSignature,
        right: &TypeSignature,
    ) -> Result<TypeSignature, ClarityTypeError> {
        TypeSignature::least_supertype(&CLARITY6_BASELINE_EPOCH, left, right)
    }

    fn parse_type_repr_clarity6<A: CostTracker>(
        expression: &SymbolicExpression,
        accounting: &mut A,
    ) -> Result<TypeSignature, CommonCheckErrorKind> {
        TypeSignature::parse_type_repr(CLARITY6_BASELINE_EPOCH, expression, accounting)
    }

    fn parse_trait_type_repr_clarity6<A: CostTracker>(
        arguments: &[SymbolicExpression],
        accounting: &mut A,
    ) -> Result<BTreeMap<ClarityName, FunctionSignature>, CommonCheckErrorKind> {
        TypeSignature::parse_trait_type_repr(
            arguments,
            accounting,
            CLARITY6_BASELINE_EPOCH,
            ClarityVersion::Clarity6,
        )
    }
}

pub trait Clarity6FunctionSignature {
    fn check_args_trait_compliance_clarity6(
        &self,
        args: Vec<TypeSignature>,
    ) -> Result<bool, CommonCheckErrorKind>;
    fn canonicalize_clarity6(&self) -> FunctionSignature;
}

impl Clarity6FunctionSignature for FunctionSignature {
    fn check_args_trait_compliance_clarity6(
        &self,
        args: Vec<TypeSignature>,
    ) -> Result<bool, CommonCheckErrorKind> {
        self.check_args_trait_compliance(&CLARITY6_BASELINE_EPOCH, args)
    }

    fn canonicalize_clarity6(&self) -> FunctionSignature {
        self.canonicalize(&CLARITY6_BASELINE_EPOCH)
    }
}

pub trait Clarity6Value {
    fn cons_list_clarity6(values: Vec<Value>) -> Result<Value, ClarityTypeError>;
    fn sanitize_value_clarity6(expected: &TypeSignature, value: Value) -> Option<(Value, bool)>;
}

impl Clarity6Value for Value {
    fn cons_list_clarity6(values: Vec<Value>) -> Result<Value, ClarityTypeError> {
        Value::cons_list(values, &CLARITY6_BASELINE_EPOCH)
    }

    fn sanitize_value_clarity6(expected: &TypeSignature, value: Value) -> Option<(Value, bool)> {
        Value::sanitize_value(&CLARITY6_BASELINE_EPOCH, expected, value)
    }
}

pub trait Clarity6SequenceData {
    fn concat_clarity6(&mut self, other: SequenceData) -> Result<(), ClarityTypeError>;
    fn slice_clarity6(self, left: usize, right: usize) -> Result<Value, ClarityTypeError>;
    fn replace_at_clarity6(self, index: usize, element: Value) -> Result<Value, ClarityTypeError>;
}

impl Clarity6SequenceData for SequenceData {
    fn concat_clarity6(&mut self, other: SequenceData) -> Result<(), ClarityTypeError> {
        self.concat(&CLARITY6_BASELINE_EPOCH, other)
    }

    fn slice_clarity6(self, left: usize, right: usize) -> Result<Value, ClarityTypeError> {
        self.slice(&CLARITY6_BASELINE_EPOCH, left, right)
    }

    fn replace_at_clarity6(self, index: usize, element: Value) -> Result<Value, ClarityTypeError> {
        self.replace_at(&CLARITY6_BASELINE_EPOCH, index, element)
    }
}

pub fn parse_name_type_pairs_clarity6<A: CostTracker, E>(
    pairs: &[SymbolicExpression],
    binding_error_type: SyntaxBindingErrorType,
    accounting: &mut A,
) -> Result<Vec<(ClarityName, TypeSignature)>, E>
where
    E: for<'a> From<(CommonCheckErrorKind, &'a SymbolicExpression)>,
{
    super::signatures::parse_name_type_pairs(
        CLARITY6_BASELINE_EPOCH,
        pairs,
        binding_error_type,
        accounting,
    )
}
