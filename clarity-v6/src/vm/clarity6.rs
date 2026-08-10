// Copyright (C) 2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Clarity 6 adapters over epoch-shaped shared runtime services.
//!
//! Shared kernel services keep their legacy-compatible entry points, while
//! this interpreter exposes only its single semantic profile to evaluator code.

use clarity_kernel::assets::AssetMap;
use clarity_kernel::transaction::{EventBatch, TransactionFrame};

use crate::CLARITY6_BASELINE_EPOCH;
use crate::vm::errors::VmExecutionError;
use crate::vm::types::PrincipalData;

pub(crate) trait Clarity6AssetMap {
    fn add_stacking_clarity6(
        &mut self,
        principal: &PrincipalData,
        amount: u128,
    ) -> Result<(), VmExecutionError>;

    fn commit_other_clarity6(&mut self, other: AssetMap) -> Result<(), VmExecutionError>;
}

impl Clarity6AssetMap for AssetMap {
    fn add_stacking_clarity6(
        &mut self,
        principal: &PrincipalData,
        amount: u128,
    ) -> Result<(), VmExecutionError> {
        self.add_stacking(principal, amount, CLARITY6_BASELINE_EPOCH)
    }

    fn commit_other_clarity6(&mut self, other: AssetMap) -> Result<(), VmExecutionError> {
        self.commit_other(other, CLARITY6_BASELINE_EPOCH)
    }
}

pub(crate) trait Clarity6TransactionFrame {
    fn commit_clarity6(
        &mut self,
    ) -> Result<(Option<AssetMap>, Option<EventBatch>), VmExecutionError>;
}

impl Clarity6TransactionFrame for TransactionFrame {
    fn commit_clarity6(
        &mut self,
    ) -> Result<(Option<AssetMap>, Option<EventBatch>), VmExecutionError> {
        self.commit(CLARITY6_BASELINE_EPOCH)
    }
}
