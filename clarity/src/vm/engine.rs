// Copyright (C) 2026 Stacks Open Internet Foundation
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

//! The legacy engine: this crate's interpreter (Clarity 1 through
//! [`ClarityVersion::latest`]) wrapped behind the kernel's [`Engine`] ABI.
//!
//! v0 caveats, tracked in the extraction plan:
//! - Costs are metered free (`LimitedCostTracker::new_free`); the shared
//!   kernel cost-budget handle is a later ABI step.
//! - Deployment does not persist a static analysis; that lands with the
//!   kernel-owned stored-interface format.
//! - `contract-call?` between contracts stays inside this engine; routing
//!   through [`clarity_kernel::engine::ContractDispatcher`] is the
//!   mixed-engine milestone.

pub use clarity_kernel::engine::{
    ContractDispatcher, DeployOutcome, Engine, EngineError, ExecutionOutcome, TransactionContext,
};
use clarity_types::types::{PrincipalData, QualifiedContractIdentifier};
use clarity_types::{ClarityName, ClarityVersion, Value};

use crate::vm::SymbolicExpression;
use crate::vm::contexts::OwnedEnvironment;
use crate::vm::errors::ClarityEvalError;

/// The interpreter-backed engine for all legacy Clarity versions.
pub struct LegacyEngine;

fn engine_error(err: ClarityEvalError) -> EngineError {
    match err {
        ClarityEvalError::Vm(e) => EngineError::Execution(e),
        ClarityEvalError::Parse(e) => EngineError::Parse(vec![e.diagnostic]),
    }
}

impl LegacyEngine {
    /// Run `interact` inside an [`OwnedEnvironment`] assembled from the
    /// transaction context's parts, restoring the database afterwards —
    /// including on error paths.
    fn with_env<F, R>(&self, ctx: &mut TransactionContext, interact: F) -> Result<R, EngineError>
    where
        F: FnOnce(&mut OwnedEnvironment) -> Result<R, EngineError>,
    {
        let db = ctx.take_db()?;
        let mut env = OwnedEnvironment::new_free(ctx.mainnet, ctx.chain_id, db, ctx.epoch);
        let result = interact(&mut env);
        let (db, _cost_tracker) = env
            .destruct()
            .ok_or_else(|| EngineError::Internal("OwnedEnvironment failed to destruct".into()))?;
        ctx.restore_db(db);
        result
    }
}

impl Engine for LegacyEngine {
    fn name(&self) -> &'static str {
        "clarity-legacy-interpreter"
    }

    fn supported_versions(&self) -> &'static [ClarityVersion] {
        ClarityVersion::ALL
    }

    fn deploy_contract(
        &self,
        ctx: &mut TransactionContext,
        contract: &QualifiedContractIdentifier,
        source: &str,
        version: ClarityVersion,
        sponsor: Option<PrincipalData>,
    ) -> Result<DeployOutcome, EngineError> {
        self.with_env(ctx, |env| {
            let ((), assets, events) = env
                .initialize_versioned_contract(contract.clone(), version, source, sponsor)
                .map_err(engine_error)?;
            Ok(DeployOutcome { assets, events })
        })
    }

    fn execute_call(
        &self,
        ctx: &mut TransactionContext,
        sender: PrincipalData,
        sponsor: Option<PrincipalData>,
        contract: &QualifiedContractIdentifier,
        function: &ClarityName,
        args: &[Value],
    ) -> Result<ExecutionOutcome, EngineError> {
        self.with_env(ctx, |env| {
            let args: Vec<_> = args
                .iter()
                .map(|arg| SymbolicExpression::atom_value(arg.clone()))
                .collect();
            let (value, assets, events) = env
                .execute_transaction(sender, sponsor, contract.clone(), function, &args)
                .map_err(EngineError::Execution)?;
            Ok(ExecutionOutcome {
                value,
                assets,
                events,
            })
        })
    }

    fn eval_read_only(
        &self,
        ctx: &mut TransactionContext,
        contract: &QualifiedContractIdentifier,
        program: &str,
    ) -> Result<Value, EngineError> {
        self.with_env(ctx, |env| {
            let (value, _assets, _events) = env
                .eval_read_only(contract, program)
                .map_err(engine_error)?;
            Ok(value)
        })
    }
}
