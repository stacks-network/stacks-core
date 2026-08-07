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

//! The engine ABI: the boundary between a Clarity execution engine (a
//! parser + analyzer + evaluator for one or more language versions) and the
//! host that embeds it.
//!
//! Data crosses this boundary only as kernel types: [`Value`]s in and out,
//! [`AssetMap`] and event batches for the host's post-condition checks, and
//! [`Diagnostic`]s for static rejection. An engine's internal representation
//! of contracts (interpreted AST, compiled Wasm, ...) never crosses.
//!
//! This is the v0 of the ABI, shaped by what the legacy interpreter can
//! provide today. Known evolution points, in dependency order:
//!
//! - **Analysis across engines**: contract interfaces are currently persisted
//!   in the engine's own serialized form; the kernel-owned stored-interface
//!   format (the `ContractAnalysis` stored/working split) will let one
//!   engine type-check calls into contracts deployed by another.
//! - **Shared cost budget**: each call currently meters costs inside the
//!   engine; a kernel-owned cost tracker handle will thread one budget
//!   through all engines in a transaction.
//! - **Cross-engine dispatch**: [`ContractDispatcher`] is defined but not yet
//!   wired through engines' `contract-call?` paths; wiring it is the
//!   mixed-engine milestone.
//! - **Epoch inversion**: [`TransactionContext`] still carries a
//!   `StacksEpochId`; it will become a kernel-owned ruleset identifier.

use clarity_types::types::{PrincipalData, QualifiedContractIdentifier};
use clarity_types::{ClarityName, ClarityVersion, Value};
use stacks_common::types::StacksEpochId;

use crate::assets::AssetMap;
use crate::database::ClarityDatabase;
use crate::diagnostic::Diagnostic;
use crate::errors::{StaticCheckError, VmExecutionError};
use crate::events::StacksTransactionEvent;

/// Errors crossing the engine ABI.
#[derive(Debug)]
pub enum EngineError {
    /// The source failed to parse. Carries only presentation data — lexer
    /// and parser error types are engine-internal.
    Parse(Vec<Diagnostic>),
    /// The contract failed static checks.
    Static(Box<StaticCheckError>),
    /// Runtime failure during evaluation.
    Execution(VmExecutionError),
    /// The engine or host violated the ABI contract (e.g. the transaction
    /// context's database was not available).
    Internal(String),
}

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EngineError::Parse(diagnostics) => {
                write!(f, "Parse failure:")?;
                for d in diagnostics {
                    write!(f, " {d}")?;
                }
                Ok(())
            }
            EngineError::Static(e) => write!(f, "Static check failure: {}", e.diagnostic),
            EngineError::Execution(e) => write!(f, "Execution failure: {e}"),
            EngineError::Internal(s) => write!(f, "Internal engine error: {s}"),
        }
    }
}

impl From<VmExecutionError> for EngineError {
    fn from(err: VmExecutionError) -> Self {
        EngineError::Execution(err)
    }
}

impl From<StaticCheckError> for EngineError {
    fn from(err: StaticCheckError) -> Self {
        EngineError::Static(Box::new(err))
    }
}

/// The transaction-scoped state a host hands to an engine for one
/// interaction (deploy, call, or read-only evaluation).
///
/// The database is transferred by value because engines assemble their own
/// execution context around it (the legacy engine's `GlobalContext` owns its
/// `ClarityDatabase`); [`Self::take_db`] / [`Self::restore_db`] make that
/// hand-off explicit, and a well-behaved engine restores the database before
/// returning — including on error paths.
pub struct TransactionContext<'a> {
    db: Option<ClarityDatabase<'a>>,
    /// Transitional: epochs are a Stacks-host concept; this becomes a
    /// kernel-owned ruleset identifier at the epoch-inversion step.
    pub epoch: StacksEpochId,
    pub mainnet: bool,
    pub chain_id: u32,
}

impl<'a> TransactionContext<'a> {
    pub fn new(
        db: ClarityDatabase<'a>,
        mainnet: bool,
        chain_id: u32,
        epoch: StacksEpochId,
    ) -> Self {
        TransactionContext {
            db: Some(db),
            epoch,
            mainnet,
            chain_id,
        }
    }

    /// Take ownership of the database for the duration of one engine
    /// interaction. Fails if a previous interaction did not restore it.
    pub fn take_db(&mut self) -> Result<ClarityDatabase<'a>, EngineError> {
        self.db.take().ok_or_else(|| {
            EngineError::Internal("Transaction context database was taken and not restored".into())
        })
    }

    /// Return the database after an engine interaction.
    pub fn restore_db(&mut self, db: ClarityDatabase<'a>) {
        self.db = Some(db);
    }

    /// Consume the context, recovering the database (if it was restored).
    pub fn into_db(self) -> Option<ClarityDatabase<'a>> {
        self.db
    }
}

/// What a contract deployment produced, for the host's post-condition and
/// event processing.
pub struct DeployOutcome {
    pub assets: AssetMap,
    pub events: Vec<StacksTransactionEvent>,
}

/// What a contract call produced.
pub struct ExecutionOutcome {
    pub value: Value,
    pub assets: AssetMap,
    pub events: Vec<StacksTransactionEvent>,
}

/// A Clarity execution engine: parser, static checker, and evaluator for one
/// or more language versions, embeddable behind this trait by any host.
///
/// Engines are stateless between interactions — all persistent state lives
/// in the [`ClarityDatabase`] carried by the [`TransactionContext`], and all
/// per-transaction state is scoped to a single method call.
pub trait Engine {
    /// Stable, human-readable engine identifier (for logs and diagnostics).
    fn name(&self) -> &'static str;

    /// The language versions this engine can execute.
    fn supported_versions(&self) -> &'static [ClarityVersion];

    /// Deploy a contract: parse, statically check, evaluate its top-level
    /// forms, and persist it (and its interface metadata) to the database.
    fn deploy_contract(
        &self,
        ctx: &mut TransactionContext,
        contract: &QualifiedContractIdentifier,
        source: &str,
        version: ClarityVersion,
        sponsor: Option<PrincipalData>,
    ) -> Result<DeployOutcome, EngineError>;

    /// Execute one public-function call on a deployed contract.
    fn execute_call(
        &self,
        ctx: &mut TransactionContext,
        sender: PrincipalData,
        sponsor: Option<PrincipalData>,
        contract: &QualifiedContractIdentifier,
        function: &ClarityName,
        args: &[Value],
    ) -> Result<ExecutionOutcome, EngineError>;

    /// Evaluate a read-only snippet in the context of a deployed contract.
    fn eval_read_only(
        &self,
        ctx: &mut TransactionContext,
        contract: &QualifiedContractIdentifier,
        program: &str,
    ) -> Result<Value, EngineError>;
}

/// Cross-engine contract-call routing: when an engine's `contract-call?`
/// targets a contract whose declared language version it does not execute,
/// it re-enters the host through this trait, and the host routes the call to
/// the right engine over the same shared transaction state.
///
/// Defined as part of the ABI now so engines can be written against it, but
/// not yet wired through the legacy interpreter's `contract-call?` path —
/// that wiring (together with kernel-enforced reentrancy and call-depth
/// checks) is the mixed-engine milestone.
pub trait ContractDispatcher {
    fn call_contract(
        &mut self,
        ctx: &mut TransactionContext,
        sender: PrincipalData,
        sponsor: Option<PrincipalData>,
        contract: &QualifiedContractIdentifier,
        function: &ClarityName,
        args: &[Value],
    ) -> Result<Value, EngineError>;
}
