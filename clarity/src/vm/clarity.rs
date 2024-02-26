use std::fmt;

use stacks_common::types::StacksEpochId;

use crate::vm::analysis::{CheckError, CheckErrors, ContractAnalysis};
use crate::vm::ast::errors::{ParseError, ParseErrors};
use crate::vm::ast::{ASTRules, ContractAST};
use crate::vm::contexts::{AssetMap, Environment, OwnedEnvironment};
use crate::vm::costs::{ExecutionCost, LimitedCostTracker};
use crate::vm::database::ClarityDatabase;
use crate::vm::errors::Error as InterpreterError;
use crate::vm::events::StacksTransactionEvent;
use crate::vm::types::{BuffData, PrincipalData, QualifiedContractIdentifier};
use crate::vm::{analysis, ast, ClarityVersion, ContractContext, SymbolicExpression, Value};

#[derive(Debug)]
pub enum Error {
    Analysis(CheckError),
    Parse(ParseError),
    Interpreter(InterpreterError),
    BadTransaction(String),
    CostError(ExecutionCost, ExecutionCost),
    AbortedByCallback(Option<Value>, AssetMap, Vec<StacksTransactionEvent>),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::CostError(ref a, ref b) => {
                write!(f, "Cost Error: {} cost exceeded budget of {} cost", a, b)
            }
            Error::Analysis(ref e) => fmt::Display::fmt(e, f),
            Error::Parse(ref e) => fmt::Display::fmt(e, f),
            Error::AbortedByCallback(..) => write!(f, "Post condition aborted transaction"),
            Error::Interpreter(ref e) => fmt::Display::fmt(e, f),
            Error::BadTransaction(ref s) => fmt::Display::fmt(s, f),
        }
    }
}

impl std::error::Error for Error {
    fn cause(&self) -> Option<&dyn std::error::Error> {
        match *self {
            Error::CostError(ref _a, ref _b) => None,
            Error::AbortedByCallback(..) => None,
            Error::Analysis(ref e) => Some(e),
            Error::Parse(ref e) => Some(e),
            Error::Interpreter(ref e) => Some(e),
            Error::BadTransaction(ref _s) => None,
        }
    }
}

impl From<CheckError> for Error {
    fn from(e: CheckError) -> Self {
        match e.err {
            CheckErrors::CostOverflow => {
                Error::CostError(ExecutionCost::max_value(), ExecutionCost::max_value())
            }
            CheckErrors::CostBalanceExceeded(a, b) => Error::CostError(a, b),
            CheckErrors::MemoryBalanceExceeded(_a, _b) => {
                Error::CostError(ExecutionCost::max_value(), ExecutionCost::max_value())
            }
            _ => Error::Analysis(e),
        }
    }
}

impl From<InterpreterError> for Error {
    fn from(e: InterpreterError) -> Self {
        match &e {
            InterpreterError::Unchecked(CheckErrors::CostBalanceExceeded(a, b)) => {
                Error::CostError(a.clone(), b.clone())
            }
            InterpreterError::Unchecked(CheckErrors::CostOverflow) => {
                Error::CostError(ExecutionCost::max_value(), ExecutionCost::max_value())
            }
            _ => Error::Interpreter(e),
        }
    }
}

impl From<ParseError> for Error {
    fn from(e: ParseError) -> Self {
        match e.err {
            ParseErrors::CostOverflow => {
                Error::CostError(ExecutionCost::max_value(), ExecutionCost::max_value())
            }
            ParseErrors::CostBalanceExceeded(a, b) => Error::CostError(a, b),
            ParseErrors::MemoryBalanceExceeded(_a, _b) => {
                Error::CostError(ExecutionCost::max_value(), ExecutionCost::max_value())
            }
            _ => Error::Parse(e),
        }
    }
}

pub trait ClarityConnection {
    /// Do something to the underlying DB that involves only reading.
    fn with_clarity_db_readonly_owned<F, R>(&mut self, to_do: F) -> R
    where
        F: FnOnce(ClarityDatabase) -> (R, ClarityDatabase);

    /// Get the current epoch for this [ClarityConnection].
    fn get_epoch(&self) -> StacksEpochId;

    fn with_clarity_db_readonly<F, R>(&mut self, to_do: F) -> R
    where
        F: FnOnce(&mut ClarityDatabase) -> R,
    {
        self.with_clarity_db_readonly_owned(|mut db| (to_do(&mut db), db))
    }

    fn with_readonly_clarity_env<F, R>(
        &mut self,
        mainnet: bool,
        chain_id: u32,
        clarity_version: ClarityVersion,
        sender: PrincipalData,
        sponsor: Option<PrincipalData>,
        cost_track: LimitedCostTracker,
        to_do: F,
    ) -> Result<R, InterpreterError>
    where
        F: FnOnce(&mut Environment) -> Result<R, InterpreterError>,
    {
        let epoch_id = self.get_epoch();
        self.with_clarity_db_readonly_owned(|clarity_db| {
            let initial_context =
                ContractContext::new(QualifiedContractIdentifier::transient(), clarity_version);
            let mut vm_env = OwnedEnvironment::new_cost_limited(
                mainnet, chain_id, clarity_db, cost_track, epoch_id,
            );
            let result = vm_env
                .execute_in_env(sender, sponsor, Some(initial_context), to_do)
                .map(|(result, _, _)| result);
            // this expect is allowed, if the database has escaped this context, then it is no longer sane
            //  and we must crash
            #[allow(clippy::expect_used)]
            let (db, _) = {
                vm_env
                    .destruct()
                    .expect("Failed to recover database reference after executing transaction")
            };
            (result, db)
        })
    }
}

pub trait TransactionConnection: ClarityConnection {
    /// Do something with this connection's Clarity environment that can be aborted
    /// with `abort_call_back`.
    ///
    /// This returns the return value of `to_do`:
    ///  * the generic term `R`,
    ///  * the asset changes during `to_do` in an [AssetMap],
    ///  * the Stacks events during the transaction,
    ///  * and a `bool` value which is `true` if the `abort_call_back` caused 
    ///    the changes to abort.
    ///
    /// If `to_do` returns an `Err` variant, then the changes are aborted.
    fn with_abort_callback<F, A, R, E>(
        &mut self,
        to_do: F,
        abort_call_back: A,
    ) -> Result<(R, AssetMap, Vec<StacksTransactionEvent>, bool), E>
    where
        A: FnOnce(&AssetMap, &mut ClarityDatabase) -> bool,
        F: FnOnce(&mut OwnedEnvironment) -> Result<(R, AssetMap, Vec<StacksTransactionEvent>), E>,
        E: From<InterpreterError>;

    /// Execute `to_do` with access to the underlying [ClarityDatabase] and a
    /// [LimitedCostTracker] instance, returning the result of `to_do`: `R`.
    fn with_clarity_db<F, R>(&mut self, to_do: F) -> R
    where
        F: FnOnce(&mut ClarityDatabase, LimitedCostTracker) -> (LimitedCostTracker, R);

    /// Analyze a provided smart contract, but do not write the resulting
    /// [ContractAnalysis] to the Clarity non-consensus database.
    fn analyze_smart_contract(
        &mut self,
        identifier: &QualifiedContractIdentifier,
        clarity_version: ClarityVersion,
        contract_content: &str,
        ast_rules: ASTRules,
    ) -> Result<(ContractAST, ContractAnalysis), Error> {
        let epoch_id = self.get_epoch();

        self.with_clarity_db(|db, mut cost_track| {
            let ast_result = ast::build_ast_with_rules(
                identifier,
                contract_content,
                &mut cost_track,
                clarity_version,
                epoch_id,
                ast_rules,
            );

            let mut contract_ast = match ast_result {
                Ok(x) => x,
                Err(e) => return (cost_track, Err(e.into())),
            };

            let result = analysis::run_analysis(
                identifier,
                &mut contract_ast.expressions,
                db,
                false,
                cost_track,
                epoch_id,
                clarity_version,
            );

            match result {
                Ok(mut contract_analysis) => {
                    let cost_track = contract_analysis.take_contract_cost_tracker();
                    (cost_track, Ok((contract_ast, contract_analysis)))
                }
                Err((e, cost_track)) => (cost_track, Err(e.into())),
            }
        })
    }

    /// Saves a [ContractAnalysis] to the Clarity non-consensus database.
    /// This will fail if the [Contract] has not already been inserted, and
    /// in general a failure here indicates a more serious problem with in
    /// the process for inserting contracts.
    fn save_analysis(
        &mut self,
        identifier: &QualifiedContractIdentifier,
        contract_analysis: &ContractAnalysis,
    ) -> Result<(), CheckError> {
        self.with_clarity_db(|db, cost_tracker| {
            db.begin();
            let result = db.insert_contract_analysis(&contract_analysis);
            match result {
                Ok(_) => {
                    let result = db
                        .commit()
                        .map_err(|e| CheckErrors::Expects(format!("{e:?}")).into());
                    (cost_tracker, result)
                }
                Err(e) => {
                    let result = db
                        .roll_back()
                        .map_err(|e| CheckErrors::Expects(format!("{e:?}")).into());
                    if result.is_err() {
                        (cost_tracker, result)
                    } else {
                        (cost_tracker, Err(e))
                    }
                }
            }
        })
        .map_err(|_| CheckError::new(CheckErrors::Expects("Failed to save contract analysis".into())))
    }

    /// Execute a STX transfer in the current block.
    /// Will throw an error if it tries to spend STX that the 'from' principal doesn't have.
    fn run_stx_transfer(
        &mut self,
        from: &PrincipalData,
        to: &PrincipalData,
        amount: u128,
        memo: &BuffData,
    ) -> Result<(Value, AssetMap, Vec<StacksTransactionEvent>), Error> {
        self.with_abort_callback(
            |vm_env| {
                vm_env
                    .stx_transfer(from, to, amount, memo)
                    .map_err(Error::from)
            },
            |_, _| false,
        )
        .and_then(|(value, assets, events, _)| Ok((value, assets, events)))
    }

    /// Execute a contract call in the current block.
    ///
    /// If an error occurs while processing the transaction, its modifications 
    /// will be rolled back.
    ///
    /// `abort_call_back` is called with an AssetMap and a ClarityDatabase reference,
    ///  where if the callback returns true, all modifications from this transaction 
    ///will be rolled back.
    ///      otherwise, they will be committed (though they may later be rolled back if the block itself is rolled back).
    fn run_contract_call<F>(
        &mut self,
        sender: &PrincipalData,
        sponsor: Option<&PrincipalData>,
        contract: &QualifiedContractIdentifier,
        public_function: &str,
        args: &[Value],
        abort_call_back: F,
    ) -> Result<(Value, AssetMap, Vec<StacksTransactionEvent>), Error>
    where
        F: FnOnce(&AssetMap, &mut ClarityDatabase) -> bool,
    {
        let expr_args: Vec<_> = args
            .iter()
            .map(|x| SymbolicExpression::atom_value(x.clone()))
            .collect();

        self.with_abort_callback(
            |vm_env| {
                vm_env
                    .execute_transaction(
                        sender.clone(),
                        sponsor.cloned(),
                        contract.clone(),
                        public_function,
                        &expr_args,
                    )
                    .map_err(Error::from)
            },
            abort_call_back,
        )
        .and_then(|(value, assets, events, aborted)| {
            if aborted {
                Err(Error::AbortedByCallback(Some(value), assets, events))
            } else {
                Ok((value, assets, events))
            }
        })
    }

    /// Initialize a contract in the current block.
    ///
    /// If an error occurs while processing the initialization, it's modifications 
    /// will be rolled back. 
    ///
    /// `abort_call_back` is called with an [AssetMap] and a [ClarityDatabase] 
    /// reference and if the callback returns true, all modifications from this 
    /// transaction will be rolled back. Otherwise, they will be committed 
    /// (though they may later be rolled back if the block itself is rolled back).
    fn initialize_smart_contract<F>(
        &mut self,
        identifier: &QualifiedContractIdentifier,
        clarity_version: ClarityVersion,
        contract_ast: &ContractAST,
        contract_str: &str,
        sponsor: Option<PrincipalData>,
        abort_call_back: F,
    ) -> Result<(AssetMap, Vec<StacksTransactionEvent>), Error>
    where
        F: FnOnce(&AssetMap, &mut ClarityDatabase) -> bool,
    {
        let (_, asset_map, events, aborted) = self.with_abort_callback(
            |vm_env| {
                vm_env
                    .initialize_contract_from_ast(
                        identifier.clone(),
                        clarity_version,
                        contract_ast,
                        contract_str,
                        sponsor,
                    )
                    .map_err(Error::from)
            },
            abort_call_back,
        )?;
        if aborted {
            Err(Error::AbortedByCallback(None, asset_map, events))
        } else {
            Ok((asset_map, events))
        }
    }
}
