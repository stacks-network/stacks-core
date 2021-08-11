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

use vm::analysis::types::{AnalysisPass, ContractAnalysis};
use vm::functions::define::DefineFunctionsParsed;
use vm::functions::tuples;
use vm::functions::NativeFunctions;
use vm::representations::SymbolicExpressionType::{
    Atom, AtomValue, Field, List, LiteralValue, TraitReference,
};
use vm::representations::{ClarityName, SymbolicExpression, SymbolicExpressionType};
use vm::types::{parse_name_type_pairs, PrincipalData, TupleTypeSignature, TypeSignature, Value};

use std::collections::HashMap;
use vm::variables::NativeVariables;

use crate::vm::ClarityVersion;

pub use super::errors::{
    check_argument_count, check_arguments_at_least, CheckError, CheckErrors, CheckResult,
};
use super::AnalysisDatabase;

#[cfg(test)]
mod tests;

/// `ReadOnlyChecker` analyzes a contract to determine whether there are any violations
/// of read-only declarations. That is, a violating contract is one in which a function
/// that is declared as read-only actually attempts to modify chainstate.
///
/// A contract that does not violate its read-only declarations is called
/// *read-only correct*.
pub struct ReadOnlyChecker<'a, 'b> {
    db: &'a mut AnalysisDatabase<'b>,
    defined_functions: HashMap<ClarityName, bool>,
    clarity_version: ClarityVersion,
    contract_analysis: &'a ContractAnalysis,
}

impl<'a, 'b> AnalysisPass for ReadOnlyChecker<'a, 'b> {
    fn run_pass(
        contract_analysis: &mut ContractAnalysis,
        analysis_db: &mut AnalysisDatabase,
    ) -> CheckResult<()> {
        let mut command = ReadOnlyChecker::new(analysis_db, &contract_analysis);
        command.run(contract_analysis)?;
        Ok(())
    }
}

impl<'a, 'b> ReadOnlyChecker<'a, 'b> {
    fn new(
        db: &'a mut AnalysisDatabase<'b>,
        contract_analysis: &'a ContractAnalysis,
    ) -> ReadOnlyChecker<'a, 'b> {
        Self {
            db,
            defined_functions: HashMap::new(),
            clarity_version: (*contract_analysis).clarity_version.clone(),
            contract_analysis: contract_analysis,
        }
    }

    /// Checks each top-level expression in `contract_analysis.expressions` for read-only correctness.
    ///
    /// Returns successfully iff this function is read-only correct.
    ///
    /// # Errors
    ///
    /// - Returns CheckErrors::WriteAttemptedInReadOnly if there is a read-only violation, i.e.
    /// if some function marked read-only attempts to modify the chainstate.
    pub fn run(&mut self, contract_analysis: &ContractAnalysis) -> CheckResult<()> {
        // Iterate over all the top-level statements in a contract.
        for exp in contract_analysis.expressions.iter() {
            let mut result = self.check_top_level_expression(&exp);
            if let Err(ref mut error) = result {
                if !error.has_expression() {
                    error.set_expression(&exp);
                }
            }
            result?
        }

        Ok(())
    }

    /// Checks the top-level expression `expression` to determine whether it is
    /// read-only compliant. `expression` maybe have composite structure that can be
    /// parsed into multiple expressions.
    ///
    /// Returns successfully iff this function is read-only correct.
    ///
    /// # Errors
    ///
    /// - Returns CheckErrors::WriteAttemptedInReadOnly if there is a read-only violation, i.e.
    /// if some function marked read-only attempts to modify the chainstate.
    fn check_top_level_expression(&mut self, expression: &SymbolicExpression) -> CheckResult<()> {
        use vm::functions::define::DefineFunctionsParsed::*;
        if let Some(define_type) = DefineFunctionsParsed::try_parse(expression)? {
            match define_type {
                // The *arguments* to Constant, PersistedVariable, FT defines must be checked to ensure that
                //   any *evaluated arguments* supplied to them are valid with respect to read-only requirements.
                Constant { value, .. } => {
                    self.check_atomic_expression_is_read_only(value, None)?;
                }
                PersistedVariable { initial, .. } => {
                    self.check_atomic_expression_is_read_only(initial, None)?;
                }
                BoundedFungibleToken { max_supply, .. } => {
                    // Only the *optional* total supply argument is eval'ed.
                    self.check_atomic_expression_is_read_only(max_supply, None)?;
                }
                PrivateFunction { signature, body } | PublicFunction { signature, body } => {
                    let (function_name, is_read_only) =
                        self.check_define_function(signature, body)?;
                    self.defined_functions.insert(function_name, is_read_only);
                }
                ReadOnlyFunction { signature, body } => {
                    let (function_name, is_read_only) =
                        self.check_define_function(signature, body)?;
                    if !is_read_only {
                        return Err(CheckErrors::WriteAttemptedInReadOnly.into());
                    } else {
                        self.defined_functions.insert(function_name, is_read_only);
                    }
                }
                Map { .. } | NonFungibleToken { .. } | UnboundedFungibleToken { .. } => {
                    // No arguments to (define-map ...) or (define-non-fungible-token) or fungible tokens without
                    // max supplies are eval'ed.
                }
                Trait { .. } | UseTrait { .. } | ImplTrait { .. } => {
                    // No arguments to (use-trait ...), (define-trait ...). or (impl-trait) are eval'ed.
                }
            }
        } else {
            self.check_atomic_expression_is_read_only(expression, None)?;
        }
        Ok(())
    }

    /// Checks that a function with signature `signature` and body `body` is read-only.
    ///
    /// This is used to check the function definitions `PrivateFunction`, `PublicFunction`
    /// and `ReadOnlyFunction`.
    ///
    /// Returns a pair of 1) the function name defined, and 2) a `bool` indicating whether the function
    /// is read-only.
    fn check_define_function(
        &mut self,
        signature: &[SymbolicExpression],
        body: &SymbolicExpression,
    ) -> CheckResult<(ClarityName, bool)> {
        let function_name = signature
            .get(0)
            .ok_or(CheckErrors::DefineFunctionBadSignature)?
            .match_atom()
            .ok_or(CheckErrors::BadFunctionName)?;

        warn!("signature2 {:?}", signature);

        let is_read_only = self.check_atomic_expression_is_read_only(body, Some(signature))?;

        Ok((function_name.clone(), is_read_only))
    }

    /// Checks an atomic `expression` to determine whether it is read-only correct.
    /// An atomic expression is one that does not need to be parsed into multiple expressions.
    ///
    /// Returns `true` iff the expression is read-only.
    fn check_atomic_expression_is_read_only(
        &mut self,
        expression: &SymbolicExpression,
        signature: Option<&[SymbolicExpression]>,
    ) -> CheckResult<bool> {
        match expression.expr {
            AtomValue(_) | LiteralValue(_) | Atom(_) | TraitReference(_, _) | Field(_) => Ok(true),
            List(ref expression) => {
                self.check_expression_application_is_read_only(expression, signature)
            }
        }
    }

    /// Checks each expression in `expressions` to determine whether each uses only
    /// read-only operations.
    ///
    /// Returns `true` iff all expressions are read-only.
    fn check_each_expression_is_read_only(
        &mut self,
        expressions: &[SymbolicExpression],
        signature: Option<&[SymbolicExpression]>,
    ) -> CheckResult<bool> {
        let mut result = true;
        for expression in expressions.iter() {
            let expr_read_only =
                self.check_atomic_expression_is_read_only(expression, signature)?;
            result = result && expr_read_only;
        }
        Ok(result)
    }

    /// Checks the native function application of the function named by the
    /// string `function` to `args` to determine whether it is read-only
    /// compliant.
    ///
    /// Returns `true` iff this function application is read-only.
    fn try_check_native_function_is_read_only(
        &mut self,
        function: &str,
        args: &[SymbolicExpression],
        signature: Option<&[SymbolicExpression]>,
    ) -> Option<CheckResult<bool>> {
        NativeFunctions::lookup_by_name_at_version(function, &self.clarity_version)
            .map(|function| self.check_native_function_is_read_only(&function, args, signature))
    }

    /// Checks the native function application of the NativeFunctions `function`
    /// to `args` to determine whether it is read-only compliant.
    ///
    /// Returns `true` iff this function application is read-only.
    fn check_native_function_is_read_only(
        &mut self,
        function: &NativeFunctions,
        args: &[SymbolicExpression],
        signature: Option<&[SymbolicExpression]>,
    ) -> CheckResult<bool> {
        use vm::functions::NativeFunctions::*;

        match function {
            Add | Subtract | Divide | Multiply | CmpGeq | CmpLeq | CmpLess | CmpGreater
            | Modulo | Power | Sqrti | Log2 | BitwiseXOR | And | Or | Not | Hash160 | Sha256
            | Keccak256 | Equals | If | Sha512 | Sha512Trunc256 | Secp256k1Recover
            | Secp256k1Verify | ConsSome | ConsOkay | ConsError | DefaultTo | UnwrapRet
            | UnwrapErrRet | IsOkay | IsNone | Asserts | Unwrap | UnwrapErr | Match | IsErr
            | IsSome | TryRet | ToUInt | ToInt | BuffToIntLe | BuffToUIntLe | BuffToIntBe
            | BuffToUIntBe | IntToAscii | IntToUtf8 | StringToInt | StringToUInt | IsStandard
            | Append | Concat | AsMaxLen | ContractOf | PrincipalOf | ListCons | GetBlockInfo
            | TupleGet | TupleMerge | Len | Print | AsContract | Begin | FetchVar
            | GetStxBalance | StxGetAccount | GetTokenBalance | GetAssetOwner | GetTokenSupply
            | ElementAt | IndexOf => {
                // Check all arguments.
                self.check_each_expression_is_read_only(args, signature)
            }
            AtBlock => {
                check_argument_count(2, args)?;

                let is_block_arg_read_only =
                    self.check_atomic_expression_is_read_only(&args[0], signature)?;
                let closure_read_only =
                    self.check_atomic_expression_is_read_only(&args[1], signature)?;
                if !closure_read_only {
                    return Err(CheckErrors::AtBlockClosureMustBeReadOnly.into());
                }
                Ok(is_block_arg_read_only)
            }
            FetchEntry => {
                check_argument_count(2, args)?;
                self.check_each_expression_is_read_only(args, signature)
            }
            StxTransfer | StxTransferMemo | StxBurn | SetEntry | DeleteEntry | InsertEntry
            | SetVar | MintAsset | MintToken | TransferAsset | TransferToken | BurnAsset
            | BurnToken => {
                self.check_each_expression_is_read_only(args, signature)?;
                Ok(false)
            }
            Let => {
                check_arguments_at_least(2, args)?;

                let binding_list = args[0].match_list().ok_or(CheckErrors::BadLetSyntax)?;

                for pair in binding_list.iter() {
                    let pair_expression = pair.match_list().ok_or(CheckErrors::BadSyntaxBinding)?;
                    if pair_expression.len() != 2 {
                        return Err(CheckErrors::BadSyntaxBinding.into());
                    }

                    if !self.check_atomic_expression_is_read_only(&pair_expression[1], None)? {
                        return Ok(false);
                    }
                }

                self.check_each_expression_is_read_only(&args[1..args.len()], signature)
            }
            Map => {
                check_arguments_at_least(2, args)?;

                // note -- we do _not_ check here to make sure we're not mapping on
                //      a special function. that check is performed by the type checker.
                //   we're pretty directly violating type checks in this recursive step:
                //   we're asking the read only checker to check whether a function application
                //     of the _mapping function_ onto the rest of the supplied arguments would be
                //     read-only or not.
                self.check_expression_application_is_read_only(args, signature)
            }
            Filter => {
                check_argument_count(2, args)?;
                self.check_expression_application_is_read_only(args, signature)
            }
            Fold => {
                check_argument_count(3, args)?;

                // note -- we do _not_ check here to make sure we're not folding on
                //      a special function. that check is performed by the type checker.
                //   we're pretty directly violating type checks in this recursive step:
                //   we're asking the read only checker to check whether a function application
                //     of the _folding function_ onto the rest of the supplied arguments would be
                //     read-only or not.
                self.check_expression_application_is_read_only(args, signature)
            }
            TupleCons => {
                for pair in args.iter() {
                    let pair_expression =
                        pair.match_list().ok_or(CheckErrors::TupleExpectsPairs)?;
                    if pair_expression.len() != 2 {
                        return Err(CheckErrors::TupleExpectsPairs.into());
                    }

                    if !self.check_atomic_expression_is_read_only(&pair_expression[1], signature)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            ContractCall => {
                check_arguments_at_least(2, args)?;

                let function_name = args[1]
                    .match_atom()
                    .ok_or(CheckErrors::ContractCallExpectName)?;

                let is_function_read_only = match &args[0].expr {
                    SymbolicExpressionType::LiteralValue(Value::Principal(
                        PrincipalData::Contract(ref contract_identifier),
                    )) => self
                        .db
                        .get_read_only_function_type(&contract_identifier, function_name)?
                        .is_some(),
                    SymbolicExpressionType::Atom(_trait_reference) => {
                        // Dynamic dispatch from a readonly-function can only be guaranteed at runtime,
                        // which would defeat granting a static readonly stamp.
                        // As such dynamic dispatch is currently forbidden.
                        // target_contract -> trait-2
                        // trait-2 -> definition1, trait-1
                        // trait-1, get-1 -> function def, includes read only

                        // Key Note: xx1
                        // This is where we reaach and conclude the function is not read-only.
                        // This should somehow use the "trait reference" to look up a trait, and check function_name and see what it's type is.
                        // let bt = backtrace::Backtrace::new();
                        // warn!("bt20: {:?}", bt);

                        // can cross-reference trait_reference with read_only_function_types
                        // But!.. how do we know which function we are in?
                        warn!("trait_reference_ {:?}", _trait_reference);
                        warn!("signature1 {:#?}", signature);
                        warn!(
                            "variable_types {:#?}",
                            self.contract_analysis.variable_types
                        );
                        warn!(
                            "defined_traits {:#?}",
                            self.contract_analysis.defined_traits
                        );
                        warn!(
                            "public_function_types {:#?}",
                            self.contract_analysis.public_function_types
                        );
                        warn!(
                            "read_only_function_types {:#?}",
                            self.contract_analysis.read_only_function_types
                        );
                        warn!(
                            "implemented_traits {:#?}",
                            self.contract_analysis.implemented_traits
                        );
                        warn!(
                            "referenced_traits {:#?}",
                            self.contract_analysis.referenced_traits
                        );
                        false
                    }
                    _ => return Err(CheckError::new(CheckErrors::ContractCallExpectName)),
                };

                self.check_each_expression_is_read_only(&args[2..], signature)
                    .map(|args_read_only| args_read_only && is_function_read_only)
            }
        }
    }

    /// Checks the native function application implied by `expressions`. The first
    /// argument is used as the function name, and the tail is used as the arguments.
    ///
    /// Returns `true` iff the function application is read-only.
    fn check_expression_application_is_read_only(
        &mut self,
        expressions: &[SymbolicExpression],
        signature: Option<&[SymbolicExpression]>,
    ) -> CheckResult<bool> {
        let (function_name, args) = expressions
            .split_first()
            .ok_or(CheckErrors::NonFunctionApplication)?;

        let function_name = function_name
            .match_atom()
            .ok_or(CheckErrors::NonFunctionApplication)?;

        if let Some(mut result) =
            self.try_check_native_function_is_read_only(function_name, args, signature)
        {
            if let Err(ref mut check_err) = result {
                check_err.set_expressions(expressions);
            }
            result
        } else {
            let is_function_read_only = self
                .defined_functions
                .get(function_name)
                .ok_or(CheckErrors::UnknownFunction(function_name.to_string()))?
                .clone();
            self.check_each_expression_is_read_only(args, signature)
                .map(|args_read_only| args_read_only && is_function_read_only)
        }
    }
}
