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
use std::collections::BTreeMap;

use std::collections::HashMap;
use vm::variables::NativeVariables;

use crate::vm::ClarityVersion;

pub use super::errors::{
    check_argument_count, check_arguments_at_least, CheckError, CheckErrors, CheckResult,
};
use super::AnalysisDatabase;

#[cfg(test)]
mod tests;

/// Mappings that are active at a parcitular part of the call stack, but
/// which are not active throughout the entire contract.
/// 
/// For example, the mapping from variable name to function type.
struct ActiveMappings {
    pub active_traits: BTreeMap<ClarityName, ClarityName>,
}

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

/// `ReadOnlyChecker` analyzes a contract to determine whether there are any violations
/// of read-only rules.
impl<'a, 'b> ReadOnlyChecker<'a, 'b> {
    /// Factory function. 
    fn new(db: &'a mut AnalysisDatabase<'b>, contract_analysis: &'a ContractAnalysis) -> ReadOnlyChecker<'a, 'b> {
        Self {
            db,
            defined_functions: HashMap::new(),
            clarity_version: contract_analysis.clarity_version.clone(),
            contract_analysis: contract_analysis,
        }
    }

    /// Checks each top-level expression in `contract_analysis.expressions` to determine
    /// whether it comprises only read-only operations.
    /// 
    /// Returns successfully iff this function is read-only compatible.
    pub fn run(&mut self, contract_analysis: &ContractAnalysis) -> CheckResult<()> {
        // Iterate over all the top-level statements in a contract.
        for exp in contract_analysis.expressions.iter() {
            warn!("exp: {:?}", exp);
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
    /// read-only compliant.
    /// 
    /// Returns successfully iff this function is read-only compatible.
    fn check_top_level_expression(&mut self, expression: &SymbolicExpression) -> CheckResult<()> {
        warn!("expression: {:?}", expression);
        use vm::functions::define::DefineFunctionsParsed::*;
        if let Some(define_type) = DefineFunctionsParsed::try_parse(expression)? {
            match define_type {
                // The _arguments_ to Constant, PersistedVariable, FT defines must be checked to ensure that
                //   any _evaluated arguments_ supplied to them are valid with respect to read-only requirements.
                Constant { value, .. } => {
                    self.check_read_only(value)?;
                }
                PersistedVariable { initial, .. } => {
                    self.check_read_only(initial)?;
                }
                BoundedFungibleToken { max_supply, .. } => {
                    // only the *optional* total supply arg is eval'ed
                    self.check_read_only(max_supply)?;
                }
                PrivateFunction { signature, body } | PublicFunction { signature, body } => {
                    let (f_name, is_read_only) = self.check_define_function(signature, body)?;
                    self.defined_functions.insert(f_name, is_read_only);
                }
                ReadOnlyFunction { signature, body } => {
                    let bt = backtrace::Backtrace::new();
                    warn!("bt3: {:?}", bt);
                    warn!("signature {:?} body {:?}", signature, body);
                    // f_name ClarityName("wrapped-get-1") is_read_only false
                    let (f_name, is_read_only) = self.check_define_function(signature, body)?;
                    warn!("f_name {:?} is_read_only {:?}", f_name, is_read_only);
                    if !is_read_only {
        warn!("reason");
                        return Err(CheckErrors::WriteAttemptedInReadOnly.into());
                    } else {
                        self.defined_functions.insert(f_name, is_read_only);
                    }
                }
                Map { .. } | NonFungibleToken { .. } | UnboundedFungibleToken { .. } => {
                    // No arguments to (define-map ...) or (define-non-fungible-token) or fungible tokens without max supplies are eval'ed.
                }
                Trait { .. } | UseTrait { .. } | ImplTrait { .. } => {
                    // No arguments to (use-trait ...), (define-trait ...). or (impl-trait) are eval'ed.
                }
            }
        } else {
            self.check_read_only(expression)?;
        }
        Ok(())
    }


    /// Checks a function with signature `signature` and body `body` for read-only compliance.
    /// 
    /// Used to check the function definitions `PrivateFunction`, `PublicFunction` and `ReadOnlyFunction`
    /// for read-only compliance.
    /// 
    /// Returns a pair of 1) the function name defined, and 2) a `bool` indicating whether the function
    /// is read-only correct.
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

        warn!("check_define_function function_name {:#?} body {:#?}", function_name, body);
        // ClarityName("wrapped-get-1") body Atom(ClarityName("contract-call?")) Atom(ClarityName("contract")) Atom(ClarityName("get-1")) LiteralValue(UInt(1))
        warn!("check_define_function signature {:#?}", signature);
        // WARN [1627434611.344313] [src/vm/analysis/read_only_checker/mod.rs:95] [vm::analysis::trait_checker::tests::test_contract_read_only] signature [SymbolicExpression { expression: Atom(ClarityName("wrapped-get-1")), id: 8, span: Span { start_line: 2, start_column: 28, end_line: 2, end_column: 40 } }, SymbolicExpression { expression: List([SymbolicExpression { expression: Atom(ClarityName("target-contract")), id: 10, span: Span { start_line: 2, start_column: 43, end_line: 2, end_column: 57 } }, SymbolicExpression { expression: TraitReference(ClarityName("trait-2"), Imported(TraitIdentifier { name: ClarityName("trait-1"), contract_identifier: QualifiedContractIdentifier { issuer: StandardPrincipalData(S1G2081040G2081040G2081040G208105NK8PE5), name: ContractName("definition1") } })), id: 11, span: Span { start_line: 2, start_column: 59, end_line: 2, end_column: 65 } }]), id: 9, span: Span { start_line: 2, start_column: 42, end_line: 2, end_column: 68 } }]
        let is_read_only = self.check_read_only(body)?;

        Ok((function_name.clone(), is_read_only))
    }

    /// Checks `expression` to determine whether it is read-only compliant.
    /// 
    /// Returns `true` iff the expression is read-only.
    fn check_read_only(&mut self, expression: &SymbolicExpression) -> CheckResult<bool> {
        // contract-call? contract get-1
        warn!("expression {:?}", expression);
        match expression.expr {
            AtomValue(_) | LiteralValue(_) | Atom(_) | TraitReference(_, _) | Field(_) => {
                warn!("method:omni");
                Ok(true)
            },
            List(ref expression) =>{
                warn!("method:list");
                // expression starts with "contract-call?"
                let ret = self.check_function_application_read_only(expression);
                warn!("method:list {:?} {:?}", expression, ret);
                ret
            },
        }
    }

    /// Checks each expression in `expressions` to determine whether each constitutes only
    /// read-only operations.
    /// 
    /// Returns `true` iff all expressions are read-only.
    fn check_all_read_only(&mut self, expressions: &[SymbolicExpression]) -> CheckResult<bool> {
        warn!("here");
        let mut result = true;
        for expression in expressions.iter() {
        warn!("expression {:?}", expression);
            let expr_read_only = self.check_read_only(expression)?;
            result = result && expr_read_only;
        }
        Ok(result)
    }

    /// Checks the native function application of the function named by the
    /// string `function` to `args` to determine whether it is read-only
    /// compliant.
    /// 
    /// Returns `true` iff all expressions are read-only compliant.
    fn try_native_function_check(
        &mut self,
        function: &str,
        args: &[SymbolicExpression],
    ) -> Option<CheckResult<bool>> {
        let bt = backtrace::Backtrace::new();
        warn!("bt1: {:?}", bt);

        // contract-call?
        warn!("function {:?}", function);
        NativeFunctions::lookup_by_name_at_version(function, &self.clarity_version)
            .map(|function| {
                // ContractCall
                warn!("inner function {:?}", function);
                self.check_native_function(&function, args)
            }
            )
    }

    /// Checks the native function application of the NativeFunctions `function`
    /// to `args` to determine whether it is read-only compliant.
    /// 
    /// Returns `true` iff all expressions are read-only compliant.
    fn check_native_function(
        &mut self,
        function: &NativeFunctions,
        args: &[SymbolicExpression],
    ) -> CheckResult<bool> {
        // function: ContractCall
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
                self.check_all_read_only(args)
            }
            AtBlock => {
                check_argument_count(2, args)?;

                let is_block_arg_read_only = self.check_read_only(&args[0])?;
                let closure_read_only = self.check_read_only(&args[1])?;
                if !closure_read_only {
                    return Err(CheckErrors::AtBlockClosureMustBeReadOnly.into());
                }
                Ok(is_block_arg_read_only)
            }
            FetchEntry => {
                check_argument_count(2, args)?;
                self.check_all_read_only(args)
            }
            StxTransfer | StxTransferMemo | StxBurn | SetEntry | DeleteEntry | InsertEntry
            | SetVar | MintAsset | MintToken | TransferAsset | TransferToken | BurnAsset
            | BurnToken => {
                self.check_all_read_only(args)?;
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

                    if !self.check_read_only(&pair_expression[1])? {
                        return Ok(false);
                    }
                }

                self.check_all_read_only(&args[1..args.len()])
            }
            Map => {
                check_arguments_at_least(2, args)?;

                // note -- we do _not_ check here to make sure we're not mapping on
                //      a special function. that check is performed by the type checker.
                //   we're pretty directly violating type checks in this recursive step:
                //   we're asking the read only checker to check whether a function application
                //     of the _mapping function_ onto the rest of the supplied arguments would be
                //     read-only or not.
                self.check_function_application_read_only(args)
            }
            Filter => {
                check_argument_count(2, args)?;
                self.check_function_application_read_only(args)
            }
            Fold => {
                check_argument_count(3, args)?;

                // note -- we do _not_ check here to make sure we're not folding on
                //      a special function. that check is performed by the type checker.
                //   we're pretty directly violating type checks in this recursive step:
                //   we're asking the read only checker to check whether a function application
                //     of the _folding function_ onto the rest of the supplied arguments would be
                //     read-only or not.
                self.check_function_application_read_only(args)
            }
            TupleCons => {
                for pair in args.iter() {
                    let pair_expression =
                        pair.match_list().ok_or(CheckErrors::TupleExpectsPairs)?;
                    if pair_expression.len() != 2 {
                        return Err(CheckErrors::TupleExpectsPairs.into());
                    }

                    if !self.check_read_only(&pair_expression[1])? {
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

                // NOTE! This is the function we are going to call.
                // function_name: ClarityName("get-1")
                warn!("function_name: {:?}", function_name);

                // args0: Atom(ClarityName("contract"))
                warn!("args0: {:?}", args[0].expr);
                let is_function_read_only = match &args[0].expr {
                    SymbolicExpressionType::LiteralValue(Value::Principal(
                        PrincipalData::Contract(ref contract_identifier),
                    )) => {
                        warn!("location");
                        self
                        .db
                        .get_read_only_function_type(&contract_identifier, function_name)?
                        .is_some()
                    },
                    SymbolicExpressionType::Atom(_trait_reference) => {
                        // we come through here
                        // ClarityName("target-contract")

                        // Need to go:
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
                        warn!("variable_types {:#?}", self.contract_analysis.variable_types);
                        warn!("defined_traits {:#?}", self.contract_analysis.defined_traits);
                        warn!("read_only_function_types {:#?}", self.contract_analysis.read_only_function_types);
                        warn!("implemented_traits {:#?}", self.contract_analysis.implemented_traits);
                        warn!("referenced_traits {:#?}", self.contract_analysis.referenced_traits);
                        //  referenced_traits {ClarityName("trait-2"): TraitIdentifier { name: ClarityName("trait-1"), contract_identifier: QualifiedContractIdentifier { issuer: StandardPrincipalData(S1G2081040G2081040G2081040G208105NK8PE5), name: ContractName("definition1") } }}

                        // WARN [1628091489.564000] [src/vm/analysis/read_only_checker/mod.rs:344] [vm::analysis::trait_checker::tests::test_contract_read_only] location ClarityName("target-contract")
                        // WARN [1628091489.565049] [src/vm/analysis/read_only_checker/mod.rs:346] [vm::analysis::trait_checker::tests::test_contract_read_only] variable_types {}
                        // WARN [1628091489.565087] [src/vm/analysis/read_only_checker/mod.rs:347] [vm::analysis::trait_checker::tests::test_contract_read_only] defined_traits {ClarityName("trait-1"): {ClarityName("get-1"): FunctionSignature { args: [UIntType], returns: ResponseType((UIntType, UIntType)), read_only: true }}}
                        // WARN [1628091489.565152] [src/vm/analysis/read_only_checker/mod.rs:348] [vm::analysis::trait_checker::tests::test_contract_read_only] implemented_traits {}
                        // WARN [1628091489.565200] [src/vm/analysis/read_only_checker/mod.rs:349] [vm::analysis::trait_checker::tests::test_contract_read_only] referenced_traits {ClarityName("trait-2"): TraitIdentifier { name: ClarityName("trait-1"), contract_identifier: QualifiedContractIdentifier { issuer: StandardPrincipalData(S1G2081040G2081040G2081040G208105NK8PE5), name: ContractName("definition1") } }}

                        // Dynamic dispatch from a readonly-function can only be guaranteed at runtime,
                        // which would defeat granting a static readonly stamp.
                        // As such dynamic dispatch is currently forbidden.
                        false
                    }
                    _ => return Err(CheckError::new(CheckErrors::ContractCallExpectName)),
                };

                // false
                warn!("location is_function_read_only {:?}", is_function_read_only); // this is false
                self.check_all_read_only(&args[2..])
                    .map(|args_read_only| {
                        warn!("args_read_only {:?}", args_read_only);
                        args_read_only && is_function_read_only}
                    )
            }
        }
    }

    /// Checks the native function application implied by `expressions`. The first
    /// argument is used as the function name, and the tail is used as the arguments.
    /// 
    /// Returns `true` iff all expressions are read-only compliant.
    fn check_function_application_read_only(
        &mut self,
        expressions: &[SymbolicExpression],
    ) -> CheckResult<bool> {
        let (function_name, args) = expressions
            .split_first()
            .ok_or(CheckErrors::NonFunctionApplication)?;

            warn!("function_name {:?} args {:?}", function_name, args);
        let function_name = function_name
            .match_atom()
            .ok_or(CheckErrors::NonFunctionApplication)?;

            warn!("function_name {:?}", function_name);
            // function name is "contract call"
        if let Some(mut result) = self.try_native_function_check(function_name, args) {
            // this is false with "contract call"
            warn!("result {:?}", result);
            if let Err(ref mut check_err) = result {
            warn!("here");
                check_err.set_expressions(expressions);
            }
            result
        } else {
            warn!("here");
            let is_function_read_only = self
                .defined_functions
                .get(function_name)
                .ok_or(CheckErrors::UnknownFunction(function_name.to_string()))?
                .clone();
            self.check_all_read_only(args)
                .map(|args_read_only| args_read_only && is_function_read_only)
        }
    }
}
