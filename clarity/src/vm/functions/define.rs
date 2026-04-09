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

use std::collections::BTreeMap;

use crate::vm::callables::{DefineType, DefinedFunction};
use crate::vm::contexts::{ContractContext, ExecutionState, InvocationContext, LocalContext};
use crate::vm::errors::{
    CommonCheckErrorKind, RuntimeCheckErrorKind, SyntaxBindingErrorType, VmExecutionError,
    check_argument_count, check_arguments_at_least,
};
use crate::vm::eval;
use crate::vm::representations::SymbolicExpressionType::Field;
use crate::vm::representations::{ClarityName, SymbolicExpression};
use crate::vm::types::signatures::FunctionSignature;
use crate::vm::types::{
    TraitIdentifier, TypeSignature, TypeSignatureExt as _, Value, parse_name_type_pairs,
};

define_named_enum!(DefineFunctions {
    Constant("define-constant"),
    PrivateFunction("define-private"),
    PublicFunction("define-public"),
    ReadOnlyFunction("define-read-only"),
    Map("define-map"),
    PersistedVariable("define-data-var"),
    FungibleToken("define-fungible-token"),
    NonFungibleToken("define-non-fungible-token"),
    Trait("define-trait"),
    UseTrait("use-trait"),
    ImplTrait("impl-trait"),
});

pub enum DefineFunctionsParsed<'a> {
    Constant {
        name: &'a ClarityName,
        value: &'a SymbolicExpression,
    },
    PrivateFunction {
        signature: &'a [SymbolicExpression],
        body: &'a SymbolicExpression,
    },
    ReadOnlyFunction {
        signature: &'a [SymbolicExpression],
        body: &'a SymbolicExpression,
    },
    PublicFunction {
        signature: &'a [SymbolicExpression],
        body: &'a SymbolicExpression,
    },
    NonFungibleToken {
        name: &'a ClarityName,
        nft_type: &'a SymbolicExpression,
    },
    BoundedFungibleToken {
        name: &'a ClarityName,
        max_supply: &'a SymbolicExpression,
    },
    UnboundedFungibleToken {
        name: &'a ClarityName,
    },
    Map {
        name: &'a ClarityName,
        key_type: &'a SymbolicExpression,
        value_type: &'a SymbolicExpression,
    },
    PersistedVariable {
        name: &'a ClarityName,
        data_type: &'a SymbolicExpression,
        initial: &'a SymbolicExpression,
    },
    Trait {
        name: &'a ClarityName,
        functions: &'a [SymbolicExpression],
    },
    UseTrait {
        name: &'a ClarityName,
        trait_identifier: &'a TraitIdentifier,
    },
    ImplTrait {
        trait_identifier: &'a TraitIdentifier,
    },
}

#[derive(Debug)]
pub enum DefineResult {
    /// `define-constant`
    Variable(ClarityName, Value),
    /// `define-private`, `define-public`, `define-read-only`
    Function(ClarityName, DefinedFunction),
    /// `define-map`
    Map(ClarityName, TypeSignature, TypeSignature),
    /// `define-data-var`
    PersistedVariable(ClarityName, TypeSignature, Value),
    /// `define-fungible-token`
    FungibleToken(ClarityName, Option<u128>),
    /// `define-non-fungible-token`
    NonFungibleAsset(ClarityName, TypeSignature),
    /// `define-trait`
    Trait(ClarityName, BTreeMap<ClarityName, FunctionSignature>),
    /// `use-trait`
    UseTrait(ClarityName, TraitIdentifier),
    /// `impl-trait`
    ImplTrait(TraitIdentifier),
    /// Not a define statement
    NoDefine,
}

fn check_legal_define(
    name: &str,
    contract_context: &ContractContext,
) -> Result<(), RuntimeCheckErrorKind> {
    if contract_context.is_name_used(name) {
        Err(RuntimeCheckErrorKind::NameAlreadyUsed(name.to_string()))
    } else {
        Ok(())
    }
}

/// Handle a define-constant statement, which defines a named constant.
fn handle_define_variable(
    variable: &ClarityName,
    expression: &SymbolicExpression,
    exec_state: &mut ExecutionState,
    invoke_ctx: &InvocationContext,
) -> Result<DefineResult, VmExecutionError> {
    // is the variable name legal?
    check_legal_define(variable, invoke_ctx.contract_context)?;
    let context = LocalContext::new();
    let value = eval(expression, exec_state, invoke_ctx, &context)?.clone_with_cost(exec_state)?;
    Ok(DefineResult::Variable(variable.clone(), value))
}

fn handle_define_function(
    signature: &[SymbolicExpression],
    expression: &SymbolicExpression,
    exec_state: &mut ExecutionState,
    invoke_ctx: &InvocationContext,
    define_type: DefineType,
) -> Result<DefineResult, VmExecutionError> {
    let (function_symbol, arg_symbols) =
        signature
            .split_first()
            .ok_or(RuntimeCheckErrorKind::Unreachable(
                "Define function bad signature".to_string(),
            ))?;

    let function_name = function_symbol
        .match_atom()
        .ok_or(RuntimeCheckErrorKind::Unreachable(
            "Expected name".to_string(),
        ))?;

    check_legal_define(function_name, invoke_ctx.contract_context)?;

    let arguments = parse_name_type_pairs::<_, RuntimeCheckErrorKind>(
        *exec_state.epoch(),
        arg_symbols,
        SyntaxBindingErrorType::Eval,
        exec_state,
    )?;

    for (argument, _) in arguments.iter() {
        check_legal_define(argument, invoke_ctx.contract_context)?;
    }

    let function = DefinedFunction::new(
        arguments,
        expression.clone(),
        define_type,
        function_name,
        &invoke_ctx.contract_context.contract_identifier.to_string(),
    );

    Ok(DefineResult::Function(function_name.clone(), function))
}

fn handle_define_persisted_variable(
    variable_str: &ClarityName,
    value_type: &SymbolicExpression,
    value: &SymbolicExpression,
    exec_state: &mut ExecutionState,
    invoke_ctx: &InvocationContext,
) -> Result<DefineResult, VmExecutionError> {
    check_legal_define(variable_str, invoke_ctx.contract_context)?;

    let value_type_signature =
        TypeSignature::parse_type_repr(*exec_state.epoch(), value_type, exec_state)?;

    let context = LocalContext::new();
    let value = eval(value, exec_state, invoke_ctx, &context)?.clone_with_cost(exec_state)?;

    Ok(DefineResult::PersistedVariable(
        variable_str.clone(),
        value_type_signature,
        value,
    ))
}

fn handle_define_nonfungible_asset(
    asset_name: &ClarityName,
    key_type: &SymbolicExpression,
    exec_state: &mut ExecutionState,
    invoke_ctx: &InvocationContext,
) -> Result<DefineResult, VmExecutionError> {
    check_legal_define(asset_name, invoke_ctx.contract_context)?;

    let key_type_signature =
        TypeSignature::parse_type_repr(*exec_state.epoch(), key_type, exec_state)?;

    Ok(DefineResult::NonFungibleAsset(
        asset_name.clone(),
        key_type_signature,
    ))
}

fn handle_define_fungible_token(
    asset_name: &ClarityName,
    total_supply: Option<&SymbolicExpression>,
    exec_state: &mut ExecutionState,
    invoke_ctx: &InvocationContext,
) -> Result<DefineResult, VmExecutionError> {
    check_legal_define(asset_name, invoke_ctx.contract_context)?;

    if let Some(total_supply_expr) = total_supply {
        let context = LocalContext::new();
        let total_supply_value = eval(total_supply_expr, exec_state, invoke_ctx, &context)?;
        if let Value::UInt(total_supply_int) = total_supply_value.as_ref() {
            Ok(DefineResult::FungibleToken(
                asset_name.clone(),
                Some(*total_supply_int),
            ))
        } else {
            Err(RuntimeCheckErrorKind::TypeValueError(
                Box::new(TypeSignature::UIntType),
                total_supply_value.as_ref().to_error_string(),
            )
            .into())
        }
    } else {
        Ok(DefineResult::FungibleToken(asset_name.clone(), None))
    }
}

fn handle_define_map(
    map_str: &ClarityName,
    key_type: &SymbolicExpression,
    value_type: &SymbolicExpression,
    exec_state: &mut ExecutionState,
    invoke_ctx: &InvocationContext,
) -> Result<DefineResult, VmExecutionError> {
    check_legal_define(map_str, invoke_ctx.contract_context)?;

    let key_type_signature =
        TypeSignature::parse_type_repr(*exec_state.epoch(), key_type, exec_state)?;
    let value_type_signature =
        TypeSignature::parse_type_repr(*exec_state.epoch(), value_type, exec_state)?;

    Ok(DefineResult::Map(
        map_str.clone(),
        key_type_signature,
        value_type_signature,
    ))
}

fn handle_define_trait(
    name: &ClarityName,
    functions: &[SymbolicExpression],
    exec_state: &mut ExecutionState,
    invoke_ctx: &InvocationContext,
) -> Result<DefineResult, VmExecutionError> {
    check_legal_define(name, invoke_ctx.contract_context)?;

    let trait_signature = TypeSignature::parse_trait_type_repr(
        functions,
        exec_state,
        *exec_state.epoch(),
        *invoke_ctx.contract_context.get_clarity_version(),
    )?;

    Ok(DefineResult::Trait(name.clone(), trait_signature))
}

fn handle_use_trait(name: &ClarityName, trait_identifier: &TraitIdentifier) -> DefineResult {
    DefineResult::UseTrait(name.clone(), trait_identifier.clone())
}

fn handle_impl_trait(trait_identifier: &TraitIdentifier) -> DefineResult {
    DefineResult::ImplTrait(trait_identifier.clone())
}

impl DefineFunctions {
    pub fn try_parse(
        expression: &SymbolicExpression,
    ) -> Option<(DefineFunctions, &[SymbolicExpression])> {
        let expression = expression.match_list()?;
        let (function_name, args) = expression.split_first()?;
        let function_name = function_name.match_atom()?;
        let define_type = DefineFunctions::lookup_by_name(function_name)?;
        Some((define_type, args))
    }
}

impl<'a> DefineFunctionsParsed<'a> {
    /// Try to parse a Top-Level Expression (e.g., (define-private (foo) 1)) as
    /// a define-statement, returns None if the supplied expression is not a define.
    pub fn try_parse(
        expression: &'a SymbolicExpression,
    ) -> std::result::Result<Option<DefineFunctionsParsed<'a>>, CommonCheckErrorKind> {
        let (define_type, args) = match DefineFunctions::try_parse(expression) {
            Some(x) => x,
            None => return Ok(None),
        };
        let result = match define_type {
            DefineFunctions::Constant => {
                check_argument_count(2, args)?;
                let name = args[0]
                    .match_atom()
                    .ok_or(CommonCheckErrorKind::ExpectedName)?;
                DefineFunctionsParsed::Constant {
                    name,
                    value: &args[1],
                }
            }
            DefineFunctions::PrivateFunction => {
                check_argument_count(2, args)?;
                let signature = args[0]
                    .match_list()
                    .ok_or(CommonCheckErrorKind::DefineFunctionBadSignature)?;
                DefineFunctionsParsed::PrivateFunction {
                    signature,
                    body: &args[1],
                }
            }
            DefineFunctions::ReadOnlyFunction => {
                check_argument_count(2, args)?;
                let signature = args[0]
                    .match_list()
                    .ok_or(CommonCheckErrorKind::DefineFunctionBadSignature)?;
                DefineFunctionsParsed::ReadOnlyFunction {
                    signature,
                    body: &args[1],
                }
            }
            DefineFunctions::PublicFunction => {
                check_argument_count(2, args)?;
                let signature = args[0]
                    .match_list()
                    .ok_or(CommonCheckErrorKind::DefineFunctionBadSignature)?;
                DefineFunctionsParsed::PublicFunction {
                    signature,
                    body: &args[1],
                }
            }
            DefineFunctions::NonFungibleToken => {
                check_argument_count(2, args)?;
                let name = args[0]
                    .match_atom()
                    .ok_or(CommonCheckErrorKind::ExpectedName)?;
                DefineFunctionsParsed::NonFungibleToken {
                    name,
                    nft_type: &args[1],
                }
            }
            DefineFunctions::FungibleToken => {
                check_arguments_at_least(1, args)?;
                let name = args[0]
                    .match_atom()
                    .ok_or(CommonCheckErrorKind::ExpectedName)?;
                if args.len() == 1 {
                    DefineFunctionsParsed::UnboundedFungibleToken { name }
                } else if args.len() == 2 {
                    DefineFunctionsParsed::BoundedFungibleToken {
                        name,
                        max_supply: &args[1],
                    }
                } else {
                    return Err(CommonCheckErrorKind::IncorrectArgumentCount(1, args.len()));
                }
            }
            DefineFunctions::Map => {
                check_argument_count(3, args)?;
                let name = args[0]
                    .match_atom()
                    .ok_or(CommonCheckErrorKind::ExpectedName)?;
                DefineFunctionsParsed::Map {
                    name,
                    key_type: &args[1],
                    value_type: &args[2],
                }
            }
            DefineFunctions::PersistedVariable => {
                check_argument_count(3, args)?;
                let name = args[0]
                    .match_atom()
                    .ok_or(CommonCheckErrorKind::ExpectedName)?;
                DefineFunctionsParsed::PersistedVariable {
                    name,
                    data_type: &args[1],
                    initial: &args[2],
                }
            }
            DefineFunctions::Trait => {
                check_argument_count(2, args)?;
                let name = args[0]
                    .match_atom()
                    .ok_or(CommonCheckErrorKind::ExpectedName)?;
                DefineFunctionsParsed::Trait {
                    name,
                    functions: &args[1..],
                }
            }
            DefineFunctions::UseTrait => {
                check_argument_count(2, args)?;
                let name = args[0]
                    .match_atom()
                    .ok_or(CommonCheckErrorKind::ExpectedName)?;
                match &args[1].expr {
                    Field(field) => DefineFunctionsParsed::UseTrait {
                        name,
                        trait_identifier: field,
                    },
                    _ => return Err(CommonCheckErrorKind::ExpectedTraitIdentifier),
                }
            }
            DefineFunctions::ImplTrait => {
                check_argument_count(1, args)?;
                match &args[0].expr {
                    Field(field) => DefineFunctionsParsed::ImplTrait {
                        trait_identifier: field,
                    },
                    _ => return Err(CommonCheckErrorKind::ExpectedTraitIdentifier),
                }
            }
        };
        Ok(Some(result))
    }
}

pub fn evaluate_define(
    expression: &SymbolicExpression,
    exec_state: &mut ExecutionState,
    invoke_ctx: &InvocationContext,
) -> Result<DefineResult, VmExecutionError> {
    if let Some(define_type) = DefineFunctionsParsed::try_parse(expression)? {
        match define_type {
            DefineFunctionsParsed::Constant { name, value } => {
                handle_define_variable(name, value, exec_state, invoke_ctx)
            }
            DefineFunctionsParsed::PrivateFunction { signature, body } => {
                handle_define_function(signature, body, exec_state, invoke_ctx, DefineType::Private)
            }
            DefineFunctionsParsed::ReadOnlyFunction { signature, body } => handle_define_function(
                signature,
                body,
                exec_state,
                invoke_ctx,
                DefineType::ReadOnly,
            ),
            DefineFunctionsParsed::PublicFunction { signature, body } => {
                handle_define_function(signature, body, exec_state, invoke_ctx, DefineType::Public)
            }
            DefineFunctionsParsed::NonFungibleToken { name, nft_type } => {
                handle_define_nonfungible_asset(name, nft_type, exec_state, invoke_ctx)
            }
            DefineFunctionsParsed::BoundedFungibleToken { name, max_supply } => {
                handle_define_fungible_token(name, Some(max_supply), exec_state, invoke_ctx)
            }
            DefineFunctionsParsed::UnboundedFungibleToken { name } => {
                handle_define_fungible_token(name, None, exec_state, invoke_ctx)
            }
            DefineFunctionsParsed::Map {
                name,
                key_type,
                value_type,
            } => handle_define_map(name, key_type, value_type, exec_state, invoke_ctx),
            DefineFunctionsParsed::PersistedVariable {
                name,
                data_type,
                initial,
            } => handle_define_persisted_variable(name, data_type, initial, exec_state, invoke_ctx),
            DefineFunctionsParsed::Trait { name, functions } => {
                handle_define_trait(name, functions, exec_state, invoke_ctx)
            }
            DefineFunctionsParsed::UseTrait {
                name,
                trait_identifier,
            } => Ok(handle_use_trait(name, trait_identifier)),
            DefineFunctionsParsed::ImplTrait { trait_identifier } => {
                Ok(handle_impl_trait(trait_identifier))
            }
        }
    } else {
        Ok(DefineResult::NoDefine)
    }
}

#[cfg(test)]
mod test {
    use clarity_types::Value;
    use clarity_types::representations::SymbolicExpression;
    use clarity_types::types::QualifiedContractIdentifier;
    use stacks_common::consts::CHAIN_ID_TESTNET;
    use stacks_common::types::StacksEpochId;

    use crate::vm::analysis::errors::RuntimeCheckErrorKind;
    use crate::vm::analysis::type_checker::v2_1::MAX_FUNCTION_PARAMETERS;
    use crate::vm::callables::DefineType;
    use crate::vm::contexts::{ExecutionState, GlobalContext, InvocationContext};
    use crate::vm::costs::LimitedCostTracker;
    use crate::vm::database::MemoryBackingStore;
    use crate::vm::errors::VmExecutionError;
    use crate::vm::functions::define::{handle_define_function, handle_define_trait};
    use crate::vm::tests::test_clarity_versions;
    use crate::vm::{CallStack, ClarityVersion, ContractContext, LocalContext};

    #[apply(test_clarity_versions)]
    fn bad_syntax_binding_define_function(
        #[case] version: ClarityVersion,
        #[case] epoch: StacksEpochId,
    ) {
        // ---- BAD SIGNATURE ----
        // Instead of ((x uint)), we pass (x)
        let bad_signature = vec![
            SymbolicExpression::atom("f".into()),
            SymbolicExpression::atom("x".into()), // NOT a (name type) list
        ];

        let body = SymbolicExpression::atom_value(Value::UInt(1));

        let mut marf = MemoryBackingStore::new();
        let mut global_context = GlobalContext::new(
            false,
            CHAIN_ID_TESTNET,
            marf.as_clarity_db(),
            LimitedCostTracker::new_free(),
            epoch,
        );

        let contract_context =
            ContractContext::new(QualifiedContractIdentifier::transient(), version);

        let context = LocalContext::new();
        let mut call_stack = CallStack::new();

        let mut exec_state = ExecutionState {
            global_context: &mut global_context,
            call_stack: &mut call_stack,
        };
        let invoke_ctx = InvocationContext {
            contract_context: &contract_context,
            sender: None,
            caller: None,
            sponsor: None,
        };

        let err = handle_define_function(
            &bad_signature,
            &body,
            &mut exec_state,
            &invoke_ctx,
            DefineType::Public,
        )
        .unwrap_err();

        assert_eq!(
            VmExecutionError::RuntimeCheck(RuntimeCheckErrorKind::Unreachable(
                "Bad syntax binding: NotList(Eval, 0)".to_string()
            )),
            err,
        );
    }

    #[apply(test_clarity_versions)]
    fn handle_define_trait_too_many_function_parameters(
        #[case] version: ClarityVersion,
        #[case] epoch: StacksEpochId,
    ) {
        if epoch < StacksEpochId::Epoch33 {
            return;
        }
        // Build a trait method with MORE than MAX_FUNCTION_PARAMETERS arguments
        // (f (uint uint uint ... ) (response uint uint))
        let too_many_args =
            vec![SymbolicExpression::atom("uint".into()); MAX_FUNCTION_PARAMETERS + 1];

        let method = SymbolicExpression::list(vec![
            SymbolicExpression::atom("f".into()),
            SymbolicExpression::list(too_many_args),
            SymbolicExpression::list(vec![
                SymbolicExpression::atom("response".into()),
                SymbolicExpression::atom("uint".into()),
                SymbolicExpression::atom("uint".into()),
            ]),
        ]);

        // This is the `( (f (...) (response ...)) )` wrapper
        let trait_body = vec![SymbolicExpression::list(vec![method])];

        let mut marf = MemoryBackingStore::new();
        let mut global_context = GlobalContext::new(
            false,
            CHAIN_ID_TESTNET,
            marf.as_clarity_db(),
            LimitedCostTracker::new_free(),
            epoch,
        );

        let contract_context =
            ContractContext::new(QualifiedContractIdentifier::transient(), version);

        let mut call_stack = CallStack::new();

        let mut exec_state = ExecutionState {
            global_context: &mut global_context,
            call_stack: &mut call_stack,
        };
        let invoke_ctx = InvocationContext {
            contract_context: &contract_context,
            sender: None,
            caller: None,
            sponsor: None,
        };

        let err = handle_define_trait(
            &"bad-trait".into(),
            &trait_body,
            &mut exec_state,
            &invoke_ctx,
        )
        .unwrap_err();

        assert_eq!(
            VmExecutionError::RuntimeCheck(RuntimeCheckErrorKind::Unreachable(
                "Too many function params: found 257, allowed 256".to_string()
            )),
            err
        );
    }
}
