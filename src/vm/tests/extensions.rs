// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2021 Stacks Open Internet Foundation
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

use std::collections::HashMap;

use crate::types::chainstate::BlockHeaderHash;
use crate::types::chainstate::StacksBlockId;
use crate::types::proof::ClarityMarfTrieId;
use chainstate::stacks::index::storage::TrieFileStorage;
use clarity_vm::clarity::ClarityInstance;
use util::hash::hex_bytes;
use vm::ast;
use vm::ast::errors::ParseErrors;
use vm::callables::FunctionIdentifier;
use vm::contexts::{ContractContext, Environment, GlobalContext, LocalContext, OwnedEnvironment};
use vm::contracts::Contract;
use vm::costs::{ExecutionCost, LimitedCostTracker};
use vm::database::{ClarityDatabase, NULL_BURN_STATE_DB, NULL_HEADER_DB};
use vm::errors::{CheckErrors, Error, RuntimeErrorType};
use vm::execute as inner_vm_execute;
use vm::representations::SymbolicExpression;
use vm::tests::{execute, symbols_from_values, with_marfed_environment, with_memory_environment};
use vm::types::{
    OptionalData, PrincipalData, QualifiedContractIdentifier, ResponseData, StandardPrincipalData,
    TypeSignature, Value,
};

use vm::errors::InterpreterResult as Result;
use vm::eval_all;
use vm::extensions::ExtensionImplementation;

use clarity_vm::database::MemoryBackingStore;

use chainstate::stacks::boot::BOOT_CODE_EXTENSIONS_2_1;
use core::StacksEpochId;
use util::boot::boot_code_id;

// (define-public (boop) (ok u3))
fn native_boop(_env: &mut Environment, _context: &LocalContext) -> Result<Value> {
    Value::okay(Value::UInt(3))
}

// (define-public (do-math (a uint) (b uint)) (ok (+ (* u2 a) b)))
fn native_do_math(env: &mut Environment, context: &LocalContext) -> Result<Value> {
    let a = context
        .variables
        .get("a".into())
        .unwrap()
        .clone()
        .expect_u128();
    let b = context
        .variables
        .get("b".into())
        .unwrap()
        .clone()
        .expect_u128();
    Value::okay(Value::UInt(2 * a + b))
}

// Test that we can replace a function's body with a native implementation
#[test]
fn test_native_function_replacement() {
    let clarity_boop = r#"
    (define-public (boop) (ok u0))
    (define-public (do-math (a uint) (b uint)) (ok (+ a b)))
    (define-public (do-boop-math (c uint) (d uint))
        (let (
            (boop-value (unwrap-panic (boop)))
        )
        (ok (+ boop-value (unwrap-panic (do-math c d)))))
    )
    "#;
    let contract_identifier = QualifiedContractIdentifier::local("boop").unwrap();

    let mut marf = MemoryBackingStore::new();

    // deploy the clarity "boop" contract
    let mut owned_env = OwnedEnvironment::new(marf.as_clarity_db());

    owned_env
        .initialize_contract(contract_identifier.clone(), clarity_boop, None)
        .unwrap();

    {
        let mut env = owned_env.get_exec_environment(None, None);
        let eval_result = env.eval_read_only(&contract_identifier, "(boop)").unwrap();

        // clarity code gets executed
        if eval_result.expect_result_ok().expect_u128() == 0 {
        } else {
            panic!("clarity boop did not return u0");
        }

        let eval_result = env
            .eval_read_only(&contract_identifier, "(do-math u1 u2)")
            .unwrap();

        // clarity code gets executed
        if eval_result.expect_result_ok().expect_u128() == 3 {
        } else {
            panic!("clarity do-math did not return u3");
        }

        let eval_result = env
            .eval_read_only(&contract_identifier, "(do-boop-math u1 u2)")
            .unwrap();

        // clarity code gets executed
        if eval_result.expect_result_ok().expect_u128() == 3 {
        } else {
            panic!("clarity do-boop-math did not return u3");
        }
    }

    // install native versions
    owned_env.insert_extension_function_implementation(
        FunctionIdentifier::new_contract_function(&contract_identifier, "boop"),
        ExtensionImplementation::new(&native_boop),
    );
    owned_env.insert_extension_function_implementation(
        FunctionIdentifier::new_contract_function(&contract_identifier, "do-math"),
        ExtensionImplementation::new(&native_do_math),
    );

    {
        let mut env = owned_env.get_exec_environment(None, None);
        let eval_result = env.eval_read_only(&contract_identifier, "(boop)").unwrap();

        // native code gets executed
        if eval_result.expect_result_ok().expect_u128() == 3 {
        } else {
            panic!("native boop did not return u3");
        }

        let eval_result = env
            .eval_read_only(&contract_identifier, "(do-math u1 u2)")
            .unwrap();

        // native code gets executed, with arguments
        if eval_result.expect_result_ok().expect_u128() == 4 {
        } else {
            panic!("native do-math did not return u4");
        }

        let eval_result = env
            .eval_read_only(&contract_identifier, "(do-boop-math u1 u2)")
            .unwrap();

        // native code gets executed, through function calls and let-bindings
        if eval_result.expect_result_ok().expect_u128() == 7 {
        } else {
            panic!("native do-boop-math did not return u7");
        }
    }
}

// Test that the epoch determines the availability of extension functions
#[test]
fn test_native_extension_in_epoch() {
    let clarity_boop = r#"
    (define-public (boop) (ok u0))
    (define-public (do-math (a uint) (b uint)) (ok (+ a b)))
    (define-public (do-boop-math (c uint) (d uint))
        (let (
            (boop-value (unwrap-panic (boop)))
        )
        (ok (+ boop-value (unwrap-panic (do-math c d)))))
    )
    "#;
    let contract_identifier = QualifiedContractIdentifier::local("boop").unwrap();
    let mut marf = MemoryBackingStore::new();

    // epoch 2.0
    {
        let mut owned_env = OwnedEnvironment::new(marf.as_clarity_db());
        owned_env
            .initialize_contract(contract_identifier.clone(), clarity_boop, None)
            .unwrap();

        let ext_2_1 = boot_code_id("ext-2_1", false);
        owned_env
            .initialize_contract(ext_2_1, BOOT_CODE_EXTENSIONS_2_1, None)
            .unwrap();

        let mut env = owned_env.get_exec_environment(None, None);
        let eval_result = env
            .eval_read_only(
                &contract_identifier,
                "(contract-call? 'ST000000000000000000002AMW42H.ext-2_1 get-epoch-id)",
            )
            .unwrap();

        // Clarity code gets executed, since the native implementation is gated
        if eval_result.expect_result_ok().expect_u128() == 0 {
        } else {
            panic!("Clarity get-epoch-id extension did not return 0");
        }
    }

    // epoch 2.1
    {
        let mut owned_env_2_1 = OwnedEnvironment::new_2_1(marf.as_clarity_db());
        let mut env = owned_env_2_1.get_exec_environment(None, None);
        let eval_result = env
            .eval_read_only(
                &contract_identifier,
                "(contract-call? 'ST000000000000000000002AMW42H.ext-2_1 get-epoch-id)",
            )
            .unwrap();

        // native code gets executed due to epoch gate
        if eval_result.expect_result_ok().expect_u128() == 0x0201 {
        } else {
            panic!("native get-epoch-id extension did not return 0x0201");
        }
    }
}
