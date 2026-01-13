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
#[cfg(any(test, feature = "testing"))]
use rstest::rstest;
#[cfg(test)]
use stacks_common::types::StacksEpochId;

use crate::vm::tests::test_clarity_versions;
#[cfg(test)]
use crate::vm::{
    ClarityVersion, ContractContext,
    analysis::type_checker::v2_1::tests::contracts::type_check_version,
    ast::parse,
    database::MemoryBackingStore,
    errors::{CheckErrorKind, StaticCheckErrorKind, VmExecutionError},
    tests::{TopLevelMemoryEnvironmentGenerator, tl_env_factory},
    types::{PrincipalData, QualifiedContractIdentifier, Value},
};

#[apply(test_clarity_versions)]
fn test_block_height(
    version: ClarityVersion,
    epoch: StacksEpochId,
    mut tl_env_factory: TopLevelMemoryEnvironmentGenerator,
) {
    let contract = "(define-read-only (test-func) block-height)";

    let placeholder_context =
        ContractContext::new(QualifiedContractIdentifier::transient(), version);

    let mut owned_env = tl_env_factory.get_env(epoch);
    let contract_identifier = QualifiedContractIdentifier::local("test-contract").unwrap();

    let mut exprs = parse(&contract_identifier, contract, version, epoch).unwrap();
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();
    let analysis = db.execute(|db| {
        type_check_version(&contract_identifier, &mut exprs, db, true, epoch, version)
    });
    if version >= ClarityVersion::Clarity3 {
        let err = analysis.unwrap_err();
        assert_eq!(
            StaticCheckErrorKind::UndefinedVariable("block-height".to_string()),
            *err.err
        );
    } else {
        assert!(analysis.is_ok());
    }

    // Initialize the contract
    // Note that we're ignoring the analysis failure here so that we can test
    // the runtime behavior. In Clarity 3, if this case somehow gets past the
    // analysis, it should fail at runtime.
    let result = owned_env.initialize_versioned_contract(
        contract_identifier.clone(),
        version,
        contract,
        None,
    );

    let mut env = owned_env.get_exec_environment(None, None, &placeholder_context);

    // Call the function
    let eval_result = env.eval_read_only(&contract_identifier, "(test-func)");
    // In Clarity 3, this should trigger a runtime error
    if version >= ClarityVersion::Clarity3 {
        let err = eval_result.unwrap_err();
        assert_eq!(
            VmExecutionError::Unchecked(CheckErrorKind::UndefinedVariable(
                "block-height".to_string(),
            )),
            err
        );
    } else {
        assert_eq!(Ok(Value::UInt(1)), eval_result);
    }
}

#[apply(test_clarity_versions)]
fn test_stacks_block_height(
    version: ClarityVersion,
    epoch: StacksEpochId,
    mut tl_env_factory: TopLevelMemoryEnvironmentGenerator,
) {
    let contract = "(define-read-only (test-func) stacks-block-height)";

    let placeholder_context =
        ContractContext::new(QualifiedContractIdentifier::transient(), version);

    let mut owned_env = tl_env_factory.get_env(epoch);
    let contract_identifier = QualifiedContractIdentifier::local("test-contract").unwrap();

    let mut exprs = parse(&contract_identifier, contract, version, epoch).unwrap();
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();
    let analysis = db.execute(|db| {
        type_check_version(&contract_identifier, &mut exprs, db, true, epoch, version)
    });
    if version < ClarityVersion::Clarity3 {
        let err = analysis.unwrap_err();
        assert_eq!(
            StaticCheckErrorKind::UndefinedVariable("stacks-block-height".to_string()),
            *err.err
        );
    } else {
        assert!(analysis.is_ok());
    }

    // Initialize the contract
    // Note that we're ignoring the analysis failure here so that we can test
    // the runtime behavior. In Clarity 3, if this case somehow gets past the
    // analysis, it should fail at runtime.
    let result = owned_env.initialize_versioned_contract(
        contract_identifier.clone(),
        version,
        contract,
        None,
    );

    let mut env = owned_env.get_exec_environment(None, None, &placeholder_context);

    // Call the function
    let eval_result = env.eval_read_only(&contract_identifier, "(test-func)");
    // In Clarity 3, this should trigger a runtime error
    if version < ClarityVersion::Clarity3 {
        let err = eval_result.unwrap_err();
        assert_eq!(
            VmExecutionError::Unchecked(CheckErrorKind::UndefinedVariable(
                "stacks-block-height".to_string(),
            )),
            err
        );
    } else {
        assert_eq!(Ok(Value::UInt(1)), eval_result);
    }
}

#[apply(test_clarity_versions)]
fn test_tenure_height(
    version: ClarityVersion,
    epoch: StacksEpochId,
    mut tl_env_factory: TopLevelMemoryEnvironmentGenerator,
) {
    let contract = "(define-read-only (test-func) tenure-height)";

    let placeholder_context =
        ContractContext::new(QualifiedContractIdentifier::transient(), version);

    let mut owned_env = tl_env_factory.get_env(epoch);
    let contract_identifier = QualifiedContractIdentifier::local("test-contract").unwrap();

    let mut exprs = parse(&contract_identifier, contract, version, epoch).unwrap();
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();
    let analysis = db.execute(|db| {
        type_check_version(&contract_identifier, &mut exprs, db, true, epoch, version)
    });
    if version < ClarityVersion::Clarity3 {
        let err = analysis.unwrap_err();
        assert_eq!(
            StaticCheckErrorKind::UndefinedVariable("tenure-height".to_string()),
            *err.err
        );
    } else {
        assert!(analysis.is_ok());
    }

    // Initialize the contract
    // Note that we're ignoring the analysis failure here so that we can test
    // the runtime behavior. In Clarity 3, if this case somehow gets past the
    // analysis, it should fail at runtime.
    let result = owned_env.initialize_versioned_contract(
        contract_identifier.clone(),
        version,
        contract,
        None,
    );

    let mut env = owned_env.get_exec_environment(None, None, &placeholder_context);

    // Call the function
    let eval_result = env.eval_read_only(&contract_identifier, "(test-func)");
    // In Clarity 3, this should trigger a runtime error
    if version < ClarityVersion::Clarity3 {
        let err = eval_result.unwrap_err();
        assert_eq!(
            VmExecutionError::Unchecked(CheckErrorKind::UndefinedVariable(
                "tenure-height".to_string(),
            )),
            err
        );
    } else {
        assert_eq!(Ok(Value::UInt(1)), eval_result);
    }
}

#[cfg(test)]
#[derive(Debug, PartialEq)]
enum ExpectedContractError {
    Analysis(StaticCheckErrorKind),
    Initialization(CheckErrorKind),
    Runtime(CheckErrorKind),
}

#[cfg(test)]
#[allow(clippy::type_complexity)]
fn expect_contract_error(
    version: ClarityVersion,
    epoch: StacksEpochId,
    tl_env_factory: &mut TopLevelMemoryEnvironmentGenerator,
    name: &str,
    contract: &str,
    expected_errors: &[(
        fn(ClarityVersion, StacksEpochId) -> bool,
        ExpectedContractError,
    )],
    expected_success: Value,
) {
    let placeholder_context =
        ContractContext::new(QualifiedContractIdentifier::local(name).unwrap(), version);

    let mut owned_env = tl_env_factory.get_env(epoch);
    let contract_identifier = QualifiedContractIdentifier::local(name).unwrap();

    let mut exprs = parse(&contract_identifier, contract, version, epoch).unwrap();
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();
    let analysis = db.execute(|db| {
        type_check_version(&contract_identifier, &mut exprs, db, true, epoch, version)
    });

    for (err_condition, expected_error) in expected_errors {
        if let ExpectedContractError::Analysis(expected_error) = expected_error
            && err_condition(version, epoch)
        {
            let err = analysis.unwrap_err();
            assert_eq!(expected_error, &*err.err);

            // Do not continue with the test if the analysis failed.
            return;
        }
    }

    // The type-checker does not report an error for the reuse of the built-in
    // name `stacks-block-height`. It is instead caught at initialization. This
    // matches the behavior of Clarity 1 and 2.
    assert!(analysis.is_ok());

    // Initialize the contract
    // Note that we're ignoring the analysis failure here so that we can test
    // the runtime behavior. In Clarity 3, if this case somehow gets past the
    // analysis, it should fail at runtime.
    let init_result = owned_env.initialize_versioned_contract(
        contract_identifier.clone(),
        version,
        contract,
        None,
    );

    for (err_condition, expected_error) in expected_errors {
        if let ExpectedContractError::Initialization(expected_error) = expected_error
            && err_condition(version, epoch)
        {
            let err = init_result.unwrap_err();
            if let VmExecutionError::Unchecked(inner_err) = &err {
                assert_eq!(expected_error, inner_err);
            } else {
                panic!("Expected an Unchecked error, but got a different error");
            }
            // Do not continue with the test if the initialization failed.
            return;
        }
    }

    let mut env = owned_env.get_exec_environment(None, None, &placeholder_context);

    // Call the function
    let eval_result = env.eval_read_only(&contract_identifier, "(test-func)");

    for (err_condition, expected_error) in expected_errors {
        if let ExpectedContractError::Runtime(expected_error) = expected_error
            && err_condition(version, epoch)
        {
            let err = eval_result.unwrap_err();
            if let VmExecutionError::Unchecked(inner_err) = &err {
                assert_eq!(expected_error, inner_err);
            } else {
                panic!("Expected an Unchecked error, but got a different error");
            }

            // Do not continue with the test if the evaluation failed.
            return;
        }
    }

    assert_eq!(Ok(expected_success), eval_result);
}

#[apply(test_clarity_versions)]
fn reuse_block_height(
    version: ClarityVersion,
    epoch: StacksEpochId,
    mut tl_env_factory: TopLevelMemoryEnvironmentGenerator,
) {
    // data var
    expect_contract_error(
        version,
        epoch,
        &mut tl_env_factory,
        "data-var",
        r#"
        (define-data-var block-height uint u1234)
        (define-read-only (test-func)
            (var-get block-height)
        )
        "#,
        &[
            (
                |version, _| version < ClarityVersion::Clarity3,
                ExpectedContractError::Initialization(CheckErrorKind::NameAlreadyUsed(
                    "block-height".to_string(),
                )),
            ),
            (
                |version, _| version >= ClarityVersion::Clarity3,
                ExpectedContractError::Analysis(StaticCheckErrorKind::ReservedWord(
                    "block-height".to_string(),
                )),
            ),
        ],
        Value::UInt(1234),
    );

    // map
    expect_contract_error(
        version,
        epoch,
        &mut tl_env_factory,
        "map",
        r#"
        (define-map block-height uint uint)
        (define-private (test-func)
            (map-insert block-height u1 u2)
        )
        "#,
        &[
            (
                |version, _| version < ClarityVersion::Clarity3,
                ExpectedContractError::Initialization(CheckErrorKind::NameAlreadyUsed(
                    "block-height".to_string(),
                )),
            ),
            (
                |version, _| version >= ClarityVersion::Clarity3,
                ExpectedContractError::Analysis(StaticCheckErrorKind::ReservedWord(
                    "block-height".to_string(),
                )),
            ),
        ],
        Value::Bool(true),
    );

    // let
    expect_contract_error(
        version,
        epoch,
        &mut tl_env_factory,
        "let",
        r#"
        (define-private (test-func)
            (let ((block-height 32))
                block-height
            )
        )
        "#,
        &[
            (
                |version, _| version < ClarityVersion::Clarity3,
                ExpectedContractError::Runtime(CheckErrorKind::NameAlreadyUsed(
                    "block-height".to_string(),
                )),
            ),
            (
                |version, _| version >= ClarityVersion::Clarity3,
                ExpectedContractError::Analysis(StaticCheckErrorKind::ReservedWord(
                    "block-height".to_string(),
                )),
            ),
        ],
        Value::Int(32),
    );

    // match binding
    expect_contract_error(
        version,
        epoch,
        &mut tl_env_factory,
        "match-binding",
        r#"
        (define-read-only (test-func)
          (let ((x (if true (ok u5) (err u7))))
            (match x
              block-height 3
              e 4
            )
          )
        )
        "#,
        &[
            (
                |version, _| version < ClarityVersion::Clarity3,
                ExpectedContractError::Runtime(CheckErrorKind::NameAlreadyUsed(
                    "block-height".to_string(),
                )),
            ),
            (
                |version, _| version >= ClarityVersion::Clarity3,
                ExpectedContractError::Analysis(StaticCheckErrorKind::ReservedWord(
                    "block-height".to_string(),
                )),
            ),
        ],
        Value::Int(3),
    );

    // private function
    expect_contract_error(
        version,
        epoch,
        &mut tl_env_factory,
        "function",
        r#"
        (define-private (block-height) true)
        (define-private (test-func) (block-height))
        "#,
        &[
            (
                |version, _| version < ClarityVersion::Clarity3,
                ExpectedContractError::Initialization(CheckErrorKind::NameAlreadyUsed(
                    "block-height".to_string(),
                )),
            ),
            (
                |version, _| version >= ClarityVersion::Clarity3,
                ExpectedContractError::Analysis(StaticCheckErrorKind::ReservedWord(
                    "block-height".to_string(),
                )),
            ),
        ],
        Value::Bool(true),
    );

    // constant
    expect_contract_error(
        version,
        epoch,
        &mut tl_env_factory,
        "constant",
        r#"
            (define-constant block-height u1234)
            (define-read-only (test-func) block-height)
            "#,
        &[
            (
                |version, _| version < ClarityVersion::Clarity3,
                ExpectedContractError::Initialization(CheckErrorKind::NameAlreadyUsed(
                    "block-height".to_string(),
                )),
            ),
            (
                |version, _| version >= ClarityVersion::Clarity3,
                ExpectedContractError::Analysis(StaticCheckErrorKind::ReservedWord(
                    "block-height".to_string(),
                )),
            ),
        ],
        Value::UInt(1234),
    );

    // define-trait
    expect_contract_error(
        version,
        epoch,
        &mut tl_env_factory,
        "trait",
        r#"
            (define-trait block-height ())
            (define-read-only (test-func) false)
            "#,
        &[
            (
                |version, _| version < ClarityVersion::Clarity3,
                ExpectedContractError::Initialization(CheckErrorKind::NameAlreadyUsed(
                    "block-height".to_string(),
                )),
            ),
            (
                |version, _| version >= ClarityVersion::Clarity3,
                ExpectedContractError::Analysis(StaticCheckErrorKind::ReservedWord(
                    "block-height".to_string(),
                )),
            ),
        ],
        Value::Bool(false),
    );

    // tuple
    expect_contract_error(
        version,
        epoch,
        &mut tl_env_factory,
        "tuple",
        r#"
            (define-read-only (test-func)
                (get block-height { block-height: 1234 })
            )
            "#,
        &[],
        Value::Int(1234),
    );

    // define-fungible-token
    expect_contract_error(
        version,
        epoch,
        &mut tl_env_factory,
        "trait",
        r#"
            (define-fungible-token block-height)
            (define-read-only (test-func) false)
            "#,
        &[
            (
                |version, _| version < ClarityVersion::Clarity3,
                ExpectedContractError::Initialization(CheckErrorKind::NameAlreadyUsed(
                    "block-height".to_string(),
                )),
            ),
            (
                |version, _| version >= ClarityVersion::Clarity3,
                ExpectedContractError::Analysis(StaticCheckErrorKind::ReservedWord(
                    "block-height".to_string(),
                )),
            ),
        ],
        Value::Bool(false),
    );

    // define-non-fungible-token
    expect_contract_error(
        version,
        epoch,
        &mut tl_env_factory,
        "trait",
        r#"
            (define-non-fungible-token block-height uint)
            (define-read-only (test-func) false)
            "#,
        &[
            (
                |version, _| version < ClarityVersion::Clarity3,
                ExpectedContractError::Initialization(CheckErrorKind::NameAlreadyUsed(
                    "block-height".to_string(),
                )),
            ),
            (
                |version, _| version >= ClarityVersion::Clarity3,
                ExpectedContractError::Analysis(StaticCheckErrorKind::ReservedWord(
                    "block-height".to_string(),
                )),
            ),
        ],
        Value::Bool(false),
    );

    // define-public
    expect_contract_error(
        version,
        epoch,
        &mut tl_env_factory,
        "function",
        r#"
        (define-public (block-height) (ok true))
        (define-private (test-func) (unwrap-panic (block-height)))
        "#,
        &[
            (
                |version, _| version < ClarityVersion::Clarity3,
                ExpectedContractError::Initialization(CheckErrorKind::NameAlreadyUsed(
                    "block-height".to_string(),
                )),
            ),
            (
                |version, _| version >= ClarityVersion::Clarity3,
                ExpectedContractError::Analysis(StaticCheckErrorKind::ReservedWord(
                    "block-height".to_string(),
                )),
            ),
        ],
        Value::Bool(true),
    );

    // define-read-only
    expect_contract_error(
        version,
        epoch,
        &mut tl_env_factory,
        "function",
        r#"
        (define-read-only (block-height) true)
        (define-private (test-func) (block-height))
        "#,
        &[
            (
                |version, _| version < ClarityVersion::Clarity3,
                ExpectedContractError::Initialization(CheckErrorKind::NameAlreadyUsed(
                    "block-height".to_string(),
                )),
            ),
            (
                |version, _| version >= ClarityVersion::Clarity3,
                ExpectedContractError::Analysis(StaticCheckErrorKind::ReservedWord(
                    "block-height".to_string(),
                )),
            ),
        ],
        Value::Bool(true),
    );
}

#[apply(test_clarity_versions)]
fn reuse_stacks_block_height(
    version: ClarityVersion,
    epoch: StacksEpochId,
    mut tl_env_factory: TopLevelMemoryEnvironmentGenerator,
) {
    // data var
    expect_contract_error(
        version,
        epoch,
        &mut tl_env_factory,
        "data-var",
        r#"
        (define-data-var stacks-block-height uint u1234)
        (define-read-only (test-func)
            (var-get stacks-block-height)
        )
        "#,
        &[(
            |version, _| version >= ClarityVersion::Clarity3,
            ExpectedContractError::Initialization(CheckErrorKind::NameAlreadyUsed(
                "stacks-block-height".to_string(),
            )),
        )],
        Value::UInt(1234),
    );

    // map
    expect_contract_error(
        version,
        epoch,
        &mut tl_env_factory,
        "map",
        r#"
        (define-map stacks-block-height uint uint)
        (define-private (test-func)
            (map-insert stacks-block-height u1 u2)
        )
        "#,
        &[(
            |version, _| version >= ClarityVersion::Clarity3,
            ExpectedContractError::Initialization(CheckErrorKind::NameAlreadyUsed(
                "stacks-block-height".to_string(),
            )),
        )],
        Value::Bool(true),
    );

    // let
    expect_contract_error(
        version,
        epoch,
        &mut tl_env_factory,
        "let",
        r#"
        (define-private (test-func)
            (let ((stacks-block-height 32))
                stacks-block-height
            )
        )
        "#,
        &[(
            |version, _| version >= ClarityVersion::Clarity3,
            ExpectedContractError::Runtime(CheckErrorKind::NameAlreadyUsed(
                "stacks-block-height".to_string(),
            )),
        )],
        Value::Int(32),
    );

    // match binding
    expect_contract_error(
        version,
        epoch,
        &mut tl_env_factory,
        "match-binding",
        r#"
        (define-read-only (test-func)
          (let ((x (if true (ok u5) (err u7))))
            (match x
              stacks-block-height 3
              e 4
            )
          )
        )
        "#,
        &[(
            |version, _| version >= ClarityVersion::Clarity3,
            ExpectedContractError::Runtime(CheckErrorKind::NameAlreadyUsed(
                "stacks-block-height".to_string(),
            )),
        )],
        Value::Int(3),
    );

    // function
    expect_contract_error(
        version,
        epoch,
        &mut tl_env_factory,
        "function",
        r#"
        (define-private (stacks-block-height) true)
        (define-private (test-func) (stacks-block-height))
        "#,
        &[(
            |version, _| version >= ClarityVersion::Clarity3,
            ExpectedContractError::Initialization(CheckErrorKind::NameAlreadyUsed(
                "stacks-block-height".to_string(),
            )),
        )],
        Value::Bool(true),
    );

    // constant
    expect_contract_error(
        version,
        epoch,
        &mut tl_env_factory,
        "constant",
        r#"
            (define-constant stacks-block-height u1234)
            (define-read-only (test-func) stacks-block-height)
            "#,
        &[(
            |version, _| version >= ClarityVersion::Clarity3,
            ExpectedContractError::Initialization(CheckErrorKind::NameAlreadyUsed(
                "stacks-block-height".to_string(),
            )),
        )],
        Value::UInt(1234),
    );

    // define-trait
    expect_contract_error(
        version,
        epoch,
        &mut tl_env_factory,
        "trait",
        r#"
            (define-trait stacks-block-height ())
            (define-read-only (test-func) false)
            "#,
        &[(
            |version, _| version >= ClarityVersion::Clarity3,
            ExpectedContractError::Initialization(CheckErrorKind::NameAlreadyUsed(
                "stacks-block-height".to_string(),
            )),
        )],
        Value::Bool(false),
    );

    // tuple
    expect_contract_error(
        version,
        epoch,
        &mut tl_env_factory,
        "tuple",
        r#"
            (define-read-only (test-func)
                (get stacks-block-height { stacks-block-height: 1234 })
            )
            "#,
        &[],
        Value::Int(1234),
    );

    // define-fungible-token
    expect_contract_error(
        version,
        epoch,
        &mut tl_env_factory,
        "trait",
        r#"
            (define-fungible-token stacks-block-height)
            (define-read-only (test-func) false)
            "#,
        &[(
            |version, _| version >= ClarityVersion::Clarity3,
            ExpectedContractError::Initialization(CheckErrorKind::NameAlreadyUsed(
                "stacks-block-height".to_string(),
            )),
        )],
        Value::Bool(false),
    );

    // define-non-fungible-token
    expect_contract_error(
        version,
        epoch,
        &mut tl_env_factory,
        "trait",
        r#"
            (define-non-fungible-token stacks-block-height uint)
            (define-read-only (test-func) false)
            "#,
        &[(
            |version, _| version >= ClarityVersion::Clarity3,
            ExpectedContractError::Initialization(CheckErrorKind::NameAlreadyUsed(
                "stacks-block-height".to_string(),
            )),
        )],
        Value::Bool(false),
    );

    // define-public
    expect_contract_error(
        version,
        epoch,
        &mut tl_env_factory,
        "function",
        r#"
        (define-public (stacks-block-height) (ok true))
        (define-private (test-func) (unwrap-panic (stacks-block-height)))
        "#,
        &[(
            |version, _| version >= ClarityVersion::Clarity3,
            ExpectedContractError::Initialization(CheckErrorKind::NameAlreadyUsed(
                "stacks-block-height".to_string(),
            )),
        )],
        Value::Bool(true),
    );

    // define-read-only
    expect_contract_error(
        version,
        epoch,
        &mut tl_env_factory,
        "function",
        r#"
        (define-read-only (stacks-block-height) true)
        (define-private (test-func) (stacks-block-height))
        "#,
        &[(
            |version, _| version >= ClarityVersion::Clarity3,
            ExpectedContractError::Initialization(CheckErrorKind::NameAlreadyUsed(
                "stacks-block-height".to_string(),
            )),
        )],
        Value::Bool(true),
    );
}

#[cfg(test)]
fn reuse_builtin_name(
    name: &str,
    version_check: fn(ClarityVersion, StacksEpochId) -> bool,
    version: ClarityVersion,
    epoch: StacksEpochId,
    mut tl_env_factory: TopLevelMemoryEnvironmentGenerator,
) {
    // data var
    expect_contract_error(
        version,
        epoch,
        &mut tl_env_factory,
        "data-var",
        &format!(
            r#"
        (define-data-var {name} uint u1234)
        (define-read-only (test-func)
            (var-get {name})
        )
        "#
        ),
        &[(
            version_check,
            ExpectedContractError::Initialization(CheckErrorKind::NameAlreadyUsed(
                name.to_string(),
            )),
        )],
        Value::UInt(1234),
    );

    // map
    expect_contract_error(
        version,
        epoch,
        &mut tl_env_factory,
        "map",
        &format!(
            r#"
        (define-map {name} uint uint)
        (define-private (test-func)
            (map-insert {name} u1 u2)
        )
        "#
        ),
        &[(
            version_check,
            ExpectedContractError::Initialization(CheckErrorKind::NameAlreadyUsed(
                name.to_string(),
            )),
        )],
        Value::Bool(true),
    );

    // let
    expect_contract_error(
        version,
        epoch,
        &mut tl_env_factory,
        "let",
        &format!(
            r#"
        (define-private (test-func)
            (let (({name} 32))
                {name}
            )
        )
        "#
        ),
        &[(
            version_check,
            ExpectedContractError::Runtime(CheckErrorKind::NameAlreadyUsed(name.to_string())),
        )],
        Value::Int(32),
    );

    // match binding
    expect_contract_error(
        version,
        epoch,
        &mut tl_env_factory,
        "match-binding",
        &format!(
            r#"
        (define-read-only (test-func)
          (let ((x (if true (ok u5) (err u7))))
            (match x
              {name} 3
              e 4
            )
          )
        )
        "#
        ),
        &[(
            version_check,
            ExpectedContractError::Runtime(CheckErrorKind::NameAlreadyUsed(name.to_string())),
        )],
        Value::Int(3),
    );

    // function
    expect_contract_error(
        version,
        epoch,
        &mut tl_env_factory,
        "function",
        &format!(
            r#"
        (define-private ({name}) true)
        (define-private (test-func) ({name}))
        "#
        ),
        &[(
            version_check,
            ExpectedContractError::Initialization(CheckErrorKind::NameAlreadyUsed(
                name.to_string(),
            )),
        )],
        Value::Bool(true),
    );

    // constant
    expect_contract_error(
        version,
        epoch,
        &mut tl_env_factory,
        "constant",
        &format!(
            r#"
            (define-constant {name} u1234)
            (define-read-only (test-func) {name})
            "#
        ),
        &[(
            version_check,
            ExpectedContractError::Initialization(CheckErrorKind::NameAlreadyUsed(
                name.to_string(),
            )),
        )],
        Value::UInt(1234),
    );

    // define-trait
    expect_contract_error(
        version,
        epoch,
        &mut tl_env_factory,
        "trait",
        &format!(
            r#"
            (define-trait {name} ())
            (define-read-only (test-func) false)
            "#
        ),
        &[(
            version_check,
            ExpectedContractError::Initialization(CheckErrorKind::NameAlreadyUsed(
                name.to_string(),
            )),
        )],
        Value::Bool(false),
    );

    // tuple
    expect_contract_error(
        version,
        epoch,
        &mut tl_env_factory,
        "tuple",
        &format!(
            r#"
            (define-read-only (test-func)
                (get {name} {{ {name}: 1234 }})
            )
            "#
        ),
        &[],
        Value::Int(1234),
    );

    // define-fungible-token
    expect_contract_error(
        version,
        epoch,
        &mut tl_env_factory,
        "trait",
        &format!(
            r#"
            (define-fungible-token {name})
            (define-read-only (test-func) false)
            "#
        ),
        &[(
            version_check,
            ExpectedContractError::Initialization(CheckErrorKind::NameAlreadyUsed(
                name.to_string(),
            )),
        )],
        Value::Bool(false),
    );

    // define-non-fungible-token
    expect_contract_error(
        version,
        epoch,
        &mut tl_env_factory,
        "trait",
        &format!(
            r#"
            (define-non-fungible-token {name} uint)
            (define-read-only (test-func) false)
            "#
        ),
        &[(
            version_check,
            ExpectedContractError::Initialization(CheckErrorKind::NameAlreadyUsed(
                name.to_string(),
            )),
        )],
        Value::Bool(false),
    );

    // define-public
    expect_contract_error(
        version,
        epoch,
        &mut tl_env_factory,
        "function",
        &format!(
            r#"
        (define-public ({name}) (ok true))
        (define-private (test-func) (unwrap-panic ({name})))
        "#
        ),
        &[(
            version_check,
            ExpectedContractError::Initialization(CheckErrorKind::NameAlreadyUsed(
                name.to_string(),
            )),
        )],
        Value::Bool(true),
    );

    // define-read-only
    expect_contract_error(
        version,
        epoch,
        &mut tl_env_factory,
        "function",
        &format!(
            r#"
        (define-read-only ({name}) true)
        (define-private (test-func) ({name}))
        "#
        ),
        &[(
            version_check,
            ExpectedContractError::Initialization(CheckErrorKind::NameAlreadyUsed(
                name.to_string(),
            )),
        )],
        Value::Bool(true),
    );
}

#[apply(test_clarity_versions)]
fn test_block_time(
    version: ClarityVersion,
    epoch: StacksEpochId,
    mut tl_env_factory: TopLevelMemoryEnvironmentGenerator,
) {
    let contract = "(define-read-only (test-func) stacks-block-time)";

    let placeholder_context =
        ContractContext::new(QualifiedContractIdentifier::transient(), version);

    let mut owned_env = tl_env_factory.get_env(epoch);
    let contract_identifier = QualifiedContractIdentifier::local("test-contract").unwrap();

    let mut exprs = parse(&contract_identifier, contract, version, epoch).unwrap();
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();
    let analysis = db.execute(|db| {
        type_check_version(&contract_identifier, &mut exprs, db, true, epoch, version)
    });

    // stacks-block-time should only be available in Clarity 4
    if version < ClarityVersion::Clarity4 {
        let err = analysis.unwrap_err();
        assert_eq!(
            StaticCheckErrorKind::UndefinedVariable("stacks-block-time".to_string()),
            *err.err
        );
    } else {
        assert!(analysis.is_ok());
    }

    // Initialize the contract
    // Note that we're ignoring the analysis failure here so that we can test
    // the runtime behavior. In earlier versions, if this case somehow gets past the
    // analysis, it should fail at runtime.
    let result = owned_env.initialize_versioned_contract(
        contract_identifier.clone(),
        version,
        contract,
        None,
    );

    let mut env = owned_env.get_exec_environment(None, None, &placeholder_context);

    // Call the function
    let eval_result = env.eval_read_only(&contract_identifier, "(test-func)");

    // In versions before Clarity 4, this should trigger a runtime error
    if version < ClarityVersion::Clarity4 {
        let err = eval_result.unwrap_err();
        assert_eq!(
            VmExecutionError::Unchecked(CheckErrorKind::UndefinedVariable(
                "stacks-block-time".to_string(),
            )),
            err
        );
    } else {
        // Always 1 in the testing environment
        assert_eq!(Ok(Value::UInt(1)), eval_result);
    }
}

#[test]
fn test_block_time_in_expressions() {
    let version = ClarityVersion::Clarity4;
    let epoch = StacksEpochId::Epoch33;
    let mut tl_env_factory = tl_env_factory();

    let contract = r#"
        (define-read-only (time-comparison (threshold uint))
            (>= stacks-block-time threshold))
        (define-read-only (time-arithmetic)
            (+ stacks-block-time u100))
        (define-read-only (time-in-response)
            (ok stacks-block-time))
    "#;

    let placeholder_context =
        ContractContext::new(QualifiedContractIdentifier::transient(), version);

    let mut owned_env = tl_env_factory.get_env(epoch);
    let contract_identifier = QualifiedContractIdentifier::local("test-contract").unwrap();

    // Initialize the contract
    let result = owned_env.initialize_versioned_contract(
        contract_identifier.clone(),
        version,
        contract,
        None,
    );
    assert!(result.is_ok());

    let mut env = owned_env.get_exec_environment(None, None, &placeholder_context);

    // Test comparison: 1 >= 0 should be true
    let eval_result = env.eval_read_only(&contract_identifier, "(time-comparison u0)");
    info!("time-comparison result: {:?}", eval_result);
    assert_eq!(Ok(Value::Bool(true)), eval_result);

    // Test arithmetic: 1 + 100 = 101
    let eval_result = env.eval_read_only(&contract_identifier, "(time-arithmetic)");
    info!("time-arithmetic result: {:?}", eval_result);
    assert_eq!(Ok(Value::UInt(101)), eval_result);

    // Test in response: (ok 1)
    let eval_result = env.eval_read_only(&contract_identifier, "(time-in-response)");
    info!("time-in-response result: {:?}", eval_result);
    assert_eq!(Ok(Value::okay(Value::UInt(1)).unwrap()), eval_result);
}

#[apply(test_clarity_versions)]
fn reuse_tenure_height(
    version: ClarityVersion,
    epoch: StacksEpochId,
    tl_env_factory: TopLevelMemoryEnvironmentGenerator,
) {
    fn version_check(version: ClarityVersion, _epoch: StacksEpochId) -> bool {
        version >= ClarityVersion::Clarity3
    }
    reuse_builtin_name(
        "tenure-height",
        version_check,
        version,
        epoch,
        tl_env_factory,
    );
}

#[apply(test_clarity_versions)]
fn test_current_contract(
    version: ClarityVersion,
    epoch: StacksEpochId,
    mut tl_env_factory: TopLevelMemoryEnvironmentGenerator,
) {
    let contract = "(define-read-only (test-func) current-contract)";

    let placeholder_context =
        ContractContext::new(QualifiedContractIdentifier::transient(), version);

    let mut owned_env = tl_env_factory.get_env(epoch);
    let contract_identifier = QualifiedContractIdentifier::local("test-contract").unwrap();

    let mut exprs = parse(&contract_identifier, contract, version, epoch).unwrap();
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();
    let analysis = db.execute(|db| {
        type_check_version(&contract_identifier, &mut exprs, db, true, epoch, version)
    });
    if version < ClarityVersion::Clarity4 {
        let err = analysis.unwrap_err();
        assert_eq!(
            StaticCheckErrorKind::UndefinedVariable("current-contract".to_string()),
            *err.err
        );
    } else {
        assert!(analysis.is_ok());
    }

    // Initialize the contract
    // Note that we're ignoring the analysis failure here so that we can test
    // the runtime behavior. In Clarity 3, if this case somehow gets past the
    // analysis, it should fail at runtime.
    let result = owned_env.initialize_versioned_contract(
        contract_identifier.clone(),
        version,
        contract,
        None,
    );

    let mut env = owned_env.get_exec_environment(None, None, &placeholder_context);

    // Call the function
    let eval_result = env.eval_read_only(&contract_identifier, "(test-func)");
    // In Clarity 3, this should trigger a runtime error
    if version < ClarityVersion::Clarity4 {
        let err = eval_result.unwrap_err();
        assert_eq!(
            VmExecutionError::Unchecked(CheckErrorKind::UndefinedVariable(
                "current-contract".to_string(),
            )),
            err
        );
    } else {
        assert_eq!(
            Ok(Value::Principal(PrincipalData::Contract(
                contract_identifier
            ))),
            eval_result
        );
    }
}

/// Test the checks on reuse of the `current-contract` name
#[apply(test_clarity_versions)]
fn reuse_current_contract(
    version: ClarityVersion,
    epoch: StacksEpochId,
    tl_env_factory: TopLevelMemoryEnvironmentGenerator,
) {
    fn version_check(version: ClarityVersion, _epoch: StacksEpochId) -> bool {
        version >= ClarityVersion::Clarity4
    }
    reuse_builtin_name(
        "current-contract",
        version_check,
        version,
        epoch,
        tl_env_factory,
    );
}
