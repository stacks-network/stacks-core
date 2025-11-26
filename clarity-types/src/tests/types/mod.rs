// Copyright (C) 2025 Stacks Open Internet Foundation
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
mod serialization;
mod signatures;

use rstest::rstest;
use stacks_common::types::StacksEpochId;

use crate::VmExecutionError;
use crate::errors::{CheckErrorKind, RuntimeError, VmInternalError};
use crate::types::{
    ASCIIData, BuffData, CharType, ListTypeData, MAX_VALUE_SIZE, PrincipalData,
    QualifiedContractIdentifier, SequenceData, SequencedValue as _, StandardPrincipalData,
    TraitIdentifier, TupleData, TupleTypeSignature, TypeSignature, UTF8Data, Value,
};

#[test]
fn test_constructors() {
    assert_eq!(
        Value::list_with_type(
            &StacksEpochId::latest(),
            vec![Value::Int(5), Value::Int(2)],
            ListTypeData::new_list(TypeSignature::BoolType, 3).unwrap()
        ),
        Err(VmInternalError::FailureConstructingListWithType.into())
    );
    assert_eq!(
        ListTypeData::new_list(TypeSignature::IntType, MAX_VALUE_SIZE),
        Err(CheckErrorKind::ValueTooLarge)
    );

    assert_eq!(
        Value::buff_from(vec![0; (MAX_VALUE_SIZE + 1) as usize]),
        Err(CheckErrorKind::ValueTooLarge.into())
    );

    // Test that wrappers (okay, error, some)
    //   correctly error when _they_ cause the value size
    //   to exceed the max value size (note, the buffer constructor
    //   isn't causing the error).
    assert_eq!(
        Value::okay(Value::buff_from(vec![0; (MAX_VALUE_SIZE) as usize]).unwrap()),
        Err(CheckErrorKind::ValueTooLarge.into())
    );

    assert_eq!(
        Value::error(Value::buff_from(vec![0; (MAX_VALUE_SIZE) as usize]).unwrap()),
        Err(CheckErrorKind::ValueTooLarge.into())
    );

    assert_eq!(
        Value::some(Value::buff_from(vec![0; (MAX_VALUE_SIZE) as usize]).unwrap()),
        Err(CheckErrorKind::ValueTooLarge.into())
    );

    // Test that the depth limit is correctly enforced:
    //   for tuples, lists, somes, okays, errors.

    let cons = || {
        Value::some(Value::some(Value::some(Value::some(Value::some(
            Value::some(Value::some(Value::some(Value::some(Value::some(
                Value::some(Value::some(Value::some(Value::some(Value::some(
                    Value::some(Value::some(Value::some(Value::some(Value::some(
                        Value::some(Value::some(Value::some(Value::some(Value::some(
                            Value::some(Value::some(Value::some(Value::some(Value::some(
                                Value::some(Value::Int(1))?,
                            )?)?)?)?)?,
                        )?)?)?)?)?,
                    )?)?)?)?)?,
                )?)?)?)?)?,
            )?)?)?)?)?,
        )?)?)?)?)
    };
    let inner_value = cons().unwrap();
    assert_eq!(
        TupleData::from_data(vec![("a".into(), inner_value.clone())]),
        Err(CheckErrorKind::TypeSignatureTooDeep.into())
    );

    assert_eq!(
        Value::list_from(vec![inner_value.clone()]),
        Err(CheckErrorKind::TypeSignatureTooDeep.into())
    );
    assert_eq!(
        Value::okay(inner_value.clone()),
        Err(CheckErrorKind::TypeSignatureTooDeep.into())
    );
    assert_eq!(
        Value::error(inner_value.clone()),
        Err(CheckErrorKind::TypeSignatureTooDeep.into())
    );
    assert_eq!(
        Value::some(inner_value),
        Err(CheckErrorKind::TypeSignatureTooDeep.into())
    );

    if std::env::var("CIRCLE_TESTING") == Ok("1".to_string()) {
        println!("Skipping allocation test on Circle");
        return;
    }

    // on 32-bit archs, this error cannot even happen, so don't test (and cause an overflow panic)
    if (u32::MAX as usize) < usize::MAX {
        assert_eq!(
            Value::buff_from(vec![0; (u32::MAX as usize) + 10]),
            Err(CheckErrorKind::ValueTooLarge.into())
        );
    }
}

#[test]
fn simple_size_test() {
    assert_eq!(Value::Int(10).size().unwrap(), 16);
}

#[test]
fn simple_tuple_get_test() {
    let t = TupleData::from_data(vec![("abc".into(), Value::Int(0))]).unwrap();
    assert_eq!(t.get("abc"), Ok(&Value::Int(0)));
    // should error!
    t.get("abcd").unwrap_err();
}

#[test]
fn test_some_displays() {
    assert_eq!(
        &format!(
            "{}",
            Value::list_from(vec![Value::Int(10), Value::Int(5)]).unwrap()
        ),
        "(10 5)"
    );
    assert_eq!(
        &format!("{}", Value::some(Value::Int(10)).unwrap()),
        "(some 10)"
    );
    assert_eq!(
        &format!("{}", Value::okay(Value::Int(10)).unwrap()),
        "(ok 10)"
    );
    assert_eq!(
        &format!("{}", Value::error(Value::Int(10)).unwrap()),
        "(err 10)"
    );
    assert_eq!(&format!("{}", Value::none()), "none");
    assert_eq!(
        &format!(
            "{}",
            Value::from(
                PrincipalData::parse_standard_principal(
                    "SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G"
                )
                .unwrap()
            )
        ),
        "SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G"
    );

    assert_eq!(
        &format!(
            "{}",
            Value::from(TupleData::from_data(vec![("a".into(), Value::Int(2))]).unwrap())
        ),
        "(tuple (a 2))"
    );
}

#[test]
fn expect_buff() {
    let buff = Value::Sequence(SequenceData::Buffer(BuffData {
        data: vec![1, 2, 3, 4, 5],
    }));
    assert_eq!(buff.clone().expect_buff(5).unwrap(), vec![1, 2, 3, 4, 5]);
    assert_eq!(buff.clone().expect_buff(6).unwrap(), vec![1, 2, 3, 4, 5]);
    assert_eq!(
        buff.clone().expect_buff_padded(6, 0).unwrap(),
        vec![1, 2, 3, 4, 5, 0]
    );
    assert_eq!(buff.clone().expect_buff(10).unwrap(), vec![1, 2, 3, 4, 5]);
    assert_eq!(
        buff.expect_buff_padded(10, 1).unwrap(),
        vec![1, 2, 3, 4, 5, 1, 1, 1, 1, 1]
    );
}

#[test]
#[should_panic]
fn expect_buff_too_small() {
    let buff = Value::Sequence(SequenceData::Buffer(BuffData {
        data: vec![1, 2, 3, 4, 5],
    }));
    let _ = buff.expect_buff(4).unwrap();
}

#[test]
fn principal_is_mainnet() {
    let principal =
        PrincipalData::parse_standard_principal("SPXACZ2NS34QHWCMAK1V2QJK0XB6WM6N5AB7RWYB")
            .unwrap();
    assert!(principal.is_mainnet());

    let principal =
        PrincipalData::parse_standard_principal("SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4")
            .unwrap();
    assert!(principal.is_mainnet());

    let principal =
        PrincipalData::parse_standard_principal("ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM")
            .unwrap();
    assert!(!principal.is_mainnet());

    let principal =
        PrincipalData::parse_standard_principal("SNBPC7AHXCBAQSW6RKGEXVG119H2933ZYR63HD32")
            .unwrap();
    assert!(!principal.is_mainnet());
}

#[test]
fn principal_is_multisig() {
    let principal =
        PrincipalData::parse_standard_principal("SPXACZ2NS34QHWCMAK1V2QJK0XB6WM6N5AB7RWYB")
            .unwrap();
    assert!(!principal.is_multisig());

    let principal =
        PrincipalData::parse_standard_principal("SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4")
            .unwrap();
    assert!(principal.is_multisig());

    let principal =
        PrincipalData::parse_standard_principal("ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM")
            .unwrap();
    assert!(!principal.is_multisig());

    let principal =
        PrincipalData::parse_standard_principal("SNBPC7AHXCBAQSW6RKGEXVG119H2933ZYR63HD32")
            .unwrap();
    assert!(principal.is_multisig());
}

#[test]
fn test_qualified_contract_identifier_local_returns_runtime_error() {
    let err = QualifiedContractIdentifier::local("1nvalid-name")
        .expect_err("Unexpected qualified contract identifier");
    assert_eq!(
        VmExecutionError::from(RuntimeError::BadNameValue(
            "ContractName",
            "1nvalid-name".into()
        )),
        err,
    );
}

#[rstest]
#[case::too_short("S162RK3CHJPCSSK6BM757FW", RuntimeError::TypeParseFailure(
    "Invalid principal literal: Expected 20 data bytes.".to_string(),
))]
#[case::too_long("S1C5H66S35CSKK6CK1C9HP8SB6CWSK4RB2CDJK8HY4", RuntimeError::TypeParseFailure(
    "Invalid principal literal: Expected 20 data bytes.".to_string(),
))]
#[case::invalid_c32("II2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G", RuntimeError::TypeParseFailure(
    "Invalid principal literal: base58ck checksum 0x1074d4f7 does not match expected 0xae29c6e0".to_string(),
))]
fn test_principal_data_parse_standard_principal_returns_runtime_error(
    #[case] input: &str,
    #[case] expected_err: RuntimeError,
) {
    let err =
        PrincipalData::parse_standard_principal(input).expect_err("Unexpected principal data");
    assert_eq!(VmExecutionError::from(expected_err), err);
}

#[rstest]
#[case::no_dot("SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0Gcontract-name", RuntimeError::TypeParseFailure(
    "Invalid principal literal: expected a `.` in a qualified contract name"
        .to_string(),
))]
#[case::invalid_contract_name("SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G.1nvalid-name", RuntimeError::BadNameValue("ContractName", "1nvalid-name".into()))]

fn test_qualified_contract_identifier_parse_returns_vm_internal_error(
    #[case] input: &str,
    #[case] expected_err: RuntimeError,
) {
    let err = QualifiedContractIdentifier::parse(input)
        .expect_err("Unexpected qualified contract identifier");
    assert_eq!(VmExecutionError::from(expected_err), err);
}

#[rstest]
#[case::no_dot("SP2PABAF9FTAJYNFZH93XENAJ8FVY99RRM50D2JG9.nft-traitnft-trait", RuntimeError::TypeParseFailure(
    "Invalid principal literal: expected a `.` in a qualified contract name"
        .to_string(),
))]
#[case::invalid_contract_name("SP2PABAF9FTAJYNFZH93XENAJ8FVY99RRM50D2JG9.1nvalid-contract.valid-trait", RuntimeError::BadNameValue("ContractName", "1nvalid-contract".into()))]
#[case::invalid_trait_name("SP2PABAF9FTAJYNFZH93XENAJ8FVY99RRM50D2JG9.valid-contract.1nvalid-trait", RuntimeError::BadNameValue("ClarityName", "1nvalid-trait".into()))]
#[case::invalid_standard_principal("S162RK3CHJPCSSK6BM757FW.valid-contract.valid-trait", RuntimeError::TypeParseFailure(
    "Invalid principal literal: Expected 20 data bytes.".to_string(),
))]
fn test_trait_identifier_parse_returns_runtime_error(
    #[case] input: &str,
    #[case] expected_err: RuntimeError,
) {
    let expected_err = VmExecutionError::from(expected_err);

    let err = TraitIdentifier::parse(input).expect_err("Unexpected trait identifier");
    assert_eq!(expected_err, err);

    let err =
        TraitIdentifier::parse_sugared_syntax(input).expect_err("Unexpected trait identifier");
    assert_eq!(expected_err, err);
}

#[rstest]
#[case::bad_type_construction(".valid-contract.valid-trait", RuntimeError::BadTypeConstruction)]
#[case::forwards_parse_errors("S162RK3CHJPCSSK6BM757FW.valid-contract.valid-trait", RuntimeError::TypeParseFailure(
    "Invalid principal literal: Expected 20 data bytes.".to_string(),
))]
fn test_trait_identifier_parse_fully_qualified_returns_runtime_error(
    #[case] input: &str,
    #[case] expected_err: RuntimeError,
) {
    let err =
        TraitIdentifier::parse_fully_qualified(input).expect_err("Unexpected trait identifier");
    assert_eq!(VmExecutionError::from(expected_err), err);
}

/// The returned VMInternalError is consensus-critical.
#[test]
fn test_standard_principal_data_new_returns_vm_internal_error_consensus_critical() {
    let result = StandardPrincipalData::new(32, [0; 20]);
    let err = result.expect_err("Unexpected principal data");

    assert_eq!(
        VmExecutionError::from(VmInternalError::Expect("Unexpected principal data".into())),
        err.into(),
    );
}

/// The returned VMInternalError is consensus-critical.
#[test]
fn test_sequence_data_element_at_returns_vm_internal_error_consensus_critical() {
    let buff = SequenceData::String(CharType::ASCII(ASCIIData { data: vec![1] }));
    let err = buff.element_at(0).unwrap_err();
    assert_eq!(
        VmExecutionError::from(VmInternalError::Expect(
            "BUG: failed to initialize single-byte ASCII buffer".into()
        )),
        err
    );
}

/// The returned VMInternalError is consensus-critical.
#[test]
fn test_ascii_data_to_value_returns_vm_internal_error_consensus_critical() {
    let err = ASCIIData::to_value(&1).unwrap_err();
    assert_eq!(
        VmExecutionError::from(VmInternalError::Expect(
            "ERROR: Invalid ASCII string successfully constructed".into()
        )),
        err
    );
}

/// The returned VMInternalError is consensus-critical.
#[test]
fn test_utf8_data_to_value_returns_vm_internal_error_consensus_critical() {
    let err = UTF8Data::to_value(&vec![0xED, 0xA0, 0x80]).unwrap_err();
    assert_eq!(
        VmExecutionError::from(VmInternalError::Expect(
            "ERROR: Invalid UTF8 string successfully constructed".into()
        )),
        err
    );
}

/// The returned VMInternalError is consensus-critical.
#[test]
fn test_tuple_data_from_data_typed_returns_vm_internal_error_consensus_critical() {
    let tuple_type =
        TupleTypeSignature::try_from(vec![("a".into(), TypeSignature::IntType)]).unwrap();
    let err = TupleData::from_data_typed(
        &StacksEpochId::Epoch32,
        vec![("a".into(), Value::UInt(1))],
        &tuple_type,
    )
    .unwrap_err();
    assert_eq!(
        VmExecutionError::from(VmInternalError::FailureConstructingTupleWithType),
        err
    );
}

#[rstest]
#[case::not_a_string(Value::none(), VmInternalError::Expect("Expected ASCII string".to_string()))]
#[case::invalid_utf8(Value::Sequence(SequenceData::String(CharType::ASCII(ASCIIData { data: vec![0xED, 0xA0, 0x80] }))), VmInternalError::Expect("Non UTF-8 data in string".to_string()))]
fn test_value_expect_ascii_returns_vm_internal_error(
    #[case] value: Value,
    #[case] expected_err: VmInternalError,
) {
    let err = value.expect_ascii().unwrap_err();
    assert_eq!(VmExecutionError::from(expected_err), err);
}

/// The returned VMInternalError is consensus-critical.
#[test]
fn test_value_expect_u128_returns_vm_internal_error_consensus_critical() {
    let err = Value::none().expect_u128().unwrap_err();
    assert_eq!(
        VmExecutionError::from(VmInternalError::Expect("Expected u128".to_string())),
        err
    );
}

#[test]
fn test_value_expect_i128_returns_vm_internal_error() {
    let err = Value::none().expect_i128().unwrap_err();
    assert_eq!(
        VmExecutionError::from(VmInternalError::Expect("Expected i128".to_string())),
        err
    );
}

#[rstest]
#[case::not_a_buffer(Value::none(), VmInternalError::Expect("Expected buff".to_string()))]
#[case::too_small(Value::buff_from(vec![1, 2, 3, 4]).unwrap(), VmInternalError::Expect("Unexpected buff length".to_string()))]
fn test_value_expect_buff_returns_vm_internal_error(
    #[case] value: Value,
    #[case] expected_err: VmInternalError,
) {
    let err = value.expect_buff(1).unwrap_err();
    assert_eq!(VmExecutionError::from(expected_err), err);
}

#[test]
fn test_value_expect_tuple_returns_vm_internal_error() {
    let err = Value::none().expect_tuple().unwrap_err();
    assert_eq!(
        VmExecutionError::from(VmInternalError::Expect("Expected tuple".to_string())),
        err
    );
}

#[test]
fn test_value_expect_list_returns_vm_internal_error() {
    let err = Value::none().expect_list().unwrap_err();
    assert_eq!(
        VmExecutionError::from(VmInternalError::Expect("Expected list".to_string())),
        err
    );
}

#[test]
fn test_value_expect_buff_padded_returns_vm_internal_error() {
    let err = Value::none().expect_buff_padded(10, 0).unwrap_err();
    assert_eq!(
        VmExecutionError::from(VmInternalError::Expect("Expected buff".to_string())),
        err
    );
}

#[test]
fn test_value_expect_bool_returns_vm_internal_error() {
    let err = Value::none().expect_bool().unwrap_err();
    assert_eq!(
        VmExecutionError::from(VmInternalError::Expect("Expected bool".to_string())),
        err
    );
}

/// The returned VMInternalError is consensus-critical.
#[test]
fn test_value_expect_optional_returns_vm_internal_error_consensus_critical() {
    let err = Value::okay_true().expect_optional().unwrap_err();
    assert_eq!(
        VmExecutionError::from(VmInternalError::Expect("Expected optional".to_string())),
        err
    );
}

/// The returned VMInternalError is consensus-critical.
#[test]
fn test_value_expect_principal_returns_vm_internal_error_consensus_critical() {
    let err = Value::none().expect_principal().unwrap_err();
    assert_eq!(
        VmExecutionError::from(VmInternalError::Expect("Expected principal".to_string())),
        err
    );
}

/// The returned VMInternalError is consensus-critical.
#[test]
fn test_value_expect_callable_returns_vm_internal_error_consensus_critical() {
    let err = Value::none().expect_callable().unwrap_err();
    assert_eq!(
        VmExecutionError::from(VmInternalError::Expect("Expected callable".to_string())),
        err
    );
}

#[test]
fn test_value_expect_result_returns_vm_internal_error() {
    let err = Value::none().expect_result().unwrap_err();
    assert_eq!(
        VmExecutionError::from(VmInternalError::Expect("Expected response".to_string())),
        err
    );
}

#[rstest]
#[case::not_a_response(Value::none(), VmInternalError::Expect("Expected response".to_string()))]
#[case::not_an_ok_response(Value::error(Value::Int(1)).unwrap(), VmInternalError::Expect("Expected ok response".to_string()))]
fn test_value_expect_result_ok_returns_vm_internal_error(
    #[case] value: Value,
    #[case] expected_err: VmInternalError,
) {
    let err = value.expect_result_ok().unwrap_err();
    assert_eq!(VmExecutionError::from(expected_err), err);
}

#[rstest]
#[case::not_a_response(Value::none(), VmInternalError::Expect("Expected response".to_string()))]
#[case::not_an_err_response(Value::okay_true(), VmInternalError::Expect("Expected err response".to_string()))]
fn test_value_expect_result_err_returns_vm_internal_error(
    #[case] value: Value,
    #[case] expected_err: VmInternalError,
) {
    let err = value.expect_result_err().unwrap_err();
    assert_eq!(VmExecutionError::from(expected_err), err);
}

/// The returned VMInternalError is consensus-critical.
#[test]
fn test_buff_data_len_returns_vm_internal_error_consensus_critical() {
    let err = BuffData {
        data: vec![1; MAX_VALUE_SIZE as usize + 1],
    }
    .len()
    .unwrap_err();
    assert_eq!(
        VmExecutionError::from(VmInternalError::Expect(
            "Data length should be valid".into()
        )),
        err
    );
}

#[test]
fn test_ascii_data_len_returns_vm_internal_error() {
    let err = ASCIIData {
        data: vec![1; MAX_VALUE_SIZE as usize + 1],
    }
    .len()
    .unwrap_err();
    assert_eq!(
        VmExecutionError::from(VmInternalError::Expect(
            "Data length should be valid".into()
        )),
        err
    );
}

#[test]
fn test_utf8_data_len_returns_vm_internal_error() {
    let err = UTF8Data {
        data: vec![vec![]; MAX_VALUE_SIZE as usize + 1],
    }
    .len()
    .unwrap_err();
    assert_eq!(
        VmExecutionError::from(VmInternalError::Expect(
            "Data length should be valid".into()
        )),
        err
    );
}

#[test]
fn invalid_utf8_encoding_from_oob_unicode_escape() {
    // This is a syntactically valid escape: \u{HEX}
    // BUT 110000 > 10FFFF (max Unicode scalar)
    // So oob Unicode → char::from_u32(None) → InvalidUTF8Encoding
    let bad_utf8_literal = "\\u{110000}".to_string();

    let err = Value::string_utf8_from_string_utf8_literal(bad_utf8_literal).unwrap_err();
    assert!(matches!(
        err,
        VmExecutionError::Unchecked(CheckErrorKind::InvalidUTF8Encoding)
    ));
}

#[test]
fn invalid_utf8_encoding() {
    // Valid hex → parse OK
    // But > 0x10FFFF → char::from_u32 returns None → InvalidUTF8Encoding
    let bad_literal = "\\u{110000}".to_string();
    let err = Value::string_utf8_from_string_utf8_literal(bad_literal).unwrap_err();
    assert!(matches!(
        err,
        VmExecutionError::Unchecked(CheckErrorKind::InvalidUTF8Encoding)
    ));
}
