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

use crate::types::{
    ASCIIData, BuffData, CharType, ClarityTypeError, ListTypeData, MAX_VALUE_SIZE, PrincipalData,
    QualifiedContractIdentifier, SequenceData, SequenceSubtype, SequencedValue as _,
    StandardPrincipalData, TraitIdentifier, TupleData, TupleTypeSignature, TypeSignature, UTF8Data,
    Value,
};

#[test]
fn test_constructors() {
    assert_eq!(
        Value::list_with_type(
            &StacksEpochId::latest(),
            vec![Value::Int(5), Value::Int(2)],
            ListTypeData::new_list(TypeSignature::BoolType, 3).unwrap()
        ),
        Err(ClarityTypeError::ListTypeMismatch)
    );
    assert_eq!(
        ListTypeData::new_list(TypeSignature::IntType, MAX_VALUE_SIZE),
        Err(ClarityTypeError::ValueTooLarge)
    );

    assert_eq!(
        Value::buff_from(vec![0; (MAX_VALUE_SIZE + 1) as usize]),
        Err(ClarityTypeError::ValueTooLarge)
    );

    // Test that wrappers (okay, error, some)
    //   correctly error when _they_ cause the value size
    //   to exceed the max value size (note, the buffer constructor
    //   isn't causing the error).
    assert_eq!(
        Value::okay(Value::buff_from(vec![0; (MAX_VALUE_SIZE) as usize]).unwrap()),
        Err(ClarityTypeError::ValueTooLarge)
    );

    assert_eq!(
        Value::error(Value::buff_from(vec![0; (MAX_VALUE_SIZE) as usize]).unwrap()),
        Err(ClarityTypeError::ValueTooLarge)
    );

    assert_eq!(
        Value::some(Value::buff_from(vec![0; (MAX_VALUE_SIZE) as usize]).unwrap()),
        Err(ClarityTypeError::ValueTooLarge)
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
        Err(ClarityTypeError::TypeSignatureTooDeep)
    );

    assert_eq!(
        Value::list_from(vec![inner_value.clone()]),
        Err(ClarityTypeError::TypeSignatureTooDeep)
    );
    assert_eq!(
        Value::okay(inner_value.clone()),
        Err(ClarityTypeError::TypeSignatureTooDeep)
    );
    assert_eq!(
        Value::error(inner_value.clone()),
        Err(ClarityTypeError::TypeSignatureTooDeep)
    );
    assert_eq!(
        Value::some(inner_value),
        Err(ClarityTypeError::TypeSignatureTooDeep)
    );

    if std::env::var("CIRCLE_TESTING") == Ok("1".to_string()) {
        println!("Skipping allocation test on Circle");
        return;
    }

    // on 32-bit archs, this error cannot even happen, so don't test (and cause an overflow panic)
    if (u32::MAX as usize) < usize::MAX {
        assert_eq!(
            Value::buff_from(vec![0; (u32::MAX as usize) + 10]),
            Err(ClarityTypeError::ValueTooLarge)
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
        ClarityTypeError::InvalidContractName("1nvalid-name".into()),
        err,
    );
}

#[rstest]
#[case::too_short("S162RK3CHJPCSSK6BM757FW", ClarityTypeError::InvalidPrincipalLength(9))]
#[case::too_long(
    "S1C5H66S35CSKK6CK1C9HP8SB6CWSK4RB2CDJK8HY4",
    ClarityTypeError::InvalidPrincipalLength(21)
)]
#[case::invalid_c32("II2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G", ClarityTypeError::InvalidPrincipalEncoding(
    "base58ck checksum 0x1074d4f7 does not match expected 0xae29c6e0".into(),
))]
fn test_principal_data_parse_standard_principal_returns_clarity_type_error(
    #[case] input: &str,
    #[case] expected_err: ClarityTypeError,
) {
    let err = PrincipalData::parse_standard_principal(input)
        .expect_err("Unexpected valid principal data");
    assert_eq!(expected_err, err);
}

#[rstest]
#[case::no_dot(
    "SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0Gcontract-name",
    ClarityTypeError::QualifiedContractMissingDot
)]
#[case::invalid_contract_name("SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G.1nvalid-name", ClarityTypeError::InvalidContractName("1nvalid-name".into()))]

fn test_qualified_contract_identifier_parse_returns_clarity_type_error(
    #[case] input: &str,
    #[case] expected_err: ClarityTypeError,
) {
    let err = QualifiedContractIdentifier::parse(input)
        .expect_err("Unexpected qualified contract identifier");
    assert_eq!(expected_err, err);
}

#[rstest]
#[case::no_dot(
    "SP2PABAF9FTAJYNFZH93XENAJ8FVY99RRM50D2JG9.nft-traitnft-trait",
    ClarityTypeError::QualifiedContractMissingDot
)]
#[case::invalid_contract_name("SP2PABAF9FTAJYNFZH93XENAJ8FVY99RRM50D2JG9.1nvalid-contract.valid-trait", ClarityTypeError::InvalidContractName("1nvalid-contract".into()))]
#[case::invalid_trait_name("SP2PABAF9FTAJYNFZH93XENAJ8FVY99RRM50D2JG9.valid-contract.1nvalid-trait", ClarityTypeError::InvalidClarityName("1nvalid-trait".into()))]
#[case::invalid_standard_principal(
    "S162RK3CHJPCSSK6BM757FW.valid-contract.valid-trait",
    ClarityTypeError::InvalidPrincipalLength(9)
)]
fn test_trait_identifier_parse_returns_clarity_type_error(
    #[case] input: &str,
    #[case] expected_err: ClarityTypeError,
) {
    let err = TraitIdentifier::parse(input).expect_err("Unexpected trait identifier");
    assert_eq!(expected_err, err);

    let err =
        TraitIdentifier::parse_sugared_syntax(input).expect_err("Unexpected trait identifier");
    assert_eq!(expected_err, err);
}

#[rstest]
#[case::bad_type_construction(
    ".valid-contract.valid-trait",
    ClarityTypeError::QualifiedContractEmptyIssuer
)]
#[case::forwards_parse_errors(
    "S162RK3CHJPCSSK6BM757FW.valid-contract.valid-trait",
    ClarityTypeError::InvalidPrincipalLength(9)
)]
fn test_trait_identifier_parse_fully_qualified_returns_clarity_type_error(
    #[case] input: &str,
    #[case] expected_err: ClarityTypeError,
) {
    let err =
        TraitIdentifier::parse_fully_qualified(input).expect_err("Unexpected trait identifier");
    assert_eq!(expected_err, err);
}

// TODO: remove this comment. Is this truly consensus critical? i.e. if it just returns an error, does it matter if it
// maintains that its a rejectable block
/// The returned ClarityTypeError::InvalidPrincipalVersion is consensus-critical.
#[test]
fn test_standard_principal_data_new_returns_clarity_type_error_invalid_principal_version_error_consensus_critical()
 {
    let result = StandardPrincipalData::new(32, [0; 20]);
    let err = result.expect_err("Unexpected valid principal data");

    assert_eq!(ClarityTypeError::InvalidPrincipalVersion(32), err,);
}

// TODO: remove this comment. Is this truly consensus critical? i.e. if it just returns an error, does it matter if it
// maintains that its a rejectable block? Currently all calls to elemant_at are converted to an VmInternal::Expects
#[test]
fn test_sequence_data_element_at_returns_clarity_type_error_consensus_critical() {
    let buff = SequenceData::String(CharType::ASCII(ASCIIData { data: vec![1] }));
    let err = buff.element_at(0).unwrap_err();
    assert_eq!(ClarityTypeError::InvalidAsciiCharacter(1), err);
}

// TODO: remove this comment. Is this truly consensus critical? i.e. if it just returns an error, does it matter if it
// maintains that its a rejectable block
#[test]
fn test_ascii_data_to_value_returns_clarity_type_error() {
    let err = ASCIIData::to_value(&1).unwrap_err();
    assert_eq!(ClarityTypeError::InvalidAsciiCharacter(1), err);
}

// TODO: remove this comment. Is this truly consensus critical? i.e. if it just returns an error, does it matter if it
// maintains that its a rejectable block
#[test]
fn test_utf8_data_to_value_returns_clarity_types_error_invalid_utf8_encoding_consensus_critical() {
    let err = UTF8Data::to_value(&vec![0xED, 0xA0, 0x80]).unwrap_err();
    assert_eq!(ClarityTypeError::InvalidUtf8Encoding, err);
}

// TODO: remove this comment. Is this truly consensus critical? i.e. if it just returns an error, does it matter if it
// maintains that its a rejectable block? Currently even without my own changes, calls to from_data_typed are already
// immediately remapped
#[test]
fn test_tuple_data_from_data_typed_returns_clarity_type_error() {
    let tuple_type =
        TupleTypeSignature::try_from(vec![("a".into(), TypeSignature::IntType)]).unwrap();
    let err = TupleData::from_data_typed(
        &StacksEpochId::Epoch32,
        vec![("a".into(), Value::UInt(1))],
        &tuple_type,
    )
    .unwrap_err();
    assert_eq!(
        ClarityTypeError::TypeMismatchValue(
            Box::new(TypeSignature::IntType),
            Box::new(Value::UInt(1)),
        ),
        err
    );
}

#[rstest]
#[case::not_a_string(
    Value::none(),
    ClarityTypeError::TypeMismatchValue(
        Box::new(TypeSignature::STRING_ASCII_MIN),
        Box::new(Value::none())
    )
)]
#[case::invalid_utf8(Value::Sequence(SequenceData::String(CharType::ASCII(ASCIIData { data: vec![0xED, 0xA0, 0x80] }))), ClarityTypeError::InvalidUtf8Encoding)]
fn test_value_expect_ascii_returns_clarity_type_error(
    #[case] value: Value,
    #[case] expected_err: ClarityTypeError,
) {
    let err = value.expect_ascii().unwrap_err();
    assert_eq!(expected_err, err);
}

// TODO: remove this comment. Is this truly consensus critical? i.e. if it just returns an error, does it matter if it
// maintains that its a rejectable block? I think its up to the caller to determine if its consensus critical issue
#[test]
fn test_value_expect_u128_returns_clarity_type_error() {
    let err = Value::none().expect_u128().unwrap_err();
    assert_eq!(
        ClarityTypeError::TypeMismatchValue(
            Box::new(TypeSignature::UIntType),
            Box::new(Value::none())
        ),
        err
    );
}

#[test]
fn test_value_expect_i128_returns_clarity_type_error() {
    let err = Value::none().expect_i128().unwrap_err();
    assert_eq!(
        ClarityTypeError::TypeMismatchValue(
            Box::new(TypeSignature::IntType),
            Box::new(Value::none())
        ),
        err
    );
}

#[rstest]
#[case::not_a_buffer(
    Value::none(),
    ClarityTypeError::TypeMismatchValue(
        Box::new(TypeSignature::BUFFER_MIN),
        Box::new(Value::none())
    )
)]
#[case::too_small(Value::buff_from(vec![1, 2, 3, 4]).unwrap(), ClarityTypeError::ValueOutOfBounds)]
fn test_value_expect_buff_returns_clarity_type_error(
    #[case] value: Value,
    #[case] expected_err: ClarityTypeError,
) {
    let err = value.expect_buff(1).unwrap_err();
    assert_eq!(expected_err, err);
}

#[test]
fn test_value_expect_tuple_returns_clarity_type_error() {
    let err = Value::none().expect_tuple().unwrap_err();
    assert_eq!(
        ClarityTypeError::TypeMismatchValue(
            // Unfortunately cannot construct an empty Tuple type
            // And to add it now would be intrusive.
            Box::new(TypeSignature::NoType),
            Box::new(Value::none()),
        ),
        err
    );
}

#[test]
fn test_value_expect_list_returns_clarity_type_error() {
    let err = Value::none().expect_list().unwrap_err();
    assert_eq!(
        ClarityTypeError::TypeMismatchValue(
            Box::new(TypeSignature::SequenceType(SequenceSubtype::ListType(
                TypeSignature::empty_list(),
            ))),
            Box::new(Value::none()),
        ),
        err
    );
}

#[test]
fn test_value_expect_buff_padded_returns_clarity_type_error() {
    let err = Value::none().expect_buff_padded(10, 0).unwrap_err();
    assert_eq!(
        ClarityTypeError::TypeMismatchValue(
            Box::new(TypeSignature::BUFFER_MIN),
            Box::new(Value::none()),
        ),
        err
    );
}

#[test]
fn test_value_expect_bool_returns_clarity_type_error() {
    let err = Value::none().expect_bool().unwrap_err();
    assert_eq!(
        ClarityTypeError::TypeMismatchValue(
            Box::new(TypeSignature::BoolType),
            Box::new(Value::none()),
        ),
        err
    );
}

/// TODO: remove this comment. Is this really consensus critical?
/// I think its up to the caller to determine if its consensus critical issue
#[test]
fn test_value_expect_optional_returns_clarity_type_error() {
    let err = Value::okay_true().expect_optional().unwrap_err();
    assert_eq!(
        ClarityTypeError::TypeMismatchValue(
            Box::new(TypeSignature::OptionalType(Box::new(TypeSignature::NoType))),
            Box::new(Value::okay_true()),
        ),
        err
    );
}

/// TODO: remove this comment. Is this really consensus critical?
/// I think its up to the caller to determine if its consensus critical issue
#[test]
fn test_value_expect_principal_returns_clarity_type_error() {
    let err = Value::none().expect_principal().unwrap_err();
    assert_eq!(
        ClarityTypeError::TypeMismatchValue(
            Box::new(TypeSignature::PrincipalType),
            Box::new(Value::none()),
        ),
        err
    );
}

/// TODO: remove this comment. Is this really consensus critical?
/// I think its up to the caller to determine if its consensus critical issue
#[test]
fn test_value_expect_callable_returns_clarity_type_error() {
    let err = Value::none().expect_callable().unwrap_err();
    // Unfortunately cannot construct an empty Callable type
    // And to add it now would be intrusive.
    assert_eq!(
        ClarityTypeError::TypeMismatchValue(
            Box::new(TypeSignature::NoType),
            Box::new(Value::none()),
        ),
        err
    );
}

#[test]
fn test_value_expect_result_returns_clarity_type_error() {
    let err = Value::none().expect_result().unwrap_err();
    assert_eq!(
        ClarityTypeError::TypeMismatchValue(
            Box::new(TypeSignature::ResponseType(Box::new((
                TypeSignature::NoType,
                TypeSignature::NoType
            )))),
            Box::new(Value::none()),
        ),
        err
    );
}

#[rstest]
#[case::not_a_response(Value::none(), ClarityTypeError::TypeMismatchValue(Box::new(TypeSignature::ResponseType(Box::new((TypeSignature::NoType, TypeSignature::NoType)))), Box::new(Value::none())))]
#[case::not_an_ok_response(Value::error(Value::Int(1)).unwrap(), ClarityTypeError::ResponseTypeMismatch { expected_ok: true, data_committed: false })]
fn test_value_expect_result_ok_returns_clarity_type_error(
    #[case] value: Value,
    #[case] expected_err: ClarityTypeError,
) {
    let err = value.expect_result_ok().unwrap_err();
    assert_eq!(expected_err, err);
}

#[rstest]
#[case::not_a_response(Value::none(), ClarityTypeError::TypeMismatchValue(Box::new(TypeSignature::ResponseType(Box::new((TypeSignature::NoType, TypeSignature::NoType)))), Box::new(Value::none())))]
#[case::not_an_err_response(Value::okay_true(), ClarityTypeError::ResponseTypeMismatch { expected_ok: false, data_committed: true })]
fn test_value_expect_result_err_returns_clarity_type_error(
    #[case] value: Value,
    #[case] expected_err: ClarityTypeError,
) {
    let err = value.expect_result_err().unwrap_err();
    assert_eq!(expected_err, err);
}

// TODO: remove this comment. Is this truly consensus critical? i.e. if it just returns an error, does it matter if it
// maintains that its a rejectable block
#[test]
fn test_buff_data_len_returns_clarity_type_error() {
    let err = BuffData {
        data: vec![1; MAX_VALUE_SIZE as usize + 1],
    }
    .len()
    .unwrap_err();
    assert_eq!(ClarityTypeError::ValueTooLarge, err);
}

#[test]
fn test_ascii_data_len_returns_clarity_type_error() {
    let err = ASCIIData {
        data: vec![1; MAX_VALUE_SIZE as usize + 1],
    }
    .len()
    .unwrap_err();
    assert_eq!(ClarityTypeError::ValueTooLarge, err);
}

#[test]
fn test_utf8_data_len_returns_clarity_type_error() {
    let err = UTF8Data {
        data: vec![vec![]; MAX_VALUE_SIZE as usize + 1],
    }
    .len()
    .unwrap_err();
    assert_eq!(ClarityTypeError::ValueTooLarge, err);
}

#[test]
fn invalid_utf8_encoding_from_oob_unicode_escape() {
    // This is a syntactically valid escape: \u{HEX}
    // BUT 110000 > 10FFFF (max Unicode scalar)
    // So oob Unicode → char::from_u32(None) → InvalidUTF8Encoding
    let bad_utf8_literal = "\\u{110000}".to_string();

    let err = Value::string_utf8_from_string_utf8_literal(bad_utf8_literal).unwrap_err();
    assert!(matches!(err, ClarityTypeError::InvalidUtf8Encoding));
}

#[test]
fn invalid_string_ascii_from_bytes() {
    // 0xFF is NOT:
    // - ASCII alphanumeric
    // - ASCII punctuation
    // - ASCII whitespace
    let bad_bytes = vec![0xFF];

    let err = Value::string_ascii_from_bytes(bad_bytes).unwrap_err();

    assert!(matches!(err, ClarityTypeError::InvalidAsciiCharacter(_)));
}

#[test]
fn invalid_utf8_string_from_bytes() {
    // 0x80 is an invalid standalone UTF-8 continuation byte
    let bad_bytes = vec![0x80];

    let err = Value::string_utf8_from_bytes(bad_bytes).unwrap_err();

    assert!(matches!(err, ClarityTypeError::InvalidUtf8Encoding));
}
