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

pub mod serialization;
pub mod signatures;

use std::str;

pub use clarity_serialization::types::{
    byte_len_of_serialization, ASCIIData, BuffData, CallableData, CharType, ContractIdentifier,
    ListData, OptionalData, PrincipalData, QualifiedContractIdentifier, ResponseData, SequenceData,
    SequencedValue, StacksAddressExtensions, TraitIdentifier, TupleData, UTF8Data, Value,
    BOUND_VALUE_SERIALIZATION_BYTES, BOUND_VALUE_SERIALIZATION_HEX, MAX_TYPE_DEPTH, MAX_VALUE_SIZE,
    NONE, WRAPPER_VALUE_SIZE,
};

pub use self::std_principals::StandardPrincipalData;
use crate::vm::errors::CheckErrors;
pub use crate::vm::types::signatures::{
    parse_name_type_pairs, AssetIdentifier, BufferLength, FixedFunction, FunctionArg,
    FunctionSignature, FunctionType, ListTypeData, SequenceSubtype, StringSubtype,
    StringUTF8Length, TupleTypeSignature, TypeSignature, TypeSignatureExt, BUFF_1, BUFF_20,
    BUFF_21, BUFF_32, BUFF_33, BUFF_64, BUFF_65,
};
use crate::vm::ClarityVersion;

mod std_principals {
    pub use clarity_serialization::types::StandardPrincipalData;
}

// Properties for "get-block-info".
define_versioned_named_enum!(BlockInfoProperty(ClarityVersion) {
    Time("time", ClarityVersion::Clarity1),
    VrfSeed("vrf-seed", ClarityVersion::Clarity1),
    HeaderHash("header-hash", ClarityVersion::Clarity1),
    IdentityHeaderHash("id-header-hash", ClarityVersion::Clarity1),
    BurnchainHeaderHash("burnchain-header-hash", ClarityVersion::Clarity1),
    MinerAddress("miner-address", ClarityVersion::Clarity1),
    MinerSpendWinner("miner-spend-winner", ClarityVersion::Clarity2),
    MinerSpendTotal("miner-spend-total", ClarityVersion::Clarity2),
    BlockReward("block-reward", ClarityVersion::Clarity2),
});

// Properties for "get-burn-block-info".
define_named_enum!(BurnBlockInfoProperty {
    HeaderHash("header-hash"),
    PoxAddrs("pox-addrs"),
});

define_named_enum!(StacksBlockInfoProperty {
    IndexHeaderHash("id-header-hash"),
    HeaderHash("header-hash"),
    Time("time"),
});

define_named_enum!(TenureInfoProperty {
    Time("time"),
    VrfSeed("vrf-seed"),
    BurnchainHeaderHash("burnchain-header-hash"),
    MinerAddress("miner-address"),
    MinerSpendWinner("miner-spend-winner"),
    MinerSpendTotal("miner-spend-total"),
    BlockReward("block-reward"),
});

impl BlockInfoProperty {
    pub fn type_result(&self) -> TypeSignature {
        use self::BlockInfoProperty::*;
        match self {
            Time | MinerSpendWinner | MinerSpendTotal | BlockReward => TypeSignature::UIntType,
            IdentityHeaderHash | VrfSeed | HeaderHash | BurnchainHeaderHash => BUFF_32.clone(),
            MinerAddress => TypeSignature::PrincipalType,
        }
    }
}

impl BurnBlockInfoProperty {
    pub fn type_result(&self) -> std::result::Result<TypeSignature, CheckErrors> {
        use self::BurnBlockInfoProperty::*;
        let result = match self {
            HeaderHash => BUFF_32.clone(),
            PoxAddrs => TupleTypeSignature::try_from(vec![
                (
                    "addrs".into(),
                    TypeSignature::list_of(
                        TypeSignature::TupleType(
                            TupleTypeSignature::try_from(vec![
                                ("version".into(), BUFF_1.clone()),
                                ("hashbytes".into(), BUFF_32.clone()),
                            ])
                            .map_err(|_| {
                                CheckErrors::Expects(
                                    "FATAL: bad type signature for pox addr".into(),
                                )
                            })?,
                        ),
                        2,
                    )
                    .map_err(|_| CheckErrors::Expects("FATAL: bad list type signature".into()))?,
                ),
                ("payout".into(), TypeSignature::UIntType),
            ])
            .map_err(|_| CheckErrors::Expects("FATAL: bad type signature for pox addr".into()))?
            .into(),
        };
        Ok(result)
    }
}

impl StacksBlockInfoProperty {
    pub fn type_result(&self) -> TypeSignature {
        use self::StacksBlockInfoProperty::*;
        match self {
            Time => TypeSignature::UIntType,
            IndexHeaderHash | HeaderHash => BUFF_32.clone(),
        }
    }
}

impl TenureInfoProperty {
    pub fn type_result(&self) -> TypeSignature {
        use self::TenureInfoProperty::*;
        match self {
            Time | MinerSpendWinner | MinerSpendTotal | BlockReward => TypeSignature::UIntType,
            VrfSeed | BurnchainHeaderHash => BUFF_32.clone(),
            MinerAddress => TypeSignature::PrincipalType,
        }
    }
}

#[cfg(test)]
mod test {
    use stacks_common::types::StacksEpochId;

    use super::*;
    use crate::vm::errors::{Error, InterpreterError, RuntimeErrorType};

    #[test]
    fn test_qualified_contract_identifier_local_returns_runtime_error() {
        let err = QualifiedContractIdentifier::local("1nvalid-name")
            .expect_err("Unexpected qualified contract identifier");
        assert_eq!(
            Error::from(RuntimeErrorType::BadNameValue(
                "ContractName",
                "1nvalid-name".into()
            )),
            err,
        );
    }

    #[rstest]
    #[case::too_short("S162RK3CHJPCSSK6BM757FW", RuntimeErrorType::ParseError(
        "Invalid principal literal: Expected 20 data bytes.".to_string(),
    ))]
    #[case::too_long("S1C5H66S35CSKK6CK1C9HP8SB6CWSK4RB2CDJK8HY4", RuntimeErrorType::ParseError(
        "Invalid principal literal: Expected 20 data bytes.".to_string(),
    ))]
    #[case::invalid_c32("II2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G", RuntimeErrorType::ParseError(
        "Invalid principal literal: base58ck checksum 0x1074d4f7 does not match expected 0xae29c6e0".to_string(),
    ))]
    fn test_principal_data_parse_standard_principal_returns_runtime_error(
        #[case] input: &str,
        #[case] expected_err: RuntimeErrorType,
    ) {
        let err =
            PrincipalData::parse_standard_principal(input).expect_err("Unexpected principal data");
        assert_eq!(Error::from(expected_err), err);
    }

    #[rstest]
    #[case::no_dot("SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0Gcontract-name", RuntimeErrorType::ParseError(
        "Invalid principal literal: expected a `.` in a qualified contract name"
            .to_string(),
    ))]
    #[case::invalid_contract_name("SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G.1nvalid-name", RuntimeErrorType::BadNameValue("ContractName", "1nvalid-name".into()))]

    fn test_qualified_contract_identifier_parse_returns_interpreter_error(
        #[case] input: &str,
        #[case] expected_err: RuntimeErrorType,
    ) {
        let err = QualifiedContractIdentifier::parse(input)
            .expect_err("Unexpected qualified contract identifier");
        assert_eq!(Error::from(expected_err), err);
    }

    #[rstest]
    #[case::no_dot("SP2PABAF9FTAJYNFZH93XENAJ8FVY99RRM50D2JG9.nft-traitnft-trait", RuntimeErrorType::ParseError(
        "Invalid principal literal: expected a `.` in a qualified contract name"
            .to_string(),
    ))]
    #[case::invalid_contract_name("SP2PABAF9FTAJYNFZH93XENAJ8FVY99RRM50D2JG9.1nvalid-contract.valid-trait", RuntimeErrorType::BadNameValue("ContractName", "1nvalid-contract".into()))]
    #[case::invalid_trait_name("SP2PABAF9FTAJYNFZH93XENAJ8FVY99RRM50D2JG9.valid-contract.1nvalid-trait", RuntimeErrorType::BadNameValue("ClarityName", "1nvalid-trait".into()))]
    #[case::invalid_standard_principal("S162RK3CHJPCSSK6BM757FW.valid-contract.valid-trait", RuntimeErrorType::ParseError(
        "Invalid principal literal: Expected 20 data bytes.".to_string(),
    ))]
    fn test_trait_identifier_parse_returns_runtime_error(
        #[case] input: &str,
        #[case] expected_err: RuntimeErrorType,
    ) {
        let expected_err = Error::from(expected_err);

        let err = TraitIdentifier::parse(input).expect_err("Unexpected trait identifier");
        assert_eq!(expected_err, err);

        let err =
            TraitIdentifier::parse_sugared_syntax(input).expect_err("Unexpected trait identifier");
        assert_eq!(expected_err, err);
    }

    #[rstest]
    #[case::bad_type_construction(
        ".valid-contract.valid-trait",
        RuntimeErrorType::BadTypeConstruction
    )]
    #[case::forwards_parse_errors("S162RK3CHJPCSSK6BM757FW.valid-contract.valid-trait", RuntimeErrorType::ParseError(
        "Invalid principal literal: Expected 20 data bytes.".to_string(),
    ))]
    fn test_trait_identifier_parse_fully_qualified_returns_runtime_error(
        #[case] input: &str,
        #[case] expected_err: RuntimeErrorType,
    ) {
        let err =
            TraitIdentifier::parse_fully_qualified(input).expect_err("Unexpected trait identifier");
        assert_eq!(Error::from(expected_err), err);
    }

    /// The returned InterpreterError is consensus-critical.
    #[test]
    fn test_standard_principal_data_new_returns_interpreter_error_consensus_critical() {
        let result = StandardPrincipalData::new(32, [0; 20]);
        let err = result.expect_err("Unexpected principal data");

        assert_eq!(
            Error::from(InterpreterError::Expect("Unexpected principal data".into())),
            err.into(),
        );
    }

    /// The returned InterpreterError is consensus-critical.
    #[test]
    fn test_sequence_data_element_at_returns_interpreter_error_consensus_critical() {
        let buff = SequenceData::String(CharType::ASCII(ASCIIData { data: vec![1] }));
        let err = buff.element_at(0).unwrap_err();
        assert_eq!(
            Error::from(InterpreterError::Expect(
                "BUG: failed to initialize single-byte ASCII buffer".into()
            )),
            err
        );
    }

    /// The returned InterpreterError is consensus-critical.
    #[test]
    fn test_ascii_data_to_value_returns_interpreter_error_consensus_critical() {
        let err = ASCIIData::to_value(&1).unwrap_err();
        assert_eq!(
            Error::from(InterpreterError::Expect(
                "ERROR: Invalid ASCII string successfully constructed".into()
            )),
            err
        );
    }

    /// The returned InterpreterError is consensus-critical.
    #[test]
    fn test_utf8_data_to_value_returns_interpreter_error_consensus_critical() {
        let err = UTF8Data::to_value(&vec![0xED, 0xA0, 0x80]).unwrap_err();
        assert_eq!(
            Error::from(InterpreterError::Expect(
                "ERROR: Invalid UTF8 string successfully constructed".into()
            )),
            err
        );
    }

    /// The returned InterpreterError is consensus-critical.
    #[test]
    fn test_tuple_data_from_data_typed_returns_interpreter_error_consensus_critical() {
        let tuple_type =
            TupleTypeSignature::try_from(vec![("a".into(), TypeSignature::IntType)]).unwrap();
        let err = TupleData::from_data_typed(
            &StacksEpochId::Epoch32,
            vec![("a".into(), Value::UInt(1))],
            &tuple_type,
        )
        .unwrap_err();
        assert_eq!(
            Error::from(InterpreterError::FailureConstructingTupleWithType),
            err
        );
    }

    #[rstest]
    #[case::not_a_string(Value::none(), InterpreterError::Expect("Expected ASCII string".to_string()))]
    #[case::invalid_utf8(Value::Sequence(SequenceData::String(CharType::ASCII(ASCIIData { data: vec![0xED, 0xA0, 0x80] }))), InterpreterError::Expect("Non UTF-8 data in string".to_string()))]
    fn test_value_expect_ascii_returns_interpreter_error(
        #[case] value: Value,
        #[case] expected_err: InterpreterError,
    ) {
        let err = value.expect_ascii().unwrap_err();
        assert_eq!(Error::from(expected_err), err);
    }

    /// The returned InterpreterError is consensus-critical.
    #[test]
    fn test_value_expect_u128_returns_interpreter_error_consensus_critical() {
        let err = Value::none().expect_u128().unwrap_err();
        assert_eq!(
            Error::from(InterpreterError::Expect("Expected u128".to_string())),
            err
        );
    }

    #[test]
    fn test_value_expect_i128_returns_interpreter_error() {
        let err = Value::none().expect_i128().unwrap_err();
        assert_eq!(
            Error::from(InterpreterError::Expect("Expected i128".to_string())),
            err
        );
    }

    #[rstest]
    #[case::not_a_buffer(Value::none(), InterpreterError::Expect("Expected buff".to_string()))]
    #[case::too_small(Value::buff_from(vec![1, 2, 3, 4]).unwrap(), InterpreterError::Expect("Unexpected buff length".to_string()))]
    fn test_value_expect_buff_returns_interpreter_error(
        #[case] value: Value,
        #[case] expected_err: InterpreterError,
    ) {
        let err = value.expect_buff(1).unwrap_err();
        assert_eq!(Error::from(expected_err), err);
    }

    #[test]
    fn test_value_expect_tuple_returns_interpreter_error() {
        let err = Value::none().expect_tuple().unwrap_err();
        assert_eq!(
            Error::from(InterpreterError::Expect("Expected tuple".to_string())),
            err
        );
    }

    #[test]
    fn test_value_expect_list_returns_interpreter_error() {
        let err = Value::none().expect_list().unwrap_err();
        assert_eq!(
            Error::from(InterpreterError::Expect("Expected list".to_string())),
            err
        );
    }

    #[test]
    fn test_value_expect_buff_padded_returns_interpreter_error() {
        let err = Value::none().expect_buff_padded(10, 0).unwrap_err();
        assert_eq!(
            Error::from(InterpreterError::Expect("Expected buff".to_string())),
            err
        );
    }

    #[test]
    fn test_value_expect_bool_returns_interpreter_error() {
        let err = Value::none().expect_bool().unwrap_err();
        assert_eq!(
            Error::from(InterpreterError::Expect("Expected bool".to_string())),
            err
        );
    }

    /// The returned InterpreterError is consensus-critical.
    #[test]
    fn test_value_expect_optional_returns_interpreter_error_consensus_critical() {
        let err = Value::okay_true().expect_optional().unwrap_err();
        assert_eq!(
            Error::from(InterpreterError::Expect("Expected optional".to_string())),
            err
        );
    }

    /// The returned InterpreterError is consensus-critical.
    #[test]
    fn test_value_expect_principal_returns_interpreter_error_consensus_critical() {
        let err = Value::none().expect_principal().unwrap_err();
        assert_eq!(
            Error::from(InterpreterError::Expect("Expected principal".to_string())),
            err
        );
    }

    /// The returned InterpreterError is consensus-critical.
    #[test]
    fn test_value_expect_callable_returns_interpreter_error_consensus_critical() {
        let err = Value::none().expect_callable().unwrap_err();
        assert_eq!(
            Error::from(InterpreterError::Expect("Expected callable".to_string())),
            err
        );
    }

    #[test]
    fn test_value_expect_result_returns_interpreter_error() {
        let err = Value::none().expect_result().unwrap_err();
        assert_eq!(
            Error::from(InterpreterError::Expect("Expected response".to_string())),
            err
        );
    }

    #[rstest]
    #[case::not_a_response(Value::none(), InterpreterError::Expect("Expected response".to_string()))]
    #[case::not_an_ok_response(Value::error(Value::Int(1)).unwrap(), InterpreterError::Expect("Expected ok response".to_string()))]
    fn test_value_expect_result_ok_returns_interpreter_error(
        #[case] value: Value,
        #[case] expected_err: InterpreterError,
    ) {
        let err = value.expect_result_ok().unwrap_err();
        assert_eq!(Error::from(expected_err), err);
    }

    #[rstest]
    #[case::not_a_response(Value::none(), InterpreterError::Expect("Expected response".to_string()))]
    #[case::not_an_err_response(Value::okay_true(), InterpreterError::Expect("Expected err response".to_string()))]
    fn test_value_expect_result_err_returns_interpreter_error(
        #[case] value: Value,
        #[case] expected_err: InterpreterError,
    ) {
        let err = value.expect_result_err().unwrap_err();
        assert_eq!(Error::from(expected_err), err);
    }

    /// The returned InterpreterError is consensus-critical.
    #[test]
    fn test_buff_data_len_returns_interpreter_error_consensus_critical() {
        let err = BuffData {
            data: vec![1; MAX_VALUE_SIZE as usize + 1],
        }
        .len()
        .unwrap_err();
        assert_eq!(
            Error::from(InterpreterError::Expect(
                "Data length should be valid".into()
            )),
            err
        );
    }

    #[test]
    fn test_ascii_data_len_returns_interpreter_error() {
        let err = ASCIIData {
            data: vec![1; MAX_VALUE_SIZE as usize + 1],
        }
        .len()
        .unwrap_err();
        assert_eq!(
            Error::from(InterpreterError::Expect(
                "Data length should be valid".into()
            )),
            err
        );
    }

    #[test]
    fn test_utf8_data_len_returns_interpreter_error() {
        let err = UTF8Data {
            data: vec![vec![]; MAX_VALUE_SIZE as usize + 1],
        }
        .len()
        .unwrap_err();
        assert_eq!(
            Error::from(InterpreterError::Expect(
                "Data length should be valid".into()
            )),
            err
        );
    }
}
