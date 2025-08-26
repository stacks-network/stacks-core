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
use crate::vm::errors::{CheckErrors, InterpreterResult as Result};
use crate::vm::representations::SymbolicExpression;
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

pub trait GetAtomValues {
    fn atom_values(&mut self) -> Result<Vec<SymbolicExpression>>;
}

pub trait Filter {
    fn filter<F>(&mut self, filter: &mut F) -> Result<()>
    where
        F: FnMut(SymbolicExpression) -> Result<bool>;
}

impl GetAtomValues for SequenceData {
    fn atom_values(&mut self) -> Result<Vec<SymbolicExpression>> {
        match self {
            SequenceData::Buffer(ref mut data) => data.atom_values(),
            SequenceData::List(ref mut data) => data.atom_values(),
            SequenceData::String(CharType::ASCII(ref mut data)) => data.atom_values(),
            SequenceData::String(CharType::UTF8(ref mut data)) => data.atom_values(),
        }
    }
}

impl Filter for SequenceData {
    fn filter<F>(&mut self, filter: &mut F) -> Result<()>
    where
        F: FnMut(SymbolicExpression) -> Result<bool>,
    {
        // Note: this macro can probably get removed once
        // ```Vec::drain_filter<F>(&mut self, filter: F) -> DrainFilter<T, F>```
        // is available in rust stable channel (experimental at this point).
        macro_rules! drain_filter {
            ($data:expr, $seq_type:ident) => {
                let mut i = 0;
                while i != $data.data.len() {
                    let atom_value =
                        SymbolicExpression::atom_value($seq_type::to_value(&$data.data[i])?);
                    match filter(atom_value) {
                        Ok(res) if res == false => {
                            $data.data.remove(i);
                        }
                        Ok(_) => {
                            i += 1;
                        }
                        Err(err) => return Err(err),
                    }
                }
            };
        }

        match self {
            SequenceData::Buffer(ref mut data) => {
                drain_filter!(data, BuffData);
            }
            SequenceData::List(ref mut data) => {
                drain_filter!(data, ListData);
            }
            SequenceData::String(CharType::ASCII(ref mut data)) => {
                drain_filter!(data, ASCIIData);
            }
            SequenceData::String(CharType::UTF8(ref mut data)) => {
                drain_filter!(data, UTF8Data);
            }
        }
        Ok(())
    }
}

impl GetAtomValues for ListData {
    fn atom_values(&mut self) -> Result<Vec<SymbolicExpression>> {
        self.drained_items()
            .iter()
            .map(|item| Ok(SymbolicExpression::atom_value(Self::to_value(item)?)))
            .collect()
    }
}

impl GetAtomValues for BuffData {
    fn atom_values(&mut self) -> Result<Vec<SymbolicExpression>> {
        self.drained_items()
            .iter()
            .map(|item| Ok(SymbolicExpression::atom_value(Self::to_value(item)?)))
            .collect()
    }
}

impl GetAtomValues for ASCIIData {
    fn atom_values(&mut self) -> Result<Vec<SymbolicExpression>> {
        self.drained_items()
            .iter()
            .map(|item| Ok(SymbolicExpression::atom_value(Self::to_value(item)?)))
            .collect()
    }
}

impl GetAtomValues for UTF8Data {
    fn atom_values(&mut self) -> Result<Vec<SymbolicExpression>> {
        self.drained_items()
            .iter()
            .map(|item| Ok(SymbolicExpression::atom_value(Self::to_value(item)?)))
            .collect()
    }
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
    fn test_constructors() {
        assert_eq!(
            Value::list_with_type(
                &StacksEpochId::latest(),
                vec![Value::Int(5), Value::Int(2)],
                ListTypeData::new_list(TypeSignature::BoolType, 3).unwrap()
            )
            .map_err(Error::from),
            Err(InterpreterError::FailureConstructingListWithType.into())
        );

        assert_eq!(
            ListTypeData::new_list(TypeSignature::IntType, MAX_VALUE_SIZE)
                .map_err(CheckErrors::from),
            Err(CheckErrors::ValueTooLarge)
        );

        assert_eq!(
            Value::buff_from(vec![0; (MAX_VALUE_SIZE + 1) as usize]).map_err(Error::from),
            Err(CheckErrors::ValueTooLarge.into())
        );

        // Test that wrappers (okay, error, some)
        //   correctly error when _they_ cause the value size
        //   to exceed the max value size (note, the buffer constructor
        //   isn't causing the error).
        assert_eq!(
            Value::okay(Value::buff_from(vec![0; (MAX_VALUE_SIZE) as usize]).unwrap())
                .map_err(Error::from),
            Err(CheckErrors::ValueTooLarge.into())
        );

        assert_eq!(
            Value::error(Value::buff_from(vec![0; (MAX_VALUE_SIZE) as usize]).unwrap())
                .map_err(Error::from),
            Err(CheckErrors::ValueTooLarge.into())
        );

        assert_eq!(
            Value::some(Value::buff_from(vec![0; (MAX_VALUE_SIZE) as usize]).unwrap())
                .map_err(Error::from),
            Err(CheckErrors::ValueTooLarge.into())
        );

        // Test that the depth limit is correctly enforced:
        //   for tuples, lists, somes, okays, errors.

        let cons = || {
            Value::some(Value::some(Value::some(Value::some(Value::some(
                Value::some(Value::some(Value::some(Value::some(Value::some(
                    Value::some(Value::some(Value::some(Value::some(Value::some(
                        Value::some(Value::some(Value::some(Value::some(Value::some(
                            Value::some(Value::some(Value::some(Value::some(Value::some(
                                Value::some(Value::some(Value::some(Value::some(
                                    Value::some(Value::some(Value::Int(1))?)?,
                                )?)?)?)?,
                            )?)?)?)?)?,
                        )?)?)?)?)?,
                    )?)?)?)?)?,
                )?)?)?)?)?,
            )?)?)?)?)
        };
        let inner_value = cons().unwrap();
        assert_eq!(
            TupleData::from_data(vec![("a".into(), inner_value.clone())]).map_err(Error::from),
            Err(CheckErrors::TypeSignatureTooDeep.into())
        );

        assert_eq!(
            Value::list_from(vec![inner_value.clone()]).map_err(Error::from),
            Err(CheckErrors::TypeSignatureTooDeep.into())
        );
        assert_eq!(
            Value::okay(inner_value.clone()).map_err(Error::from),
            Err(CheckErrors::TypeSignatureTooDeep.into())
        );
        assert_eq!(
            Value::error(inner_value.clone()).map_err(Error::from),
            Err(CheckErrors::TypeSignatureTooDeep.into())
        );
        assert_eq!(
            Value::some(inner_value).map_err(Error::from),
            Err(CheckErrors::TypeSignatureTooDeep.into())
        );

        if std::env::var("CIRCLE_TESTING") == Ok("1".to_string()) {
            println!("Skipping allocation test on Circle");
            return;
        }

        // on 32-bit archs, this error cannot even happen, so don't test (and cause an overflow panic)
        if (u32::MAX as usize) < usize::MAX {
            assert_eq!(
                Value::buff_from(vec![0; (u32::MAX as usize) + 10]).map_err(Error::from),
                Err(CheckErrors::ValueTooLarge.into())
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
        matches!(t.get("abc"), Ok(&Value::Int(0)));
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
    fn test_qualified_contract_identifier_local_returns_runtime_error() {
        let err = QualifiedContractIdentifier::local("1nvalid-name")
            .expect_err("Unexpected qualified contract identifier");
        assert_eq!(
            Error::from(RuntimeErrorType::BadNameValue(
                "ContractName",
                "1nvalid-name".into()
            )),
            err.into(),
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
        assert_eq!(Error::from(expected_err), err.into());
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
        assert_eq!(Error::from(expected_err), err.into());
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
        assert_eq!(expected_err, err.into());

        let err =
            TraitIdentifier::parse_sugared_syntax(input).expect_err("Unexpected trait identifier");
        assert_eq!(expected_err, err.into());
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
        assert_eq!(Error::from(expected_err), err.into());
    }

    #[test]
    fn test_standard_principal_data_new_returns_interpreter_error() {
        let result = StandardPrincipalData::new(32, [0; 20]);
        let err = result.expect_err("Unexpected principal data");

        assert_eq!(
            Error::from(InterpreterError::Expect("Unexpected principal data".into())),
            err.into(),
        );
    }

    #[test]
    pub fn test_sequence_data_element_at_returns_interpreter_error() {
        let buff = SequenceData::String(CharType::ASCII(ASCIIData { data: vec![1] }));
        let err = buff.element_at(0).unwrap_err();
        assert_eq!(
            Error::from(InterpreterError::Expect("Unexpected principal data".into())),
            err.into()
        );
    }

    #[test]
    pub fn test_ascii_data_to_value_returns_interpreter_error() {
        let err = ASCIIData::to_value(&1).unwrap_err();
        assert_eq!(
            Error::from(InterpreterError::Expect(
                "ERROR: Invalid ASCII string successfully constructed".into()
            )),
            err.into()
        );
    }

    #[test]
    pub fn test_utf8_data_to_value_returns_interpreter_error() {
        let err = UTF8Data::to_value(&vec![1]).unwrap_err();
        assert_eq!(
            Error::from(InterpreterError::Expect(
                "ERROR: Invalid ASCII string successfully constructed".into()
            )),
            err.into()
        );
    }

    #[test]
    pub fn test_value_some_returns_interpreter_error() {
        let err = Value::some(Value::Int(1)).unwrap_err();
        assert_eq!(
            Error::from(InterpreterError::Expect("Unexpected principal data".into())),
            err.into()
        );
    }
}
