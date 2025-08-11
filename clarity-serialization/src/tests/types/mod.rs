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

use stacks_common::types::StacksEpochId;

use crate::CodecError;
use crate::types::{
    BuffData, ListTypeData, MAX_VALUE_SIZE, PrincipalData, SequenceData, TupleData, TypeSignature,
    Value,
};

#[test]
fn test_constructors() {
    assert!(matches!(
        Value::list_with_type(
            &StacksEpochId::latest(),
            vec![Value::Int(5), Value::Int(2)],
            ListTypeData::new_list(TypeSignature::BoolType, 3).unwrap()
        ),
        Err(CodecError::FailureConstructingListWithType)
    ));
    assert!(matches!(
        ListTypeData::new_list(TypeSignature::IntType, MAX_VALUE_SIZE),
        Err(CodecError::ValueTooLarge)
    ));

    assert!(matches!(
        Value::buff_from(vec![0; (MAX_VALUE_SIZE + 1) as usize]),
        Err(CodecError::ValueTooLarge)
    ));

    // Test that wrappers (okay, error, some)
    //   correctly error when _they_ cause the value size
    //   to exceed the max value size (note, the buffer constructor
    //   isn't causing the error).
    assert!(matches!(
        Value::okay(Value::buff_from(vec![0; (MAX_VALUE_SIZE) as usize]).unwrap()),
        Err(CodecError::ValueTooLarge)
    ));

    assert!(matches!(
        Value::error(Value::buff_from(vec![0; (MAX_VALUE_SIZE) as usize]).unwrap()),
        Err(CodecError::ValueTooLarge)
    ));

    assert!(matches!(
        Value::some(Value::buff_from(vec![0; (MAX_VALUE_SIZE) as usize]).unwrap()),
        Err(CodecError::ValueTooLarge)
    ));

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
    assert!(matches!(
        TupleData::from_data(vec![("a".into(), inner_value.clone())]),
        Err(CodecError::TypeSignatureTooDeep)
    ));

    assert!(matches!(
        Value::list_from(vec![inner_value.clone()]),
        Err(CodecError::TypeSignatureTooDeep)
    ));
    assert!(matches!(
        Value::okay(inner_value.clone()),
        Err(CodecError::TypeSignatureTooDeep)
    ));
    assert!(matches!(
        Value::error(inner_value.clone()),
        Err(CodecError::TypeSignatureTooDeep)
    ));
    assert!(matches!(
        Value::some(inner_value),
        Err(CodecError::TypeSignatureTooDeep)
    ));

    if std::env::var("CIRCLE_TESTING") == Ok("1".to_string()) {
        println!("Skipping allocation test on Circle");
        return;
    }

    // on 32-bit archs, this error cannot even happen, so don't test (and cause an overflow panic)
    if (u32::MAX as usize) < usize::MAX {
        assert!(matches!(
            Value::buff_from(vec![0; (u32::MAX as usize) + 10]),
            Err(CodecError::ValueTooLarge)
        ));
    }
}

#[test]
fn simple_size_test() {
    assert_eq!(Value::Int(10).size().unwrap(), 16);
}

#[test]
fn simple_tuple_get_test() {
    let t = TupleData::from_data(vec![("abc".into(), Value::Int(0))]).unwrap();
    assert!(matches!(t.get("abc"), Ok(&Value::Int(0))));
    // should error!
    t.get("abcd").expect_err("should error");
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
