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

use rstest::rstest;
use rstest_reuse::{self, *};
use stacks_common::address::{
    AddressHashMode, C32_ADDRESS_VERSION_MAINNET_SINGLESIG, C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
};
use stacks_common::consts::{CHAIN_ID_MAINNET, CHAIN_ID_TESTNET};
use stacks_common::types::chainstate::{StacksAddress, StacksPrivateKey, StacksPublicKey};
use stacks_common::types::StacksEpochId;
use stacks_common::util::hash::{hex_bytes, to_hex};

use crate::vm::ast::{parse, ASTRules};
use crate::vm::callables::DefinedFunction;
use crate::vm::contexts::OwnedEnvironment;
use crate::vm::costs::LimitedCostTracker;
use crate::vm::database::MemoryBackingStore;
use crate::vm::errors::{CheckErrors, Error, RuntimeErrorType, ShortReturnType};
use crate::vm::tests::{execute, test_clarity_versions};
use crate::vm::types::signatures::*;
use crate::vm::types::{
    ASCIIData, BuffData, CharType, PrincipalData, QualifiedContractIdentifier, SequenceData,
    StacksAddressExtensions, TypeSignature,
};
use crate::vm::{
    eval, execute as vm_execute, execute_v2 as vm_execute_v2, execute_with_parameters, CallStack,
    ClarityVersion, ContractContext, Environment, GlobalContext, LocalContext, Value,
};

#[test]
fn test_doubly_defined_persisted_vars() {
    let tests = [
        "(define-non-fungible-token cursor uint) (define-non-fungible-token cursor uint)",
        "(define-fungible-token cursor) (define-fungible-token cursor)",
        "(define-data-var cursor int 0) (define-data-var cursor int 0)",
        "(define-map cursor { cursor: int } { place: uint }) (define-map cursor { cursor: int } { place: uint })" ];
    for p in tests.iter() {
        assert_eq!(
            vm_execute(p).unwrap_err(),
            CheckErrors::NameAlreadyUsed("cursor".into()).into()
        );
    }
}

#[apply(test_clarity_versions)]
fn test_simple_let(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
    /*
      test program:
      (let ((x 1) (y 2))
        (+ x
           (let ((x 3))
                 (+ x y))
           x))
    */

    let program = "(let ((x 1) (y 2))
                     (+ x
                        (let ((z 3))
                             (+ z y))
                        x))";
    let contract_id = QualifiedContractIdentifier::transient();
    let placeholder_context =
        ContractContext::new(QualifiedContractIdentifier::transient(), version);
    if let Ok(parsed_program) = parse(&contract_id, program, version, epoch) {
        let context = LocalContext::new();
        let mut marf = MemoryBackingStore::new();
        let mut env = OwnedEnvironment::new(marf.as_clarity_db(), epoch);

        assert_eq!(
            Ok(Value::Int(7)),
            eval(
                &parsed_program[0],
                &mut env.get_exec_environment(None, None, &placeholder_context),
                &context
            )
        );
    } else {
        panic!("Failed to parse program.");
    }
}

#[test]
fn test_sha256() {
    let sha256_evals = [
        "(sha256 0x)",
        "(sha256 0)",
        "(sha256 0x54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67)", // The quick brown fox jumps over the lazy dog
    ];

    fn to_buffer(hex: &str) -> Value {
        Value::Sequence(SequenceData::Buffer(BuffData {
            data: hex_bytes(hex).unwrap(),
        }))
    }

    let expectations = [
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "374708fff7719dd5979ec875d56cd2286f6d3cf7ec317a3b25632aab28ec37bb",
        "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
    ];

    sha256_evals
        .iter()
        .zip(expectations.iter())
        .for_each(|(program, expectation)| assert_eq!(to_buffer(expectation), execute(program)));
}

#[test]
fn test_sha512() {
    let sha512_evals = [
        "(sha512 0x)",
        "(sha512 0)",
        "(sha512 0x54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67)", // The quick brown fox jumps over the lazy dog
    ];

    fn p_to_hex(val: Value) -> String {
        match val {
            Value::Sequence(SequenceData::Buffer(BuffData { data })) => to_hex(&data),
            _ => panic!("Failed"),
        }
    }

    let expectations = [
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        "0b6cbac838dfe7f47ea1bd0df00ec282fdf45510c92161072ccfb84035390c4da743d9c3b954eaa1b0f86fc9861b23cc6c8667ab232c11c686432ebb5c8c3f27",
        "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6"
    ];

    sha512_evals
        .iter()
        .zip(expectations.iter())
        .for_each(|(program, expectation)| assert_eq!(expectation, &p_to_hex(execute(program))));
}

#[test]
fn test_sha512trunc256() {
    let sha512_evals = [
        "(sha512/256 0x)",
        "(sha512/256 0)",
        "(sha512/256 0x54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67)", // The quick brown fox jumps over the lazy dog
    ];

    fn p_to_hex(val: Value) -> String {
        match val {
            Value::Sequence(SequenceData::Buffer(BuffData { data })) => to_hex(&data),
            _ => panic!("Failed"),
        }
    }

    let expectations = [
        "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a",
        "e41c9660b04714cdf7249f0fd6e6c5556f54a7e04d299958b69a877e0fada2fb",
        "dd9d67b371519c339ed8dbd25af90e976a1eeefd4ad3d889005e532fc5bef04d",
    ];

    sha512_evals
        .iter()
        .zip(expectations.iter())
        .for_each(|(program, expectation)| assert_eq!(expectation, &p_to_hex(execute(program))));
}

#[test]
fn test_keccak256() {
    let keccak256_evals = [
        "(keccak256 0x)",
        "(keccak256 0)",
        "(keccak256 0x54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67)", // The quick brown fox jumps over the lazy dog
    ];

    fn to_buffer(hex: &str) -> Value {
        Value::Sequence(SequenceData::Buffer(BuffData {
            data: hex_bytes(hex).unwrap(),
        }))
    }

    let expectations = [
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "f490de2920c8a35fabeb13208852aa28c76f9be9b03a4dd2b3c075f7a26923b4",
        "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15",
    ];

    keccak256_evals
        .iter()
        .zip(expectations.iter())
        .for_each(|(program, expectation)| assert_eq!(to_buffer(expectation), execute(program)));
}

#[test]
/// This test serializes two different values which do fit in
///  the Clarity maximum value size, but whose serializations
///  do not. These tests would _not_ pass typechecking: in fact,
///  the code comes from `type_checker::tests::test_to_consensus_buff`
///  failure cases.
fn test_to_consensus_buff_too_big() {
    let buff_setup = "
     ;; Make a buffer with repeated concatenation.
     (define-private (make-buff-10)
        0x11223344556677889900)
     (define-private (octo-buff (x (buff 100000)))
        (concat (concat (concat x x) (concat x x))
                (concat (concat x x) (concat x x))))
     (define-private (make-buff-80)
        (unwrap-panic (as-max-len? (octo-buff (make-buff-10)) u80)))
     (define-private (make-buff-640)
        (unwrap-panic (as-max-len? (octo-buff (make-buff-80)) u640)))
     (define-private (make-buff-5120)
        (unwrap-panic (as-max-len? (octo-buff (make-buff-640)) u5120)))
     (define-private (make-buff-40960)
        (unwrap-panic (as-max-len? (octo-buff (make-buff-5120)) u40960)))
     (define-private (make-buff-327680)
        (unwrap-panic (as-max-len? (octo-buff (make-buff-40960)) u327680)))

     (define-private (make-buff-24567)
        (let ((x (make-buff-5120))
              (y (make-buff-640))
              (z (make-buff-80))
              (a 0x11223344556677))
          ;; 4x + 6y + 3z + a = 24567
          (concat
            (concat
             ;; 4x
             (concat (concat x x) (concat x x))
             ;; 6y
             (concat (concat (concat y y) (concat y y)) (concat y y)))
            ;; 3z + a
            (concat (concat z z) (concat z a)))))

     ;; (3 * 327680) + 40960 + 24567 = 1048567
     (define-private (make-buff-1048567)
        (let ((x (make-buff-327680))
              (y (make-buff-40960))
              (z (make-buff-24567)))
         (concat (concat (concat x x) (concat x y)) z)))

     (define-private (make-buff-1048570)
         (concat (make-buff-1048567) 0x112233))
    ";

    // this program prints the length of the
    // constructed 1048570 buffer and then executes
    // to-consensus-buff? on it. if the buffer wasn't the
    // expect length, just return (some buffer), which will
    // cause the test assertion to fail.
    let program_check_1048570 = format!(
        "{}
     (let ((a (make-buff-1048570)))
        (if (is-eq (len a) u1048570)
            (to-consensus-buff? a)
            (some 0x00)))
    ",
        buff_setup
    );

    let result = vm_execute_v2(&program_check_1048570)
        .expect("Should execute")
        .expect("Should have return value");

    assert!(result.expect_optional().unwrap().is_none());

    // this program prints the length of the
    // constructed 1048567 buffer and then executes
    // to-consensus-buff? on it. if the buffer wasn't the
    // expect length, just return (some buffer), which will
    // cause the test assertion to fail.
    let program_check_1048567 = format!(
        "{}
     (let ((a (make-buff-1048567)))
        (if (is-eq (len a) u1048567)
            (to-consensus-buff? a)
            (some 0x00)))
    ",
        buff_setup
    );

    let result = vm_execute_v2(&program_check_1048567)
        .expect("Should execute")
        .expect("Should have return value");

    assert!(result.expect_optional().unwrap().is_none());
}

#[test]
fn test_from_consensus_buff_type_checks() {
    let vectors = [
        (
            "(from-consensus-buff? uint 0x10 0x00)",
            "Unchecked(IncorrectArgumentCount(2, 3))",
        ),
        (
            "(from-consensus-buff? uint 1)",
            "Unchecked(TypeValueError(SequenceType(BufferType(BufferLength(1048576))), Int(1)))",
        ),
        (
            "(from-consensus-buff? 2 0x10)",
            "Unchecked(InvalidTypeDescription)",
        ),
    ];

    for (input, expected) in vectors.iter() {
        let result = vm_execute_v2(input).expect_err("Should raise an error");
        assert_eq!(&result.to_string(), expected);
    }
}

#[test]
/// This test tries a bunch of buffers which either
///  do not parse, or parse to the incorrect type
fn test_from_consensus_buff_missed_expectations() {
    let vectors = [
        ("0x0000000000000000000000000000000001", "uint"),
        ("0x00ffffffffffffffffffffffffffffffff", "uint"),
        ("0x0100000000000000000000000000000001", "int"),
        ("0x010000000000000000000000000000000101", "uint"),
        ("0x0200000004deadbeef", "(buff 2)"),
        ("0x0200000004deadbeef", "(buff 3)"),
        ("0x0200000004deadbeef", "(string-ascii 8)"),
        ("0x03", "uint"),
        ("0x04", "(optional int)"),
        ("0x0700ffffffffffffffffffffffffffffffff", "(response uint int)"), 
        ("0x0800ffffffffffffffffffffffffffffffff", "(response int uint)"),
        ("0x09", "(response int int)"),
        ("0x0b0000000400000000000000000000000000000000010000000000000000000000000000000002000000000000000000000000000000000300fffffffffffffffffffffffffffffffc",
         "(list 3 int)"),
        ("0x0c000000020362617a0906666f6f62617203", "{ bat: (optional int), foobar: bool }"),
        ("0xff", "int"),
    ];

    for (buff_repr, type_repr) in vectors.iter() {
        let program = format!("(from-consensus-buff? {} {})", type_repr, buff_repr);
        eprintln!("{}", program);
        let result_val = vm_execute_v2(&program)
            .expect("from-consensus-buff? should succeed")
            .expect("from-consensus-buff? should return")
            .expect_optional()
            .unwrap();
        assert!(
            result_val.is_none(),
            "from-consensus-buff? should return none"
        );
    }
}

#[test]
fn test_to_from_consensus_buff_vectors() {
    let vectors = [
        ("0x0000000000000000000000000000000001", "1", "int"),
        ("0x00ffffffffffffffffffffffffffffffff", "-1", "int"),
        ("0x0100000000000000000000000000000001", "u1", "uint"),
        ("0x0200000004deadbeef", "0xdeadbeef", "(buff 8)"),
        ("0x03", "true", "bool"),
        ("0x04", "false", "bool"),
        ("0x050011deadbeef11ababffff11deadbeef11ababffff", "'S08XXBDYXW8TQAZZZW8XXBDYXW8TQAZZZZ88551S", "principal"),
        ("0x060011deadbeef11ababffff11deadbeef11ababffff0461626364", "'S08XXBDYXW8TQAZZZW8XXBDYXW8TQAZZZZ88551S.abcd", "principal"),
        ("0x0700ffffffffffffffffffffffffffffffff", "(ok -1)", "(response int int)"), 
        ("0x0800ffffffffffffffffffffffffffffffff", "(err -1)", "(response int int)"),
        ("0x09", "none", "(optional int)"),
        ("0x0a00ffffffffffffffffffffffffffffffff", "(some -1)", "(optional int)"),
        ("0x0b0000000400000000000000000000000000000000010000000000000000000000000000000002000000000000000000000000000000000300fffffffffffffffffffffffffffffffc",
         "(list 1 2 3 -4)", "(list 4 int)"),
        ("0x0c000000020362617a0906666f6f62617203", "{ baz: none, foobar: true }", "{ baz: (optional int), foobar: bool }"),
    ];

    // do `from-consensus-buff?` tests
    for (buff_repr, value_repr, type_repr) in vectors.iter() {
        let program = format!("(from-consensus-buff? {} {})", type_repr, buff_repr);
        eprintln!("{}", program);
        let result_val = vm_execute_v2(&program)
            .expect("from-consensus-buff? should succeed")
            .expect("from-consensus-buff? should return")
            .expect_optional()
            .unwrap()
            .expect("from-consensus-buff? should return (some value)");
        let expected_val = execute(value_repr);
        assert_eq!(result_val, expected_val);
    }

    // do `to-consensus-buff?` tests
    for (buff_repr, value_repr, _) in vectors.iter() {
        let program = format!("(to-consensus-buff? {})", value_repr);
        let result_buffer = vm_execute_v2(&program)
            .expect("to-consensus-buff? should succeed")
            .expect("to-consensus-buff? should return")
            .expect_optional()
            .unwrap()
            .expect("to-consensus-buff? should return (some buff)");
        let expected_buff = execute(buff_repr);
        assert_eq!(result_buffer, expected_buff);
    }
}

#[test]
fn test_secp256k1() {
    let secp256k1_evals = [
        "(unwrap! (secp256k1-recover? 0xde5b9eb9e7c5592930eb2e30a01369c36586d872082ed8181ee83d2a0ec20f04 0x8738487ebe69b93d8e51583be8eee50bb4213fc49c767d329632730cc193b873554428fc936ca3569afc15f1c9365f6591d6251a89fee9c9ac661116824d3a1301) 2)",
        "(unwrap-err! (secp256k1-recover? 0x0000000000000000000000000000000000000000000000000000000000000000 0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000) 3)",
        "(unwrap-err! (secp256k1-recover? 0xde5b9eb9e7c5592930eb2e30a01369c36586d872082ed8181ee83d2a0ec20f04 0x8738487ebe69b93d8e51583be8eee50bb4213fc49c767d329632730cc193b873554428fc936ca3569afc15f1c9365f6591d6251a89fee9c9ac661116824d3a1306) 3)",
        "(secp256k1-verify 0xde5b9eb9e7c5592930eb2e30a01369c36586d872082ed8181ee83d2a0ec20f04 0x8738487ebe69b93d8e51583be8eee50bb4213fc49c767d329632730cc193b873554428fc936ca3569afc15f1c9365f6591d6251a89fee9c9ac661116824d3a1301 0x03adb8de4bfb65db2cfd6120d55c6526ae9c52e675db7e47308636534ba7786110)",
        "(secp256k1-verify 0xde5b9eb9e7c5592930eb2e30a01369c36586d872082ed8181ee83d2a0ec20f04 0x8738487ebe69b93d8e51583be8eee50bb4213fc49c767d329632730cc193b873554428fc936ca3569afc15f1c9365f6591d6251a89fee9c9ac661116824d3a13 0x03adb8de4bfb65db2cfd6120d55c6526ae9c52e675db7e47308636534ba7786110)",
        "(secp256k1-verify 0x0000000000000000000000000000000000000000000000000000000000000000 0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 0x03adb8de4bfb65db2cfd6120d55c6526ae9c52e675db7e47308636534ba7786110)",
        "(secp256k1-verify 0xde5b9eb9e7c5592930eb2e30a01369c36586d872082ed8181ee83d2a0ec20f04 0x8738487ebe69b93d8e51583be8eee50bb4213fc49c767d329632730cc193b873554428fc936ca3569afc15f1c9365f6591d6251a89fee9c9ac661116824d3a1305 0x03adb8de4bfb65db2cfd6120d55c6526ae9c52e675db7e47308636534ba7786110)",
        "(unwrap! (principal-of? 0x03adb8de4bfb65db2cfd6120d55c6526ae9c52e675db7e47308636534ba7786110) 4)", // (buff 33)
        "(unwrap-err! (principal-of? 0x000000000000000000000000000000000000000000000000000000000000000000) 3)",
    ];

    let privk = StacksPrivateKey::from_hex(
        "510f96a8efd0b11e211733c1ac5e3fa6f3d3fcdd62869e376c47decb3e14fea101",
    )
    .unwrap(); // need the "compressed extra 0x01 to match, as this changes the address"
    eprintln!("privk {:?}", &privk);
    eprintln!("from_private {:?}", &StacksPublicKey::from_private(&privk));
    let addr = StacksAddress::from_public_keys(
        C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
        &AddressHashMode::SerializeP2PKH,
        1,
        &vec![StacksPublicKey::from_private(&privk)],
    )
    .unwrap();
    eprintln!("addr from privk {:?}", &addr);
    let principal = addr.into();
    if let PrincipalData::Standard(data) = principal {
        eprintln!("test_secp256k1 principal {:?}", data.to_address());
    }

    let addr = StacksAddress::from_public_keys(
        C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
        &AddressHashMode::SerializeP2PKH,
        1,
        &vec![StacksPublicKey::from_hex(
            "03adb8de4bfb65db2cfd6120d55c6526ae9c52e675db7e47308636534ba7786110",
        )
        .unwrap()],
    )
    .unwrap();
    eprintln!("addr from hex {:?}", addr);
    let principal: PrincipalData = addr.into();
    if let PrincipalData::Standard(data) = principal.clone() {
        eprintln!("test_secp256k1 principal {:?}", data.to_address());
    }

    let expectations = [
        Value::Sequence(SequenceData::Buffer(BuffData {
            data: hex_bytes("03adb8de4bfb65db2cfd6120d55c6526ae9c52e675db7e47308636534ba7786110")
                .unwrap(),
        })),
        Value::UInt(1),
        Value::UInt(2),
        Value::Bool(true),
        Value::Bool(true),
        Value::Bool(false),
        Value::Bool(false),
        Value::Principal(principal),
        Value::UInt(1),
    ];

    secp256k1_evals
        .iter()
        .zip(expectations.iter())
        .for_each(|(program, expectation)| assert_eq!(expectation.clone(), execute(program)));
}

#[test]
fn test_principal_of_fix() {
    // There is a bug with principal-of in Clarity1. The address returned is always testnet. In Clarity2, we fix this.
    // So, we need to test that:
    //   1) In Clarity1, the returned address is always a testnet address.
    //   2) In Clarity2, the returned address is a function of the network type.
    let principal_of_program =
        "(unwrap! (principal-of? 0x03adb8de4bfb65db2cfd6120d55c6526ae9c52e675db7e47308636534ba7786110) 4)";

    let mainnet_principal = StacksAddress::from_public_keys(
        C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
        &AddressHashMode::SerializeP2PKH,
        1,
        &vec![StacksPublicKey::from_hex(
            "03adb8de4bfb65db2cfd6120d55c6526ae9c52e675db7e47308636534ba7786110",
        )
        .unwrap()],
    )
    .unwrap()
    .into();
    let testnet_principal: PrincipalData = StacksAddress::from_public_keys(
        C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
        &AddressHashMode::SerializeP2PKH,
        1,
        &vec![StacksPublicKey::from_hex(
            "03adb8de4bfb65db2cfd6120d55c6526ae9c52e675db7e47308636534ba7786110",
        )
        .unwrap()],
    )
    .unwrap()
    .into();

    // Clarity2, mainnet, should have a mainnet principal.
    assert_eq!(
        Value::Principal(mainnet_principal),
        execute_with_parameters(
            principal_of_program,
            ClarityVersion::Clarity2,
            StacksEpochId::Epoch20,
            ASTRules::PrecheckSize,
            true
        )
        .unwrap()
        .unwrap()
    );

    // Clarity2, testnet, should have a testnet principal.
    assert_eq!(
        Value::Principal(testnet_principal.clone()),
        execute_with_parameters(
            principal_of_program,
            ClarityVersion::Clarity2,
            StacksEpochId::Epoch20,
            ASTRules::PrecheckSize,
            false
        )
        .unwrap()
        .unwrap()
    );

    // Clarity1, mainnet, should have a test principal (this is the bug that we need to preserve).
    assert_eq!(
        Value::Principal(testnet_principal.clone()),
        execute_with_parameters(
            principal_of_program,
            ClarityVersion::Clarity1,
            StacksEpochId::Epoch20,
            ASTRules::PrecheckSize,
            true
        )
        .unwrap()
        .unwrap()
    );

    // Clarity1, testnet, should have a testnet principal.
    assert_eq!(
        Value::Principal(testnet_principal),
        execute_with_parameters(
            principal_of_program,
            ClarityVersion::Clarity1,
            StacksEpochId::Epoch20,
            ASTRules::PrecheckSize,
            false
        )
        .unwrap()
        .unwrap()
    );
}

#[test]
fn test_secp256k1_errors() {
    let secp256k1_evals = [
        "(secp256k1-recover? 0xde5b9eb9e7c5592930eb2e30a01369c36586d872082ed8181ee83d2a0ec20f 0x8738487ebe69b93d8e51583be8eee50bb4213fc49c767d329632730cc193b873554428fc936ca3569afc15f1c9365f6591d6251a89fee9c9ac661116824d3a1301)",
        "(secp256k1-recover? 0xde5b9eb9e7c5592930eb2e30a01369c36586d872082ed8181ee83d2a0ec20f04 0x8738487ebe69b93d8e51583be8eee50bb4213fc49c767d329632730cc193b873554428fc936ca3569afc15f1c9365f6591d6251a89fee9c9ac661116824d3a130100)",
        "(secp256k1-recover? 0xde5b9eb9e7c5592930eb2e30a01369c36586d872082ed8181ee83d2a0ec20f04)",
        "(secp256k1-recover? 0xde5b9eb9e7c5592930eb2e30a01369c36586d872082ed8181ee83d2a0ec20f04 0x8738487ebe69b93d8e51583be8eee50bb4213fc49c767d329632730cc193b873554428fc936ca3569afc15f1c9365f6591d6251a89fee9c9ac661116824d3a1301 3)",

        "(secp256k1-verify 0xde5b9eb9e7c5592930eb2e30a01369c36586d872082ed8181ee83d2a0ec20f 0x8738487ebe69b93d8e51583be8eee50bb4213fc49c767d329632730cc193b873554428fc936ca3569afc15f1c9365f6591d6251a89fee9c9ac661116824d3a1301 0x03adb8de4bfb65db2cfd6120d55c6526ae9c52e675db7e47308636534ba7786110)",
        "(secp256k1-verify 0xde5b9eb9e7c5592930eb2e30a01369c36586d872082ed8181ee83d2a0ec20f04 0x8738487ebe69b93d8e51583be8eee50bb4213fc49c767d329632730cc193b873554428fc936ca3569afc15f1c9365f6591d6251a89fee9c9ac661116824d3a130111 0x03adb8de4bfb65db2cfd6120d55c6526ae9c52e675db7e47308636534ba7786110)",
        "(secp256k1-verify 0xde5b9eb9e7c5592930eb2e30a01369c36586d872082ed8181ee83d2a0ec20f04 0x8738487ebe69b93d8e51583be8eee50bb4213fc49c767d329632730cc193b873554428fc936ca3569afc15f1c9365f6591d6251a89fee9c9ac661116824d3a1301 0x03adb8de4bfb65db2cfd6120d55c6526ae9c52e675db7e47308636534ba7)",
        "(secp256k1-verify 0xde5b9eb9e7c5592930eb2e30a01369c36586d872082ed8181ee83d2a0ec20f04 0x8738487ebe69b93d8e51583be8eee50bb4213fc49c767d329632730cc193b873554428fc936ca3569afc15f1c9365f6591d6251a89fee9c9ac661116824d3a1301)",

        "(principal-of? 0x03adb8de4bfb65db2cfd6120d55c6526ae9c52e675db7e47308636534ba77861 0x03adb8de4bfb65db2cfd6120d55c6526ae9c52e675db7e47308636534ba77861)",
        "(principal-of?)",
    ];

    let expectations: &[Error] = &[
        CheckErrors::TypeValueError(BUFF_32.clone(), Value::Sequence(SequenceData::Buffer(BuffData { data: hex_bytes("de5b9eb9e7c5592930eb2e30a01369c36586d872082ed8181ee83d2a0ec20f").unwrap() }))).into(),
        CheckErrors::TypeValueError(BUFF_65.clone(), Value::Sequence(SequenceData::Buffer(BuffData { data: hex_bytes("8738487ebe69b93d8e51583be8eee50bb4213fc49c767d329632730cc193b873554428fc936ca3569afc15f1c9365f6591d6251a89fee9c9ac661116824d3a130100").unwrap() }))).into(),
        CheckErrors::IncorrectArgumentCount(2, 1).into(),
        CheckErrors::IncorrectArgumentCount(2, 3).into(),

        CheckErrors::TypeValueError(BUFF_32.clone(), Value::Sequence(SequenceData::Buffer(BuffData { data: hex_bytes("de5b9eb9e7c5592930eb2e30a01369c36586d872082ed8181ee83d2a0ec20f").unwrap() }))).into(),
        CheckErrors::TypeValueError(BUFF_65.clone(), Value::Sequence(SequenceData::Buffer(BuffData { data: hex_bytes("8738487ebe69b93d8e51583be8eee50bb4213fc49c767d329632730cc193b873554428fc936ca3569afc15f1c9365f6591d6251a89fee9c9ac661116824d3a130111").unwrap() }))).into(),
        CheckErrors::TypeValueError(BUFF_33.clone(), Value::Sequence(SequenceData::Buffer(BuffData { data: hex_bytes("03adb8de4bfb65db2cfd6120d55c6526ae9c52e675db7e47308636534ba7").unwrap() }))).into(),
        CheckErrors::IncorrectArgumentCount(3, 2).into(),

        CheckErrors::IncorrectArgumentCount(1, 2).into(),
        CheckErrors::IncorrectArgumentCount(1, 0).into(),
    ];

    for (program, expectation) in secp256k1_evals.iter().zip(expectations.iter()) {
        assert_eq!(*expectation, vm_execute(program).unwrap_err());
    }
}

#[test]
fn test_buffer_equality() {
    let tests = [
        "(is-eq \"a b c\" \"a b c\")",
        "(is-eq \"\\\" a b d\"
               \"\\\" a b d\")",
        "(not (is-eq \"\\\" a b d\"
                    \" a b d\"))",
    ];
    let expectations = [Value::Bool(true), Value::Bool(true), Value::Bool(true)];

    tests
        .iter()
        .zip(expectations.iter())
        .for_each(|(program, expectation)| assert_eq!(expectation.clone(), execute(program)));
}

#[test]
fn test_principal_equality() {
    let tests = [
        "(is-eq 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)",
        "(not (is-eq 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR
                   'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G))"];
    let expectations = [Value::Bool(true), Value::Bool(true)];

    tests
        .iter()
        .zip(expectations.iter())
        .for_each(|(program, expectation)| assert_eq!(expectation.clone(), execute(program)));
}

#[apply(test_clarity_versions)]
fn test_simple_if_functions(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
    //
    //  test program:
    //  (define (with_else x) (if (is-eq 5 x) 1 0)
    //  (define (without_else x) (if (is-eq 5 x) 1)
    //  (with_else 5)
    //  (with_else 3)
    //  (without_else 3)

    use crate::vm::callables::DefineType::Private;

    let contract_id = QualifiedContractIdentifier::transient();

    let evals = parse(
        &contract_id,
        "(with_else 5)
         (without_else 3)
         (with_else 3)",
        version,
        epoch,
    );

    let contract_id = QualifiedContractIdentifier::transient();

    let function_bodies = parse(
        &contract_id,
        "(if (is-eq 5 x) 1 0)
                                  (if (is-eq 5 x) 1 3)",
        version,
        epoch,
    );

    if let Ok(parsed_bodies) = function_bodies {
        let func_args1 = vec![("x".into(), TypeSignature::IntType)];
        let func_args2 = vec![("x".into(), TypeSignature::IntType)];
        let user_function1 = DefinedFunction::new(
            func_args1,
            parsed_bodies[0].clone(),
            Private,
            &"with_else".into(),
            "",
        );

        let user_function2 = DefinedFunction::new(
            func_args2,
            parsed_bodies[1].clone(),
            Private,
            &"without_else".into(),
            "",
        );

        let context = LocalContext::new();
        let mut contract_context = ContractContext::new(
            QualifiedContractIdentifier::transient(),
            ClarityVersion::Clarity1,
        );
        let mut marf = MemoryBackingStore::new();
        let mut global_context = GlobalContext::new(
            false,
            CHAIN_ID_TESTNET,
            marf.as_clarity_db(),
            LimitedCostTracker::new_free(),
            StacksEpochId::Epoch20,
        );

        contract_context
            .functions
            .insert("with_else".into(), user_function1);
        contract_context
            .functions
            .insert("without_else".into(), user_function2);

        let mut call_stack = CallStack::new();
        let mut env = Environment::new(
            &mut global_context,
            &contract_context,
            &mut call_stack,
            None,
            None,
            None,
        );

        if let Ok(tests) = evals {
            assert_eq!(Ok(Value::Int(1)), eval(&tests[0], &mut env, &context));
            assert_eq!(Ok(Value::Int(3)), eval(&tests[1], &mut env, &context));
            assert_eq!(Ok(Value::Int(0)), eval(&tests[2], &mut env, &context));
        } else {
            panic!("Failed to parse function bodies.");
        }
    } else {
        panic!("Failed to parse function bodies.");
    }
}

#[test]
fn test_concat_append_supertype() {
    let tests = [
        "(concat (list) (list 4 5))",
        "(concat (list (list 2) (list) (list 4 5))
                 (list (list) (list) (list 7 8 9)))",
        "(append (list) 1)",
        "(append (list (list 3 4) (list)) (list 4 5 7))",
    ];

    let expectations = [
        Value::list_from(vec![Value::Int(4), Value::Int(5)]).unwrap(),
        Value::list_from(vec![
            Value::list_from(vec![Value::Int(2)]).unwrap(),
            Value::list_from(vec![]).unwrap(),
            Value::list_from(vec![Value::Int(4), Value::Int(5)]).unwrap(),
            Value::list_from(vec![]).unwrap(),
            Value::list_from(vec![]).unwrap(),
            Value::list_from(vec![Value::Int(7), Value::Int(8), Value::Int(9)]).unwrap(),
        ])
        .unwrap(),
        Value::list_from(vec![Value::Int(1)]).unwrap(),
        Value::list_from(vec![
            Value::list_from(vec![Value::Int(3), Value::Int(4)]).unwrap(),
            Value::list_from(vec![]).unwrap(),
            Value::list_from(vec![Value::Int(4), Value::Int(5), Value::Int(7)]).unwrap(),
        ])
        .unwrap(),
    ];

    tests
        .iter()
        .zip(expectations.iter())
        .for_each(|(program, expectation)| assert_eq!(expectation.clone(), execute(program)));
}

#[test]
fn test_simple_arithmetic_functions() {
    let tests = [
        "(* 52314 414)",
        "(/ 52314 414)",
        "(* 2 3 4 5)",
        "(/ 10 13)",
        "(mod 51 2)",
        "(- 5 4 1)",
        "(+ 5 4 1)",
        "(is-eq (* 2 3)
              (+ 2 2 2))",
        "(> 1 2)",
        "(< 1 2)",
        "(<= 1 1)",
        "(>= 2 1)",
        "(>= 1 1)",
        "(pow 2 16)",
        "(pow 2 32)",
        "(pow 0 0)",
        "(pow 170141183460469231731687303715884105727 1)",
        "(pow u340282366920938463463374607431768211455 u1)",
        "(pow 0 170141183460469231731687303715884105727)",
        "(pow u1 u340282366920938463463374607431768211455)",
        "(sqrti u81)",
        "(sqrti u80)",
        "(sqrti 81)",
        "(sqrti 80)",
        // from https://en.wikipedia.org/wiki/128-bit_computing
        "(sqrti 170141183460469231731687303715884105727)", // max i128
        "(sqrti u340282366920938463463374607431768211455)", // max u128
        "(log2 u8)",
        "(log2 u9)",
        "(log2 8)",
        "(log2 9)",
        "(log2 170141183460469231731687303715884105727)", // max i128
        "(log2 u340282366920938463463374607431768211455)", // max u128
        "(+ (pow u2 u127) (- (pow u2 u127) u1))",
        "(+ (to-uint 127) u10)",
        "(to-int (- (pow u2 u127) u1))",
        "(- (pow 2 32))",
    ];

    let expectations = [
        Value::Int(21657996),
        Value::Int(126),
        Value::Int(120),
        Value::Int(0),
        Value::Int(1),
        Value::Int(0),
        Value::Int(10),
        Value::Bool(true),
        Value::Bool(false),
        Value::Bool(true),
        Value::Bool(true),
        Value::Bool(true),
        Value::Bool(true),
        Value::Int(65536),
        Value::Int(u32::MAX as i128 + 1),
        Value::Int(1),
        Value::Int(170_141_183_460_469_231_731_687_303_715_884_105_727),
        Value::UInt(340_282_366_920_938_463_463_374_607_431_768_211_455),
        Value::Int(0),
        Value::UInt(1),
        Value::UInt(9),
        Value::UInt(8),
        Value::Int(9),
        Value::Int(8),
        Value::Int(13_043_817_825_332_782_212),
        Value::UInt(18_446_744_073_709_551_615),
        Value::UInt(3),
        Value::UInt(3),
        Value::Int(3),
        Value::Int(3),
        Value::Int(126),
        Value::UInt(127),
        Value::UInt(u128::MAX),
        Value::UInt(137),
        Value::Int(i128::MAX),
        Value::Int(-(u32::MAX as i128 + 1)),
    ];

    tests
        .iter()
        .zip(expectations.iter())
        .for_each(|(program, expectation)| assert_eq!(expectation.clone(), execute(program)));
}

#[test]
fn test_sequence_comparisons_clarity1() {
    // Tests the sequence comparisons against ClarityVersion1. The new kinds of
    // sequence comparison *should not* work.

    // Note: Equality between sequences already works in Clarity1.
    let success_tests = [
        ("(is-eq \"aaa\" \"aaa\")", Value::Bool(true)),
        ("(is-eq u\"aaa\" u\"aaa\")", Value::Bool(true)),
        ("(is-eq 0x010203 0x010203)", Value::Bool(true)),
        ("(is-eq \"aa\" \"aaa\")", Value::Bool(false)),
        ("(is-eq u\"aa\" u\"aaa\")", Value::Bool(false)),
        ("(is-eq 0x0102 0x010203)", Value::Bool(false)),
    ];

    // Note: Execute against Clarity1.
    success_tests
        .iter()
        .for_each(|(program, expectation)| assert_eq!(expectation.clone(), execute(program)));

    // Inequality comparisons between sequences do not work in Clarity1.
    let error_tests = [
        "(> \"baa\" \"aaa\")",
        "(< \"baa\" \"aaa\")",
        "(>= \"baa\" \"aaa\")",
        "(<= \"baa\" \"aaa\")",
    ];
    let error_expectations: &[Error] = &[
        CheckErrors::UnionTypeValueError(
            vec![TypeSignature::IntType, TypeSignature::UIntType],
            Value::Sequence(SequenceData::String(CharType::ASCII(ASCIIData {
                data: "baa".as_bytes().to_vec(),
            }))),
        )
        .into(),
        CheckErrors::UnionTypeValueError(
            vec![TypeSignature::IntType, TypeSignature::UIntType],
            Value::Sequence(SequenceData::String(CharType::ASCII(ASCIIData {
                data: "baa".as_bytes().to_vec(),
            }))),
        )
        .into(),
        CheckErrors::UnionTypeValueError(
            vec![TypeSignature::IntType, TypeSignature::UIntType],
            Value::Sequence(SequenceData::String(CharType::ASCII(ASCIIData {
                data: "baa".as_bytes().to_vec(),
            }))),
        )
        .into(),
        CheckErrors::UnionTypeValueError(
            vec![TypeSignature::IntType, TypeSignature::UIntType],
            Value::Sequence(SequenceData::String(CharType::ASCII(ASCIIData {
                data: "baa".as_bytes().to_vec(),
            }))),
        )
        .into(),
    ];

    // Note: Execute against Clarity1.
    error_tests
        .iter()
        .zip(error_expectations)
        .for_each(|(program, expectation)| {
            assert_eq!(*expectation, vm_execute(program).unwrap_err())
        });
}

#[test]
fn test_sequence_comparisons_clarity2() {
    // Tests the sequence comparisons against ClarityVersion2. The new kinds of
    // sequence comparison *should* work.
    let success_tests = [
        (r#"(is-eq "aaa" "aaa")"#, Value::Bool(true)),
        (r#"(is-eq "aba" "aaa")"#, Value::Bool(false)),
        (r#"(is-eq u"aaa" u"aaa")"#, Value::Bool(true)),
        (r#"(is-eq u"aba" u"aaa")"#, Value::Bool(false)),
        (r#"(is-eq 0x010203 0x010203)"#, Value::Bool(true)),
        (r#"(is-eq 0x090203 0x010203)"#, Value::Bool(false)),
        (r#"(< 0x0100 0x0100)"#, Value::Bool(false)),
        (r#"(< 0x0101 0x010101)"#, Value::Bool(true)),
        (r#"(< 0x010101 0x0101)"#, Value::Bool(false)),
        (r#"(< "aaa" "aaa")"#, Value::Bool(false)),
        (r#"(< "aa" "aaa")"#, Value::Bool(true)),
        (r#"(< "aaa" "aa")"#, Value::Bool(false)),
        (r#"(< u"aaa" u"aaa")"#, Value::Bool(false)),
        (r#"(< u"aa" u"aaa")"#, Value::Bool(true)),
        (r#"(< u"aaa" u"aa")"#, Value::Bool(false)),
        (r#"(<= 0x0100 0x0100)"#, Value::Bool(true)),
        (r#"(<= 0x0101 0x010101)"#, Value::Bool(true)),
        (r#"(<= 0x010101 0x0101)"#, Value::Bool(false)),
        (r#"(<= "aaa" "aaa")"#, Value::Bool(true)),
        (r#"(<= "aa" "aaa")"#, Value::Bool(true)),
        (r#"(<= "aaa" "aa")"#, Value::Bool(false)),
        (r#"(<= u"aaa" u"aaa")"#, Value::Bool(true)),
        (r#"(<= u"aa" u"aaa")"#, Value::Bool(true)),
        (r#"(<= u"aaa" u"aa")"#, Value::Bool(false)),
        (r#"(> 0x0100 0x0100)"#, Value::Bool(false)),
        (r#"(> 0x0101 0x010101)"#, Value::Bool(false)),
        (r#"(> 0x010101 0x0101)"#, Value::Bool(true)),
        (r#"(> "aaa" "aaa")"#, Value::Bool(false)),
        (r#"(> "aa" "aaa")"#, Value::Bool(false)),
        (r#"(> "aaa" "aa")"#, Value::Bool(true)),
        (r#"(> u"aaa" u"aaa")"#, Value::Bool(false)),
        (r#"(> u"aa" u"aaa")"#, Value::Bool(false)),
        (r#"(> u"aaa" u"aa")"#, Value::Bool(true)),
        (r#"(>= 0x0100 0x0100)"#, Value::Bool(true)),
        (r#"(>= 0x0101 0x010101)"#, Value::Bool(false)),
        (r#"(>= 0x010101 0x0101)"#, Value::Bool(true)),
        (r#"(>= "aaa" "aaa")"#, Value::Bool(true)),
        (r#"(>= "aa" "aaa")"#, Value::Bool(false)),
        (r#"(>= "aaa" "aa")"#, Value::Bool(true)),
        (r#"(>= u"aaa" u"aaa")"#, Value::Bool(true)),
        (r#"(>= u"aa" u"aaa")"#, Value::Bool(false)),
        (r#"(>= u"aaa" u"aa")"#, Value::Bool(true)),
    ];

    // Note: Execute against Clarity2.
    success_tests.iter().for_each(|(program, expectation)| {
        assert_eq!(
            expectation.clone(),
            vm_execute_v2(program).unwrap().unwrap(),
            "{:?}, {:?}",
            program,
            expectation.clone()
        )
    });
}

#[test]
fn test_sequence_comparisons_mismatched_types() {
    // Tests that comparing objects of different types results in an error in Clarity1.
    let error_tests = ["(> 0 u1)", "(< 0 u1)"];
    let v1_error_expectations: &[Error] = &[
        CheckErrors::UnionTypeValueError(
            vec![TypeSignature::IntType, TypeSignature::UIntType],
            Value::Int(0),
        )
        .into(),
        CheckErrors::UnionTypeValueError(
            vec![TypeSignature::IntType, TypeSignature::UIntType],
            Value::Int(0),
        )
        .into(),
    ];

    // Note: Execute against Clarity1.
    error_tests
        .iter()
        .zip(v1_error_expectations)
        .for_each(|(program, expectation)| {
            assert_eq!(*expectation, vm_execute(program).unwrap_err())
        });

    let v2_error_expectations: &[Error] = &[
        CheckErrors::UnionTypeValueError(
            vec![
                TypeSignature::IntType,
                TypeSignature::UIntType,
                TypeSignature::max_string_ascii().unwrap(),
                TypeSignature::max_string_utf8().unwrap(),
                TypeSignature::max_buffer().unwrap(),
            ],
            Value::Int(0),
        )
        .into(),
        CheckErrors::UnionTypeValueError(
            vec![
                TypeSignature::IntType,
                TypeSignature::UIntType,
                TypeSignature::max_string_ascii().unwrap(),
                TypeSignature::max_string_utf8().unwrap(),
                TypeSignature::max_buffer().unwrap(),
            ],
            Value::Int(0),
        )
        .into(),
    ];
    // Note: Execute against Clarity2.
    error_tests
        .iter()
        .zip(v2_error_expectations)
        .for_each(|(program, expectation)| {
            assert_eq!(*expectation, vm_execute_v2(program).unwrap_err())
        });

    // Tests that comparing objects of different types results in an error in Clarity2.
    let error_tests = ["(> \"baa\" u\"aaa\")", "(> \"baa\" 0x0001)"];
    let error_expectations: &[Error] = &[
        CheckErrors::UnionTypeValueError(
            vec![
                TypeSignature::IntType,
                TypeSignature::UIntType,
                TypeSignature::max_string_ascii().unwrap(),
                TypeSignature::max_string_utf8().unwrap(),
                TypeSignature::max_buffer().unwrap(),
            ],
            Value::Sequence(SequenceData::String(CharType::ASCII(ASCIIData {
                data: "baa".as_bytes().to_vec(),
            }))),
        )
        .into(),
        CheckErrors::UnionTypeValueError(
            vec![
                TypeSignature::IntType,
                TypeSignature::UIntType,
                TypeSignature::max_string_ascii().unwrap(),
                TypeSignature::max_string_utf8().unwrap(),
                TypeSignature::max_buffer().unwrap(),
            ],
            Value::Sequence(SequenceData::String(CharType::ASCII(ASCIIData {
                data: "baa".as_bytes().to_vec(),
            }))),
        )
        .into(),
    ];

    // Note: Execute against Clarity2.
    error_tests
        .iter()
        .zip(error_expectations)
        .for_each(|(program, expectation)| {
            assert_eq!(*expectation, vm_execute_v2(program).unwrap_err())
        });
}

#[apply(test_clarity_versions)]
fn test_simple_arithmetic_errors(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
    let tests = [
        "(>= 1)",
        "(+ 1 true)",
        "(/ 10 0)",
        "(mod 10 0)",
        "(pow 2 128)",
        "(* 10 (pow 2 126))",
        "(+ (pow 2 126) (pow 2 126))",
        "(- 0 (pow 2 126) (pow 2 126) 1)",
        "(-)",
        "(/)",
        "(mod 1)",
        "(pow 1)",
        "(sqrti)",
        "(sqrti 256 16)",
        "(sqrti -1)",
        "(log2)",
        "(log2 8 9)",
        "(log2 -8)",
        "(xor 1)",
        "(pow 2 (pow 2 32))",
        "(pow 2 (- 1))",
        "(is-eq (some 1) (some true))",
    ];

    let expectations: &[Error] = &[
        CheckErrors::IncorrectArgumentCount(2, 1).into(),
        CheckErrors::TypeValueError(TypeSignature::IntType, Value::Bool(true)).into(),
        RuntimeErrorType::DivisionByZero.into(),
        RuntimeErrorType::DivisionByZero.into(),
        RuntimeErrorType::ArithmeticOverflow.into(),
        RuntimeErrorType::ArithmeticOverflow.into(),
        RuntimeErrorType::ArithmeticOverflow.into(),
        RuntimeErrorType::ArithmeticUnderflow.into(),
        CheckErrors::IncorrectArgumentCount(1, 0).into(),
        CheckErrors::IncorrectArgumentCount(1, 0).into(),
        CheckErrors::IncorrectArgumentCount(2, 1).into(),
        CheckErrors::IncorrectArgumentCount(2, 1).into(),
        CheckErrors::IncorrectArgumentCount(1, 0).into(),
        CheckErrors::IncorrectArgumentCount(1, 2).into(),
        RuntimeErrorType::Arithmetic("sqrti must be passed a positive integer".to_string()).into(),
        CheckErrors::IncorrectArgumentCount(1, 0).into(),
        CheckErrors::IncorrectArgumentCount(1, 2).into(),
        RuntimeErrorType::Arithmetic("log2 must be passed a positive integer".to_string()).into(),
        CheckErrors::IncorrectArgumentCount(2, 1).into(),
        RuntimeErrorType::Arithmetic(
            "Power argument to (pow ...) must be a u32 integer".to_string(),
        )
        .into(),
        RuntimeErrorType::Arithmetic(
            "Power argument to (pow ...) must be a u32 integer".to_string(),
        )
        .into(),
        CheckErrors::TypeError(
            TypeSignature::from_string("bool", version, epoch),
            TypeSignature::from_string("int", version, epoch),
        )
        .into(),
    ];

    for (program, expectation) in tests.iter().zip(expectations.iter()) {
        assert_eq!(*expectation, vm_execute(program).unwrap_err());
    }
}

#[test]
fn test_unsigned_arithmetic() {
    let tests = [
        "(- u10)",
        "(- u10 u11)",
        "(> u10 80)",
        "(+ u10 80)",
        "(to-uint -10)",
        "(to-int (pow u2 u127))",
    ];

    let expectations: &[Error] = &[
        RuntimeErrorType::ArithmeticUnderflow.into(),
        RuntimeErrorType::ArithmeticUnderflow.into(),
        CheckErrors::UnionTypeValueError(
            vec![TypeSignature::IntType, TypeSignature::UIntType],
            Value::UInt(10),
        )
        .into(),
        CheckErrors::TypeValueError(TypeSignature::UIntType, Value::Int(80)).into(),
        RuntimeErrorType::ArithmeticUnderflow.into(),
        RuntimeErrorType::ArithmeticOverflow.into(),
    ];

    for (program, expectation) in tests.iter().zip(expectations.iter()) {
        assert_eq!(*expectation, vm_execute(program).unwrap_err());
    }
}

#[test]
fn test_options_errors() {
    let tests = [
        "(is-none 2 1)",
        "(is-none true)",
        "(is-ok 2 1)",
        "(is-ok true)",
        "(is-err 2 1)",
        "(is-err true)",
        "(is-some 2 1)",
        "(is-some true)",
        "(ok 2 3)",
        "(some 2 3)",
        "(err 4 5)",
        "(default-to 4 5 7)",
        "(default-to 4 true)",
        "(get field-0 (some 1))",
        "(get field-0 1)",
    ];

    let expectations: &[Error] = &[
        CheckErrors::IncorrectArgumentCount(1, 2).into(),
        CheckErrors::ExpectedOptionalValue(Value::Bool(true)).into(),
        CheckErrors::IncorrectArgumentCount(1, 2).into(),
        CheckErrors::ExpectedResponseValue(Value::Bool(true)).into(),
        CheckErrors::IncorrectArgumentCount(1, 2).into(),
        CheckErrors::ExpectedResponseValue(Value::Bool(true)).into(),
        CheckErrors::IncorrectArgumentCount(1, 2).into(),
        CheckErrors::ExpectedOptionalValue(Value::Bool(true)).into(),
        CheckErrors::IncorrectArgumentCount(1, 2).into(),
        CheckErrors::IncorrectArgumentCount(1, 2).into(),
        CheckErrors::IncorrectArgumentCount(1, 2).into(),
        CheckErrors::IncorrectArgumentCount(2, 3).into(),
        CheckErrors::ExpectedOptionalValue(Value::Bool(true)).into(),
        CheckErrors::ExpectedTuple(TypeSignature::IntType).into(),
        CheckErrors::ExpectedTuple(TypeSignature::IntType).into(),
    ];

    for (program, expectation) in tests.iter().zip(expectations.iter()) {
        assert_eq!(*expectation, vm_execute(program).unwrap_err());
    }
}

#[test]
fn test_stx_ops_errors() {
    let tests = [
        r#"(stx-transfer? u4 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)"#,
        r#"(stx-transfer? 4 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)"#,
        r#"(stx-transfer? u4 u3 u2)"#,
        r#"(stx-transfer? true 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)"#,
        r#"(stx-transfer-memo? u4 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR 0x0102)"#,
        r#"(stx-transfer-memo? 4 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR 0x0102)"#,
        r#"(stx-transfer-memo? u4 u3 u2 0x0102)"#,
        r#"(stx-transfer-memo? true 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR 0x0102)"#,
        "(stx-burn? u4)",
        "(stx-burn? 4 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)",
    ];

    let expectations: &[Error] = &[
        CheckErrors::IncorrectArgumentCount(3, 2).into(),
        CheckErrors::BadTransferSTXArguments.into(),
        CheckErrors::BadTransferSTXArguments.into(),
        CheckErrors::BadTransferSTXArguments.into(),
        CheckErrors::IncorrectArgumentCount(4, 3).into(),
        CheckErrors::BadTransferSTXArguments.into(),
        CheckErrors::BadTransferSTXArguments.into(),
        CheckErrors::BadTransferSTXArguments.into(),
        CheckErrors::IncorrectArgumentCount(2, 1).into(),
        CheckErrors::BadTransferSTXArguments.into(),
    ];

    for (program, expectation) in tests.iter().zip(expectations.iter()) {
        assert_eq!(
            *expectation,
            execute_with_parameters(
                program,
                ClarityVersion::Clarity2,
                StacksEpochId::Epoch20,
                ASTRules::PrecheckSize,
                false
            )
            .unwrap_err()
        );
    }
}

#[test]
fn test_bitwise() {
    // NOTE: Type safety checks (e.g. that the 2nd argument to bit-shift-left and bit-shift-right must be uint) are not included in this test.
    // Tests for the type checker are included in analysis/type_checker/tests/mod.rs instead.

    let tests = [
        "(bit-and 24 16)",                                                     // 16
        "(bit-and u24 u16)",                                                   // u16
        "(bit-xor 24 4)",                                                      // 28
        "(bit-xor u24 u4)",                                                    // u28
        "(bit-or 128 16)",                                                     // 144
        "(bit-or u128 u16)",                                                   // u144
        "(bit-not 128)",                                                       // -129
        "(bit-not u128)", // u340282366920938463463374607431768211327
        "(bit-not u340282366920938463463374607431768211327)", // u128
        "(bit-shift-right u128 u2)", // u32
        "(bit-shift-left u4 u2)", // u16
        "(bit-and -128 -64)", // -128
        "(bit-or -64 -32)", // -32
        "(bit-xor -128 64)", // -64
        "(bit-not -128)", // 127
        "(bit-shift-right -64 u1)", // -32
        "(bit-shift-left -64 u1)", // -128
        "(bit-shift-right 32 u2)", // 8
        "(bit-shift-left 4 u4)", // 64
        "(bit-or 1 2 4)", // 7
        "(bit-or 64 -32 -16)", // -16
        "(bit-or u2 u4 u32)", // u38
        "(bit-and 28 24 -1)", // 24
        "(bit-xor 1 2 4 -1)", // -8
        "(bit-shift-right u123 u9999999999)", // u0
        "(bit-shift-left u123 u9999999999)", // u170141183460469231731687303715884105728
        "(bit-shift-right u240282366920938463463374607431768211327 u2402823)", // u1877205991569831745807614120560689150
        "(bit-shift-left u240282366920938463463374607431768211327 u2402823)", // u130729942995661611608235082407192018816
        "(bit-shift-left u340282366920938463463374607431768211455 u1)", // u340282366920938463463374607431768211454
        "(bit-shift-left -1 u7)",                                       // -128
        "(bit-shift-left -1 u128)",                                     // -1
        "(bit-shift-right -128 u7)",                                    // -1
        "(bit-shift-right -256 u1)",                                    // -128
        "(bit-shift-right 5 u2)",                                       // 1
        "(bit-shift-right -5 u2)",                                      // -2
        "(bit-shift-left 123 u9999999999)", // -170141183460469231731687303715884105728
        "(bit-shift-right 123 u9999999999)", // 0
        "(bit-shift-left -64 u121)",        // -170141183460469231731687303715884105728
    ];

    let expectations: &[Result<Value, Error>] = &[
        Ok(Value::Int(16)),                                       // (bit-and 24 16)
        Ok(Value::UInt(16)),                                      // (bit-and u24 u16)
        Ok(Value::Int(28)),                                       // (bit-xor 24 4)y
        Ok(Value::UInt(28)),                                      // (bit-xor u24 u4)
        Ok(Value::Int(144)),                                      // (bit-or 128 16)
        Ok(Value::UInt(144)),                                     // (bit-or u128 u16)
        Ok(Value::Int(-129)),                                     // (bit-not 128)
        Ok(Value::UInt(340282366920938463463374607431768211327)), // (bit-not u128)
        Ok(Value::UInt(128)), // (bit-not u340282366920938463463374607431768211327)
        Ok(Value::UInt(32)),  // (bit-shift-right u128 u2)
        Ok(Value::UInt(16)),  // (bit-shift-left u4 u2)
        Ok(Value::Int(-128)), // (bit-and -128 -64)
        Ok(Value::Int(-32)),  // (bit-or -64 -32)
        Ok(Value::Int(-64)),  // (bit-xor -128 64)
        Ok(Value::Int(127)),  // (bit-not -128)
        Ok(Value::Int(-32)),  // (bit-shift-right -64 u1)
        Ok(Value::Int(-128)), // (bit-shift-left -64 u1)
        Ok(Value::Int(8)),    // (bit-shift-right 32 u2)
        Ok(Value::Int(64)),   // (bit-shift-left 4 u4)
        Ok(Value::Int(7)),    // (bit-or 1 2 4)
        Ok(Value::Int(-16)),  // (bit-or 64 -32 -16)
        Ok(Value::UInt(38)),  // (bit-or u2 u4 u32)
        Ok(Value::Int(24)),   // (bit-and 28 24 -1)
        Ok(Value::Int(-8)),   // (bit-xor 1 2 4 -1)
        Ok(Value::UInt(0)),   // (bit-shift-right u123 u9999999999)
        Ok(Value::UInt(u128::try_from(i128::MAX).unwrap() + 1)), // (bit-shift-left u123 u9999999999)
        Ok(Value::UInt(1877205991569831745807614120560689150)),
        Ok(Value::UInt(130729942995661611608235082407192018816)),
        Ok(Value::UInt(u128::MAX - 1)), // (bit-shift-left u340282366920938463463374607431768211455 u1)
        Ok(Value::Int(-128)),           // (bit-shift-left -1 7)
        Ok(Value::Int(-1)),             // (bit-shift-left -1 128)
        Ok(Value::Int(-1)),             // (bit-shift-right -128 u7)
        Ok(Value::Int(-128)),           // (bit-shift-right -256 64)
        Ok(Value::Int(1)),              // (bit-shift-right 5 u2)
        Ok(Value::Int(-2)),             // (bit-shift-right -5 u2)
        Ok(Value::Int(i128::MIN)),      // (bit-shift-left 123 u9999999999)
        Ok(Value::Int(0)),              // (bit-shift-right 123 u9999999999)
        Ok(Value::Int(i128::MIN)),      // (bit-shift-left -64 u121)
    ];

    for (program, expectation) in tests.iter().zip(expectations.iter()) {
        assert_eq!(*expectation, vm_execute_v2(program).map(|x| x.unwrap()));
    }
}

#[test]
fn test_some() {
    let tests = [
        "(is-eq (some 1) (some 1))",
        "(is-eq none none)",
        "(is-none (some 1))",
        "(is-some (some 1))",
        "(is-some none)",
        "(is-none none)",
        "(is-eq (some 1) none)",
        "(is-eq none (some 1))",
        "(is-eq (some 1) (some 2))",
    ];

    let expectations = [
        Value::Bool(true),
        Value::Bool(true),
        Value::Bool(false),
        Value::Bool(true),
        Value::Bool(false),
        Value::Bool(true),
        Value::Bool(false),
        Value::Bool(false),
        Value::Bool(false),
    ];

    for (program, expectation) in tests.iter().zip(expectations.iter()) {
        assert_eq!(*expectation, vm_execute(program).unwrap().unwrap());
    }
}

#[test]
fn test_option_destructs() {
    let tests = [
        "(unwrap! (some 1) 2)",
        "(unwrap-err! (err 1) 2)",
        "(unwrap-err! (some 2) 2)",
        "(unwrap! (ok 3) 2)",
        "(unwrap! (err 3) 2)",
        "(unwrap-panic (ok 3))",
        "(unwrap-panic (some 3))",
        "(unwrap-err-panic (err 3))",
        "(unwrap-err-panic (ok 3))",
        "(unwrap-panic none)",
        "(unwrap-panic (err 3))",
        "(match (some 1) inner-value (+ 1 inner-value) (/ 1 0))",
        "(match none inner-value (/ 1 0) (+ 1 8))",
        "(match (ok 1) ok-val (+ 1 ok-val) err-val (/ err-val 0))",
        "(match (err 1) ok-val (/ ok-val 0) err-val (+ err-val 7))",
        "(match 1 ok-val (/ ok-val 0) err-val (+ err-val 7))",
        "(match 2 ok-val (/ ok-val 0) (+ 3 7))",
        "(try! (err u1))",
        "(try! (ok 3))",
        "(try! none)",
        "(try! (some true))",
        "(try! none 1)",
        "(try! 1)",
    ];

    let expectations: &[Result<Value, Error>] = &[
        Ok(Value::Int(1)),
        Ok(Value::Int(1)),
        Err(CheckErrors::ExpectedResponseValue(Value::some(Value::Int(2)).unwrap()).into()),
        Ok(Value::Int(3)),
        Err(ShortReturnType::ExpectedValue(Value::Int(2)).into()),
        Ok(Value::Int(3)),
        Ok(Value::Int(3)),
        Ok(Value::Int(3)),
        Err(RuntimeErrorType::UnwrapFailure.into()),
        Err(RuntimeErrorType::UnwrapFailure.into()),
        Err(RuntimeErrorType::UnwrapFailure.into()),
        Ok(Value::Int(2)),
        Ok(Value::Int(9)),
        Ok(Value::Int(2)),
        Ok(Value::Int(8)),
        Err(CheckErrors::BadMatchInput(TypeSignature::IntType).into()),
        Err(CheckErrors::BadMatchInput(TypeSignature::IntType).into()),
        Err(ShortReturnType::ExpectedValue(Value::error(Value::UInt(1)).unwrap()).into()),
        Ok(Value::Int(3)),
        Err(ShortReturnType::ExpectedValue(Value::none()).into()),
        Ok(Value::Bool(true)),
        Err(CheckErrors::IncorrectArgumentCount(1, 2).into()),
        Err(CheckErrors::ExpectedOptionalOrResponseValue(Value::Int(1)).into()),
    ];

    for (program, expectation) in tests.iter().zip(expectations.iter()) {
        assert_eq!(*expectation, vm_execute(program).map(|x| x.unwrap()));
    }
}

#[test]
fn test_hash_errors() {
    let tests = [
        "(sha256 2 1)",
        "(keccak256 3 1)",
        "(hash160 2 1)",
        "(sha256 true)",
        "(keccak256 true)",
        "(hash160 true)",
        "(sha512 true)",
        "(sha512 1 2)",
        "(sha512/256 true)",
        "(sha512/256 1 2)",
    ];

    let expectations: &[Error] = &[
        CheckErrors::IncorrectArgumentCount(1, 2).into(),
        CheckErrors::IncorrectArgumentCount(1, 2).into(),
        CheckErrors::IncorrectArgumentCount(1, 2).into(),
        CheckErrors::UnionTypeValueError(
            vec![
                TypeSignature::IntType,
                TypeSignature::UIntType,
                TypeSignature::max_buffer().unwrap(),
            ],
            Value::Bool(true),
        )
        .into(),
        CheckErrors::UnionTypeValueError(
            vec![
                TypeSignature::IntType,
                TypeSignature::UIntType,
                TypeSignature::max_buffer().unwrap(),
            ],
            Value::Bool(true),
        )
        .into(),
        CheckErrors::UnionTypeValueError(
            vec![
                TypeSignature::IntType,
                TypeSignature::UIntType,
                TypeSignature::max_buffer().unwrap(),
            ],
            Value::Bool(true),
        )
        .into(),
        CheckErrors::UnionTypeValueError(
            vec![
                TypeSignature::IntType,
                TypeSignature::UIntType,
                TypeSignature::max_buffer().unwrap(),
            ],
            Value::Bool(true),
        )
        .into(),
        CheckErrors::IncorrectArgumentCount(1, 2).into(),
        CheckErrors::UnionTypeValueError(
            vec![
                TypeSignature::IntType,
                TypeSignature::UIntType,
                TypeSignature::max_buffer().unwrap(),
            ],
            Value::Bool(true),
        )
        .into(),
        CheckErrors::IncorrectArgumentCount(1, 2).into(),
    ];

    for (program, expectation) in tests.iter().zip(expectations.iter()) {
        assert_eq!(*expectation, vm_execute(program).unwrap_err());
    }
}

#[test]
fn test_bool_functions() {
    let tests = [
        "true",
        "(and true true true)",
        "(and false true true)",
        "(and false (> 1 (/ 10 0)))",
        "(or true (> 1 (/ 10 0)))",
        "(or false false false)",
        "(not true)",
        "(and true false)",
        "(or false true)",
    ];

    let expectations = [
        Value::Bool(true),
        Value::Bool(true),
        Value::Bool(false),
        Value::Bool(false),
        Value::Bool(true),
        Value::Bool(false),
        Value::Bool(false),
        Value::Bool(false),
        Value::Bool(true),
    ];

    tests
        .iter()
        .zip(expectations.iter())
        .for_each(|(program, expectation)| assert_eq!(expectation.clone(), execute(program)));
}

#[test]
fn test_bad_lets() {
    let tests = [
        "(let ((tx-sender 1)) (+ tx-sender tx-sender))",
        "(let ((* 1)) (+ * *))",
        "(let ((a 1) (a 2)) (+ a a))",
        "(let ((a 1) (b 2)) (var-set cursor a) (var-set cursor (+ b (var-get cursor))) (+ a b))",
        "(let ((true 0)) true)",
        "(let ((false 1)) false)",
    ];

    let expectations: &[Error] = &[
        CheckErrors::NameAlreadyUsed("tx-sender".to_string()).into(),
        CheckErrors::NameAlreadyUsed("*".to_string()).into(),
        CheckErrors::NameAlreadyUsed("a".to_string()).into(),
        CheckErrors::NoSuchDataVariable("cursor".to_string()).into(),
        CheckErrors::NameAlreadyUsed("true".to_string()).into(),
        CheckErrors::NameAlreadyUsed("false".to_string()).into(),
    ];

    tests
        .iter()
        .zip(expectations.iter())
        .for_each(|(program, expectation)| {
            assert_eq!((*expectation), vm_execute(program).unwrap_err())
        });
}

#[test]
fn test_lets() {
    let tests = [
        "(let ((a 1) (b 2)) (+ a b))",
        "(define-data-var cursor int 0) (let ((a 1) (b 2)) (var-set cursor a) (var-set cursor (+ b (var-get cursor))) (var-get cursor))"];

    let expectations = [Value::Int(3), Value::Int(3)];

    tests
        .iter()
        .zip(expectations.iter())
        .for_each(|(program, expectation)| assert_eq!(expectation.clone(), execute(program)));
}

#[test]
// tests that the type signature of the result of a merge tuple is updated.
//  this is required to pass the type admission checks of, e.g., data store
//  operations like `(define-data-var ...)`
fn merge_update_type_signature_2239() {
    let tests = [
        "(define-data-var a {p: uint} (merge {p: 2} {p: u2})) (var-get a)",
        "(merge {p: 2} {p: u2})",
        "(merge {p: 2} {q: 3})",
        "(define-data-var c {p: uint} {p: u2}) (var-get c)",
        "(define-data-var d {p: uint} (merge {p: u2} {p: u2})) (var-get d)",
        "(define-data-var e {p: int, q: int} {p: 2, q: 3}) (var-get e)",
        "(define-data-var f {p: int, q: int} (merge {q: 2, p: 3} {p: 4})) (var-get f)",
    ];

    let expectations = [
        "(tuple (p u2))",
        "(tuple (p u2))",
        "(tuple (p 2) (q 3))",
        "(tuple (p u2))",
        "(tuple (p u2))",
        "(tuple (p 2) (q 3))",
        "(tuple (p 4) (q 2))",
    ];

    tests
        .iter()
        .zip(expectations.iter())
        .for_each(|(program, expectation)| {
            assert_eq!(expectation.to_string(), execute(program).to_string())
        });
}

#[test]
fn test_2053_stacked_user_funcs() {
    let test = "
(define-read-only (identity (n int)) n)
(begin (identity (identity 1)))
";

    let expectation = Value::Int(1);

    assert_eq!(expectation, execute(test));
}

#[test]
fn test_asserts() {
    let tests = [
        "(begin (asserts! (is-eq 1 1) (err 0)) (ok 1))",
        "(begin (asserts! (is-eq 1 1) (err 0)) (asserts! (is-eq 2 2) (err 1)) (ok 2))",
    ];

    let expectations = [
        Value::okay(Value::Int(1)).unwrap(),
        Value::okay(Value::Int(2)).unwrap(),
    ];

    tests
        .iter()
        .zip(expectations.iter())
        .for_each(|(program, expectation)| assert_eq!(expectation.clone(), execute(program)));
}

#[test]
fn test_asserts_short_circuit() {
    let tests = [
        "(begin (asserts! (is-eq 1 0) (err 0)) (ok 1))",
        "(begin (asserts! (is-eq 1 1) (err 0)) (asserts! (is-eq 2 1) (err 1)) (ok 2))",
    ];

    let expectations: &[Error] = &[
        Error::ShortReturn(ShortReturnType::AssertionFailed(
            Value::error(Value::Int(0)).unwrap(),
        )),
        Error::ShortReturn(ShortReturnType::AssertionFailed(
            Value::error(Value::Int(1)).unwrap(),
        )),
    ];

    tests
        .iter()
        .zip(expectations.iter())
        .for_each(|(program, expectation)| {
            assert_eq!((*expectation), vm_execute(program).unwrap_err())
        });
}

#[test]
fn test_is_mainnet() {
    let tests = [
        "is-in-mainnet", // true only on "mainnet"
        "is-in-regtest", // always true in a regtest
    ];

    let mainnet_expectations = [Value::Bool(true), Value::Bool(true)];

    tests
        .iter()
        .zip(mainnet_expectations.iter())
        .for_each(|(program, expectation)| {
            assert_eq!(
                expectation.clone(),
                execute_with_parameters(
                    program,
                    ClarityVersion::Clarity2,
                    StacksEpochId::Epoch20,
                    ASTRules::PrecheckSize,
                    true
                )
                .unwrap()
                .unwrap()
            )
        });

    let testnet_expectations = [Value::Bool(false), Value::Bool(true)];

    tests
        .iter()
        .zip(testnet_expectations.iter())
        .for_each(|(program, expectation)| {
            assert_eq!(
                expectation.clone(),
                execute_with_parameters(
                    program,
                    ClarityVersion::Clarity2,
                    StacksEpochId::Epoch20,
                    ASTRules::PrecheckSize,
                    false
                )
                .unwrap()
                .unwrap()
            )
        });
}

#[test]
fn test_chain_id() {
    let tests = ["chain-id"];

    let mainnet_expectations = [Value::UInt(CHAIN_ID_MAINNET.into())];

    tests
        .iter()
        .zip(mainnet_expectations.iter())
        .for_each(|(program, expectation)| {
            assert_eq!(
                expectation.clone(),
                execute_with_parameters(
                    program,
                    ClarityVersion::Clarity2,
                    StacksEpochId::Epoch21,
                    ASTRules::PrecheckSize,
                    true
                )
                .unwrap()
                .unwrap()
            )
        });

    let testnet_expectations = [Value::UInt(CHAIN_ID_TESTNET.into())];

    tests
        .iter()
        .zip(testnet_expectations.iter())
        .for_each(|(program, expectation)| {
            assert_eq!(
                expectation.clone(),
                execute_with_parameters(
                    program,
                    ClarityVersion::Clarity2,
                    StacksEpochId::Epoch21,
                    ASTRules::PrecheckSize,
                    false
                )
                .unwrap()
                .unwrap()
            )
        });
}

#[test]
fn test_execution_time_expiration() {
    let program = String::from(
        r#";; Block Limits
;; {
;;   "read_count": 15_000,
;;   "read_length": 100_000_000,
;;   "runtime": 5_000_000_000,
;;   "write_count": 15_000,
;;   "write_length": 15_000_000,
;; }

(define-constant ERR_UNWRAP (err u101))

;; Variables
(define-data-var value-used-read-count uint u0)
(define-data-var temp-list (list 2000 uint) 
  (list ))

(define-map test-map uint uint)

;; ;; Functions
(define-private (initialize) 
  (begin 
    (var-set temp-list (list ))
    (var-set value-used-read-count u0)
  )
)

;; ;; Test read count limit
(define-private (read-count-one (current-number uint)) 
  (begin
    (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) 
    (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) 
    (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) 
    (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) 
    (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) 
    (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) 
    (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) 
    (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) 
    (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) 
    (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) (var-get value-used-read-count) 
    (ok true)
  )
)

(define-public (read-count-test (current-numbers (list 1000 uint))) 
  (begin 
    (initialize)
    (ok (map read-count-one current-numbers))
  )
)


;; ;; Test read length limit
(define-private (read-length-one (position uint)) 
  (begin
    (var-get value-used-read-length) (var-get value-used-read-length) (var-get value-used-read-length) (var-get value-used-read-length) (var-get value-used-read-length) (var-get value-used-read-length) (var-get value-used-read-length) (var-get value-used-read-length) (var-get value-used-read-length) (var-get value-used-read-length) 
    (var-get value-used-read-length) (var-get value-used-read-length) (var-get value-used-read-length) (var-get value-used-read-length) (var-get value-used-read-length) (var-get value-used-read-length) (var-get value-used-read-length) (var-get value-used-read-length) (var-get value-used-read-length) (var-get value-used-read-length) 
    (var-get value-used-read-length) (var-get value-used-read-length) (var-get value-used-read-length) (var-get value-used-read-length) (var-get value-used-read-length) (var-get value-used-read-length) (var-get value-used-read-length) (var-get value-used-read-length) (var-get value-used-read-length) (var-get value-used-read-length) 
    (var-get value-used-read-length) (var-get value-used-read-length) (var-get value-used-read-length) (var-get value-used-read-length) (var-get value-used-read-length) (var-get value-used-read-length) (var-get value-used-read-length) (var-get value-used-read-length) (var-get value-used-read-length) (var-get value-used-read-length) 
    (var-get value-used-read-length) (var-get value-used-read-length) (var-get value-used-read-length) (var-get value-used-read-length) (var-get value-used-read-length) (var-get value-used-read-length) (var-get value-used-read-length) (var-get value-used-read-length) (var-get value-used-read-length) (var-get value-used-read-length) 
    (ok true)
  )
)

(define-public (read-length-test (current-numbers (list 1200 uint))) 
  (begin 
    (initialize)
    (ok (map read-length-one current-numbers))
  )
)

;; Test write count limit
;; (define-private (write-count-one (current-number uint))
;;   (begin 
;;     (var-set value-used-read-count (+ (* current-number current-number) current-number))
;;     (var-set value-used-read-count (* u2 (var-get value-used-read-count)))
;;     (var-set value-used-read-count u3)
;;   )
;; )

;; Test write count limit
(define-private (write-count-one (current-number uint))
  (begin 
  ;; Counts a write count as a read count as well
    ;; (var-set value-used-read-count u2)
    ;; (var-set value-used-read-count u2)
    ;; (var-set value-used-read-count u2)
    ;; (var-set value-used-read-count u2)
    ;; (var-set value-used-read-count u2)
    ;; (var-set value-used-read-count u2)
    ;; (var-set value-used-read-count u2)
    ;; (var-set value-used-read-count u2)
    ;; (var-set value-used-read-count u2)
    ;; (var-set value-used-read-count u2)
    ;; (var-set value-used-read-count u2)
  ;; Counts a write count as a read count as well
    ;; (map-set test-map current-number u1)
    ;; (map-set test-map (+ current-number u1000) u2)
    ;; (map-set test-map (+ current-number u2000) u3)
    ;; (map-set test-map (+ current-number u3000) u4)
    ;; (map-set test-map (+ current-number u4000) u5)
    ;; (map-set test-map (+ current-number u5000) u6)
    ;; (map-set test-map (+ current-number u6000) u7)
    ;; (map-set test-map (+ current-number u7000) u8)
    ;; (map-set test-map (+ current-number u8000) u9)
    ;; (map-set test-map (+ current-number u9000) u10)
    ;; (map-set test-map (+ current-number u10000) u11)
    ;; (map-set test-map (+ current-number u11000) u12)
    ;; (map-set test-map (+ current-number u12000) u13)
    ;; (map-set test-map (+ current-number u13000) u14)
    ;; (map-set test-map (+ current-number u14000) u15)
  ;; Counts a write count as a read count as well
    (var-set temp-list (unwrap! (as-max-len? (append (list ) current-number) u2000) ERR_UNWRAP))
    (var-set temp-list (unwrap! (as-max-len? (append (list ) current-number) u2000) ERR_UNWRAP))
    (var-set temp-list (unwrap! (as-max-len? (append (list ) current-number) u2000) ERR_UNWRAP))
    (var-set temp-list (unwrap! (as-max-len? (append (list ) current-number) u2000) ERR_UNWRAP))
    (var-set temp-list (unwrap! (as-max-len? (append (list ) current-number) u2000) ERR_UNWRAP))
    (var-set temp-list (unwrap! (as-max-len? (append (list ) current-number) u2000) ERR_UNWRAP))
    (var-set temp-list (unwrap! (as-max-len? (append (list ) current-number) u2000) ERR_UNWRAP))
    (var-set temp-list (unwrap! (as-max-len? (append (list ) current-number) u2000) ERR_UNWRAP))
    (var-set temp-list (unwrap! (as-max-len? (append (list ) current-number) u2000) ERR_UNWRAP))
    (var-set temp-list (unwrap! (as-max-len? (append (list ) current-number) u2000) ERR_UNWRAP))
    (var-set temp-list (unwrap! (as-max-len? (append (list ) current-number) u2000) ERR_UNWRAP))
    (var-set temp-list (unwrap! (as-max-len? (append (list ) current-number) u2000) ERR_UNWRAP))
    (var-set temp-list (unwrap! (as-max-len? (append (list ) current-number) u2000) ERR_UNWRAP))
    (var-set temp-list (unwrap! (as-max-len? (append (list ) current-number) u2000) ERR_UNWRAP))
    (var-set temp-list (unwrap! (as-max-len? (append (list ) current-number) u2000) ERR_UNWRAP))
    (ok true)
  )
)

(define-public (write-count-test (current-numbers (list 1000 uint))) 
  (begin 
    (initialize )
    (ok (map write-count-one current-numbers))
  )
)


;; Test write length limit
(define-private (write-length-one (current-number uint))
  (begin 
    (var-set temp-list (unwrap! (as-max-len? (append (var-get temp-list) current-number) u2000) ERR_UNWRAP))
    (ok true)
  )
)

(define-public (write-length-test (current-numbers (list 1000 uint))) 
  (begin 
    (initialize )
    ;; Chain multiple write operations
    (map write-length-one current-numbers)
    (map write-length-one current-numbers)
    (map write-length-one current-numbers)
    (map write-length-one current-numbers)
    (map write-length-one current-numbers)
    ;; Store final result
    (var-set value-used-read-length (var-get temp-list))
    (ok true)
  )
)

;; Test computation limit
(define-private (computation-one (x int) (y int))
  (begin 
    (+ 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
    )
    (+ 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
    )
    (+ 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
    )
    (+ 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
    )
    (+ 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
    )
    (+ 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
    )
    (+ 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
    )
    (+ 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
    )
    (+ 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
    )
    (+ 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
    )
    (+ 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
    )
    (+ 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
    )
    (+ 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
    )
    (+ 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
    )
    (+ 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
    )
    (+ 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
    )
    (+ 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
    )
    (+ 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
    )
    (+ 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
    )
    (+ 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
    )
    (+ 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
    )
    (+ 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
    )
    (+ 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
    )
    (+ 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
    )
    (+ 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
      (+ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* (/ (* x x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x) x)) 
    )
    
    y
  )
)

(define-private (computation-three (x int) (y int))
  (+ (computation-one x y) (computation-one x y) (computation-one x y))
)

(define-public (computation-test (l (list 1000 int)) (init int))
  (begin 
    (initialize )
    (ok (fold computation-three l init))
  )
)

;; List of values
(define-data-var value-used-read-length (list 5000 uint)
  (list
    u0 u1 u2 u3 u4 u5 u6 u7 u8 u9 u10 u11 u12 u13 u14 u15 u16 u17 u18 u19 
    u20 u21 u22 u23 u24 u25 u26 u27 u28 u29 u30 u31 u32 u33 u34 u35 u36 u37 u38 u39 
    u40 u41 u42 u43 u44 u45 u46 u47 u48 u49 u50 u51 u52 u53 u54 u55 u56 u57 u58 u59 
    u60 u61 u62 u63 u64 u65 u66 u67 u68 u69 u70 u71 u72 u73 u74 u75 u76 u77 u78 u79 
    u80 u81 u82 u83 u84 u85 u86 u87 u88 u89 u90 u91 u92 u93 u94 u95 u96 u97 u98 u99 
    u100 u101 u102 u103 u104 u105 u106 u107 u108 u109 u110 u111 u112 u113 u114 u115 u116 u117 u118 u119 
    u120 u121 u122 u123 u124 u125 u126 u127 u128 u129 u130 u131 u132 u133 u134 u135 u136 u137 u138 u139 
    u140 u141 u142 u143 u144 u145 u146 u147 u148 u149 u150 u151 u152 u153 u154 u155 u156 u157 u158 u159 
    u160 u161 u162 u163 u164 u165 u166 u167 u168 u169 u170 u171 u172 u173 u174 u175 u176 u177 u178 u179 
    u180 u181 u182 u183 u184 u185 u186 u187 u188 u189 u190 u191 u192 u193 u194 u195 u196 u197 u198 u199 
    u200 u201 u202 u203 u204 u205 u206 u207 u208 u209 u210 u211 u212 u213 u214 u215 u216 u217 u218 u219 
    u220 u221 u222 u223 u224 u225 u226 u227 u228 u229 u230 u231 u232 u233 u234 u235 u236 u237 u238 u239 
    u240 u241 u242 u243 u244 u245 u246 u247 u248 u249 u250 u251 u252 u253 u254 u255 u256 u257 u258 u259 
    u260 u261 u262 u263 u264 u265 u266 u267 u268 u269 u270 u271 u272 u273 u274 u275 u276 u277 u278 u279 
    u280 u281 u282 u283 u284 u285 u286 u287 u288 u289 u290 u291 u292 u293 u294 u295 u296 u297 u298 u299 
    u300 u301 u302 u303 u304 u305 u306 u307 u308 u309 u310 u311 u312 u313 u314 u315 u316 u317 u318 u319 
    u320 u321 u322 u323 u324 u325 u326 u327 u328 u329 u330 u331 u332 u333 u334 u335 u336 u337 u338 u339 
    u340 u341 u342 u343 u344 u345 u346 u347 u348 u349 u350 u351 u352 u353 u354 u355 u356 u357 u358 u359 
    u360 u361 u362 u363 u364 u365 u366 u367 u368 u369 u370 u371 u372 u373 u374 u375 u376 u377 u378 u379 
    u380 u381 u382 u383 u384 u385 u386 u387 u388 u389 u390 u391 u392 u393 u394 u395 u396 u397 u398 u399 
    u400 u401 u402 u403 u404 u405 u406 u407 u408 u409 u410 u411 u412 u413 u414 u415 u416 u417 u418 u419 
    u420 u421 u422 u423 u424 u425 u426 u427 u428 u429 u430 u431 u432 u433 u434 u435 u436 u437 u438 u439 
    u440 u441 u442 u443 u444 u445 u446 u447 u448 u449 u450 u451 u452 u453 u454 u455 u456 u457 u458 u459 
    u460 u461 u462 u463 u464 u465 u466 u467 u468 u469 u470 u471 u472 u473 u474 u475 u476 u477 u478 u479 
    u480 u481 u482 u483 u484 u485 u486 u487 u488 u489 u490 u491 u492 u493 u494 u495 u496 u497 u498 u499 
    u500 u501 u502 u503 u504 u505 u506 u507 u508 u509 u510 u511 u512 u513 u514 u515 u516 u517 u518 u519 
    u520 u521 u522 u523 u524 u525 u526 u527 u528 u529 u530 u531 u532 u533 u534 u535 u536 u537 u538 u539 
    u540 u541 u542 u543 u544 u545 u546 u547 u548 u549 u550 u551 u552 u553 u554 u555 u556 u557 u558 u559 
    u560 u561 u562 u563 u564 u565 u566 u567 u568 u569 u570 u571 u572 u573 u574 u575 u576 u577 u578 u579 
    u580 u581 u582 u583 u584 u585 u586 u587 u588 u589 u590 u591 u592 u593 u594 u595 u596 u597 u598 u599 
    u600 u601 u602 u603 u604 u605 u606 u607 u608 u609 u610 u611 u612 u613 u614 u615 u616 u617 u618 u619 
    u620 u621 u622 u623 u624 u625 u626 u627 u628 u629 u630 u631 u632 u633 u634 u635 u636 u637 u638 u639 
    u640 u641 u642 u643 u644 u645 u646 u647 u648 u649 u650 u651 u652 u653 u654 u655 u656 u657 u658 u659 
    u660 u661 u662 u663 u664 u665 u666 u667 u668 u669 u670 u671 u672 u673 u674 u675 u676 u677 u678 u679 
    u680 u681 u682 u683 u684 u685 u686 u687 u688 u689 u690 u691 u692 u693 u694 u695 u696 u697 u698 u699 
    u700 u701 u702 u703 u704 u705 u706 u707 u708 u709 u710 u711 u712 u713 u714 u715 u716 u717 u718 u719 
    u720 u721 u722 u723 u724 u725 u726 u727 u728 u729 u730 u731 u732 u733 u734 u735 u736 u737 u738 u739 
    u740 u741 u742 u743 u744 u745 u746 u747 u748 u749 u750 u751 u752 u753 u754 u755 u756 u757 u758 u759 
    u760 u761 u762 u763 u764 u765 u766 u767 u768 u769 u770 u771 u772 u773 u774 u775 u776 u777 u778 u779 
    u780 u781 u782 u783 u784 u785 u786 u787 u788 u789 u790 u791 u792 u793 u794 u795 u796 u797 u798 u799 
    u800 u801 u802 u803 u804 u805 u806 u807 u808 u809 u810 u811 u812 u813 u814 u815 u816 u817 u818 u819 
    u820 u821 u822 u823 u824 u825 u826 u827 u828 u829 u830 u831 u832 u833 u834 u835 u836 u837 u838 u839 
    u840 u841 u842 u843 u844 u845 u846 u847 u848 u849 u850 u851 u852 u853 u854 u855 u856 u857 u858 u859 
    u860 u861 u862 u863 u864 u865 u866 u867 u868 u869 u870 u871 u872 u873 u874 u875 u876 u877 u878 u879 
    u880 u881 u882 u883 u884 u885 u886 u887 u888 u889 u890 u891 u892 u893 u894 u895 u896 u897 u898 u899 
    u900 u901 u902 u903 u904 u905 u906 u907 u908 u909 u910 u911 u912 u913 u914 u915 u916 u917 u918 u919 
    u920 u921 u922 u923 u924 u925 u926 u927 u928 u929 u930 u931 u932 u933 u934 u935 u936 u937 u938 u939 
    u940 u941 u942 u943 u944 u945 u946 u947 u948 u949 u950 u951 u952 u953 u954 u955 u956 u957 u958 u959 
    u960 u961 u962 u963 u964 u965 u966 u967 u968 u969 u970 u971 u972 u973 u974 u975 u976 u977 u978 u979 
    u980 u981 u982 u983 u984 u985 u986 u987 u988 u989 u990 u991 u992 u993 u994 u995 u996 u997 u998 u999 
    u1000 u1001 u1002 u1003 u1004 u1005 u1006 u1007 u1008 u1009 u1010 u1011 u1012 u1013 u1014 u1015 u1016 u1017 u1018 u1019 
    u1020 u1021 u1022 u1023 u1024 u1025 u1026 u1027 u1028 u1029 u1030 u1031 u1032 u1033 u1034 u1035 u1036 u1037 u1038 u1039 
    u1040 u1041 u1042 u1043 u1044 u1045 u1046 u1047 u1048 u1049 u1050 u1051 u1052 u1053 u1054 u1055 u1056 u1057 u1058 u1059 
    u1060 u1061 u1062 u1063 u1064 u1065 u1066 u1067 u1068 u1069 u1070 u1071 u1072 u1073 u1074 u1075 u1076 u1077 u1078 u1079 
    u1080 u1081 u1082 u1083 u1084 u1085 u1086 u1087 u1088 u1089 u1090 u1091 u1092 u1093 u1094 u1095 u1096 u1097 u1098 u1099 
    u1100 u1101 u1102 u1103 u1104 u1105 u1106 u1107 u1108 u1109 u1110 u1111 u1112 u1113 u1114 u1115 u1116 u1117 u1118 u1119 
    u1120 u1121 u1122 u1123 u1124 u1125 u1126 u1127 u1128 u1129 u1130 u1131 u1132 u1133 u1134 u1135 u1136 u1137 u1138 u1139 
    u1140 u1141 u1142 u1143 u1144 u1145 u1146 u1147 u1148 u1149 u1150 u1151 u1152 u1153 u1154 u1155 u1156 u1157 u1158 u1159 
    u1160 u1161 u1162 u1163 u1164 u1165 u1166 u1167 u1168 u1169 u1170 u1171 u1172 u1173 u1174 u1175 u1176 u1177 u1178 u1179 
    u1180 u1181 u1182 u1183 u1184 u1185 u1186 u1187 u1188 u1189 u1190 u1191 u1192 u1193 u1194 u1195 u1196 u1197 u1198 u1199 
    u1200 u1201 u1202 u1203 u1204 u1205 u1206 u1207 u1208 u1209 u1210 u1211 u1212 u1213 u1214 u1215 u1216 u1217 u1218 u1219 
    u1220 u1221 u1222 u1223 u1224 u1225 u1226 u1227 u1228 u1229 u1230 u1231 u1232 u1233 u1234 u1235 u1236 u1237 u1238 u1239 
    u1240 u1241 u1242 u1243 u1244 u1245 u1246 u1247 u1248 u1249 u1250 u1251 u1252 u1253 u1254 u1255 u1256 u1257 u1258 u1259 
    u1260 u1261 u1262 u1263 u1264 u1265 u1266 u1267 u1268 u1269 u1270 u1271 u1272 u1273 u1274 u1275 u1276 u1277 u1278 u1279 
    u1280 u1281 u1282 u1283 u1284 u1285 u1286 u1287 u1288 u1289 u1290 u1291 u1292 u1293 u1294 u1295 u1296 u1297 u1298 u1299 
    u1300 u1301 u1302 u1303 u1304 u1305 u1306 u1307 u1308 u1309 u1310 u1311 u1312 u1313 u1314 u1315 u1316 u1317 u1318 u1319 
    u1320 u1321 u1322 u1323 u1324 u1325 u1326 u1327 u1328 u1329 u1330 u1331 u1332 u1333 u1334 u1335 u1336 u1337 u1338 u1339 
    u1340 u1341 u1342 u1343 u1344 u1345 u1346 u1347 u1348 u1349 u1350 u1351 u1352 u1353 u1354 u1355 u1356 u1357 u1358 u1359 
    u1360 u1361 u1362 u1363 u1364 u1365 u1366 u1367 u1368 u1369 u1370 u1371 u1372 u1373 u1374 u1375 u1376 u1377 u1378 u1379 
    u1380 u1381 u1382 u1383 u1384 u1385 u1386 u1387 u1388 u1389 u1390 u1391 u1392 u1393 u1394 u1395 u1396 u1397 u1398 u1399 
    u1400 u1401 u1402 u1403 u1404 u1405 u1406 u1407 u1408 u1409 u1410 u1411 u1412 u1413 u1414 u1415 u1416 u1417 u1418 u1419 
    u1420 u1421 u1422 u1423 u1424 u1425 u1426 u1427 u1428 u1429 u1430 u1431 u1432 u1433 u1434 u1435 u1436 u1437 u1438 u1439 
    u1440 u1441 u1442 u1443 u1444 u1445 u1446 u1447 u1448 u1449 u1450 u1451 u1452 u1453 u1454 u1455 u1456 u1457 u1458 u1459 
    u1460 u1461 u1462 u1463 u1464 u1465 u1466 u1467 u1468 u1469 u1470 u1471 u1472 u1473 u1474 u1475 u1476 u1477 u1478 u1479 
    u1480 u1481 u1482 u1483 u1484 u1485 u1486 u1487 u1488 u1489 u1490 u1491 u1492 u1493 u1494 u1495 u1496 u1497 u1498 u1499 
    u1500 u1501 u1502 u1503 u1504 u1505 u1506 u1507 u1508 u1509 u1510 u1511 u1512 u1513 u1514 u1515 u1516 u1517 u1518 u1519 
    u1520 u1521 u1522 u1523 u1524 u1525 u1526 u1527 u1528 u1529 u1530 u1531 u1532 u1533 u1534 u1535 u1536 u1537 u1538 u1539 
    u1540 u1541 u1542 u1543 u1544 u1545 u1546 u1547 u1548 u1549 u1550 u1551 u1552 u1553 u1554 u1555 u1556 u1557 u1558 u1559 
    u1560 u1561 u1562 u1563 u1564 u1565 u1566 u1567 u1568 u1569 u1570 u1571 u1572 u1573 u1574 u1575 u1576 u1577 u1578 u1579 
    u1580 u1581 u1582 u1583 u1584 u1585 u1586 u1587 u1588 u1589 u1590 u1591 u1592 u1593 u1594 u1595 u1596 u1597 u1598 u1599 
    u1600 u1601 u1602 u1603 u1604 u1605 u1606 u1607 u1608 u1609 u1610 u1611 u1612 u1613 u1614 u1615 u1616 u1617 u1618 u1619 
    u1620 u1621 u1622 u1623 u1624 u1625 u1626 u1627 u1628 u1629 u1630 u1631 u1632 u1633 u1634 u1635 u1636 u1637 u1638 u1639 
    u1640 u1641 u1642 u1643 u1644 u1645 u1646 u1647 u1648 u1649 u1650 u1651 u1652 u1653 u1654 u1655 u1656 u1657 u1658 u1659 
    u1660 u1661 u1662 u1663 u1664 u1665 u1666 u1667 u1668 u1669 u1670 u1671 u1672 u1673 u1674 u1675 u1676 u1677 u1678 u1679 
    u1680 u1681 u1682 u1683 u1684 u1685 u1686 u1687 u1688 u1689 u1690 u1691 u1692 u1693 u1694 u1695 u1696 u1697 u1698 u1699 
    u1700 u1701 u1702 u1703 u1704 u1705 u1706 u1707 u1708 u1709 u1710 u1711 u1712 u1713 u1714 u1715 u1716 u1717 u1718 u1719 
    u1720 u1721 u1722 u1723 u1724 u1725 u1726 u1727 u1728 u1729 u1730 u1731 u1732 u1733 u1734 u1735 u1736 u1737 u1738 u1739 
    u1740 u1741 u1742 u1743 u1744 u1745 u1746 u1747 u1748 u1749 u1750 u1751 u1752 u1753 u1754 u1755 u1756 u1757 u1758 u1759 
    u1760 u1761 u1762 u1763 u1764 u1765 u1766 u1767 u1768 u1769 u1770 u1771 u1772 u1773 u1774 u1775 u1776 u1777 u1778 u1779 
    u1780 u1781 u1782 u1783 u1784 u1785 u1786 u1787 u1788 u1789 u1790 u1791 u1792 u1793 u1794 u1795 u1796 u1797 u1798 u1799 
    u1800 u1801 u1802 u1803 u1804 u1805 u1806 u1807 u1808 u1809 u1810 u1811 u1812 u1813 u1814 u1815 u1816 u1817 u1818 u1819 
    u1820 u1821 u1822 u1823 u1824 u1825 u1826 u1827 u1828 u1829 u1830 u1831 u1832 u1833 u1834 u1835 u1836 u1837 u1838 u1839 
    u1840 u1841 u1842 u1843 u1844 u1845 u1846 u1847 u1848 u1849 u1850 u1851 u1852 u1853 u1854 u1855 u1856 u1857 u1858 u1859 
    u1860 u1861 u1862 u1863 u1864 u1865 u1866 u1867 u1868 u1869 u1870 u1871 u1872 u1873 u1874 u1875 u1876 u1877 u1878 u1879 
    u1880 u1881 u1882 u1883 u1884 u1885 u1886 u1887 u1888 u1889 u1890 u1891 u1892 u1893 u1894 u1895 u1896 u1897 u1898 u1899 
    u1900 u1901 u1902 u1903 u1904 u1905 u1906 u1907 u1908 u1909 u1910 u1911 u1912 u1913 u1914 u1915 u1916 u1917 u1918 u1919 
    u1920 u1921 u1922 u1923 u1924 u1925 u1926 u1927 u1928 u1929 u1930 u1931 u1932 u1933 u1934 u1935 u1936 u1937 u1938 u1939 
    u1940 u1941 u1942 u1943 u1944 u1945 u1946 u1947 u1948 u1949 u1950 u1951 u1952 u1953 u1954 u1955 u1956 u1957 u1958 u1959 
    u1960 u1961 u1962 u1963 u1964 u1965 u1966 u1967 u1968 u1969 u1970 u1971 u1972 u1973 u1974 u1975 u1976 u1977 u1978 u1979 
    u1980 u1981 u1982 u1983 u1984 u1985 u1986 u1987 u1988 u1989 u1990 u1991 u1992 u1993 u1994 u1995 u1996 u1997 u1998 u1999 
    u2000 u2001 u2002 u2003 u2004 u2005 u2006 u2007 u2008 u2009 u2010 u2011 u2012 u2013 u2014 u2015 u2016 u2017 u2018 u2019 
    u2020 u2021 u2022 u2023 u2024 u2025 u2026 u2027 u2028 u2029 u2030 u2031 u2032 u2033 u2034 u2035 u2036 u2037 u2038 u2039 
    u2040 u2041 u2042 u2043 u2044 u2045 u2046 u2047 u2048 u2049 u2050 u2051 u2052 u2053 u2054 u2055 u2056 u2057 u2058 u2059 
    u2060 u2061 u2062 u2063 u2064 u2065 u2066 u2067 u2068 u2069 u2070 u2071 u2072 u2073 u2074 u2075 u2076 u2077 u2078 u2079 
    u2080 u2081 u2082 u2083 u2084 u2085 u2086 u2087 u2088 u2089 u2090 u2091 u2092 u2093 u2094 u2095 u2096 u2097 u2098 u2099 
    u2100 u2101 u2102 u2103 u2104 u2105 u2106 u2107 u2108 u2109 u2110 u2111 u2112 u2113 u2114 u2115 u2116 u2117 u2118 u2119 
    u2120 u2121 u2122 u2123 u2124 u2125 u2126 u2127 u2128 u2129 u2130 u2131 u2132 u2133 u2134 u2135 u2136 u2137 u2138 u2139 
    u2140 u2141 u2142 u2143 u2144 u2145 u2146 u2147 u2148 u2149 u2150 u2151 u2152 u2153 u2154 u2155 u2156 u2157 u2158 u2159 
    u2160 u2161 u2162 u2163 u2164 u2165 u2166 u2167 u2168 u2169 u2170 u2171 u2172 u2173 u2174 u2175 u2176 u2177 u2178 u2179 
    u2180 u2181 u2182 u2183 u2184 u2185 u2186 u2187 u2188 u2189 u2190 u2191 u2192 u2193 u2194 u2195 u2196 u2197 u2198 u2199 
    u2200 u2201 u2202 u2203 u2204 u2205 u2206 u2207 u2208 u2209 u2210 u2211 u2212 u2213 u2214 u2215 u2216 u2217 u2218 u2219 
    u2220 u2221 u2222 u2223 u2224 u2225 u2226 u2227 u2228 u2229 u2230 u2231 u2232 u2233 u2234 u2235 u2236 u2237 u2238 u2239 
    u2240 u2241 u2242 u2243 u2244 u2245 u2246 u2247 u2248 u2249 u2250 u2251 u2252 u2253 u2254 u2255 u2256 u2257 u2258 u2259 
    u2260 u2261 u2262 u2263 u2264 u2265 u2266 u2267 u2268 u2269 u2270 u2271 u2272 u2273 u2274 u2275 u2276 u2277 u2278 u2279 
    u2280 u2281 u2282 u2283 u2284 u2285 u2286 u2287 u2288 u2289 u2290 u2291 u2292 u2293 u2294 u2295 u2296 u2297 u2298 u2299 
    u2300 u2301 u2302 u2303 u2304 u2305 u2306 u2307 u2308 u2309 u2310 u2311 u2312 u2313 u2314 u2315 u2316 u2317 u2318 u2319 
    u2320 u2321 u2322 u2323 u2324 u2325 u2326 u2327 u2328 u2329 u2330 u2331 u2332 u2333 u2334 u2335 u2336 u2337 u2338 u2339 
    u2340 u2341 u2342 u2343 u2344 u2345 u2346 u2347 u2348 u2349 u2350 u2351 u2352 u2353 u2354 u2355 u2356 u2357 u2358 u2359 
    u2360 u2361 u2362 u2363 u2364 u2365 u2366 u2367 u2368 u2369 u2370 u2371 u2372 u2373 u2374 u2375 u2376 u2377 u2378 u2379 
    u2380 u2381 u2382 u2383 u2384 u2385 u2386 u2387 u2388 u2389 u2390 u2391 u2392 u2393 u2394 u2395 u2396 u2397 u2398 u2399 
    u2400 u2401 u2402 u2403 u2404 u2405 u2406 u2407 u2408 u2409 u2410 u2411 u2412 u2413 u2414 u2415 u2416 u2417 u2418 u2419 
    u2420 u2421 u2422 u2423 u2424 u2425 u2426 u2427 u2428 u2429 u2430 u2431 u2432 u2433 u2434 u2435 u2436 u2437 u2438 u2439 
    u2440 u2441 u2442 u2443 u2444 u2445 u2446 u2447 u2448 u2449 u2450 u2451 u2452 u2453 u2454 u2455 u2456 u2457 u2458 u2459 
    u2460 u2461 u2462 u2463 u2464 u2465 u2466 u2467 u2468 u2469 u2470 u2471 u2472 u2473 u2474 u2475 u2476 u2477 u2478 u2479 
    u2480 u2481 u2482 u2483 u2484 u2485 u2486 u2487 u2488 u2489 u2490 u2491 u2492 u2493 u2494 u2495 u2496 u2497 u2498 u2499))
    
    (computation-test (list 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 61 62 63 64 65 66 67 68 69 70 71 72 73 74 75 76 77 78 79 80 81 82 83 84 85 86 87 88 89 90 91 92 93 94 95 96 97 98 99 100 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 61 62 63 64 65 66 67 68 69 70 71 72 73 74 75 76 77 78 79 80 81 82 83 84 85 86 87 88 89 90 91 92 93 94 95 96 97 98 99 100 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 61 62 63 64 65 66 67 68 69 70 71 72 73 74 75 76 77 78 79 80 81 82 83 84 85 86 87 88 89 90 91 92 93 94 95 96 97 98 99 100 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 61 62 63 64 65 66 67 68 69 70 71 72 73 74 75 76 77 78 79 80 81 82 83 84 85 86 87 88 89 90 91 92 93 94 95 96 97 98 99 100 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 61 62 63 64 65 66 67 68 69 70 71 72 73 74 75 76 77 78 79 80 81 82 83 84 85 86 87 88 89 90 91 92 93 94 95 96 97 98 99 100)
 0)"#,
    );

    assert_eq!(
        vm_execute(&program).err().unwrap(),
        CheckErrors::ExecutionTimeExpired.into()
    );
}
