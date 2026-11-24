// Copyright (C) 2026 Stacks Open Internet Foundation
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

use clarity_types::codec::StacksMessageCodec;
use clarity_types::types::{PrincipalData, QualifiedContractIdentifier, StandardPrincipalData};
use clarity_types::{ClarityName, ContractName};
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};
#[cfg(target_family = "wasm")]
use wasm_bindgen_test::wasm_bindgen_test as test;

use crate::classes::ErrorClass;
use crate::deploy::{CustomSectionError, DeployRejection, check_custom_sections};
use crate::host::IMPORT_MODULE;
use crate::interface::{ABI_VERSION, Function, FunctionKind, Interface, InterfaceError};
use crate::limits::Limits;
use crate::names::{
    CONTRACT_NAME_MAX_LEN, NAME_MAX_LEN, Name, NameError, check_contract_name, check_name,
    parse_contract_name,
};
use crate::principals::{
    PRINCIPAL_MAX_LEN, PrincipalError, STANDARD_PRINCIPAL_LEN, decode_principal, encode_principal,
};
use crate::status::*;

const NAME_VECTORS: &str = include_str!("../vectors/names.txt");
const PRINCIPAL_VECTORS: &str = include_str!("../vectors/principals.txt");
const INTERFACE_VECTORS: &str = include_str!("../vectors/interfaces.txt");

/// One line of a vector file: `<kind> <expected> 0x<hex> [# note]`.
struct Vector<'a> {
    kind: &'a str,
    expected: &'a str,
    input: Vec<u8>,
}

fn parse_vectors(file: &str) -> Vec<Vector<'_>> {
    file.lines()
        .map(|line| line.split('#').next().unwrap().trim())
        .filter(|line| !line.is_empty())
        .map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let [kind, expected, input] = fields[..] else {
                panic!("malformed vector: {line}");
            };
            let hex = input.strip_prefix("0x").expect("input starts with 0x");
            assert!(hex.len() % 2 == 0, "odd hex length: {line}");
            let input = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex digits"))
                .collect();
            Vector {
                kind,
                expected,
                input,
            }
        })
        .collect()
}

/// Asserts that the vectors of `kind` reach "ok" and every one of `reasons`.
fn assert_covered(vectors: &[Vector], kind: &str, reasons: &[&str]) {
    for expected in ["ok"].iter().chain(reasons) {
        assert!(
            vectors
                .iter()
                .any(|v| v.kind == kind && v.expected == *expected),
            "no {kind} vector expects {expected}"
        );
    }
}

#[test]
fn name_vectors() {
    let vectors = parse_vectors(NAME_VECTORS);
    for v in &vectors {
        let got = match v.kind {
            "name" => check_name(&v.input),
            "contract-name" => check_contract_name(&v.input),
            kind => panic!("unknown kind {kind}"),
        };
        let got_str = got.map_or_else(NameError::as_str, |()| "ok");
        assert_eq!(got_str, v.expected, "{} {:02x?}", v.kind, v.input);

        // The typed constructors agree with the checks.
        match v.kind {
            "name" => assert_eq!(
                Name::try_from(v.input.as_slice()).map(|n| n.as_bytes().to_vec()),
                got.map(|()| v.input.clone())
            ),
            _ => assert_eq!(
                parse_contract_name(&v.input).map(|n| n.as_bytes().to_vec()),
                got.map(|()| v.input.clone())
            ),
        }
    }
    let reasons = NameError::ALL.map(NameError::as_str);
    assert_covered(&vectors, "name", &reasons);
    assert_covered(&vectors, "contract-name", &reasons);
}

#[test]
fn principal_vectors() {
    let vectors = parse_vectors(PRINCIPAL_VECTORS);
    for v in &vectors {
        assert_eq!(v.kind, "principal");
        match decode_principal(&v.input) {
            Ok(principal) => {
                assert_eq!(v.expected, "ok", "{:02x?}", v.input);
                assert_eq!(encode_principal(&principal).unwrap(), v.input);
            }
            Err(e) => assert_eq!(e.as_str(), v.expected, "{:02x?}", v.input),
        }
    }
    let reasons = PrincipalError::ALL.map(PrincipalError::as_str);
    assert_covered(&vectors, "principal", &reasons);
}

/// Every byte value, as the first and as a later byte of a name, against the
/// character sets of ABI 2.1 written out.
#[test]
fn name_bytes_exhaustive() {
    const LETTERS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const DIGITS: &[u8] = b"0123456789";
    const NAME_SYMBOLS: &[u8] = b"-_!?+<>=/*^";
    const CONTRACT_SYMBOLS: &[u8] = b"-_";

    for b in 0..=u8::MAX {
        let letter = LETTERS.contains(&b);
        let digit = DIGITS.contains(&b);

        let in_set = letter || digit || NAME_SYMBOLS.contains(&b);
        let first = match (in_set, digit) {
            (false, _) => Err(NameError::BadByte),
            (true, true) => Err(NameError::BadStart),
            (true, false) => Ok(()),
        };
        let later = if in_set {
            Ok(())
        } else {
            Err(NameError::BadByte)
        };
        assert_eq!(check_name(&[b]), first, "name starting with {b:#04x}");
        assert_eq!(check_name(&[b'a', b]), later, "name with {b:#04x}");
        // After a sign, `u`, or both, a digit still starts a number.
        for prefix in [&b"-"[..], b"+", b"u", b"-u", b"+u"] {
            let name = [prefix, &[b][..]].concat();
            assert_eq!(check_name(&name), first, "name {name:02x?}");
        }

        let in_set = letter || digit || CONTRACT_SYMBOLS.contains(&b);
        let first = match (in_set, letter) {
            (false, _) => Err(NameError::BadByte),
            (true, false) => Err(NameError::BadStart),
            (true, true) => Ok(()),
        };
        let later = if in_set {
            Ok(())
        } else {
            Err(NameError::BadByte)
        };
        assert_eq!(check_contract_name(&[b]), first, "contract {b:#04x}");
        assert_eq!(check_contract_name(&[b'a', b]), later, "contract {b:#04x}");
    }
}

#[test]
fn name_lengths() {
    for len in 0..=300 {
        let name = vec![b'a'; len];
        let expected = |max| match len {
            0 => Err(NameError::Empty),
            l if l > max => Err(NameError::TooLong),
            _ => Ok(()),
        };
        assert_eq!(check_name(&name), expected(NAME_MAX_LEN), "{len}");
        assert_eq!(
            check_contract_name(&name),
            expected(CONTRACT_NAME_MAX_LEN),
            "{len}"
        );
    }
    assert_eq!(NAME_MAX_LEN, 128);
    assert_eq!(CONTRACT_NAME_MAX_LEN, 40);
}

/// Names sort by their bytes, the order the ABI sorts lists of names in.
#[test]
fn names_order_by_bytes() {
    let mut names: Vec<Name> = ["b", "a", "B", "ab", "a-", "^", "_a", "a0"]
        .iter()
        .map(|n| Name::try_from(n.as_bytes()).unwrap())
        .collect();
    names.sort();
    let sorted: Vec<&str> = names.iter().map(Name::as_str).collect();
    assert_eq!(sorted, ["B", "^", "_a", "a", "a-", "a0", "ab", "b"]);
    assert_eq!(names[0].to_string(), "B");
}

/// The ABI's function-name grammar adds `^` to legacy's and lets any symbol
/// start a name. It rejects the legacy names that start like a number, such
/// as `u1`, which no contract can define, since the lexer reads them as
/// numbers.
#[test]
fn names_against_legacy_names() {
    for name in ["transfer", "get-balance", "is-ok?", "+", "<=", "a_b!"] {
        assert!(ClarityName::try_from(name.to_string()).is_ok());
        assert_eq!(check_name(name.as_bytes()), Ok(()));
    }
    for name in ["^", "-a", "_a", "a^b", "?"] {
        assert!(ClarityName::try_from(name.to_string()).is_err());
        assert_eq!(check_name(name.as_bytes()), Ok(()));
    }
    for name in ["u1", "u1x"] {
        assert!(ClarityName::try_from(name.to_string()).is_ok());
        assert_eq!(check_name(name.as_bytes()), Err(NameError::BadStart));
    }
}

#[test]
fn principal_round_trips() {
    for version in 0..32 {
        let issuer = StandardPrincipalData::new(version, [version; 20]).unwrap();
        let standard = PrincipalData::Standard(issuer.clone());
        let bytes = encode_principal(&standard).unwrap();
        assert_eq!(bytes.len(), STANDARD_PRINCIPAL_LEN);
        assert_eq!(decode_principal(&bytes), Ok(standard));

        for name_len in 1..=CONTRACT_NAME_MAX_LEN {
            let name = ContractName::try_from("c".repeat(name_len)).unwrap();
            let contract =
                PrincipalData::Contract(QualifiedContractIdentifier::new(issuer.clone(), name));
            let bytes = encode_principal(&contract).unwrap();
            assert_eq!(bytes.len(), STANDARD_PRINCIPAL_LEN + 1 + name_len);
            assert!(bytes.len() <= PRINCIPAL_MAX_LEN);
            assert_eq!(decode_principal(&bytes), Ok(contract));
        }
    }
    assert_eq!(PRINCIPAL_MAX_LEN, 63);
}

/// The encoding is the SIP-005 encoding of a principal value.
#[test]
fn principal_encoding_is_sip005() {
    let issuer = StandardPrincipalData::new(22, [7; 20]).unwrap();
    let name = ContractName::try_from("a-contract".to_string()).unwrap();
    for principal in [
        PrincipalData::Standard(issuer.clone()),
        PrincipalData::Contract(QualifiedContractIdentifier::new(issuer, name)),
    ] {
        let value = clarity_types::Value::Principal(principal.clone());
        assert_eq!(
            encode_principal(&principal).unwrap(),
            value.serialize_to_vec().unwrap()
        );
    }
}

fn pick(rng: &mut StdRng, from: &[u8]) -> u8 {
    *from.choose(rng).unwrap()
}

/// Bytes shaped like a principal, with every field sometimes invalid.
fn principal_candidate(rng: &mut StdRng) -> Vec<u8> {
    let prefix = pick(
        rng,
        &[0x05, 0x05, 0x06, 0x06, 0x06, 0x06, 0x00, 0x04, 0x07, 0xff],
    );
    let version = match rng.gen_range(0..8) {
        0 => pick(rng, &[32, 33, 0x80, 0xff]),
        _ => (rng.gen_range(0..32)) as u8,
    };
    let mut bytes = vec![prefix, version];
    bytes.extend((0..20).map(|_| rng.r#gen::<u8>()));
    if prefix != 0x05 {
        let len = match rng.gen_range(0..4) {
            0 => rng.gen_range(0..45),
            _ => usize::from(pick(rng, &[0, 1, 2, 39, 40, 41, 127, 128, 129, 255])),
        };
        let mut name: Vec<u8> = match rng.gen_range(0..6) {
            0 => b"__transient".to_vec(),
            1 => (0..len)
                .map(|_| pick(rng, b"aZ0-_!^. \x00\x80\xff"))
                .collect(),
            _ => (0..len).map(|_| pick(rng, b"abcXYZ019-_")).collect(),
        };
        if !rng.gen_ratio(1, 6)
            && let Some(first) = name.first_mut()
        {
            *first = pick(rng, b"abcXYZ");
        }
        let len_byte = name.len() as u8;
        bytes.push(match rng.gen_range(0..8) {
            0 => len_byte.wrapping_add(1),
            1 => len_byte.wrapping_sub(1),
            _ => len_byte,
        });
        bytes.extend(name);
    }
    match rng.gen_range(0..8) {
        0 => bytes.truncate(rng.gen_range(0..bytes.len())),
        1 => bytes.extend((0..1 + rng.gen_range(0..3)).map(|_| rng.r#gen::<u8>())),
        _ => {}
    }
    bytes
}

/// Pins how this crate's decoder relates to the consensus decoder of
/// `clarity-types`: it accepts an input exactly when the consensus decoder
/// accepts it and consumes all of it, and the contract name, if any, is at
/// most 40 bytes and is not `__transient`. Both then give the same principal.
#[test]
fn decoder_is_the_consensus_decoder_restricted() {
    let mut inputs: Vec<Vec<u8>> = parse_vectors(PRINCIPAL_VECTORS)
        .into_iter()
        .map(|v| v.input)
        .collect();
    let mut rng = StdRng::seed_from_u64(0x9e37_79b9_7f4a_7c15);
    inputs.extend((0..20_000).map(|_| principal_candidate(&mut rng)));

    // How many inputs fall in each case, so that none goes untested.
    let (mut both, mut neither, mut trailing, mut too_long, mut transient) = (0, 0, 0, 0, 0);
    for input in &inputs {
        let mut rest = input.as_slice();
        let consensus = PrincipalData::consensus_deserialize(&mut rest).ok();
        let expected = consensus.filter(|principal| {
            let name = match principal {
                PrincipalData::Standard(_) => "",
                PrincipalData::Contract(id) => id.name.as_str(),
            };
            if !rest.is_empty() {
                trailing += 1;
            } else if name.len() > 40 {
                too_long += 1;
            } else if name == "__transient" {
                transient += 1;
            } else {
                return true;
            }
            false
        });
        match &expected {
            Some(_) => both += 1,
            None => neither += 1,
        }
        assert_eq!(decode_principal(input).ok(), expected, "{input:02x?}");
    }
    for (case, count) in [
        ("both accept", both),
        ("this decoder rejects", neither),
        ("trailing bytes", trailing),
        ("name over 40 bytes", too_long),
        ("__transient", transient),
    ] {
        assert!(count >= 100, "{case}: only {count} inputs");
    }
}

/// A principal legacy admits but the ABI does not has no encoding.
#[test]
fn encode_rejects_legacy_only_principals() {
    let issuer = StandardPrincipalData::new(22, [7; 20]).unwrap();
    let contract = |name: &str| {
        PrincipalData::Contract(QualifiedContractIdentifier::new(
            issuer.clone(),
            ContractName::try_from(name.to_string()).unwrap(),
        ))
    };
    assert_eq!(
        encode_principal(&contract(&"a".repeat(CONTRACT_NAME_MAX_LEN + 1))),
        Err(PrincipalError::BadName(NameError::TooLong))
    );
    assert_eq!(
        encode_principal(&contract("__transient")),
        Err(PrincipalError::BadName(NameError::BadStart))
    );
}

/// Pins every limit to the table of ABI 9.3.
#[test]
fn limits_v1() {
    const KIB: u32 = 1024;
    const MIB: u32 = 1024 * 1024;
    let Limits {
        call_depth,
        instance_memory,
        table_entries,
        transaction_memory,
        wasm_stack,
        module_size,
        nft_identifier,
        storage_key,
        storage_value,
        arguments,
        result,
        event_data,
        allowances,
        transaction_event_bytes,
    } = Limits::V1;
    assert_eq!(call_depth, 64);
    assert_eq!(instance_memory, 16 * MIB);
    assert_eq!(transaction_memory, 64 * MIB);
    assert_eq!(nft_identifier, MIB);
    assert_eq!(storage_key, KIB);
    assert_eq!(storage_value, MIB);
    assert_eq!(arguments, MIB);
    assert_eq!(result, MIB);
    assert_eq!(event_data, MIB);
    assert_eq!(allowances, 128);
    assert_eq!(table_entries, 16 * KIB);
    assert_eq!(wasm_stack, 64 * KIB);
    assert_eq!(module_size, MIB);
    assert_eq!(transaction_event_bytes, 4 * MIB);

    // What the values must satisfy whatever they become: an instance fits the
    // transaction, a module fits a block (2 MiB), and one event of the
    // largest data fits the transaction's event bytes.
    assert!(instance_memory <= transaction_memory);
    assert!(module_size < 2 * MIB);
    assert!(event_data < transaction_event_bytes);
}

/// Pins every class name: these strings are in receipts.
#[test]
fn error_class_names() {
    let names = [
        "budget-exceeded",
        "memory-exceeded",
        "stack-exceeded",
        "depth-exceeded",
        "events-exceeded",
        "reentrancy",
        "read-only-violation",
        "no-such-function",
        "no-result",
        "bad-host-argument",
        "unbalanced-frame",
        "trap",
        "module-abort",
        "supply-exceeded",
        "legacy-error",
    ];
    let all: Vec<&str> = ErrorClass::ALL.iter().map(|c| c.get_name_str()).collect();
    assert_eq!(all, names);
    for class in ErrorClass::ALL {
        assert_eq!(
            ErrorClass::lookup_by_name(class.get_name_str()),
            Some(*class)
        );
        assert_eq!(class.to_string(), class.get_name_str());
    }
    assert_eq!(ErrorClass::lookup_by_name("Trap"), None);
    assert_eq!(ErrorClass::lookup_by_name(""), None);
}

/// Pins every status code to the lists of ABI 6.2.
#[test]
fn status_codes() {
    fn codes<S: Copy + Into<i32>>(all: &[S]) -> Vec<i32> {
        all.iter().map(|s| (*s).into()).collect()
    }
    assert_eq!(SUCCESS, 0);
    assert_eq!(codes(BlockLookupStatus::ALL), [1]);
    assert_eq!(codes(BlockRewardStatus::ALL), [1, 2]);
    assert_eq!(codes(FtMintStatus::ALL), [1]);
    assert_eq!(codes(FtBurnStatus::ALL), [1]);
    assert_eq!(codes(FtTransferStatus::ALL), [1, 2, 3]);
    assert_eq!(codes(NftMintStatus::ALL), [1]);
    assert_eq!(codes(NftBurnStatus::ALL), [1, 3]);
    assert_eq!(codes(NftTransferStatus::ALL), [1, 2, 3]);
    assert_eq!(codes(StxTransferStatus::ALL), [1, 2, 3, 4]);
    assert_eq!(codes(StxBurnStatus::ALL), [1, 3, 4]);
    assert_eq!(codes(ContractHashStatus::ALL), [1, 2]);
    assert_eq!(codes(Secp256k1RecoverStatus::ALL), [1, 2]);
    assert_eq!(codes(Secp256k1DecompressStatus::ALL), [1]);

    // The same condition has the same code wherever it can occur.
    assert_eq!(FtTransferStatus::InsufficientBalance.code(), 1);
    assert_eq!(StxTransferStatus::InsufficientBalance.code(), 1);
    assert_eq!(StxBurnStatus::InsufficientBalance.code(), 1);
    assert_eq!(FtTransferStatus::SameParty.code(), 2);
    assert_eq!(NftTransferStatus::SameParty.code(), 2);
    assert_eq!(StxTransferStatus::SameParty.code(), 2);
    assert_eq!(FtTransferStatus::ZeroAmount.code(), 3);
    assert_eq!(StxTransferStatus::ZeroAmount.code(), 3);
    assert_eq!(StxBurnStatus::ZeroAmount.code(), 3);
    assert_eq!(NftBurnStatus::NotFound.code(), 3);
    assert_eq!(NftTransferStatus::NotFound.code(), 3);
    assert_eq!(StxTransferStatus::NotSender.code(), 4);
    assert_eq!(StxBurnStatus::NotSender.code(), 4);

    assert_eq!(StxBurnStatus::from_code(3), Some(StxBurnStatus::ZeroAmount));
    assert_eq!(StxBurnStatus::from_code(2), None);
    assert_eq!(StxBurnStatus::from_code(SUCCESS), None);
    assert_eq!(StxBurnStatus::from_code(-1), None);
}

/// The custom-section names of a vector: each a u8 length and its bytes.
fn section_names(mut input: &[u8]) -> Vec<&str> {
    let mut names = Vec::new();
    while let Some((len, rest)) = input.split_first() {
        let (name, rest) = rest.split_at(usize::from(*len));
        names.push(std::str::from_utf8(name).unwrap());
        input = rest;
    }
    names
}

#[test]
fn interface_vectors() {
    let vectors = parse_vectors(INTERFACE_VECTORS);
    for v in &vectors {
        let got = match v.kind {
            "interface" => match Interface::decode(&v.input) {
                Ok(interface) => {
                    assert_eq!(interface.encode(), v.input);
                    "ok"
                }
                Err(e) => e.as_str(),
            },
            "custom-sections" => check_custom_sections(section_names(&v.input))
                .map_or_else(CustomSectionError::as_str, |()| "ok"),
            kind => panic!("unknown kind {kind}"),
        };
        assert_eq!(got, v.expected, "{} {:02x?}", v.kind, v.input);
    }
    let reasons = InterfaceError::ALL.map(InterfaceError::as_str);
    assert_covered(&vectors, "interface", &reasons);
    let reasons = CustomSectionError::ALL.map(CustomSectionError::as_str);
    assert_covered(&vectors, "custom-sections", &reasons);
}

fn name(name: &str) -> Name {
    Name::try_from(name.as_bytes()).unwrap()
}

fn names<const N: usize>(list: [&str; N]) -> Vec<Name> {
    list.map(name).to_vec()
}

fn function(function: &str, kind: FunctionKind) -> Function {
    Function {
        name: name(function),
        kind,
    }
}

/// A built interface has the encoding and the hash of ABI 4.1, field by
/// field.
#[test]
fn interface_encoding_and_hash() {
    use FunctionKind::{Public, ReadOnly};
    let functions = vec![
        function("get-balance", ReadOnly),
        function("mint!", Public),
        function("transfer", Public),
    ];
    let interface = Interface::new(
        ABI_VERSION,
        functions.clone(),
        names(["stx-wrapped", "token"]),
        names(["deed"]),
        names(["burn", "mint", "transfer"]),
    )
    .unwrap();
    assert_eq!(interface.abi_version(), 1);
    assert_eq!(interface.functions(), functions);
    assert_eq!(interface.fts(), names(["stx-wrapped", "token"]));
    assert_eq!(interface.nfts(), names(["deed"]));
    assert_eq!(interface.events(), names(["burn", "mint", "transfer"]));

    let mut expected = vec![0, 0, 0, 1];
    expected.extend(b"\x00\x00\x00\x03\x0bget-balance\x01\x05mint!\x00\x08transfer\x00");
    expected.extend(b"\x00\x00\x00\x02\x0bstx-wrapped\x05token");
    expected.extend(b"\x00\x00\x00\x01\x04deed");
    expected.extend(b"\x00\x00\x00\x03\x04burn\x04mint\x08transfer");
    assert_eq!(interface.encode(), expected);
    assert_eq!(Interface::decode(&expected), Ok(interface.clone()));

    // `sha512/256` of the bytes above, computed independently.
    assert_eq!(
        interface.hash().to_hex(),
        "03d05cd5b2abc2af05aa9e291bcb5313eda014d3db5a98823fc1b75a804e41b0"
    );
    let empty = Interface::new(ABI_VERSION, vec![], vec![], vec![], vec![]).unwrap();
    assert_eq!(
        empty.encode(),
        [0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    );
    assert_eq!(
        empty.hash().to_hex(),
        "d114b7163ce5ea5e147ac5c664bca82afc61c832734a61da3eb4529d24ee67ac"
    );

    assert_eq!(FunctionKind::from_byte(Public.byte()), Some(Public));
    assert_eq!(FunctionKind::from_byte(ReadOnly.byte()), Some(ReadOnly));
    assert_eq!(FunctionKind::from_byte(2), None);
}

/// A list that is not in strictly ascending order makes no interface,
/// whichever list it is.
#[test]
fn interface_lists_must_ascend() {
    use FunctionKind::Public;
    let build = |functions: &[&str], fts: &[&str], nfts: &[&str], events: &[&str]| {
        let list = |list: &[&str]| list.iter().map(|n| name(n)).collect::<Vec<_>>();
        let functions = functions.iter().map(|f| function(f, Public)).collect();
        Interface::new(ABI_VERSION, functions, list(fts), list(nfts), list(events)).map(|_| ())
    };
    assert_eq!(
        build(&["a", "b"], &["a", "b"], &["a", "b"], &["a", "b"]),
        Ok(())
    );
    for (bad, reason) in [
        (["b", "a"], InterfaceError::Unsorted),
        (["a", "a"], InterfaceError::Duplicate),
    ] {
        assert_eq!(build(&bad, &[], &[], &[]), Err(reason));
        assert_eq!(build(&[], &bad, &[], &[]), Err(reason));
        assert_eq!(build(&[], &[], &bad, &[]), Err(reason));
        assert_eq!(build(&[], &[], &[], &bad), Err(reason));
    }
}

/// An interface has exactly one encoding: every generated interface decodes
/// from its encoding, and whatever bytes decode are the encoding of what
/// they decode to.
#[test]
fn interface_encoding_is_unique() {
    let mut rng = StdRng::seed_from_u64(0x1f);
    let pool: Vec<Name> = ["a", "a-b", "aa", "b", "burn", "mint", "transfer", "z!"]
        .map(name)
        .to_vec();
    let mut accepted = 0;
    for _ in 0..2_000 {
        let mut list = || -> Vec<Name> {
            let mut list: Vec<Name> = pool.iter().filter(|_| rng.gen_bool(0.4)).cloned().collect();
            list.sort();
            list
        };
        let (fts, nfts, events) = (list(), list(), list());
        let functions = list()
            .into_iter()
            .map(|name| {
                let kind = FunctionKind::from_byte(rng.gen_range(0..2)).unwrap();
                Function { name, kind }
            })
            .collect();
        let interface = Interface::new(rng.r#gen(), functions, fts, nfts, events).unwrap();
        let bytes = interface.encode();
        assert_eq!(Interface::decode(&bytes), Ok(interface));

        // Mutations of a valid encoding: change, remove or add bytes.
        for _ in 0..10 {
            let mut mutated = bytes.clone();
            let at = rng.gen_range(0..mutated.len());
            match rng.gen_range(0..4) {
                0 => mutated[at] = rng.r#gen(),
                1 => mutated[at] ^= 1 << rng.gen_range(0..8),
                2 => {
                    mutated.remove(at);
                }
                _ => mutated.insert(at, rng.r#gen()),
            }
            if let Ok(interface) = Interface::decode(&mutated) {
                assert_eq!(interface.encode(), mutated);
                accepted += 1;
            }
        }
    }
    // Some mutations are other valid interfaces, so the check above ran.
    assert!(accepted > 100, "{accepted}");
}

/// Pins every rejection reason: these strings are in receipts.
#[test]
fn deploy_rejection_names() {
    let names = [
        "module-size",
        "invalid-wasm",
        "profile",
        "imports",
        "custom-sections",
        "interface",
        "abi-version",
        "exports",
        "engine",
    ];
    assert_eq!(DeployRejection::ALL_NAMES, names);
    for (reason, name) in DeployRejection::ALL.iter().zip(names) {
        assert_eq!(reason.get_name_str(), name);
        assert_eq!(reason.to_string(), name);
        assert_eq!(DeployRejection::lookup_by_name(name), Some(*reason));
    }
    assert_eq!(DeployRejection::lookup_by_name("Engine"), None);
}

/// The import module's name carries the ABI version (ABI 11).
#[test]
fn import_module_names_the_abi_version() {
    assert_eq!(IMPORT_MODULE, format!("stacks-abi-v{ABI_VERSION}"));
}
