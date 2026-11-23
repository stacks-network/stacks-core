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

use std::collections::HashSet;

#[cfg(target_family = "wasm")]
use wasm_bindgen_test::wasm_bindgen_test as test;

use super::Charge::*;
use super::{Group, HOST_FUNCTIONS, ParamKind, ResultKind, ValType, host_function};

/// Lowercase words of letters and digits joined by one `_` each, starting
/// with a letter.
fn is_name(name: &str) -> bool {
    let is_word = |word: &str| {
        !word.is_empty()
            && word
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    };
    name.starts_with(|c: char| c.is_ascii_lowercase()) && name.split('_').all(is_word)
}

/// The 66 functions of ABI 6.2, group by group, each with its own name.
#[test]
fn table_has_every_function() {
    let groups = [
        (Group::Boundary, 4),
        (Group::Context, 12),
        (Group::BlockData, 13),
        (Group::Storage, 4),
        (Group::Assets, 15),
        (Group::Frames, 2),
        (Group::Calls, 4),
        (Group::Events, 2),
        (Group::Crypto, 10),
    ];
    let expected = groups
        .iter()
        .flat_map(|(group, count)| std::iter::repeat_n(*group, *count));
    assert!(HOST_FUNCTIONS.iter().map(|f| f.group).eq(expected));
    assert_eq!(HOST_FUNCTIONS.len(), 66);

    let mut names = HashSet::new();
    for function in &HOST_FUNCTIONS {
        assert!(is_name(function.name), "{}", function.name);
        assert!(names.insert(function.name), "{}", function.name);
        assert_eq!(host_function(function.name), Some(function));
    }
    assert_eq!(host_function("kv_put"), None);
}

/// The kinds of ABI 6.1 expand to its Wasm types, and its example has the
/// type it gives.
#[test]
fn wasm_types_follow_the_conventions() {
    use ValType::{I32, I64};
    assert_eq!(ParamKind::I32.wasm(), [I32]);
    assert_eq!(ParamKind::U128.wasm(), [I64, I64]);
    assert_eq!(ParamKind::Principal.wasm(), [I32, I32]);
    assert_eq!(ParamKind::Bytes.wasm(), [I32, I32]);
    assert_eq!(ParamKind::FixedBytes(32).wasm(), [I32]);
    assert_eq!(ParamKind::Out(16).wasm(), [I32]);
    assert_eq!(ParamKind::Buf.wasm(), [I32, I32]);

    assert_eq!(ResultKind::None.wasm(), None);
    for result in [
        ResultKind::I32,
        ResultKind::Len,
        ResultKind::Status(&[1]),
        ResultKind::Bool,
    ] {
        assert_eq!(result.wasm(), Some(I32));
    }

    // `(param i64 i64 i32 i32) (result i32)`
    let stx_burn = host_function("stx_burn").unwrap();
    assert_eq!(stx_burn.wasm_params(), [I64, I64, I32, I32]);
    assert_eq!(stx_burn.result.wasm(), Some(I32));

    let call = host_function("call").unwrap();
    assert_eq!(call.wasm_params(), [I32; 10]);
    assert_eq!(call.result, ResultKind::Len);
    assert_eq!(host_function("abort").unwrap().result.wasm(), None);
}

/// Parameters have their own valid names and sizes, and status codes
/// increase from 1.
#[test]
fn signatures_are_well_formed() {
    for function in &HOST_FUNCTIONS {
        let name = function.name;
        let mut names = HashSet::new();
        for param in function.params {
            assert!(is_name(param.name), "{name}");
            assert!(names.insert(param.name), "{name}");
            if let ParamKind::FixedBytes(size) | ParamKind::Out(size) = param.kind {
                assert!(size > 0, "{name}");
            }
        }
        if let ResultKind::Status(codes) = function.result {
            assert!(codes.first().is_some_and(|code| *code > 0), "{name}");
            assert!(codes.is_sorted_by(|a, b| a < b), "{name}");
        }
    }
}

/// Every charge formula keeps the rules of [`super::Charge`].
#[test]
fn charges_are_well_formed() {
    for function in &HOST_FUNCTIONS {
        let name = function.name;
        let charges = function.charges;
        let kind = |param: &str| function.param(param).map(|param| param.kind);

        assert_eq!(charges.first(), Some(&Base), "{name}");
        let mut terms = HashSet::new();
        for charge in charges {
            // A storage access has one term; no other term repeats.
            let term = match *charge {
                Read(_) => Read(0),
                Write(_) => Write(0),
                other => other,
            };
            assert!(terms.insert(term), "{name}");
            let valid = match *charge {
                Base => true,
                Input(param) => {
                    matches!(kind(param), Some(ParamKind::Bytes | ParamKind::Principal))
                }
                Output(param) => matches!(kind(param), Some(ParamKind::Buf | ParamKind::I32)),
                Read(count) | Write(count) => count > 0,
                Stored(param) => {
                    let accessed = charges.iter().any(|c| matches!(c, Read(_) | Write(_)));
                    accessed && matches!(kind(param), Some(ParamKind::Bytes | ParamKind::Buf))
                }
            };
            assert!(valid, "{name}: {charge:?}");
        }

        // Every input and output of variable length is charged per byte.
        for param in function.params {
            let term = match param.kind {
                ParamKind::Bytes | ParamKind::Principal => Input(param.name),
                ParamKind::Buf => Output(param.name),
                _ => continue,
            };
            assert!(charges.contains(&term), "{name}: {}", param.name);
        }
    }
}
