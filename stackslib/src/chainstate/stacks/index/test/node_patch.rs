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

//! MARF tests related to [`TrieNodePatch`] node type.

use std::io::Cursor;

use super::*;
use crate::codec::{Error as codec_error, StacksMessageCodec};

#[test]
fn trie_node_patch_try_from_nodetype_returns_none_when_no_diffs() {
    let node = TrieNodeType::Node4(TrieNode4::new(&[1]));

    let old_node_ptr = TriePtr::default();
    let old_node = &node;
    let new_node = &node;
    let result = TrieNodePatch::try_from_nodetype(old_node_ptr, old_node, new_node);

    assert!(
        result.is_none(),
        "None because the computed patch has no diffs"
    );
}

#[test]
fn trie_node_patch_try_from_patch_returns_none_when_no_diffs() {
    let old_patch_ptr = TriePtr::new(TrieNodeID::Node4 as u8, 0, 0);
    let old_patch = TrieNodePatch {
        ptr: old_patch_ptr.clone(),
        ptr_diff: vec![],
    };
    let new_node = TrieNodeType::Node4(TrieNode4::new(&[1]));
    let result = TrieNodePatch::try_from_patch(old_patch_ptr, &old_patch, &new_node);

    assert!(
        result.is_none(),
        "None because the computed patch has no diffs"
    );
}

#[test]
fn trie_node_patch_serialize_ok() {
    let patch_node = TrieNodePatch {
        ptr: TriePtr::new(1, 10, 0),
        ptr_diff: vec![TriePtr::new(1, 20, 0).clone(); 1],
    };

    let mut buffer = Cursor::new(Vec::new());
    patch_node
        .consensus_serialize(&mut buffer)
        .expect("serialization should be ok");

    // To fit in 1 byte, diff count is serialized 0-based (where 0 => 1 and 255 => 256)
    let diff_count = 0u8;
    assert_eq!(
        vec![6, 65, 10, 0, 0, 0, 0, diff_count, 65, 20, 0, 0, 0, 0],
        buffer.into_inner(),
    );
}

#[test]
fn trie_node_patch_serialize_fails_with_ptr_diffs_len_0() {
    let patch_node = TrieNodePatch {
        ptr: TriePtr::default(),
        ptr_diff: vec![],
    };

    let mut buffer = Cursor::new(Vec::new());
    let error = patch_node
        .consensus_serialize(&mut buffer)
        .expect_err("serialization should fail");

    assert!(
        matches!(&error, codec_error::SerializeError(msg) if msg.contains("len 0")),
        "instead got: {error}"
    );
}

#[test]
fn trie_node_patch_serialize_ok_with_ptr_diffs_len_256() {
    let patch_node = TrieNodePatch {
        ptr: TriePtr::default(),
        ptr_diff: vec![TriePtr::default(); 256],
    };

    let mut buffer = Cursor::new(Vec::new());
    let result = patch_node.consensus_serialize(&mut buffer);
    assert!(
        result.is_ok(),
        "Got Error: {}",
        result.unwrap_err().to_string()
    );
}

#[test]
fn trie_node_patch_serialize_fails_with_ptr_diffs_len_257() {
    let patch_node = TrieNodePatch {
        ptr: TriePtr::default(),
        ptr_diff: vec![TriePtr::default(); 257],
    };

    let mut buffer = Cursor::new(Vec::new());
    let error = patch_node
        .consensus_serialize(&mut buffer)
        .expect_err("serialization should fail");

    assert!(
        matches!(&error, codec_error::SerializeError(msg) if msg.contains("len 257")),
        "instead got: {error}"
    );
}

#[test]
fn trie_node_patch_deserialize_ok_with_ptr_diffs_len_1() {
    // To fit in 1 byte, diff count is serialized 0-based (where 0 => 1 and 255 => 256)
    let diff_count = 0u8;
    let mut buffer = Cursor::new(vec![6, 65, 10, 0, 0, 0, 0, diff_count, 65, 20, 0, 0, 0, 0]);

    let patch_node =
        TrieNodePatch::consensus_deserialize(&mut buffer).expect("deserialization should be ok");

    let expected = TrieNodePatch {
        ptr: TriePtr::new(1, 10, 0),
        ptr_diff: vec![TriePtr::new(1, 20, 0); 1],
    };
    assert_eq!(expected, patch_node);
}

#[test]
fn trie_node_patch_u64_ptr_roundtrip_ok() {
    let patch_node = TrieNodePatch {
        ptr: TriePtr::new(1, 10, u64::from(u32::MAX) + 7),
        ptr_diff: vec![TriePtr::new(1, 20, u64::from(u32::MAX) + 11)],
    };

    let mut buffer = Cursor::new(Vec::new());
    patch_node
        .consensus_serialize(&mut buffer)
        .expect("u64 ptr serialization should be ok");

    let decoded = TrieNodePatch::consensus_deserialize(&mut Cursor::new(buffer.into_inner()))
        .expect("u64 ptr deserialization should be ok");
    assert_eq!(patch_node, decoded);
}

#[test]
fn trie_node_patch_apply_node4_preserves_inline_payload_pointer_identity() {
    let mut old_node = TrieNode4::new(&[]);
    let mut inline_with_payload = TriePtr::new(TrieNodeID::Node16 as u8, 0x10, 1234);
    inline_with_payload.back_block = 55;
    assert!(old_node.insert(&inline_with_payload));

    let patch = TrieNodePatch {
        ptr: TriePtr::new_backptr(TrieNodeID::Node4 as u8, 0x00, 1, 7),
        ptr_diff: vec![TriePtr::new(TrieNodeID::Node16 as u8, 0x20, 2345)],
    };

    let patched = patch
        .apply_node4(old_node, 8, 99)
        .expect("patch application should succeed");
    let patched_ptr = patched
        .walk(0x10)
        .expect("inline child with payload should still exist");
    assert!(is_backptr(patched_ptr.id()));
    assert_eq!(patched_ptr.back_block(), 55);
}

#[test]
fn trie_node_patch_u64_ptr_serialize_fails_with_ptr_diffs_len_0() {
    let patch_node = TrieNodePatch {
        ptr: TriePtr::new(TrieNodeID::Node4 as u8, 1, 77),
        ptr_diff: vec![],
    };
    let mut buffer = Cursor::new(Vec::new());
    let error = patch_node
        .consensus_serialize(&mut buffer)
        .expect_err("u64 ptr serialization should fail");
    assert!(
        matches!(&error, codec_error::SerializeError(msg) if msg.contains("len 0")),
        "instead got: {error}"
    );
}

#[test]
fn trie_node_patch_u64_ptr_serialize_fails_with_ptr_diffs_len_257() {
    let patch_node = TrieNodePatch {
        ptr: TriePtr::new(TrieNodeID::Node4 as u8, 1, 77),
        ptr_diff: vec![TriePtr::new(TrieNodeID::Node4 as u8, 2, 88); 257],
    };
    let mut buffer = Cursor::new(Vec::new());
    let error = patch_node
        .consensus_serialize(&mut buffer)
        .expect_err("u64 ptr serialization should fail");
    assert!(
        matches!(&error, codec_error::SerializeError(msg) if msg.contains("len 257")),
        "instead got: {error}"
    );
}

#[test]
fn trie_node_patch_u64_ptr_deserialize_fails_on_truncated_payload() {
    let patch_node = TrieNodePatch {
        ptr: TriePtr::new_backptr(TrieNodeID::Node4 as u8, 0x01, u64::from(u32::MAX) + 2, 5),
        ptr_diff: vec![
            TriePtr::new(TrieNodeID::Node16 as u8, 0x02, u64::from(u32::MAX) + 3),
            TriePtr::new_backptr(TrieNodeID::Node16 as u8, 0x03, u64::from(u32::MAX) + 4, 7),
        ],
    };

    let mut buffer = Cursor::new(Vec::new());
    patch_node
        .consensus_serialize(&mut buffer)
        .expect("u64 ptr serialization should be ok");
    let mut payload = buffer.into_inner();
    payload.pop();

    let error = TrieNodePatch::consensus_deserialize(&mut Cursor::new(payload))
        .expect_err("u64 ptr deserialization should fail on truncated payload");
    assert!(
        error.to_string().contains("fill whole buffer"),
        "instead got: {error}"
    );
}

#[test]
fn trie_node_patch_u64_ptr_deserialize_fails_on_malformed_payload() {
    let patch_node = TrieNodePatch {
        ptr: TriePtr::new(TrieNodeID::Node4 as u8, 1, 2),
        ptr_diff: vec![TriePtr::new(TrieNodeID::Node16 as u8, 2, 3)],
    };
    let mut buffer = Cursor::new(Vec::new());
    patch_node
        .consensus_serialize(&mut buffer)
        .expect("u64 ptr serialization should be ok");
    let mut payload = buffer.into_inner();

    // Corrupt the patch node marker.
    payload[0] = TrieNodeID::Leaf as u8;

    let error = TrieNodePatch::consensus_deserialize(&mut Cursor::new(payload))
        .expect_err("u64 ptr deserialization should fail on malformed payload");
    assert!(
        error
            .to_string()
            .contains("Did not read a TrieNodeID::Patch"),
        "instead got: {error}"
    );
}

#[test]
fn trie_node_patch_u64_ptr_roundtrip_mixed_backptrs() {
    let patch_node = TrieNodePatch {
        ptr: TriePtr::new_backptr(TrieNodeID::Node16 as u8, 0x10, u64::from(u32::MAX) + 55, 42),
        ptr_diff: vec![
            TriePtr::new(TrieNodeID::Node4 as u8, 0x11, u64::from(u32::MAX) + 56),
            TriePtr::new_backptr(TrieNodeID::Node48 as u8, 0x12, u64::from(u32::MAX) + 57, 43),
            TriePtr::new(TrieNodeID::Node256 as u8, 0x13, 19),
        ],
    };

    let mut buffer = Cursor::new(Vec::new());
    patch_node
        .consensus_serialize(&mut buffer)
        .expect("u64 ptr mixed serialization should be ok");
    let decoded = TrieNodePatch::consensus_deserialize(&mut Cursor::new(buffer.into_inner()))
        .expect("u64 ptr mixed deserialization should be ok");
    assert_eq!(patch_node, decoded);
}

/// [`TrieNodePatch::make_ptr_diff`] in the following scenario:
///
/// ## Input
/// - `old_ptrs` is empty
/// - `new_ptrs` contains a single empty pointer
///
/// ## Expected behavior
/// - No differences are produced
#[test]
fn trie_node_patch_make_ptr_diff_case1() {
    let old_node_ptr = TriePtr::new_backptr(TrieNodeID::Patch as u8, 0x00, 0, 1);
    let old_ptrs = [];
    let new_ptrs = [TriePtr::new(TrieNodeID::Empty as u8, 0x00, 0)];

    let diff = TrieNodePatch::make_ptr_diff_for_test(&old_node_ptr, &old_ptrs, &new_ptrs);
    assert_eq!(0, diff.len());
}

/// [`TrieNodePatch::make_ptr_diff`] in the following scenario:
///
/// ## Input
/// - `old_ptrs` is empty
/// - `new_ptrs` contains:
///   - one normal (non-backpointer) node
///   - one backpointer node
///
/// ## Expected behavior
/// - Both pointers are reported as differences
#[test]
fn trie_node_patch_make_ptr_diff_case2() {
    let old_node_ptr = TriePtr::new_backptr(TrieNodeID::Patch as u8, 0x00, 0, 1);
    let old_ptrs = [];
    let new_ptrs = [
        TriePtr::new(TrieNodeID::Node4 as u8, 0x00, 0),
        TriePtr::new_backptr(TrieNodeID::Node4 as u8, 0x01, 0, 1),
    ];

    let diff = TrieNodePatch::make_ptr_diff_for_test(&old_node_ptr, &old_ptrs, &new_ptrs);
    assert_eq!(2, diff.len());
    assert_eq!(TriePtr::new(TrieNodeID::Node4 as u8, 0x00, 0), diff[0]);
    assert_eq!(
        TriePtr::new_backptr(TrieNodeID::Node4 as u8, 0x01, 0, 1),
        diff[1]
    );
}

/// [`TrieNodePatch::make_ptr_diff`] in the following scenario:
///
/// ## Input
/// - `old_ptr` is **not** a backpointer
/// - `new_ptr` **is** a backpointer
/// - `new_ptr.back_block` matches `old_node_ptr.back_block`
/// - After normalization, `new_ptr` equals `old_ptr`
///
/// ## Expected behavior
/// - No differences are produced
#[test]
fn trie_node_patch_make_ptr_diff_case3() {
    let old_node_ptr = TriePtr::new_backptr(TrieNodeID::Patch as u8, 0x00, 0, 1);
    let old_ptrs = [TriePtr::new(TrieNodeID::Node4 as u8, 0x00, 0)];
    let new_ptrs = [TriePtr::new_backptr(TrieNodeID::Node4 as u8, 0x00, 0, 1)];

    let diff = TrieNodePatch::make_ptr_diff_for_test(&old_node_ptr, &old_ptrs, &new_ptrs);
    assert_eq!(0, diff.len());
}

/// [`TrieNodePatch::make_ptr_diff`] in the following scenario:
///
/// ## Input
/// - `old_ptr` is **not** a backpointer
/// - `new_ptr` **is** a backpointer
/// - `new_ptr.back_block` matches `old_node_ptr.back_block`
/// - After normalization, `new_ptr` does **not** equal `old_ptr`
///
/// ## Expected behavior
/// - The new pointer is reported as a difference
#[test]
fn trie_node_patch_make_ptr_diff_case4() {
    let old_node_ptr = TriePtr::new_backptr(TrieNodeID::Patch as u8, 0x00, 0, 1);
    let old_ptrs = [TriePtr::new(TrieNodeID::Node4 as u8, 0x00, 0)];
    let new_ptrs = [TriePtr::new_backptr(TrieNodeID::Node4 as u8, 0x00, 100, 1)];

    let diff = TrieNodePatch::make_ptr_diff_for_test(&old_node_ptr, &old_ptrs, &new_ptrs);
    assert_eq!(1, diff.len());
    assert_eq!(
        TriePtr::new_backptr(TrieNodeID::Node4 as u8, 0x00, 100, 1),
        diff[0]
    );
}

/// [`TrieNodePatch::make_ptr_diff`] in the following scenario:
///
/// ## Input
/// - `old_ptr` is **not** a backpointer
/// - `new_ptr` **is** a backpointer
/// - `new_ptr.back_block` does **not** match `old_node_ptr.back_block`
/// - `new_ptr` does **not** equal `old_ptr`
///
/// ## Expected behavior
/// - The new pointer is reported as a difference
#[test]
fn trie_node_patch_make_ptr_diff_case5() {
    let old_node_ptr = TriePtr::new_backptr(TrieNodeID::Patch as u8, 0x00, 0, 1);
    let old_ptrs = [TriePtr::new(TrieNodeID::Node4 as u8, 0x00, 0)];
    let new_ptrs = [TriePtr::new_backptr(
        TrieNodeID::Node4 as u8,
        0x00,
        100,
        100,
    )];

    let diff = TrieNodePatch::make_ptr_diff_for_test(&old_node_ptr, &old_ptrs, &new_ptrs);
    assert_eq!(1, diff.len());
    assert_eq!(
        TriePtr::new_backptr(TrieNodeID::Node4 as u8, 0x00, 100, 100),
        diff[0]
    );
}

/// [`TrieNodePatch::make_ptr_diff`] in the following scenario:
///
/// ## Input
/// - `old_ptr` **is** a backpointer
/// - `new_ptr` **is** a backpointer
/// - `new_ptr` equals `old_ptr`
///
/// ## Expected behavior
/// - No differences are produced
#[test]
fn trie_node_patch_make_ptr_diff_case6() {
    let old_node_ptr = TriePtr::new_backptr(TrieNodeID::Patch as u8, 0x00, 0, 1);
    let old_ptrs = [TriePtr::new_backptr(TrieNodeID::Node4 as u8, 0x00, 0x00, 2)];
    let new_ptrs = [TriePtr::new_backptr(TrieNodeID::Node4 as u8, 0x00, 0x00, 2)];

    let diff = TrieNodePatch::make_ptr_diff_for_test(&old_node_ptr, &old_ptrs, &new_ptrs);
    assert_eq!(0, diff.len());
}

/// [`TrieNodePatch::make_ptr_diff`] in the following scenario:
///
/// ## Input
/// - `old_ptr` is **not** a backpointer
/// - `new_ptr` is **not** a backpointer
/// - `new_ptr` equals `old_ptr`
///
/// ## Expected behavior
/// - The pointer is reported as a difference
#[test]
fn trie_node_patch_make_ptr_diff_case7() {
    let old_node_ptr = TriePtr::new_backptr(TrieNodeID::Patch as u8, 0x00, 0, 1);
    let old_ptrs = [TriePtr::new(TrieNodeID::Node4 as u8, 0x00, 0x00)];
    let new_ptrs = [TriePtr::new(TrieNodeID::Node4 as u8, 0x00, 0x00)];

    let diff = TrieNodePatch::make_ptr_diff_for_test(&old_node_ptr, &old_ptrs, &new_ptrs);
    assert_eq!(1, diff.len());
    assert_eq!(TriePtr::new(TrieNodeID::Node4 as u8, 0x00, 0x00), diff[0]);
}

/// [`TrieNodePatch::make_ptr_diff`] in the following scenario:
///
/// ## Input
/// - `old_ptrs` contains a non-empty pointer
/// - `new_ptrs` contains a single empty pointer
///
/// ## Expected behavior
/// - No differences are produced
///
/// ## Note
/// In real scenarios, a Trie node with only empty pointers won't exist,
/// as nodes are created only when at least one child is present.
/// This test exists purely to exercise `make_ptr_diff` with such an input,
/// ensuring all code paths are covered and behavior is well-defined.
#[test]
fn trie_node_patch_make_ptr_diff_case8() {
    let old_node_ptr = TriePtr::new_backptr(TrieNodeID::Patch as u8, 0x00, 0, 1);
    let old_ptrs = [TriePtr::new(TrieNodeID::Node4 as u8, 0x00, 0)];
    let new_ptrs = [TriePtr::new(TrieNodeID::Empty as u8, 0x00, 0)];

    let diff = TrieNodePatch::make_ptr_diff_for_test(&old_node_ptr, &old_ptrs, &new_ptrs);
    assert_eq!(0, diff.len());
}

/// [`TrieNodePatch::make_ptr_diff`] in the following scenario:
///
/// ## Input
/// - `old_ptr` **is** a backpointer
/// - `new_ptr` is **not** a backpointer
/// - Both pointers refer to the same logical node
///
/// ## Expected behavior
/// - The new pointer is reported as a difference
#[test]
fn trie_node_patch_make_ptr_diff_case9() {
    let old_node_ptr = TriePtr::new_backptr(TrieNodeID::Patch as u8, 0x00, 0, 1);
    let old_ptrs = [TriePtr::new_backptr(TrieNodeID::Node4 as u8, 0x00, 42, 2)];
    let new_ptrs = [TriePtr::new(TrieNodeID::Node4 as u8, 0x00, 42)];

    let diff = TrieNodePatch::make_ptr_diff_for_test(&old_node_ptr, &old_ptrs, &new_ptrs);
    assert_eq!(1, diff.len());
    assert_eq!(TriePtr::new(TrieNodeID::Node4 as u8, 0x00, 42), diff[0]);
}

/// [`TrieNodePatch::make_ptr_diff`] in the following scenario:
///
/// ## Input
/// - `old_ptr` **is** a backpointer
/// - `new_ptr` is **not** a backpointer
/// - `new_ptr` does **not** equal `old_ptr`
///
/// ## Expected behavior
/// - The new pointer is reported as a difference
#[test]
fn trie_node_patch_make_ptr_diff_case10() {
    let old_node_ptr = TriePtr::new_backptr(TrieNodeID::Patch as u8, 0x00, 0, 1);
    let old_ptrs = [TriePtr::new_backptr(TrieNodeID::Node4 as u8, 0x00, 10, 2)];
    let new_ptrs = [TriePtr::new(TrieNodeID::Node4 as u8, 0x00, 99)];

    let diff = TrieNodePatch::make_ptr_diff_for_test(&old_node_ptr, &old_ptrs, &new_ptrs);
    assert_eq!(1, diff.len());
    assert_eq!(TriePtr::new(TrieNodeID::Node4 as u8, 0x00, 99), diff[0]);
}

/// [`TrieNodePatch::make_ptr_diff`] in the following scenario:
///
/// ## Input
/// - `old_ptr` **is** a backpointer
/// - `new_ptr` **is** a backpointer
/// - `new_ptr.back_block` matches `old_node_ptr.back_block`
/// - `new_ptr` does **not** equal `old_ptr`
///
/// ## Expected behavior
/// - The new pointer is reported as a difference
#[test]
fn trie_node_patch_make_ptr_diff_case11() {
    let old_node_ptr = TriePtr::new_backptr(TrieNodeID::Patch as u8, 0x00, 0, 1);
    let old_ptrs = [TriePtr::new_backptr(TrieNodeID::Node4 as u8, 0x00, 10, 1)];
    let new_ptrs = [TriePtr::new_backptr(TrieNodeID::Node4 as u8, 0x00, 20, 1)];

    let diff = TrieNodePatch::make_ptr_diff_for_test(&old_node_ptr, &old_ptrs, &new_ptrs);
    assert_eq!(1, diff.len());
    assert_eq!(
        TriePtr::new_backptr(TrieNodeID::Node4 as u8, 0x00, 20, 1),
        diff[0]
    );
}

/// [`TrieNodePatch::make_ptr_diff`] in the following scenario:
///
/// ## Input
/// - `old_ptrs` contains multiple pointers with the same `chr`
/// - The last pointer with that `chr` overwrites the previous one
/// - `new_ptr` matches the last `old_ptr`
///
/// ## Expected behavior
/// - No differences are produced
///
/// ## Note
/// In real scenarios, a Trie node has at most one pointer per `chr` value.
/// This test exists purely to exercise `make_ptr_diff` with such an input,
/// ensuring all code paths are covered and behavior is well-defined.
#[test]
fn trie_node_patch_make_ptr_diff_case12() {
    let old_node_ptr = TriePtr::new_backptr(TrieNodeID::Patch as u8, 0x00, 0, 1);
    let old_ptrs = [
        TriePtr::new(TrieNodeID::Node4 as u8, 0x01, 10),
        TriePtr::new(TrieNodeID::Node4 as u8, 0x01, 20),
    ];
    let new_ptrs = [TriePtr::new(TrieNodeID::Node4 as u8, 0x01, 20)];

    let diff = TrieNodePatch::make_ptr_diff_for_test(&old_node_ptr, &old_ptrs, &new_ptrs);
    assert_eq!(1, diff.len());
    assert_eq!(TriePtr::new(TrieNodeID::Node4 as u8, 0x01, 20), diff[0]);
}

/// Aggregated test of [`TrieNodePatch::make_ptr_diff`] combining all singular scenarios.
///
/// ## Input
/// - `old_ptrs` contains a mix of:
///   - non-backpointers
///   - backpointers
///   - duplicate `chr` entries (last one wins)
/// - `new_ptrs` contains a mix of:
///   - empty pointers
///   - normalized backpointers
///   - mismatching backpointers
///   - matching and non-matching non-backpointers
///
/// ## Expected behavior
/// - Only pointers that semantically differ from their corresponding old pointers
///   are included in the diff
#[test]
fn trie_node_patch_make_ptr_diff_all_in_one() {
    let old_node_ptr = TriePtr::new_backptr(TrieNodeID::Patch as u8, 0x00, 0, 1);

    let old_ptrs = [
        // Case 3 / 4 / 5
        TriePtr::new(TrieNodeID::Node4 as u8, 0x00, 0),
        // Case 6 / 9 / 10
        TriePtr::new_backptr(TrieNodeID::Node4 as u8, 0x01, 10, 2),
        // Case 7
        TriePtr::new(TrieNodeID::Node4 as u8, 0x02, 20),
        // Case 12: duplicate chr, first (overwritten)
        TriePtr::new(TrieNodeID::Node4 as u8, 0x03, 30),
        // Case 12: duplicate chr, second (effective)
        TriePtr::new(TrieNodeID::Node4 as u8, 0x03, 40),
    ];

    let new_ptrs = [
        // Case 1 / 8: empty pointer (ignored)
        TriePtr::new(TrieNodeID::Empty as u8, 0xFF, 0),
        // Case 3: normalized backptr equals old_ptr (no diff)
        TriePtr::new_backptr(TrieNodeID::Node4 as u8, 0x00, 0, 1),
        // Case 4: normalized backptr != old_ptr (diff)
        TriePtr::new_backptr(TrieNodeID::Node4 as u8, 0x00, 100, 1),
        // Case 9: old backptr, new non-backptr, same target (diff)
        TriePtr::new(TrieNodeID::Node4 as u8, 0x01, 10),
        // Case 10: old backptr, new non-backptr, different target (diff)
        TriePtr::new(TrieNodeID::Node4 as u8, 0x01, 99),
        // Case 7: both non-backptr equal (diff)
        TriePtr::new(TrieNodeID::Node4 as u8, 0x02, 20),
        // Case 11: both backptr, unequal, same back_block (diff)
        TriePtr::new_backptr(TrieNodeID::Node4 as u8, 0x02, 200, 1),
        // Case 12: duplicate chr, matches last old_ptr (diff)
        TriePtr::new(TrieNodeID::Node4 as u8, 0x03, 40),
        // Case 2: new_ptr with no corresponding old_ptr (diff)
        TriePtr::new_backptr(TrieNodeID::Node4 as u8, 0x04, 0, 1),
    ];

    let diff = TrieNodePatch::make_ptr_diff_for_test(&old_node_ptr, &old_ptrs, &new_ptrs);

    let expected = vec![
        // Case 4
        TriePtr::new_backptr(TrieNodeID::Node4 as u8, 0x00, 100, 1),
        // Case 9
        TriePtr::new(TrieNodeID::Node4 as u8, 0x01, 10),
        // Case 10
        TriePtr::new(TrieNodeID::Node4 as u8, 0x01, 99),
        // Case 7
        TriePtr::new(TrieNodeID::Node4 as u8, 0x02, 20),
        // Case 11
        TriePtr::new_backptr(TrieNodeID::Node4 as u8, 0x02, 200, 1),
        // Case 12
        TriePtr::new(TrieNodeID::Node4 as u8, 0x03, 40),
        // Case 2
        TriePtr::new_backptr(TrieNodeID::Node4 as u8, 0x04, 0, 1),
    ];

    assert_eq!(diff, expected);
}
