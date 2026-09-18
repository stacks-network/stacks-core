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

//! Core value types: [`RecordValue`], [`Record`], [`Counter`], and [`Tag`].

/// A dynamically-typed value that can be attached to a span via [`record!`](crate::record).
#[derive(Debug, Clone)]
pub enum RecordValue {
    U64(u64),
    I64(i64),
    Str(Box<str>),
    Bytes(Box<[u8]>),
}

impl From<u64> for RecordValue {
    #[inline(always)]
    fn from(v: u64) -> Self {
        RecordValue::U64(v)
    }
}
impl From<i64> for RecordValue {
    #[inline(always)]
    fn from(v: i64) -> Self {
        RecordValue::I64(v)
    }
}
impl From<&str> for RecordValue {
    #[inline]
    fn from(v: &str) -> Self {
        RecordValue::Str(v.into())
    }
}
impl From<String> for RecordValue {
    #[inline]
    fn from(v: String) -> Self {
        RecordValue::Str(v.into_boxed_str())
    }
}
impl From<&[u8]> for RecordValue {
    #[inline]
    fn from(v: &[u8]) -> Self {
        RecordValue::Bytes(v.into())
    }
}

impl std::fmt::Display for RecordValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecordValue::U64(v) => write!(f, "{v}"),
            RecordValue::I64(v) => write!(f, "{v}"),
            RecordValue::Str(v) => write!(f, "{v}"),
            RecordValue::Bytes(v) => {
                write!(f, "0x")?;
                for byte in v.iter() {
                    write!(f, "{byte:02x}")?;
                }
                Ok(())
            }
        }
    }
}

/// A per-occurrence key/value record attached to a span via [`record!`](crate::record).
/// Use [`Counter`] for additive metrics.
#[derive(Debug, Clone)]
pub struct Record {
    pub key: &'static str,
    pub value: RecordValue,
}

/// An aggregated counter on a span via [`counter_add!`](crate::counter_add).
/// Same-key counters are summed (saturating).
#[derive(Debug, Clone)]
pub struct Counter {
    pub key: &'static str,
    pub value: u64,
}

/// A `Copy` discriminator for spans sharing the same [`SpanId`](crate::SpanId) (e.g., different
/// transaction indices). Each distinct `(SpanId, Tag)` pair gets its own tree node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tag {
    U64(u64),
    I64(i64),
    Usize(usize),
    Str(&'static str),
}

impl From<u64> for Tag {
    #[inline(always)]
    fn from(v: u64) -> Self {
        Tag::U64(v)
    }
}

impl From<i64> for Tag {
    #[inline(always)]
    fn from(v: i64) -> Self {
        Tag::I64(v)
    }
}

impl From<u32> for Tag {
    #[inline(always)]
    fn from(v: u32) -> Self {
        Tag::U64(v as u64)
    }
}

impl From<i32> for Tag {
    #[inline(always)]
    fn from(v: i32) -> Self {
        Tag::I64(v as i64)
    }
}

impl From<usize> for Tag {
    #[inline(always)]
    fn from(v: usize) -> Self {
        Tag::Usize(v)
    }
}

impl From<&'static str> for Tag {
    #[inline(always)]
    fn from(v: &'static str) -> Self {
        Tag::Str(v)
    }
}

impl From<String> for Tag {
    #[inline]
    fn from(v: String) -> Self {
        Tag::Str(crate::intern_tag_str(v))
    }
}

impl std::fmt::Display for Tag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Tag::U64(v) => write!(f, "{v}"),
            Tag::I64(v) => write!(f, "{v}"),
            Tag::Usize(v) => write!(f, "{v}"),
            Tag::Str(v) => write!(f, "{v}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{RecordValue, Tag};

    #[test]
    fn record_value_conversions_and_display() {
        assert_eq!(RecordValue::from(7u64).to_string(), "7");
        assert_eq!(RecordValue::from(-7i64).to_string(), "-7");
        assert_eq!(RecordValue::from("hello").to_string(), "hello");
        assert_eq!(
            RecordValue::from(String::from("owned")).to_string(),
            "owned"
        );
        assert_eq!(RecordValue::from(&[0xabu8, 0xcd][..]).to_string(), "0xabcd");
    }

    #[test]
    fn tag_conversions_and_display() {
        let tags = [
            Tag::from(7u64),
            Tag::from(7u32),
            Tag::from(-7i64),
            Tag::from(-7i32),
            Tag::from(7usize),
            Tag::from("static-tag"),
        ];

        assert_eq!(tags[0], Tag::U64(7));
        assert_eq!(tags[1], Tag::U64(7));
        assert_eq!(tags[2], Tag::I64(-7));
        assert_eq!(tags[3], Tag::I64(-7));
        assert_eq!(tags[4], Tag::Usize(7));
        assert_eq!(tags[5], Tag::Str("static-tag"));
        assert_eq!(
            tags.iter().map(ToString::to_string).collect::<Vec<_>>(),
            vec!["7", "7", "-7", "-7", "7", "static-tag"]
        );

        let owned = Tag::from(String::from("owned-tag"));
        assert_eq!(owned.to_string(), "owned-tag");
        assert!(matches!(owned, Tag::Str("owned-tag")));
    }
}
