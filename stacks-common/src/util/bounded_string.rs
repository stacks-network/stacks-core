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

use std::fmt;
use std::fmt::Write as _;

/// A `fmt::Write` sink with a byte budget. Once the budget is exhausted it
/// returns `fmt::Error`, which aborts the formatting traversal, so at most
/// O(budget) output is rendered even when the full rendering would be huge.
struct BoundedWriter<'a> {
    buf: &'a mut String,
    remaining: usize,
    truncated: bool,
}

impl fmt::Write for BoundedWriter<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        if s.len() <= self.remaining {
            self.buf.push_str(s);
            self.remaining -= s.len();
            Ok(())
        } else {
            let end = (0..=self.remaining)
                .rev()
                .find(|&i| s.is_char_boundary(i))
                .unwrap_or(0);
            self.buf.push_str(&s[..end]);
            self.remaining = 0;
            self.truncated = true;
            Err(fmt::Error)
        }
    }
}

/// Render `args` into at most `max_len` bytes — marker included — without
/// ever building the full rendering first. When the rendering is clipped,
/// the tail is replaced with `...` so the bound still holds.
fn render_bounded(args: fmt::Arguments, max_len: usize) -> String {
    let mut buf = String::new();
    let mut writer = BoundedWriter {
        buf: &mut buf,
        remaining: max_len,
        truncated: false,
    };
    // An `Err` here means the byte budget ran out, not a formatting failure.
    let _ = writer.write_fmt(args);
    if writer.truncated {
        let mut end = max_len.saturating_sub(3).min(buf.len());
        while !buf.is_char_boundary(end) {
            end -= 1;
        }
        buf.truncate(end);
        buf.push_str(&"..."[..max_len.min(3)]);
    }
    buf
}

/// A string lossily clamped to `MAX_LEN` bytes at construction.
/// The constructors render through a byte-budgeted writer that aborts the
/// traversal once the budget is spent. Only output is metered: a `Display`
/// impl that builds its own intermediates is not.
#[derive(Clone, PartialEq, Eq)]
pub struct BoundedString<const MAX_LEN: usize>(String);

/// Error messages are rendered eagerly by error constructors, so the bound
/// must be applied at construction.
pub const MAX_ERROR_MESSAGE_LEN: usize = 4096;

/// A rendered human-readable error message.
pub type BoundedErrorString = BoundedString<MAX_ERROR_MESSAGE_LEN>;

// Transparent, so replacing a `String` field with a `BoundedString` doesn't
// change `Debug` output (e.g. snapshot tests).
impl<const MAX_LEN: usize> fmt::Debug for BoundedString<MAX_LEN> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<const MAX_LEN: usize> BoundedString<MAX_LEN> {
    /// Render pre-built format arguments, bounded as described on
    /// [`bounded_format!`], which expands to this.
    pub fn from_args(args: fmt::Arguments) -> Self {
        Self(render_bounded(args, MAX_LEN))
    }

    /// Render `value`'s `Display` form, bounded like [`Self::from_args`].
    pub fn from_display(value: &dyn fmt::Display) -> Self {
        Self::from_args(format_args!("{value}"))
    }

    /// `Debug`-rendering twin of [`Self::from_display`].
    pub fn from_debug(value: &dyn fmt::Debug) -> Self {
        Self::from_args(format_args!("{value:?}"))
    }
}

/// The bounded `format!`: renders at most `MAX_LEN` bytes into a
/// [`BoundedString`], aborting the traversal once the budget is spent
/// (only output is metered, see [`BoundedString`]). The bound is inferred
/// from the sink type (usually [`BoundedErrorString`]).
#[macro_export]
macro_rules! bounded_format {
    ($($arg:tt)*) => {
        $crate::util::bounded_string::BoundedString::from_args(::core::format_args!($($arg)*))
    };
}

// Unlike `From<String>`, this can't hide an unbounded render at the call
// site: a `'static` str is a constant, never rendered runtime data.
impl<const MAX_LEN: usize> From<&'static str> for BoundedString<MAX_LEN> {
    fn from(value: &'static str) -> Self {
        Self::from_display(&value)
    }
}

impl<const MAX_LEN: usize> From<BoundedString<MAX_LEN>> for String {
    fn from(bounded: BoundedString<MAX_LEN>) -> String {
        bounded.0
    }
}

impl<const MAX_LEN: usize> std::ops::Deref for BoundedString<MAX_LEN> {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl<const MAX_LEN: usize> fmt::Display for BoundedString<MAX_LEN> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<const MAX_LEN: usize> PartialEq<str> for BoundedString<MAX_LEN> {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl<const MAX_LEN: usize> PartialEq<&str> for BoundedString<MAX_LEN> {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl<const MAX_LEN: usize> PartialEq<BoundedString<MAX_LEN>> for str {
    fn eq(&self, other: &BoundedString<MAX_LEN>) -> bool {
        self == other.0
    }
}

impl<const MAX_LEN: usize> PartialEq<BoundedString<MAX_LEN>> for &str {
    fn eq(&self, other: &BoundedString<MAX_LEN>) -> bool {
        *self == other.0
    }
}

impl<const MAX_LEN: usize> PartialEq<String> for BoundedString<MAX_LEN> {
    fn eq(&self, other: &String) -> bool {
        &self.0 == other
    }
}

impl<const MAX_LEN: usize> PartialEq<BoundedString<MAX_LEN>> for String {
    fn eq(&self, other: &BoundedString<MAX_LEN>) -> bool {
        self == &other.0
    }
}

/// Serializes as a plain string.
impl<const MAX_LEN: usize> serde::Serialize for BoundedString<MAX_LEN> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

/// Deserializes from a plain string, clamping over-long input. Parsing
/// never fails on length. The visitor clamps straight from the
/// deserializer's borrowed view of the input, so an over-long string is
/// never copied in full — though the format parser itself still scans the
/// whole token before handing it over; only transport-level limits (e.g.
/// the HTTP body size cap) bound that.
impl<'de, const MAX_LEN: usize> serde::Deserialize<'de> for BoundedString<MAX_LEN> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ClampVisitor<const MAX_LEN: usize>;

        impl<const MAX_LEN: usize> serde::de::Visitor<'_> for ClampVisitor<MAX_LEN> {
            type Value = BoundedString<MAX_LEN>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "a string (clamped to {MAX_LEN} bytes)")
            }

            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Self::Value, E> {
                if s.len() <= MAX_LEN {
                    Ok(BoundedString(s.to_owned()))
                } else {
                    Ok(BoundedString::from_display(&s))
                }
            }

            // Reuses the allocation when the deserializer already owns the
            // string (e.g. `serde_json::from_value`).
            fn visit_string<E: serde::de::Error>(self, s: String) -> Result<Self::Value, E> {
                if s.len() <= MAX_LEN {
                    Ok(BoundedString(s))
                } else {
                    Ok(BoundedString::from_display(&s))
                }
            }
        }

        deserializer.deserialize_str(ClampVisitor)
    }
}

#[cfg(test)]
mod bounded_string_test {
    use std::cell::Cell;

    use super::*;

    type Bounded16 = BoundedString<16>;

    #[test]
    fn from_display_clamps() {
        let cases: [(&str, bool); 4] = [
            ("abc", false),
            ("aaaaaaaaaaaaaaaa", false), // exactly MAX_LEN
            ("aaaaaaaaaaaaaaaaa", true), // one over
            ("€€€€€€", true),            // multibyte boundary
        ];
        for (input, expect_truncated) in cases {
            let bounded = Bounded16::from_display(&input);
            if expect_truncated {
                assert!(bounded.ends_with("..."), "{input}");
                assert!(bounded.len() <= 16, "{input}");
                let body = &bounded[..bounded.len() - 3];
                assert!(input.starts_with(body), "{input}");
            } else {
                assert_eq!(&*bounded, input);
            }
        }
    }

    /// Emits far more than any test budget in 16-byte chunks, counting how
    /// many the sink accepts before aborting.
    struct ChattyDisplay {
        chunks_written: Cell<usize>,
    }

    impl fmt::Display for ChattyDisplay {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            for _ in 0..1000 {
                f.write_str("0123456789abcdef")?;
                self.chunks_written.set(self.chunks_written.get() + 1);
            }
            Ok(())
        }
    }

    #[test]
    fn from_display_aborts_once_budget_is_spent() {
        let source = ChattyDisplay {
            chunks_written: Cell::new(0),
        };
        let bounded = Bounded16::from_display(&source);
        assert!(bounded.ends_with("..."));
        assert!(bounded.len() <= 16);
        assert!(source.chunks_written.get() <= 2);
    }

    #[test]
    fn from_static_str_accepts_literals_and_still_clamps() {
        // The ergonomic path for static reason strings.
        // 19 bytes, so it clamps at this test type's 16-byte budget.
        let clamped: Bounded16 = "Block has no parent".into();
        assert_eq!(&*clamped, "Block has no ...");

        let fits: Bounded16 = "abc".into();
        assert_eq!(&*fits, "abc");
        assert_eq!(fits, "abc");
    }

    #[test]
    fn deserialize_clamps_rather_than_fails() {
        let cases: [(&str, &str); 3] = [
            ("\"abc\"", "abc"),
            ("\"aaaaaaaaaaaaaaaa\"", "aaaaaaaaaaaaaaaa"), // at capacity
            ("\"aaaaaaaaaaaaaaaaa\"", "aaaaaaaaaaaaa..."), // over capacity
        ];
        for (input, expected) in cases {
            let bounded: Bounded16 =
                serde_json::from_str(input).expect("parse never fails on length");
            assert_eq!(&*bounded, expected);
        }
    }
}
