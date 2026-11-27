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

//! Property tests for the `Uint256`/`Uint512` operations that the Kani proofs in
//! `kani_proofs.rs` cannot reach: multiplication, division and the hex codecs.

use proptest::prelude::*;

/// Words biased towards the values where carries, borrows and shifts change behaviour.
fn word_strategy() -> impl Strategy<Value = u64> {
    prop_oneof![
        3 => any::<u64>(),
        1 => Just(0),
        1 => Just(u64::MAX),
        1 => (0..64u32).prop_map(|k| 1 << k),
        1 => (0..64u32).prop_map(|k| u64::MAX >> k),
    ]
}

/// Values with a random number of high words cleared, so short and long values both occur.
fn words_strategy<const N: usize>() -> impl Strategy<Value = [u64; N]> {
    (prop::array::uniform::<_, N>(word_strategy()), 0..=N).prop_map(|(mut words, cleared)| {
        words[N - cleared..].fill(0);
        words
    })
}

macro_rules! uint_proptests {
    ($module:ident, $name:ident, $n_words:expr) => {
        mod $module {
            use pinny::tag;
            use proptest::prelude::*;

            use super::words_strategy;
            use crate::util::hash::to_hex;
            use crate::util::uint::{reference, $name, BitArray};

            const N: usize = $n_words;

            proptest! {
                #[tag(t_prop)]
                #[test]
                fn mul_matches_reference(a in words_strategy::<N>(), b in words_strategy::<N>()) {
                    let product = reference::mul_full(&a, &b);
                    prop_assert_eq!(&($name(a) * $name(b)).0[..], &product[..N]);
                }

                #[tag(t_prop)]
                #[test]
                fn mul_u32_matches_reference(a in words_strategy::<N>(), m in any::<u32>()) {
                    prop_assert_eq!($name(a).mul_u32(m).0, reference::mul_word(&a, m.into()));
                }

                #[tag(t_prop)]
                #[test]
                fn mul_matches_u128_on_single_words(a in any::<u64>(), b in any::<u64>()) {
                    prop_assert_eq!(
                        $name::from_u64(a) * $name::from_u64(b),
                        $name::from_u128(u128::from(a) * u128::from(b))
                    );
                }

                /// `a = q·b + r` with `r < b`, where `q·b` does not overflow.
                #[tag(t_prop)]
                #[test]
                fn div_satisfies_the_division_identity(
                    a in words_strategy::<N>(),
                    b in words_strategy::<N>(),
                ) {
                    prop_assume!(b != [0; N]);
                    let quotient = ($name(a) / $name(b)).0;
                    let product = reference::mul_full(&quotient, &b);
                    prop_assert!(product[N..].iter().all(|word| *word == 0), "q·b overflows");
                    let product: [u64; N] = product[..N].try_into().unwrap();
                    let (remainder, borrowed) = reference::sub(&a, &product);
                    prop_assert!(!borrowed, "q·b exceeds a");
                    prop_assert!(reference::sub(&remainder, &b).1, "remainder is not below b");
                }

                #[tag(t_prop)]
                #[test]
                fn div_matches_u128(a in any::<u128>(), b in 1..=u128::MAX) {
                    prop_assert_eq!(
                        $name::from_u128(a) / $name::from_u128(b),
                        $name::from_u128(a / b)
                    );
                }

                #[tag(t_prop)]
                #[test]
                fn div_by_one_and_by_itself(a in words_strategy::<N>()) {
                    prop_assert_eq!($name(a) / $name::one(), $name(a));
                    if a != [0; N] {
                        prop_assert_eq!($name(a) / $name(a), $name::one());
                    }
                }

                #[tag(t_prop)]
                #[test]
                fn hex_round_trips(a in words_strategy::<N>()) {
                    let value = $name(a);
                    prop_assert_eq!($name::from_hex_le(&value.to_hex_le()), Some(value));
                    prop_assert_eq!($name::from_hex_be(&value.to_hex_be()), Some(value));
                    prop_assert_eq!(value.to_string(), format!("0x{}", value.to_hex_be()));
                }

                #[tag(t_prop)]
                #[test]
                fn hex_of_the_wrong_length_is_rejected(
                    bytes in prop::collection::vec(any::<u8>(), 0..=8 * N + 16),
                ) {
                    prop_assume!(bytes.len() != 8 * N);
                    let hex = to_hex(&bytes);
                    prop_assert_eq!($name::from_hex_le(&hex), None);
                    prop_assert_eq!($name::from_hex_be(&hex), None);
                }
            }
        }
    };
}

uint_proptests!(uint256, Uint256, 4);
uint_proptests!(uint512, Uint512, 8);
