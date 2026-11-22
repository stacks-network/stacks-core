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

//! Kani proofs for the linear and bit-level `Uint256`/`Uint512` operations, over all inputs.
//!
//! Run with `cargo kani -p stacks-common`. Multiplication (including `mul_u32`) and division are
//! out of reach for the solver at these widths; the property tests in `proptests.rs` cover them.

/// Proofs for one `Uint*` type. `$unwind` must exceed the value's byte count: comparing arrays
/// unrolls to a byte-wise `memcmp`, which is the longest loop in every harness.
macro_rules! uint_proofs {
    ($module:ident, $name:ident, $n_words:expr, $unwind:tt) => {
        mod $module {
            use crate::util::uint::{reference, $name, BitArray};

            const BITS: usize = 64 * $n_words;

            fn any_value() -> [u64; $n_words] {
                kani::any()
            }

            fn any_bit_index() -> usize {
                let index: usize = kani::any();
                kani::assume(index < BITS);
                index
            }

            #[kani::proof]
            #[kani::unwind($unwind)]
            fn add_matches_reference() {
                let (a, b) = (any_value(), any_value());
                assert_eq!(($name(a) + $name(b)).0, reference::add(&a, &b));
            }

            #[kani::proof]
            #[kani::unwind($unwind)]
            fn sub_matches_reference() {
                let (a, b) = (any_value(), any_value());
                assert_eq!(($name(a) - $name(b)).0, reference::sub(&a, &b).0);
            }

            #[kani::proof]
            #[kani::unwind($unwind)]
            fn cmp_is_numeric_order() {
                let (a, b) = (any_value(), any_value());
                let ordering = $name(a).cmp(&$name(b));
                assert_eq!(ordering.is_lt(), reference::sub(&a, &b).1);
                assert_eq!(ordering.is_eq(), a == b);
                assert_eq!($name(a) == $name(b), a == b);
            }

            #[kani::proof]
            #[kani::unwind($unwind)]
            fn shl_moves_every_bit_up() {
                let (a, shift, index) = (any_value(), kani::any::<usize>(), any_bit_index());
                let shifted = ($name(a) << shift).0;
                let expected = index >= shift && reference::bit(&a, index - shift);
                assert_eq!(reference::bit(&shifted, index), expected);
            }

            #[kani::proof]
            #[kani::unwind($unwind)]
            fn shr_moves_every_bit_down() {
                let (a, shift, index) = (any_value(), kani::any::<usize>(), any_bit_index());
                let shifted = ($name(a) >> shift).0;
                let expected = shift
                    .checked_add(index)
                    .is_some_and(|source| reference::bit(&a, source));
                assert_eq!(reference::bit(&shifted, index), expected);
            }

            #[kani::proof]
            #[kani::unwind($unwind)]
            fn bit_reads_one_bit() {
                let (a, index) = (any_value(), any_bit_index());
                assert_eq!($name(a).bit(index), reference::bit(&a, index));
            }

            #[kani::proof]
            #[kani::unwind($unwind)]
            fn bits_is_one_past_the_highest_set_bit() {
                let (a, index) = (any_value(), any_bit_index());
                let bits = $name(a).bits();
                assert!(bits <= BITS);
                if bits > 0 {
                    assert!(reference::bit(&a, bits - 1));
                }
                if index >= bits {
                    assert!(!reference::bit(&a, index));
                }
            }

            #[kani::proof]
            #[kani::unwind($unwind)]
            fn trailing_zeros_counts_the_low_zero_bits() {
                let (a, index) = (any_value(), any_bit_index());
                let zeros = $name(a).trailing_zeros();
                assert!(zeros <= BITS);
                assert_eq!(zeros == BITS, a == [0; $n_words]);
                if zeros < BITS {
                    assert!(reference::bit(&a, zeros));
                }
                if index < zeros {
                    assert!(!reference::bit(&a, index));
                }
            }

            #[kani::proof]
            #[kani::unwind($unwind)]
            fn mask_keeps_the_low_bits() {
                let (a, n, index) = (any_value(), kani::any::<usize>(), any_bit_index());
                let masked = $name(a).mask(n).0;
                assert_eq!(
                    reference::bit(&masked, index),
                    index < n && reference::bit(&a, index)
                );
            }

            #[kani::proof]
            #[kani::unwind($unwind)]
            fn bit_slice_extracts_the_range() {
                let (a, start, end) = (any_value(), kani::any::<usize>(), kani::any::<usize>());
                kani::assume(start <= end);
                let index = any_bit_index();
                let slice = $name(a).bit_slice(start, end).0;
                let expected = index < end - start
                    && start
                        .checked_add(index)
                        .is_some_and(|source| reference::bit(&a, source));
                assert_eq!(reference::bit(&slice, index), expected);
            }

            #[kani::proof]
            #[kani::unwind($unwind)]
            fn bitwise_ops_act_per_bit() {
                let (a, b, index) = (any_value(), any_value(), any_bit_index());
                let (x, y) = (reference::bit(&a, index), reference::bit(&b, index));
                let (a, b) = ($name(a), $name(b));
                assert_eq!(reference::bit(&(a & b).0, index), x & y);
                assert_eq!(reference::bit(&(a | b).0, index), x | y);
                assert_eq!(reference::bit(&(a ^ b).0, index), x ^ y);
                assert_eq!(reference::bit(&(!a).0, index), !x);
            }

            #[kani::proof]
            #[kani::unwind($unwind)]
            fn byte_arrays_hold_the_words_in_order() {
                let a = any_value();
                let index: usize = kani::any();
                kani::assume(index < 8 * $n_words);
                let le_byte = (a[index / 8] >> (8 * (index % 8))) as u8;
                assert_eq!($name(a).to_u8_slice()[index], le_byte);
                assert_eq!($name(a).to_u8_slice_be()[8 * $n_words - 1 - index], le_byte);
            }

            #[kani::proof]
            #[kani::unwind($unwind)]
            fn small_conversions_round_trip() {
                let (small, signed, wide): (u64, i64, u128) =
                    (kani::any(), kani::any(), kani::any());
                let from_u64 = $name::from_u64(small);
                assert_eq!(from_u64.low_u64(), small);
                assert_eq!(from_u64.low_u32(), small as u32);
                assert_eq!(from_u64.bits(), 64 - small.leading_zeros() as usize);
                assert!(from_u64.0[1..].iter().all(|word| *word == 0));

                let from_u128 = $name::from_u128(wide);
                assert_eq!(
                    u128::from(from_u128.0[1]) << 64 | u128::from(from_u128.low_u64()),
                    wide
                );
                assert!(from_u128.0[2..].iter().all(|word| *word == 0));

                kani::assume(signed >= 0);
                assert_eq!($name::from_i64(signed), $name::from_u64(signed as u64));
            }
        }
    };
}

uint_proofs!(uint256, Uint256, 4, 33);
uint_proofs!(uint512, Uint512, 8, 65);

mod conversions {
    use crate::util::uint::{reference, Uint256, Uint512};

    #[kani::proof]
    #[kani::unwind(33)]
    fn increment_adds_one() {
        let a: [u64; 4] = kani::any();
        let mut incremented = Uint256(a);
        incremented.increment();
        assert_eq!(incremented.0, reference::add(&a, &[1, 0, 0, 0]));
    }

    #[kani::proof]
    #[kani::unwind(65)]
    fn uint512_widening_and_narrowing() {
        let narrow: [u64; 4] = kani::any();
        let widened = Uint512::from_uint256(&Uint256(narrow));
        assert_eq!(widened.0[..4], narrow);
        assert!(widened.0[4..].iter().all(|word| *word == 0));

        let wide: [u64; 8] = kani::any();
        assert_eq!(Uint512(wide).to_uint256().0, wide[..4]);
    }
}
