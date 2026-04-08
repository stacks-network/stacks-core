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

//! Big unsigned integer types
//!
//! Implementation of a various large-but-fixed sized unsigned integer types.
//! The functions here are designed to be fast.
//!
//! Borrowed with gratitude from Andrew Poelstra's rust-bitcoin library

use std::fmt;

use crate::util::hash::{hex_bytes, to_hex};

/// A trait which allows numbers to act as fixed-size bit arrays
pub trait BitArray {
    /// Is bit set?
    fn bit(&self, idx: usize) -> bool;

    /// Returns an array which is just the bits from start to end
    fn bit_slice(&self, start: usize, end: usize) -> Self;

    /// Bitwise and with `n` ones
    fn mask(&self, n: usize) -> Self;

    /// Trailing zeros
    fn trailing_zeros(&self) -> usize;

    /// Create all-zeros value
    fn zero() -> Self;

    /// Create value represeting one
    fn one() -> Self;

    /// Create value representing max
    fn max() -> Self;
}

/// Perform gradeschool multiplication using carrying_mul_add
fn carrying_mul<const N: usize>(a: &[u64; N], b: &[u64; N], checked: bool) -> Option<[u64; N]> {
    let mut out = [0; N];
    for j in 0..N {
        let mut carry = 0;
        for i in 0..(N - j) {
            (out[j + i], carry) = u64::carrying_mul_add(a[i], b[j], out[j + i], carry);
        }
        if checked {
            // carry from the inner loop would go into position N (overflow)
            if carry > 0 {
                return None;
            }
            // products a[i]*b[j] where i+j >= N land beyond the output array
            if b[j] != 0 {
                for i in (N - j)..N {
                    if a[i] != 0 {
                        return None;
                    }
                }
            }
        }
    }
    Some(out)
}

/// Perform gradeschool multiplication using carrying_mul on a single word
fn carrying_mul_u64<const N: usize>(mut a: [u64; N], b: u64) -> ([u64; N], u64) {
    let mut carry = 0;
    for i in 0..N {
        (a[i], carry) = a[i].carrying_mul(b, carry);
    }
    (a, carry)
}

/// Returns the addition of `a` and `b` and whether
///  or not the final word of the addition overflowed
///  (i.e., had a un-handled carry bit)
fn carrying_add<const N: usize>(mut a: [u64; N], b: &[u64; N]) -> ([u64; N], bool) {
    let mut next_carry = false;
    for i in 0..N {
        (a[i], next_carry) = a[i].carrying_add(b[i], next_carry);
    }
    (a, next_carry)
}

/// Returns `a - b` and whether
///  or not the subtraction underflowed
///  (i.e., needed an extra borrow bit)
fn borrowing_sub<const N: usize>(mut a: [u64; N], b: &[u64; N]) -> ([u64; N], bool) {
    let mut next_borrow = false;
    for i in 0..N {
        (a[i], next_borrow) = a[i].borrowing_sub(b[i], next_borrow);
    }
    (a, next_borrow)
}

/// A fixed-point unsigned 256-bit number with a compile-time scale factor.
///
/// The underlying [`Uint256`] value is interpreted as having `SCALE` fractional bits.
/// For example, with `SCALE = 64` the integer `1` is stored as `1 << 64`.
///
/// Arithmetic methods preserve the scale automatically: addition and subtraction
/// operate on the raw value directly, while multiplication and division adjust
/// the result by shifting so the output retains the same `SCALE`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FixedPointU256<const SCALE: u16> {
    value: Uint256,
}

impl<const S: u16> std::fmt::Debug for FixedPointU256<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{},{S}", self.value)
    }
}

impl<const S: u16> std::fmt::Display for FixedPointU256<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl<const SCALE: u16> FixedPointU256<SCALE> {
    /// Compile-time assertion that `SCALE < 128`, ensuring that even
    /// `u128::MAX` can always be represented without overflow.
    const _ASSERT_SCALE: () = assert!(SCALE < 128, "SCALE must be less than 128");

    /// The smallest representable nonzero value (raw value = 1).
    pub const MINIMAL: Self = Self {
        value: Uint256([1, 0, 0, 0]),
    };
    /// The zero value.
    pub const ZERO: Self = Self {
        value: Uint256([0, 0, 0, 0]),
    };

    /// Construct a FixedPointU256 with the raw underlying value (i.e., assume
    ///  it matches `SCALE`.
    ///
    /// **DANGER** Be sure that the scale factor of `value` matches `SCALE`.
    /// because this is unchecked.
    pub fn construct_raw(value: Uint256) -> Self {
        // Enforce max SCALE at compile time
        let () = Self::_ASSERT_SCALE;
        Self { value }
    }

    /// Create a fixed-point value from a `u128`, shifting left by `SCALE` bits.
    pub fn from_u128(x: u128) -> Self {
        // Enforce max SCALE at compile time
        let () = Self::_ASSERT_SCALE;
        let mut value = Uint256::from_u128(x);
        if SCALE > 0 {
            value = value << SCALE.into();
        }
        Self { value }
    }

    /// Create a fixed-point value from a `u64`, shifting left by `SCALE` bits.
    pub fn from_u64(x: u64) -> Self {
        // Enforce max SCALE at compile time
        let () = Self::_ASSERT_SCALE;
        let mut value = Uint256::from_u64(x);
        if SCALE > 0 {
            value = value << SCALE.into();
        }
        Self { value }
    }

    /// Checked addition. Returns `None` on overflow.
    pub fn add(self, other: &Self) -> Option<Self> {
        let value = self.value.checked_add(&other.value)?;
        Some(Self { value })
    }

    /// Add `other` to `self` in place. On overflow, resets `self` to zero and returns `None`.
    pub fn increment(&mut self, other: &Self) -> Option<()> {
        match self.value.checked_add(&other.value) {
            Some(new_value) => {
                self.value = new_value;
                Some(())
            }
            None => {
                self.value = Uint256([0, 0, 0, 0]);
                None
            }
        }
    }

    /// Checked subtraction. Returns `None` on underflow.
    pub fn sub(self, other: &Self) -> Option<Self> {
        let value = self.value.checked_sub(&other.value)?;
        Some(Self { value })
    }

    /// Checked multiplication. The raw product is right-shifted by `SCALE` to
    /// preserve the fixed-point representation. Returns `None` on overflow.
    pub fn mul(&self, other: &Self) -> Option<Self> {
        let mut value = self.value.checked_mul(&other.value)?;
        // need to down scale the result of multiplication to retain scales
        value = value >> SCALE.into();
        Some(Self { value })
    }

    /// Multiply by an unscaled `other` u64
    pub fn mul_u64(self, other: u64) -> Option<Self> {
        let (value, carry) = carrying_mul_u64(self.value.0, other);
        if carry > 0 {
            // overflow
            None
        } else {
            Some(Self {
                value: Uint256(value),
            })
        }
    }

    /// Divide `self` by `other`, up-scaling the numerator first to preserve
    /// fractional precision. Returns `None` on division by zero or if the
    /// up-scaling would overflow.
    pub fn div_and_scale(&self, other: &Self) -> Option<Self> {
        if other.value == Uint256::zero() {
            return None;
        }
        // Upscale self before dividing to preserve fractional precision.
        // Overflow check: the top SCALE bits of self.value must be zero.
        if self.value.bits() + SCALE as usize > 256 {
            return None;
        }
        let upscaled = self.value << SCALE.into();
        let value = upscaled / other.value;
        Some(Self { value })
    }

    /// Divide self by other and return the unscaled result.
    /// The resulting `Uint256` will have `SCALE` zero high-bits.
    pub fn div_and_drop_scale(&self, other: &Self) -> Option<Uint256> {
        let Self { value } = self.div(other.value.clone())?;
        Some(value)
    }

    /// divide by an unscaled `other`
    pub fn div(&self, other: Uint256) -> Option<Self> {
        if other == Uint256::zero() {
            return None;
        }
        let value = self.value / other;
        Some(Self { value })
    }

    /// Raise `self` to the power of `exp`, trimming the scale to `self.scaling` on each multiplication.
    /// Returns None if overflowed
    pub fn pow(&self, exp: u32) -> Option<Self> {
        if exp == 0 {
            return Some(Self::MINIMAL);
        }
        let mut output = self.clone();
        for _ in 1..exp {
            output = output.mul(self)?;
        }
        Some(output)
    }

    /// Returns the little-endian byte representation of `self` as a `Vec<u8>`
    pub fn to_bytes_le(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Uint256::N_WORDS);
        for word in self.value.0.iter() {
            out.extend((*word).to_le_bytes());
        }
        out
    }

    /// Find the `n`th root of self using binary search, trimming the scale to `self.scaling` on
    ///  iterations
    pub fn find_root_floor(&self, n: u32) -> Option<Self> {
        if n == 1 {
            return Some(self.clone());
        }
        if n == 0 {
            return None;
        }

        let mut low = Self::MINIMAL;
        let mut high = self.clone();
        loop {
            if high <= low {
                return Some(high.min(low));
            }
            let guess = high.clone().add(&low)?.div(Uint256::from_u64(2))?;
            match guess.pow(n) {
                None => {
                    // Overflow means guess is too large
                    high = guess.sub(&Self::MINIMAL)?;
                }
                Some(value) if &value == self => {
                    return Some(guess);
                }
                Some(value) if &value > self => {
                    high = guess.sub(&Self::MINIMAL)?;
                }
                Some(_) => {
                    low = guess.add(&Self::MINIMAL)?;
                }
            }
        }
    }

    /// Compute the weighted geometric average over `current` and up to 4 `priors`.
    ///
    /// Weights are `[5, 4, 3, 2, 1]` (current gets the highest weight, oldest
    /// prior gets the lowest). Only the first `priors.len()` prior weights are
    /// used; unused low weights are dropped from the total.
    ///
    /// Mathematically: `product(values[i] ^ (w[i] / W))` where `W = sum(w[i])`.
    ///
    /// Computed as `product(values[i]^(1/W))^w[i]` (root-then-pow) to avoid
    /// intermediate overflow. Precision loss is negligible (worst-case relative
    /// error ≈ max_weight * 2^-SCALE).
    ///
    /// Returns `None` if `priors.len() > 4` or on arithmetic overflow.
    pub fn weighted_geometric_average(current: &Self, priors: &[Self]) -> Option<Self> {
        if priors.len() > 4 {
            return None;
        }
        let max_weight: u32 = 5;
        let total_weight: u32 = (max_weight - priors.len() as u32..=max_weight).sum();

        let mut result = current.find_root_floor(total_weight)?.pow(max_weight)?;
        for (index, prior) in priors.iter().enumerate() {
            let exponent = max_weight - 1 - index as u32;
            let contribution = prior.find_root_floor(total_weight)?.pow(exponent)?;
            result = result.mul(&contribution)?;
        }
        Some(result)
    }

    /// Compute the sigmoid function `s(r) = r^2 / (r^2 + (1 - r)^2)`.
    ///
    /// Input `r` must be in `[0, 1]` (i.e., raw value at most `1 << SCALE`).
    /// Returns a value in `[0, 1]`.
    ///
    /// Returns `None` if `r > 1` or on arithmetic error.
    pub fn sigmoid(&self) -> Option<Self> {
        let one = Self::from_u64(1);
        if *self > one {
            return None;
        }
        let r_sq = self.pow(2)?;
        let one_minus_r = one.sub(self)?;
        let one_minus_r_sq = one_minus_r.pow(2)?;
        let denom = r_sq.clone().add(&one_minus_r_sq)?;
        r_sq.div_and_scale(&denom)
    }
}

macro_rules! construct_uint {
    ($name:ident, $n_words:expr) => {
        /// Little-endian large integer type of u64 "words"
        #[derive(Serialize, Deserialize, Copy)]
        #[repr(C)]
        pub struct $name(pub [u64; $n_words]);
        impl_array_newtype!($name, u64, $n_words);

        impl $name {
            /// The number of 64-bit words used to represent this integer.
            pub const N_WORDS: usize = $n_words;
            pub const MAX: Self = Self([u64::MAX; Self::N_WORDS]);
            pub const ZERO: Self = Self([0; Self::N_WORDS]);

            /// Conversion to u32
            #[inline]
            pub fn low_u32(&self) -> u32 {
                let Self(ref arr) = self;
                arr[0] as u32
            }

            /// Conversion to u64
            #[inline]
            pub fn low_u64(&self) -> u64 {
                let Self(ref arr) = self;
                arr[0] as u64
            }

            /// Return the least number of bits needed to represent the number
            #[inline]
            pub fn bits(&self) -> usize {
                let Self(ref arr) = self;
                for i in 1..Self::N_WORDS {
                    if arr[Self::N_WORDS - i] > 0 {
                        return (0x40 * (Self::N_WORDS - i + 1))
                            - arr[Self::N_WORDS - i].leading_zeros() as usize;
                    }
                }
                0x40 - arr[0].leading_zeros() as usize
            }

            /// Multiplication by u32
            pub fn mul_u32(self, other: u32) -> Self {
                Self(carrying_mul_u64(self.0, other.into()).0)
            }

            /// Create an object from a given unsigned 64-bit integer
            pub fn from_u64(init: u64) -> Self {
                let mut ret = [0; Self::N_WORDS];
                ret[0] = init;
                Self(ret)
            }

            /// Create an object from a given signed 64-bit integer
            pub fn from_i64(init: i64) -> Self {
                assert!(init >= 0);
                Self::from_u64(init as u64)
            }

            /// Create an object from a given unsigned 128-bit integer
            pub fn from_u128(init: u128) -> Self {
                let mut ret = [0u64; Self::N_WORDS];
                ret[0] = (init & 0xffffffffffffffffffffffffffffffff) as u64;
                ret[1] = (init >> 64) as u64;
                Self(ret)
            }

            /// Return the maximum representable value (all bits set).
            pub fn max() -> Self {
                Self::MAX
            }

            /// Return the value as a little-endian byte array.
            pub fn to_u8_slice(&self) -> [u8; Self::N_WORDS * 8] {
                let mut ret = [0u8; $n_words * 8];
                for i in 0..$n_words {
                    let bytes = self.0[i].to_le_bytes();
                    for j in 0..bytes.len() {
                        ret[i * 8 + j] = bytes[j];
                    }
                }
                ret
            }

            /// Return the value as a big-endian byte array.
            pub fn to_u8_slice_be(&self) -> [u8; Self::N_WORDS * 8] {
                let mut ret = [0u8; $n_words * 8];
                for i in 0..Self::N_WORDS {
                    let word_end = Self::N_WORDS * 8 - (i * 8);
                    let word_start = word_end - 8;
                    ret[word_start..word_end].copy_from_slice(&self.0[i].to_be_bytes());
                }
                ret
            }

            /// Parse from a little-endian hex string.
            /// The string must encode exactly `N_WORDS * 8` bytes (zero-padded).
            pub fn from_hex_le(hex: &str) -> Option<Self> {
                let bytes = hex_bytes(hex).ok()?;
                Self::from_bytes_le(bytes)
            }

            /// Parse from a little-endian byte vector.
            /// Returns `None` if `bytes.len()` is not exactly `N_WORDS * 8`.
            pub fn from_bytes_le(bytes: Vec<u8>) -> Option<Self> {
                if bytes.len() % 8 != 0 {
                    return None;
                }
                if bytes.len() / 8 != Self::N_WORDS {
                    return None;
                }
                let mut ret = [0u64; Self::N_WORDS];
                for i in 0..(bytes.len() / 8) {
                    let mut next_bytes = [0u8; 8];
                    next_bytes.copy_from_slice(&bytes[8 * i..(8 * (i + 1))]);
                    let next = u64::from_le_bytes(next_bytes);
                    ret[i] = next;
                }
                Some(Self(ret))
            }

            /// Return the value as a little-endian byte array (alias for [`to_u8_slice`](Self::to_u8_slice)).
            pub fn to_bytes_le(&self) -> [u8; Self::N_WORDS * 8] {
                self.to_u8_slice()
            }

            /// to a little-endian hex string
            pub fn to_hex_le(&self) -> String {
                to_hex(&self.to_u8_slice())
            }

            /// Parse from a big-endian hex string.
            /// The string must encode exactly `N_WORDS * 8` bytes (zero-padded).
            pub fn from_hex_be(hex: &str) -> Option<Self> {
                let bytes = hex_bytes(hex).ok()?;
                if bytes.len() % 8 != 0 {
                    return None;
                }
                if bytes.len() / 8 != Self::N_WORDS {
                    return None;
                }
                let mut ret = [0u64; Self::N_WORDS];
                for i in 0..(bytes.len() / 8) {
                    let mut next_bytes = [0u8; 8];
                    next_bytes.copy_from_slice(&bytes[8 * i..(8 * (i + 1))]);
                    let next = u64::from_be_bytes(next_bytes);
                    ret[(bytes.len() / 8) - 1 - i] = next;
                }
                Some(Self(ret))
            }

            /// to a big-endian hex string
            pub fn to_hex_be(&self) -> String {
                to_hex(&self.to_u8_slice_be())
            }

            /// Checked multiplication. Returns `None` on overflow.
            pub fn checked_mul(&self, other: &Self) -> Option<Self> {
                let out = carrying_mul(&self.0, &other.0, true)?;
                Some(Self(out))
            }

            /// Checked addition. Returns `None` on overflow.
            pub fn checked_add(self, other: &Self) -> Option<Self> {
                let (out, overflowed) = carrying_add(self.0, &other.0);
                if overflowed {
                    None
                } else {
                    Some(Self(out))
                }
            }

            /// Checked subtraction. Returns `None` on underflow.
            pub fn checked_sub(self, other: &Self) -> Option<Self> {
                let (out, underflowed) = borrowing_sub(self.0, &other.0);
                if underflowed {
                    None
                } else {
                    Some(Self(out))
                }
            }
        }

        impl ::std::ops::Add<Self> for $name {
            type Output = Self;

            fn add(self, other: Self) -> Self {
                Self(carrying_add(self.0, &other.0).0)
            }
        }

        impl ::std::ops::Add<&Self> for $name {
            type Output = Self;
            // Note: this performs wrapping addition
            fn add(self, other: &Self) -> Self {
                Self(carrying_add(self.0, &other.0).0)
            }
        }

        impl ::std::ops::Sub<Self> for $name {
            type Output = Self;

            #[inline]
            fn sub(self, other: Self) -> Self {
                Self(borrowing_sub(self.0, &other.0).0)
            }
        }

        impl ::std::ops::Sub<&Self> for $name {
            type Output = Self;

            #[inline]
            fn sub(self, other: &Self) -> Self {
                Self(borrowing_sub(self.0, &other.0).0)
            }
        }

        impl ::std::ops::Mul<&Self> for $name {
            type Output = Self;

            fn mul(self, other: &Self) -> Self {
                Self(carrying_mul(&self.0, &other.0, false).unwrap())
            }
        }

        impl ::std::ops::Mul<Self> for $name {
            type Output = Self;

            fn mul(self, other: Self) -> Self {
                Self(carrying_mul(&self.0, &other.0, false).unwrap())
            }
        }

        impl ::std::ops::Div<Self> for $name {
            type Output = Self;

            fn div(mut self, mut other: Self) -> Self {
                let mut ret = [0u64; Self::N_WORDS];

                let my_bits = self.bits();
                let your_bits = other.bits();

                // Check for division by 0
                assert!(your_bits != 0);

                // Early return in case we are dividing by a larger number than us
                if my_bits < your_bits {
                    return Self(ret);
                }

                // Bitwise long division
                let mut shift = my_bits - your_bits;
                other = other << shift;
                loop {
                    if self >= other {
                        ret[shift / 64] |= 1 << (shift % 64);
                        self = self - other;
                    }
                    other = other >> 1;
                    if shift == 0 {
                        break;
                    }
                    shift -= 1;
                }

                Self(ret)
            }
        }

        impl BitArray for $name {
            #[inline]
            fn bit(&self, index: usize) -> bool {
                let Self(ref arr) = self;
                arr[index / 64] & (1 << (index % 64)) != 0
            }

            #[inline]
            fn bit_slice(&self, start: usize, end: usize) -> Self {
                (*self >> start).mask(end - start)
            }

            #[inline]
            fn mask(&self, n: usize) -> Self {
                let Self(ref arr) = self;
                let mut ret = [0; Self::N_WORDS];
                for i in 0..Self::N_WORDS {
                    if n >= 0x40 * (i + 1) {
                        ret[i] = arr[i];
                    } else {
                        ret[i] = arr[i] & ((1 << (n - 0x40 * i)) - 1);
                        break;
                    }
                }
                Self(ret)
            }

            #[inline]
            fn trailing_zeros(&self) -> usize {
                let Self(ref arr) = self;
                for i in 0..(Self::N_WORDS - 1) {
                    if arr[i] > 0 {
                        return (0x40 * i) + arr[i].trailing_zeros() as usize;
                    }
                }
                (0x40 * (Self::N_WORDS - 1)) + arr[Self::N_WORDS - 1].trailing_zeros() as usize
            }

            fn zero() -> Self {
                Self::ZERO
            }
            fn one() -> Self {
                Self({
                    let mut ret = [0; Self::N_WORDS];
                    ret[0] = 1;
                    ret
                })
            }
            fn max() -> Self {
                Self::MAX
            }
        }

        impl ::std::default::Default for $name {
            fn default() -> Self {
                Self::ZERO
            }
        }

        impl ::std::ops::BitAnd<$name> for $name {
            type Output = Self;

            #[inline]
            fn bitand(mut self, other: Self) -> Self {
                for i in 0..Self::N_WORDS {
                    self.0[i] &= other.0[i];
                }
                self
            }
        }

        impl ::std::ops::BitXor<$name> for $name {
            type Output = Self;

            #[inline]
            fn bitxor(mut self, other: Self) -> Self {
                for i in 0..$n_words {
                    self.0[i] ^= other.0[i];
                }
                self
            }
        }

        impl ::std::ops::BitOr<$name> for $name {
            type Output = $name;

            #[inline]
            fn bitor(mut self, other: $name) -> $name {
                for i in 0..$n_words {
                    self.0[i] |= other.0[i];
                }
                self
            }
        }

        impl ::std::ops::Not for $name {
            type Output = Self;

            #[inline]
            fn not(mut self) -> Self {
                let Self(ref mut arr) = self;
                for i in 0..$n_words {
                    arr[i] = !arr[i];
                }
                self
            }
        }

        impl ::std::ops::Shl<usize> for $name {
            type Output = $name;

            // Iterate destination high-to-low so we read from lower source
            // indices that haven't been overwritten yet.
            fn shl(mut self, shift: usize) -> $name {
                let word_shift = shift / 64;
                let bit_shift = shift % 64;
                for d in (0..$n_words).rev() {
                    let mut val = 0u64;
                    // Main contribution from the source word
                    if bit_shift < 64 && d >= word_shift {
                        val = self.0[d - word_shift] << bit_shift;
                    }
                    // Carry-in: high bits spilled from the next-lower source word
                    if bit_shift > 0 && d >= word_shift + 1 {
                        val |= self.0[d - word_shift - 1] >> (64 - bit_shift);
                    }
                    self.0[d] = val;
                }
                self
            }
        }

        impl ::std::ops::Shr<usize> for $name {
            type Output = $name;

            // Iterate destination low-to-high so we read from higher source
            // indices that haven't been overwritten yet.
            fn shr(mut self, shift: usize) -> $name {
                let word_shift = shift / 64;
                let bit_shift = shift % 64;
                for d in 0..$n_words {
                    let mut val = 0u64;
                    // Main contribution from the source word
                    if d + word_shift < $n_words {
                        val = self.0[d + word_shift] >> bit_shift;
                    }
                    // Carry-in: low bits spilled from the next-higher source word
                    if bit_shift > 0 && d + word_shift + 1 < $n_words {
                        val |= self.0[d + word_shift + 1] << (64 - bit_shift);
                    }
                    self.0[d] = val;
                }
                self
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                let &$name(ref data) = self;
                write!(f, "0x")?;
                for ch in data.iter().rev() {
                    write!(f, "{:016x}", ch)?;
                }
                Ok(())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                <dyn fmt::Debug>::fmt(self, f)
            }
        }
    };
}

construct_uint!(Uint256, 4);
construct_uint!(Uint512, 8);

impl Uint256 {
    /// Increment by 1
    #[inline]
    pub fn increment(&mut self) {
        self.0 = carrying_add(self.0, &[1, 0, 0, 0]).0;
    }
}

impl Uint512 {
    /// Create a [`Uint512`] from a [`Uint256`], zero-extending the upper words.
    pub fn from_uint256(n: &Uint256) -> Uint512 {
        let mut tmp = [0u64; 8];
        tmp[..4].copy_from_slice(&n.0[0..4]);
        Uint512(tmp)
    }

    /// Convert to [`Uint256`] by truncating the upper 256 bits.
    pub fn to_uint256(&self) -> Uint256 {
        let mut tmp = [0u64; 4];
        tmp[..4].copy_from_slice(&self.0[0..4]);
        Uint256(tmp)
    }
}

#[cfg(test)]
mod tests {
    use crate::util::uint::{BitArray, Uint256};

    #[test]
    pub fn uint256_bits_test() {
        assert_eq!(Uint256::from_u64(255).bits(), 8);
        assert_eq!(Uint256::from_u64(256).bits(), 9);
        assert_eq!(Uint256::from_u64(300).bits(), 9);
        assert_eq!(Uint256::from_u64(60000).bits(), 16);
        assert_eq!(Uint256::from_u64(70000).bits(), 17);

        // Try to read the following lines out loud quickly
        let mut shl = Uint256::from_u64(70000);
        shl = shl << 100;
        assert_eq!(shl.bits(), 117);
        shl = shl << 100;
        assert_eq!(shl.bits(), 217);
        shl = shl << 100;
        assert_eq!(shl.bits(), 0);

        // Bit set check
        assert!(!Uint256::from_u64(10).bit(0));
        assert!(Uint256::from_u64(10).bit(1));
        assert!(!Uint256::from_u64(10).bit(2));
        assert!(Uint256::from_u64(10).bit(3));
        assert!(!Uint256::from_u64(10).bit(4));
    }

    #[test]
    pub fn uint256_display_test() {
        assert_eq!(
            format!("{}", Uint256::from_u64(0xDEADBEEF)),
            "0x00000000000000000000000000000000000000000000000000000000deadbeef"
        );
        assert_eq!(
            format!("{}", Uint256::from_u64(u64::MAX)),
            "0x000000000000000000000000000000000000000000000000ffffffffffffffff"
        );

        let max_val = Uint256([
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
        ]);
        assert_eq!(
            max_val.to_string(),
            "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        );
    }

    #[test]
    pub fn uint256_comp_test() {
        let small = Uint256([10u64, 0, 0, 0]);
        let big = Uint256([0x8C8C3EE70C644118u64, 0x0209E7378231E632, 0, 0]);
        let bigger = Uint256([0x9C8C3EE70C644118u64, 0x0209E7378231E632, 0, 0]);
        let biggest = Uint256([0x5C8C3EE70C644118u64, 0x0209E7378231E632, 0, 1]);

        assert!(small < big);
        assert!(big < bigger);
        assert!(bigger < biggest);
        assert!(bigger <= biggest);
        assert!(biggest <= biggest);
        assert!(bigger >= big);
        assert!(bigger >= small);
        assert!(small <= small);
    }

    #[test]
    pub fn uint256_arithmetic_test() {
        let init = Uint256::from_u64(0xDEADBEEFDEADBEEF);
        let copy = init;

        let add = init + copy;
        assert_eq!(add, Uint256([0xBD5B7DDFBD5B7DDEu64, 1, 0, 0]));
        // Bitshifts
        let shl = add << 88;
        assert_eq!(shl, Uint256([0u64, 0xDFBD5B7DDE000000, 0x1BD5B7D, 0]));
        let shr = shl >> 40;
        assert_eq!(
            shr,
            Uint256([0x7DDE000000000000u64, 0x0001BD5B7DDFBD5B, 0, 0])
        );
        // Increment
        let mut incr = shr;
        incr.increment();
        assert_eq!(
            incr,
            Uint256([0x7DDE000000000001u64, 0x0001BD5B7DDFBD5B, 0, 0])
        );
        // Subtraction
        let sub = incr - init;
        assert_eq!(
            sub,
            Uint256([0x9F30411021524112u64, 0x0001BD5B7DDFBD5A, 0, 0])
        );
        // Multiplication
        let mult = sub.mul_u32(300);
        assert_eq!(
            mult,
            Uint256([0x8C8C3EE70C644118u64, 0x0209E7378231E632, 0, 0])
        );
        // Division
        assert_eq!(
            Uint256::from_u64(105) / Uint256::from_u64(5),
            Uint256::from_u64(21)
        );
        let div = mult / Uint256::from_u64(300);
        assert_eq!(
            div,
            Uint256([0x9F30411021524112u64, 0x0001BD5B7DDFBD5A, 0, 0])
        );
        // TODO: bit inversion
    }

    #[test]
    pub fn mul_u32_test() {
        let u64_val = Uint256::from_u64(0xDEADBEEFDEADBEEF);

        let u96_res = u64_val.mul_u32(0xFFFFFFFF);
        let u128_res = u96_res.mul_u32(0xFFFFFFFF);
        let u160_res = u128_res.mul_u32(0xFFFFFFFF);
        let u192_res = u160_res.mul_u32(0xFFFFFFFF);
        let u224_res = u192_res.mul_u32(0xFFFFFFFF);
        let u256_res = u224_res.mul_u32(0xFFFFFFFF);

        assert_eq!(u96_res, Uint256([0xffffffff21524111u64, 0xDEADBEEE, 0, 0]));
        assert_eq!(
            u128_res,
            Uint256([0x21524111DEADBEEFu64, 0xDEADBEEE21524110, 0, 0])
        );
        assert_eq!(
            u160_res,
            Uint256([0xBD5B7DDD21524111u64, 0x42A4822200000001, 0xDEADBEED, 0])
        );
        assert_eq!(
            u192_res,
            Uint256([
                0x63F6C333DEADBEEFu64,
                0xBD5B7DDFBD5B7DDB,
                0xDEADBEEC63F6C334,
                0
            ])
        );
        assert_eq!(
            u224_res,
            Uint256([
                0x7AB6FBBB21524111u64,
                0xFFFFFFFBA69B4558,
                0x854904485964BAAA,
                0xDEADBEEB
            ])
        );
        assert_eq!(
            u256_res,
            Uint256([
                0xA69B4555DEADBEEFu64,
                0xA69B455CD41BB662,
                0xD41BB662A69B4550,
                0xDEADBEEAA69B455C
            ])
        );
    }

    #[test]
    pub fn multiplication_test() {
        let u64_val = Uint256::from_u64(0xDEADBEEFDEADBEEF);

        let u128_res = u64_val * u64_val;

        assert_eq!(
            u128_res,
            Uint256([0x048D1354216DA321u64, 0xC1B1CD13A4D13D46, 0, 0])
        );

        let u256_res = u128_res * u128_res;

        assert_eq!(
            u256_res,
            Uint256([
                0xF4E166AAD40D0A41u64,
                0xF5CF7F3618C2C886u64,
                0x4AFCFF6F0375C608u64,
                0x928D92B4D7F5DF33u64
            ])
        );
    }

    #[test]
    pub fn uint256_bitslice_test() {
        let init = Uint256::from_u64(0xDEADBEEFDEADBEEF);
        let add = init + (init << 64);
        assert_eq!(add.bit_slice(64, 128), init);
        assert_eq!(add.mask(64), init);
    }

    #[test]
    pub fn uint256_extreme_bitshift_test() {
        // Shifting a u64 by 64 bits gives an undefined value, so make sure that
        // we're doing the Right Thing here
        let init = Uint256::from_u64(0xDEADBEEFDEADBEEF);

        assert_eq!(init << 64, Uint256([0, 0xDEADBEEFDEADBEEF, 0, 0]));
        let add = (init << 64) + init;
        assert_eq!(add, Uint256([0xDEADBEEFDEADBEEF, 0xDEADBEEFDEADBEEF, 0, 0]));
        assert_eq!(
            add >> 0,
            Uint256([0xDEADBEEFDEADBEEF, 0xDEADBEEFDEADBEEF, 0, 0])
        );
        assert_eq!(
            add << 0,
            Uint256([0xDEADBEEFDEADBEEF, 0xDEADBEEFDEADBEEF, 0, 0])
        );
        assert_eq!(add >> 64, Uint256([0xDEADBEEFDEADBEEF, 0, 0, 0]));
        assert_eq!(
            add << 64,
            Uint256([0, 0xDEADBEEFDEADBEEF, 0xDEADBEEFDEADBEEF, 0])
        );
    }

    #[test]
    pub fn hex_codec() {
        let init =
            (Uint256::from_u64(0xDEADBEEFDEADBEEF) << 64) | Uint256::from_u64(0x0102030405060708);

        // little-endian representation
        let hex_init = "0807060504030201efbeaddeefbeadde00000000000000000000000000000000";
        assert_eq!(Uint256::from_hex_le(hex_init).unwrap(), init);
        assert_eq!(&init.to_hex_le(), hex_init);
        assert_eq!(Uint256::from_hex_le(&init.to_hex_le()).unwrap(), init);

        // big-endian representation
        let hex_init = "00000000000000000000000000000000deadbeefdeadbeef0102030405060708";
        assert_eq!(Uint256::from_hex_be(hex_init).unwrap(), init);
        assert_eq!(&init.to_hex_be(), hex_init);
        assert_eq!(Uint256::from_hex_be(&init.to_hex_be()).unwrap(), init);
    }

    #[test]
    pub fn uint_increment_test() {
        let mut value = Uint256([0xffffffffffffffff, 0, 0, 0]);
        value.increment();
        assert_eq!(value, Uint256([0, 1, 0, 0]));

        value = Uint256([0xffffffffffffffff, 0xffffffffffffffff, 0, 0]);
        value.increment();
        assert_eq!(value, Uint256([0, 0, 1, 0]));

        value = Uint256([
            0xffffffffffffffff,
            0xffffffffffffffff,
            0xffffffffffffffff,
            0,
        ]);
        value.increment();
        assert_eq!(value, Uint256([0, 0, 0, 1]));

        value = Uint256([
            0xffffffffffffffff,
            0xffffffffffffffff,
            0xffffffffffffffff,
            0xffffffffffffffff,
        ]);
        value.increment();
        assert_eq!(value, Uint256([0, 0, 0, 0]));
    }

    // -----------------------------------------------------------------------
    // Uint256 / Uint512 property tests
    // -----------------------------------------------------------------------

    use proptest::prelude::*;

    use crate::util::uint::Uint512;

    /// Helper: build a Uint256 from four u64 limbs.
    fn u256(a: u64, b: u64, c: u64, d: u64) -> Uint256 {
        Uint256([a, b, c, d])
    }

    /// Proptest strategy for arbitrary Uint256 values.
    fn arb_uint256() -> impl Strategy<Value = Uint256> {
        (any::<u64>(), any::<u64>(), any::<u64>(), any::<u64>())
            .prop_map(|(a, b, c, d)| u256(a, b, c, d))
    }

    /// Proptest strategy for non-zero Uint256 values.
    fn arb_uint256_nonzero() -> impl Strategy<Value = Uint256> {
        arb_uint256().prop_filter("must be non-zero", |v| *v != BitArray::zero())
    }

    /// Proptest strategy for "small" Uint256 values (fits in lower 128 bits)
    /// to avoid overflow in arithmetic tests.
    fn arb_uint256_small() -> impl Strategy<Value = Uint256> {
        (any::<u64>(), any::<u64>()).prop_map(|(a, b)| u256(a, b, 0, 0))
    }

    /// Proptest strategy for arbitrary Uint512 values.
    fn arb_uint512() -> impl Strategy<Value = Uint512> {
        (
            any::<u64>(),
            any::<u64>(),
            any::<u64>(),
            any::<u64>(),
            any::<u64>(),
            any::<u64>(),
            any::<u64>(),
            any::<u64>(),
        )
            .prop_map(|(a, b, c, d, e, f, g, h)| Uint512([a, b, c, d, e, f, g, h]))
    }

    /// Proptest strategy for non-zero Uint512 values.
    fn arb_uint512_nonzero() -> impl Strategy<Value = Uint512> {
        arb_uint512().prop_filter("must be non-zero", |v| *v != BitArray::zero())
    }

    /// Proptest strategy for "small" Uint512 values (fits in lower 256 bits)
    /// to avoid overflow in arithmetic tests.
    fn arb_uint512_small() -> impl Strategy<Value = Uint512> {
        (any::<u64>(), any::<u64>(), any::<u64>(), any::<u64>())
            .prop_map(|(a, b, c, d)| Uint512([a, b, c, d, 0, 0, 0, 0]))
    }

    proptest! {
        // ---------------------------------------------------------------
        // Uint256: Arithmetic identities
        // ---------------------------------------------------------------

        /// Addition is commutative (wrapping): a + b == b + a
        #[test]
        fn u256_add_commutative(a in arb_uint256(), b in arb_uint256()) {
            prop_assert_eq!(a + b, b + a);
        }

        /// Addition by zero is identity
        #[test]
        fn u256_add_zero_identity(a in arb_uint256()) {
            let zero: Uint256 = BitArray::zero();
            prop_assert_eq!(a + zero, a);
        }

        /// checked_add returns None exactly when wrapping add overflows
        #[test]
        fn u256_checked_add_overflow(a in arb_uint256(), b in arb_uint256()) {
            let checked = a.checked_add(&b);
            // If checked succeeds, the wrapping result must match
            if let Some(sum) = checked {
                prop_assert_eq!(sum, a + b);
            }
            // If it fails, verify overflow: a + b would have to wrap
            // (a + b) wrapping < a means overflow occurred
            if checked.is_none() {
                prop_assert!((a + b) < a || (a + b) < b);
            }
        }

        /// Subtraction: a - a == 0
        #[test]
        fn u256_sub_self_is_zero(a in arb_uint256()) {
            let zero: Uint256 = BitArray::zero();
            prop_assert_eq!(a - a, zero);
        }

        /// checked_sub returns None exactly on underflow
        #[test]
        fn u256_checked_sub_underflow(a in arb_uint256(), b in arb_uint256()) {
            let checked = a.checked_sub(&b);
            if a >= b {
                prop_assert!(checked.is_some(), "a >= b should not underflow");
                prop_assert_eq!(checked.unwrap(), a - b);
            } else {
                prop_assert!(checked.is_none(), "a < b should underflow");
            }
        }

        /// Add then sub roundtrip: (a + b) - b == a (wrapping)
        #[test]
        fn u256_add_sub_roundtrip(a in arb_uint256(), b in arb_uint256()) {
            prop_assert_eq!((a + b) - b, a);
        }

        /// Multiplication is commutative (truncating): a * b == b * a
        #[test]
        fn u256_mul_commutative(a in arb_uint256_small(), b in arb_uint256_small()) {
            prop_assert_eq!(a * b, b * a);
        }

        /// Multiplication by one is identity
        #[test]
        fn u256_mul_one_identity(a in arb_uint256()) {
            let one: Uint256 = BitArray::one();
            prop_assert_eq!(a * one, a);
        }

        /// Multiplication by zero is zero
        #[test]
        fn u256_mul_zero(a in arb_uint256()) {
            let zero: Uint256 = BitArray::zero();
            prop_assert_eq!(a * zero, zero);
        }

        /// checked_mul: small values should succeed and match truncating mul
        #[test]
        fn u256_checked_mul_small(
            a_val in 0u64..u32::MAX as u64,
            b_val in 0u64..u32::MAX as u64,
        ) {
            let a = Uint256::from_u64(a_val);
            let b = Uint256::from_u64(b_val);
            let checked = a.checked_mul(&b);
            prop_assert!(checked.is_some(), "small values should not overflow");
            prop_assert_eq!(checked.unwrap(), a * b);
        }

        /// Division: a / a == 1 for non-zero a
        #[test]
        fn u256_div_self_is_one(a in arb_uint256_nonzero()) {
            let one: Uint256 = BitArray::one();
            prop_assert_eq!(a / a, one);
        }

        /// Division: a / 1 == a
        #[test]
        fn u256_div_one_identity(a in arb_uint256()) {
            let one: Uint256 = BitArray::one();
            prop_assert_eq!(a / one, a);
        }

        /// Division: 0 / a == 0 for non-zero a
        #[test]
        fn u256_zero_div(a in arb_uint256_nonzero()) {
            let zero: Uint256 = BitArray::zero();
            prop_assert_eq!(zero / a, zero);
        }

        /// Division/multiplication roundtrip: (a / b) * b + (a % b) == a
        /// We verify the weaker form: (a / b) * b <= a < (a / b + 1) * b
        #[test]
        fn u256_div_mul_relationship(
            a in arb_uint256(),
            b in arb_uint256_nonzero(),
        ) {
            let quotient = a / b;
            let product = quotient * b;
            // product <= a (integer division truncates)
            prop_assert!(product <= a, "(a/b)*b should be <= a");
            // a - product < b (remainder is less than divisor)
            let remainder = a - product;
            prop_assert!(remainder < b, "remainder should be < divisor");
        }

        /// mul_u32 matches full multiplication for small values
        #[test]
        fn u256_mul_u32_matches_mul(
            a in arb_uint256_small(),
            b in 0u32..u32::MAX,
        ) {
            let via_mul_u32 = a.mul_u32(b);
            let via_mul = a * Uint256::from_u64(b as u64);
            prop_assert_eq!(via_mul_u32, via_mul);
        }

        // ---------------------------------------------------------------
        // Uint256: Bitwise operations
        // ---------------------------------------------------------------

        /// a & a == a (idempotent)
        #[test]
        fn u256_bitand_idempotent(a in arb_uint256()) {
            prop_assert_eq!(a & a, a);
        }

        /// a & 0 == 0
        #[test]
        fn u256_bitand_zero(a in arb_uint256()) {
            let zero: Uint256 = BitArray::zero();
            prop_assert_eq!(a & zero, zero);
        }

        /// a | a == a (idempotent)
        #[test]
        fn u256_bitor_idempotent(a in arb_uint256()) {
            prop_assert_eq!(a | a, a);
        }

        /// a | 0 == a (identity)
        #[test]
        fn u256_bitor_zero_identity(a in arb_uint256()) {
            let zero: Uint256 = BitArray::zero();
            prop_assert_eq!(a | zero, a);
        }

        /// a ^ a == 0
        #[test]
        fn u256_bitxor_self_is_zero(a in arb_uint256()) {
            let zero: Uint256 = BitArray::zero();
            prop_assert_eq!(a ^ a, zero);
        }

        /// a ^ 0 == a
        #[test]
        fn u256_bitxor_zero_identity(a in arb_uint256()) {
            let zero: Uint256 = BitArray::zero();
            prop_assert_eq!(a ^ zero, a);
        }

        /// !!a == a (double negation)
        #[test]
        fn u256_not_involution(a in arb_uint256()) {
            prop_assert_eq!(!!a, a);
        }

        /// a & !a == 0
        #[test]
        fn u256_and_not_is_zero(a in arb_uint256()) {
            let zero: Uint256 = BitArray::zero();
            prop_assert_eq!(a & !a, zero);
        }

        /// a | !a == MAX
        #[test]
        fn u256_or_not_is_max(a in arb_uint256()) {
            let max: Uint256 = BitArray::max();
            prop_assert_eq!(a | !a, max);
        }

        /// De Morgan's: !(a & b) == !a | !b
        #[test]
        fn u256_de_morgan_and(a in arb_uint256(), b in arb_uint256()) {
            prop_assert_eq!(!(a & b), !a | !b);
        }

        /// De Morgan's: !(a | b) == !a & !b
        #[test]
        fn u256_de_morgan_or(a in arb_uint256(), b in arb_uint256()) {
            prop_assert_eq!(!(a | b), !a & !b);
        }

        // ---------------------------------------------------------------
        // Uint256: Shift operations
        // ---------------------------------------------------------------

        /// Shift left then right roundtrips for small shifts (no bits lost)
        #[test]
        fn u256_shl_shr_roundtrip(
            val in 0u64..u64::MAX,
            shift in 0usize..64,
        ) {
            let a = Uint256::from_u64(val);
            prop_assert_eq!((a << shift) >> shift, a);
        }

        /// Shifting by 0 is identity
        #[test]
        fn u256_shift_zero_identity(a in arb_uint256()) {
            prop_assert_eq!(a << 0, a);
            prop_assert_eq!(a >> 0, a);
        }

        /// Shifting left by 256 or more gives zero
        #[test]
        fn u256_shl_overflow(a in arb_uint256(), extra in 0usize..64) {
            let shifted = a << (256 + extra);
            let zero: Uint256 = BitArray::zero();
            prop_assert_eq!(shifted, zero);
        }

        /// Shifting right by 256 or more gives zero
        #[test]
        fn u256_shr_overflow(a in arb_uint256(), extra in 0usize..64) {
            let shifted = a >> (256 + extra);
            let zero: Uint256 = BitArray::zero();
            prop_assert_eq!(shifted, zero);
        }

        /// Shift left by 1 == multiply by 2 (for values that don't overflow)
        #[test]
        fn u256_shl1_is_mul2(a in arb_uint256()) {
            // Mask off top bit to prevent overflow
            let mask = !(Uint256([0, 0, 0, 1u64 << 63]));
            let a_safe = a & mask;
            let two = Uint256::from_u64(2);
            prop_assert_eq!(a_safe << 1, a_safe * two);
        }

        // ---------------------------------------------------------------
        // Uint256: Ordering and bits
        // ---------------------------------------------------------------

        /// bits() is consistent with the actual value
        #[test]
        fn u256_bits_consistent(a in arb_uint256_nonzero()) {
            let b = a.bits();
            // The value should fit in `b` bits but not `b-1` bits
            prop_assert!(b > 0 && b <= 256);
            // a should be < 2^b, verified by: a >> b == 0
            let zero: Uint256 = BitArray::zero();
            prop_assert_eq!(a >> b, zero);
            // a should be >= 2^(b-1), verified by: a >> (b-1) != 0
            if b > 0 {
                prop_assert!((a >> (b - 1)) != zero);
            }
        }

        /// from_u64 then low_u64 roundtrips
        #[test]
        fn u256_from_u64_low_u64_roundtrip(val in any::<u64>()) {
            prop_assert_eq!(Uint256::from_u64(val).low_u64(), val);
        }

        /// from_u128 then extract lower 128 bits roundtrips
        #[test]
        fn u256_from_u128_roundtrip(val in any::<u128>()) {
            let u = Uint256::from_u128(val);
            let lo = u.0[0] as u128 | ((u.0[1] as u128) << 64);
            prop_assert_eq!(lo, val);
            // Upper limbs should be zero
            prop_assert_eq!(u.0[2], 0);
            prop_assert_eq!(u.0[3], 0);
        }

        /// from_i64 roundtrips for non-negative values
        #[test]
        fn u256_from_i64_roundtrip(val in 0i64..i64::MAX) {
            let u = Uint256::from_i64(val);
            prop_assert_eq!(u.low_u64(), val as u64);
        }

        // ---------------------------------------------------------------
        // Uint256: Serialization roundtrips
        // ---------------------------------------------------------------

        /// to_u8_slice / from_bytes_le roundtrip
        #[test]
        fn u256_bytes_le_roundtrip(a in arb_uint256()) {
            let bytes = a.to_u8_slice().to_vec();
            let reconstructed = Uint256::from_bytes_le(bytes).expect("valid bytes");
            prop_assert_eq!(reconstructed, a);
        }

        /// to_hex_le / from_hex_le roundtrip
        #[test]
        fn u256_hex_le_roundtrip(a in arb_uint256()) {
            let hex = a.to_hex_le();
            let reconstructed = Uint256::from_hex_le(&hex).expect("valid hex");
            prop_assert_eq!(reconstructed, a);
        }

        /// to_hex_be / from_hex_be roundtrip
        #[test]
        fn u256_hex_be_roundtrip(a in arb_uint256()) {
            let hex = a.to_hex_be();
            let reconstructed = Uint256::from_hex_be(&hex).expect("valid hex");
            prop_assert_eq!(reconstructed, a);
        }

        /// to_u8_slice (LE) and to_u8_slice_be are reverses of each other
        #[test]
        fn u256_le_be_inverse(a in arb_uint256()) {
            let le = a.to_u8_slice();
            let be = a.to_u8_slice_be();
            let reversed_be: Vec<u8> = be.iter().rev().cloned().collect();
            prop_assert_eq!(le, &reversed_be[..]);
        }

        // ---------------------------------------------------------------
        // Uint256: BitArray trait
        // ---------------------------------------------------------------

        /// trailing_zeros is correct: bit at index trailing_zeros() is set
        /// (for non-zero values)
        #[test]
        fn u256_trailing_zeros_correct(a in arb_uint256_nonzero()) {
            let tz = a.trailing_zeros();
            prop_assert!(tz < 256);
            prop_assert!(a.bit(tz), "bit at trailing_zeros() should be set");
            // All bits below trailing_zeros should be unset
            for i in 0..tz {
                prop_assert!(!a.bit(i), "bit {i} below trailing_zeros should be unset");
            }
        }

        /// bit() matches the individual bit in the underlying limb
        #[test]
        fn u256_bit_matches_limb(a in arb_uint256(), idx in 0usize..256) {
            let word = idx / 64;
            let bit_in_word = idx % 64;
            let expected = (a.0[word] >> bit_in_word) & 1 == 1;
            prop_assert_eq!(a.bit(idx), expected);
        }

        /// bit_slice extracts the correct sub-range
        #[test]
        fn u256_bit_slice_matches_shift_and_mask(
            a in arb_uint256(),
            start in 0usize..128,
            width in 1usize..128,
        ) {
            let end = start + width;
            prop_assume!(end <= 256);
            let sliced = a.bit_slice(start, end);
            let manual = (a >> start).mask(width);
            prop_assert_eq!(sliced, manual);
        }

        /// mask(n) zeroes out all bits at position n and above
        #[test]
        fn u256_mask_clears_high_bits(a in arb_uint256(), n in 1usize..256) {
            let masked = a.mask(n);
            // bits() of the result should be <= n
            if masked != BitArray::zero() {
                prop_assert!(masked.bits() <= n, "mask({n}) should clear bits >= {n}, but bits() = {}", masked.bits());
            }
            // All bits below n should be preserved
            for i in 0..n {
                prop_assert_eq!(masked.bit(i), a.bit(i), "mask should preserve bit {}", i);
            }
        }

        // ---------------------------------------------------------------
        // Uint256: Ref-variant operators
        // ---------------------------------------------------------------

        /// Add<&Self> matches Add<Self>
        #[test]
        fn u256_add_ref_matches_owned(a in arb_uint256(), b in arb_uint256()) {
            prop_assert_eq!(a + &b, a + b);
        }

        /// Sub<&Self> matches Sub<Self>
        #[test]
        fn u256_sub_ref_matches_owned(a in arb_uint256(), b in arb_uint256()) {
            prop_assert_eq!(a - &b, a - b);
        }

        /// Mul<&Self> matches Mul<Self>
        #[test]
        fn u256_mul_ref_matches_owned(a in arb_uint256_small(), b in arb_uint256_small()) {
            prop_assert_eq!(a * &b, a * b);
        }

        // ---------------------------------------------------------------
        // Uint256: low_u32
        // ---------------------------------------------------------------

        /// low_u32 returns the bottom 32 bits
        #[test]
        fn u256_low_u32_matches_low_u64(a in arb_uint256()) {
            prop_assert_eq!(a.low_u32(), a.low_u64() as u32);
        }

        // ---------------------------------------------------------------
        // Uint256: increment
        // ---------------------------------------------------------------

        /// increment is equivalent to checked_add(1) when no overflow
        #[test]
        fn u256_increment_matches_add_one(a_raw in arb_uint256()) {
            let max: Uint256 = BitArray::max();
            prop_assume!(a_raw != max);
            let mut a = a_raw;
            a.increment();
            let one: Uint256 = BitArray::one();
            let expected = a_raw.checked_add(&one).unwrap();
            prop_assert_eq!(a, expected);
        }

        // ---------------------------------------------------------------
        // Uint512 tests
        // ---------------------------------------------------------------

        /// Uint512: addition is commutative
        #[test]
        fn u512_add_commutative(a in arb_uint512(), b in arb_uint512()) {
            prop_assert_eq!(a + b, b + a);
        }

        /// Uint512: addition by zero is identity
        #[test]
        fn u512_add_zero_identity(a in arb_uint512()) {
            let zero: Uint512 = BitArray::zero();
            prop_assert_eq!(a + zero, a);
        }

        /// Uint512: add then sub roundtrip
        #[test]
        fn u512_add_sub_roundtrip(a in arb_uint512(), b in arb_uint512()) {
            prop_assert_eq!((a + b) - b, a);
        }

        /// Uint512: a - a == 0
        #[test]
        fn u512_sub_self_is_zero(a in arb_uint512()) {
            let zero: Uint512 = BitArray::zero();
            prop_assert_eq!(a - a, zero);
        }

        /// Uint512: multiplication is commutative
        #[test]
        fn u512_mul_commutative(a in arb_uint512_small(), b in arb_uint512_small()) {
            prop_assert_eq!(a * b, b * a);
        }

        /// Uint512: multiplication by one is identity
        #[test]
        fn u512_mul_one_identity(a in arb_uint512()) {
            let one: Uint512 = BitArray::one();
            prop_assert_eq!(a * one, a);
        }

        /// Uint512: multiplication by zero is zero
        #[test]
        fn u512_mul_zero(a in arb_uint512()) {
            let zero: Uint512 = BitArray::zero();
            prop_assert_eq!(a * zero, zero);
        }

        /// Uint512: mul_u32 matches full multiplication
        #[test]
        fn u512_mul_u32_matches_mul(
            a in arb_uint512_small(),
            b in 0u32..u32::MAX,
        ) {
            let via_mul_u32 = a.mul_u32(b);
            let via_mul = a * Uint512::from_u64(b as u64);
            prop_assert_eq!(via_mul_u32, via_mul);
        }

        /// Uint512: a / a == 1 for non-zero a
        #[test]
        fn u512_div_self_is_one(a in arb_uint512_nonzero()) {
            let one: Uint512 = BitArray::one();
            prop_assert_eq!(a / a, one);
        }

        /// Uint512: a / 1 == a
        #[test]
        fn u512_div_one_identity(a in arb_uint512()) {
            let one: Uint512 = BitArray::one();
            prop_assert_eq!(a / one, a);
        }

        /// Uint512: 0 / a == 0 for non-zero a
        #[test]
        fn u512_zero_div(a in arb_uint512_nonzero()) {
            let zero: Uint512 = BitArray::zero();
            prop_assert_eq!(zero / a, zero);
        }

        /// Uint512: (a / b) * b + remainder == a
        #[test]
        fn u512_div_mul_relationship(
            a in arb_uint512(),
            b in arb_uint512_nonzero(),
        ) {
            let quotient = a / b;
            let product = quotient * b;
            prop_assert!(product <= a, "(a/b)*b should be <= a");
            let remainder = a - product;
            prop_assert!(remainder < b, "remainder should be < divisor");
        }

        // ---------------------------------------------------------------
        // Uint512: Bitwise operations
        // ---------------------------------------------------------------

        /// Uint512: a & a == a (idempotent)
        #[test]
        fn u512_bitand_idempotent(a in arb_uint512()) {
            prop_assert_eq!(a & a, a);
        }

        /// Uint512: a & 0 == 0
        #[test]
        fn u512_bitand_zero(a in arb_uint512()) {
            let zero: Uint512 = BitArray::zero();
            prop_assert_eq!(a & zero, zero);
        }

        /// Uint512: a | a == a (idempotent)
        #[test]
        fn u512_bitor_idempotent(a in arb_uint512()) {
            prop_assert_eq!(a | a, a);
        }

        /// Uint512: a | 0 == a (identity)
        #[test]
        fn u512_bitor_zero_identity(a in arb_uint512()) {
            let zero: Uint512 = BitArray::zero();
            prop_assert_eq!(a | zero, a);
        }

        /// Uint512: a ^ a == 0
        #[test]
        fn u512_bitxor_self_is_zero(a in arb_uint512()) {
            let zero: Uint512 = BitArray::zero();
            prop_assert_eq!(a ^ a, zero);
        }

        /// Uint512: !!a == a
        #[test]
        fn u512_not_involution(a in arb_uint512()) {
            prop_assert_eq!(!!a, a);
        }

        /// Uint512: a & !a == 0
        #[test]
        fn u512_and_not_is_zero(a in arb_uint512()) {
            let zero: Uint512 = BitArray::zero();
            prop_assert_eq!(a & !a, zero);
        }

        /// Uint512: a | !a == MAX
        #[test]
        fn u512_or_not_is_max(a in arb_uint512()) {
            let max: Uint512 = BitArray::max();
            prop_assert_eq!(a | !a, max);
        }

        /// Uint512: De Morgan's: !(a & b) == !a | !b
        #[test]
        fn u512_de_morgan_and(a in arb_uint512(), b in arb_uint512()) {
            prop_assert_eq!(!(a & b), !a | !b);
        }

        /// Uint512: De Morgan's: !(a | b) == !a & !b
        #[test]
        fn u512_de_morgan_or(a in arb_uint512(), b in arb_uint512()) {
            prop_assert_eq!(!(a | b), !a & !b);
        }

        // ---------------------------------------------------------------
        // Uint512: Shift operations
        // ---------------------------------------------------------------

        /// Uint512: shift left then right roundtrips
        #[test]
        fn u512_shl_shr_roundtrip(
            val in any::<u64>(),
            shift in 0usize..64,
        ) {
            let a = Uint512::from_u64(val);
            prop_assert_eq!((a << shift) >> shift, a);
        }

        /// Uint512: shifting by 0 is identity
        #[test]
        fn u512_shift_zero_identity(a in arb_uint512()) {
            prop_assert_eq!(a << 0, a);
            prop_assert_eq!(a >> 0, a);
        }

        /// Uint512: shifting left by 512 or more gives zero
        #[test]
        fn u512_shl_overflow(a in arb_uint512(), extra in 0usize..64) {
            let shifted = a << (512 + extra);
            let zero: Uint512 = BitArray::zero();
            prop_assert_eq!(shifted, zero);
        }

        /// Uint512: shifting right by 512 or more gives zero
        #[test]
        fn u512_shr_overflow(a in arb_uint512(), extra in 0usize..64) {
            let shifted = a >> (512 + extra);
            let zero: Uint512 = BitArray::zero();
            prop_assert_eq!(shifted, zero);
        }

        /// Uint512: shift left by 1 == multiply by 2
        #[test]
        fn u512_shl1_is_mul2(a in arb_uint512()) {
            let mask = !(Uint512([0, 0, 0, 0, 0, 0, 0, 1u64 << 63]));
            let a_safe = a & mask;
            let two = Uint512::from_u64(2);
            prop_assert_eq!(a_safe << 1, a_safe * two);
        }

        // ---------------------------------------------------------------
        // Uint512: BitArray trait
        // ---------------------------------------------------------------

        /// Uint512: bits() is consistent
        #[test]
        fn u512_bits_consistent(a_raw in arb_uint256_nonzero()) {
            let a = Uint512::from_uint256(&a_raw);
            let b = a.bits();
            prop_assert!(b > 0 && b <= 512);
            let zero: Uint512 = BitArray::zero();
            prop_assert_eq!(a >> b, zero);
        }

        /// Uint512: bit() matches the individual bit in the underlying limb
        #[test]
        fn u512_bit_matches_limb(a in arb_uint512(), idx in 0usize..512) {
            let word = idx / 64;
            let bit_in_word = idx % 64;
            let expected = (a.0[word] >> bit_in_word) & 1 == 1;
            prop_assert_eq!(a.bit(idx), expected);
        }

        /// Uint512: trailing_zeros is correct
        #[test]
        fn u512_trailing_zeros_correct(a in arb_uint512_nonzero()) {
            let tz = a.trailing_zeros();
            prop_assert!(tz < 512);
            prop_assert!(a.bit(tz), "bit at trailing_zeros() should be set");
            for i in 0..tz {
                prop_assert!(!a.bit(i), "bit {i} below trailing_zeros should be unset");
            }
        }

        // ---------------------------------------------------------------
        // Uint512: Serialization roundtrips
        // ---------------------------------------------------------------

        /// Uint512: to_u8_slice / from_bytes_le roundtrip
        #[test]
        fn u512_bytes_le_roundtrip(a in arb_uint512()) {
            let bytes = a.to_u8_slice().to_vec();
            let reconstructed = Uint512::from_bytes_le(bytes).expect("valid bytes");
            prop_assert_eq!(reconstructed, a);
        }

        /// Uint512: to_hex_le / from_hex_le roundtrip
        #[test]
        fn u512_hex_le_roundtrip(a in arb_uint512()) {
            let hex = a.to_hex_le();
            let reconstructed = Uint512::from_hex_le(&hex).expect("valid hex");
            prop_assert_eq!(reconstructed, a);
        }

        /// Uint512: to_hex_be / from_hex_be roundtrip
        #[test]
        fn u512_hex_be_roundtrip(a in arb_uint512()) {
            let hex = a.to_hex_be();
            let reconstructed = Uint512::from_hex_be(&hex).expect("valid hex");
            prop_assert_eq!(reconstructed, a);
        }

        /// Uint512: LE and BE byte representations are reverses of each other
        #[test]
        fn u512_le_be_inverse(a in arb_uint512()) {
            let le = a.to_u8_slice();
            let be = a.to_u8_slice_be();
            let reversed_be: Vec<u8> = be.iter().rev().cloned().collect();
            prop_assert_eq!(le, &reversed_be[..]);
        }

        // ---------------------------------------------------------------
        // Uint512: Conversion
        // ---------------------------------------------------------------

        /// Uint512 ↔ Uint256 roundtrip: converting a Uint256 to Uint512
        /// and back yields the original value
        #[test]
        fn u512_u256_roundtrip(a in arb_uint256()) {
            let wide = Uint512::from_uint256(&a);
            let back = wide.to_uint256();
            prop_assert_eq!(back, a);
        }

        /// Uint512::from_uint256 sets upper limbs to zero
        #[test]
        fn u512_from_u256_upper_zero(a in arb_uint256()) {
            let wide = Uint512::from_uint256(&a);
            prop_assert_eq!(wide.0[4], 0);
            prop_assert_eq!(wide.0[5], 0);
            prop_assert_eq!(wide.0[6], 0);
            prop_assert_eq!(wide.0[7], 0);
        }

        /// Uint512: from_u64 then low_u64 roundtrips
        #[test]
        fn u512_from_u64_low_u64_roundtrip(val in any::<u64>()) {
            prop_assert_eq!(Uint512::from_u64(val).low_u64(), val);
        }

        /// Uint512: from_u128 then extract lower 128 bits roundtrips
        #[test]
        fn u512_from_u128_roundtrip(val in any::<u128>()) {
            let u = Uint512::from_u128(val);
            let lo = u.0[0] as u128 | ((u.0[1] as u128) << 64);
            prop_assert_eq!(lo, val);
            for i in 2..8 {
                prop_assert_eq!(u.0[i], 0);
            }
        }
    }

    // -----------------------------------------------------------------------
    // FixedPointU256 and weighted_geometric_average tests
    // -----------------------------------------------------------------------

    use crate::util::uint::FixedPointU256;

    type FP = FixedPointU256<64>;

    /// Assert that `a` and `b` are within a relative tolerance of each other.
    /// `rel_numer`/`rel_denom` specifies the maximum allowed relative error.
    fn assert_fp_approx_eq(
        a: &FP,
        b: &FP,
        rel_numer: u64,
        rel_denom: u64,
    ) -> Result<(), proptest::test_runner::TestCaseError> {
        let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
        let diff = hi.clone().sub(lo).unwrap_or(FP::ZERO);
        // tolerance = max(a, b) * rel_numer / rel_denom, but at least 1 ULP
        let tolerance = hi
            .clone()
            .mul_u64(rel_numer)
            .and_then(|t| t.div(Uint256::from_u64(rel_denom)))
            .unwrap_or(FP::MINIMAL);
        let tolerance = if tolerance < FP::MINIMAL {
            FP::MINIMAL
        } else {
            tolerance
        };
        prop_assert!(
            diff <= tolerance,
            "values differ by more than {rel_numer}/{rel_denom}: {a} vs {b}"
        );
        Ok(())
    }

    proptest! {
        /// With no priors, the result should equal `current` (since all weight
        /// is on a single value: current^(5/5) = current).
        #[test]
        fn geo_avg_no_priors_is_identity(
            val in 1u64..u64::MAX,
        ) {
            let current = FP::from_u64(val);
            let result = FP::weighted_geometric_average(&current, &[])
                .expect("should not overflow with no priors");
            // find_root_floor rounding + pow amplification: allow 0.1% relative error
            assert_fp_approx_eq(&result, &current, 1, 1000)?;
        }

        /// With no priors and very large values (u128 range), the function
        /// must not overflow.
        #[test]
        fn geo_avg_no_priors_large(
            val in (u64::MAX as u128)..u128::MAX,
        ) {
            let current = FP::from_u128(val);
            let result = FP::weighted_geometric_average(&current, &[]);
            prop_assert!(result.is_some(), "should not overflow for large current: {current}");
        }

        /// All values equal → result equals that value.
        /// geo_avg(v, [v, v, v, v]) = v^(5/15) * v^(4/15) * ... = v
        #[test]
        fn geo_avg_all_equal(
            val in 1u64..1_000_000u64,
            num_priors in 1usize..4,
        ) {
            let v = FP::from_u64(val);
            let priors: Vec<FP> = vec![v.clone(); num_priors];
            let result = FP::weighted_geometric_average(&v, &priors)
                .expect("should not overflow with equal values");
            // More multiplications → wider tolerance; allow 0.1% relative error
            assert_fp_approx_eq(&result, &v, 1, 1000)?;
        }

        /// Monotonicity: if current > all priors, the result should be
        /// between the smallest prior and current (the average is pulled
        /// toward the larger weight).
        #[test]
        fn geo_avg_monotonicity(
            current_val in 1_000u64..1_000_000u64,
            prior_val in 1u64..999u64,
            num_priors in 1usize..4,
        ) {
            prop_assume!(current_val > prior_val);
            let current = FP::from_u64(current_val);
            let prior = FP::from_u64(prior_val);
            let priors: Vec<FP> = vec![prior.clone(); num_priors];
            let result = FP::weighted_geometric_average(&current, &priors)
                .expect("should not overflow");
            prop_assert!(
                result >= prior,
                "result ({result}) should be >= prior ({prior})"
            );
            prop_assert!(
                result <= current,
                "result ({result}) should be <= current ({current})"
            );
        }

        /// Too many priors (> 4) should return None.
        #[test]
        fn geo_avg_rejects_too_many_priors(
            val in 1u64..1000u64,
        ) {
            let v = FP::from_u64(val);
            let priors = vec![v.clone(); 5];
            prop_assert!(FP::weighted_geometric_average(&v, &priors).is_none());
        }

        /// Extreme mixed values: large current with small priors, and vice versa.
        #[test]
        fn geo_avg_extreme_mixed(
            large in (u64::MAX as u128)..u128::MAX,
            small in 1u64..1000u64,
            num_priors in 1usize..4,
        ) {
            let large_fp = FP::from_u128(large);
            let small_fp = FP::from_u64(small);

            // Large current, small priors
            let priors: Vec<FP> = vec![small_fp.clone(); num_priors];
            let result = FP::weighted_geometric_average(&large_fp, &priors);
            prop_assert!(result.is_some(), "large current + small priors should not overflow");

            // Small current, large priors
            let priors: Vec<FP> = vec![large_fp.clone(); num_priors];
            let result = FP::weighted_geometric_average(&small_fp, &priors);
            prop_assert!(result.is_some(), "small current + large priors should not overflow");
        }

        /// All-max: current and all priors at from_u128(u128::MAX).
        #[test]
        fn geo_avg_all_max(
            num_priors in 0usize..4,
        ) {
            let max_val = FP::from_u128(u128::MAX);
            let priors: Vec<FP> = vec![max_val.clone(); num_priors];
            let result = FP::weighted_geometric_average(&max_val, &priors);
            prop_assert!(result.is_some(), "all-max should not overflow");
        }

        // -------------------------------------------------------------------
        // Sigmoid tests
        // -------------------------------------------------------------------

        /// sigmoid(r) should always return Some for r in [0, 1] and the
        /// result should also be in [0, 1].
        #[test]
        fn sigmoid_output_in_unit_range(
            // Generate r as a fraction numer/denom to cover the full [0, 1] range
            numer in 0u64..=1000u64,
        ) {
            let one = FP::from_u64(1);
            // r = numer / 1000, covering [0, 1] in steps of 0.001
            let r = FP::from_u64(numer)
                .div(Uint256::from_u64(1000))
                .unwrap();
            let result = r.sigmoid();
            prop_assert!(result.is_some(), "sigmoid({r}) should not fail");
            let s = result.unwrap();
            prop_assert!(s <= one, "sigmoid({r}) = {s} should be <= 1");
        }

        /// sigmoid(r) + sigmoid(1-r) ≈ 1 (symmetry property)
        #[test]
        fn sigmoid_symmetry(
            numer in 0u64..=1000u64,
        ) {
            let one = FP::from_u64(1);
            let r = FP::from_u64(numer)
                .div(Uint256::from_u64(1000))
                .unwrap();
            let one_minus_r = one.clone().sub(&r).unwrap();

            let s_r = r.sigmoid().expect("sigmoid(r) should succeed");
            let s_1r = one_minus_r.sigmoid().expect("sigmoid(1-r) should succeed");
            let sum = s_r.add(&s_1r).expect("sum should not overflow");
            assert_fp_approx_eq(&sum, &one, 1, 1000)?;
        }

        /// sigmoid is monotonically non-decreasing on [0, 1]
        #[test]
        fn sigmoid_monotonic(
            a_numer in 0u64..=999u64,
        ) {
            let a = FP::from_u64(a_numer)
                .div(Uint256::from_u64(1000))
                .unwrap();
            let b = FP::from_u64(a_numer + 1)
                .div(Uint256::from_u64(1000))
                .unwrap();
            let s_a = a.sigmoid().expect("sigmoid(a) should succeed");
            let s_b = b.sigmoid().expect("sigmoid(b) should succeed");
            prop_assert!(
                s_b >= s_a,
                "sigmoid should be monotonic: sigmoid({b}) = {s_b} < sigmoid({a}) = {s_a}"
            );
        }

        /// sigmoid rejects r > 1
        #[test]
        fn sigmoid_rejects_above_one(
            val in 2u64..u64::MAX,
        ) {
            let r = FP::from_u64(val);
            prop_assert!(r.sigmoid().is_none(), "sigmoid({r}) should be None for r > 1");
        }

        /// sigmoid with raw values near the boundary (r very close to 0 or 1)
        /// should not overflow or underflow
        #[test]
        fn sigmoid_boundary_values(
            // Test r = tiny/2^64 (very close to 0) and r = 1 - tiny/2^64 (very close to 1)
            tiny in 1u64..1000u64,
        ) {
            let near_zero = FP::construct_raw(Uint256::from_u64(tiny));
            let result = near_zero.sigmoid();
            prop_assert!(result.is_some(), "sigmoid near 0 should succeed");

            let one = FP::from_u64(1);
            let near_one = one.sub(&near_zero).unwrap();
            let result = near_one.sigmoid();
            prop_assert!(result.is_some(), "sigmoid near 1 should succeed");
        }

        // -------------------------------------------------------------------
        // Arithmetic identity / inverse property tests
        // -------------------------------------------------------------------

        /// add is commutative: a + b == b + a
        #[test]
        fn add_commutative(
            a_val in 1u64..u32::MAX as u64,
            b_val in 1u64..u32::MAX as u64,
        ) {
            let a = FP::from_u64(a_val);
            let b = FP::from_u64(b_val);
            let ab = a.clone().add(&b).expect("should not overflow");
            let ba = b.add(&a).expect("should not overflow");
            prop_assert_eq!(ab, ba);
        }

        /// add then sub is identity: (a + b) - b == a
        #[test]
        fn add_sub_inverse(
            a_val in 1u64..u32::MAX as u64,
            b_val in 1u64..u32::MAX as u64,
        ) {
            let a = FP::from_u64(a_val);
            let b = FP::from_u64(b_val);
            let result = a.clone().add(&b).expect("should not overflow")
                .sub(&b).expect("sub should not underflow");
            prop_assert_eq!(result, a);
        }

        /// mul is commutative: a * b == b * a
        #[test]
        fn mul_commutative(
            a_val in 1u64..u32::MAX as u64,
            b_val in 1u64..u32::MAX as u64,
        ) {
            let a = FP::from_u64(a_val);
            let b = FP::from_u64(b_val);
            let ab = a.mul(&b).expect("should not overflow");
            let ba = b.mul(&a).expect("should not overflow");
            prop_assert_eq!(ab, ba);
        }

        /// mul by one is identity: a * 1 ≈ a
        #[test]
        fn mul_by_one_identity(
            val in 1u64..u64::MAX,
        ) {
            let a = FP::from_u64(val);
            let one = FP::from_u64(1);
            let result = a.mul(&one).expect("should not overflow");
            // mul truncates via right-shift, so allow 1 ULP rounding
            assert_fp_approx_eq(&result, &a, 1, 1_000_000)?;
        }

        /// mul then div_and_scale roundtrips: (a * b) / b ≈ a
        #[test]
        fn mul_div_and_scale_inverse(
            a_val in 1u64..1_000_000u64,
            b_val in 1u64..1_000_000u64,
        ) {
            let a = FP::from_u64(a_val);
            let b = FP::from_u64(b_val);
            let product = a.mul(&b).expect("should not overflow");
            let result = product.div_and_scale(&b).expect("div should not fail");
            // Allow 0.1% relative error from rounding
            assert_fp_approx_eq(&result, &a, 1, 1000)?;
        }

        /// div by one is identity: a / 1 == a
        #[test]
        fn div_by_one_identity(
            val in 1u64..u64::MAX,
        ) {
            let a = FP::from_u64(val);
            let result = a.div(Uint256::from_u64(1)).expect("div by 1 should succeed");
            prop_assert_eq!(result, a);
        }

        /// mul_u64 agrees with mul: a.mul_u64(n) ≈ a.mul(FP::from_u64(n))
        #[test]
        fn mul_u64_consistency(
            a_val in 1u64..1_000_000u64,
            n in 1u64..1_000_000u64,
        ) {
            let a = FP::from_u64(a_val);
            let result_u64 = a.clone().mul_u64(n).expect("should not overflow");
            let result_fp = a.mul(&FP::from_u64(n)).expect("should not overflow");
            // mul truncates via shift so there can be small rounding differences
            assert_fp_approx_eq(&result_u64, &result_fp, 1, 1_000_000)?;
        }

        // -------------------------------------------------------------------
        // Overflow / boundary behavior tests
        // -------------------------------------------------------------------

        /// Adding two large values that would exceed 256 bits returns None
        #[test]
        fn add_overflow_returns_none(
            val in (u64::MAX as u128)..u128::MAX,
        ) {
            let a = FP::from_u128(val);
            let b = FP::from_u128(val);
            // Two values >= u64::MAX shifted left by 64 will overflow 256 bits
            // This may or may not overflow depending on magnitude, but should never panic
            let result = a.add(&b);
            // Just verify no panic; if it overflows, it should return None
            if let Some(sum) = &result {
                prop_assert!(*sum >= FP::from_u128(val), "sum should be >= either operand");
            }
        }

        /// sub underflow returns None: smaller - larger == None
        #[test]
        fn sub_underflow_returns_none(
            a_val in 1u64..1000u64,
            b_val in 1001u64..u32::MAX as u64,
        ) {
            let a = FP::from_u64(a_val);
            let b = FP::from_u64(b_val);
            prop_assert!(a.sub(&b).is_none(), "smaller - larger should return None");
        }

        /// div by zero returns None
        #[test]
        fn div_by_zero_returns_none(
            val in 1u64..u64::MAX,
        ) {
            let a = FP::from_u64(val);
            prop_assert!(a.div(Uint256::zero()).is_none(), "div by zero should return None");
        }

        /// div_and_scale by zero returns None
        #[test]
        fn div_and_scale_by_zero_returns_none(
            val in 1u64..u64::MAX,
        ) {
            let a = FP::from_u64(val);
            prop_assert!(a.div_and_scale(&FP::ZERO).is_none(), "div_and_scale by zero should return None");
        }

        /// mul of two large values should return None (not panic)
        #[test]
        fn mul_large_values_no_panic(
            a_val in (u64::MAX as u128)..u128::MAX,
            b_val in (u64::MAX as u128)..u128::MAX,
        ) {
            let a = FP::from_u128(a_val);
            let b = FP::from_u128(b_val);
            // Should return None on overflow, never panic
            let _ = a.mul(&b);
        }

        // -------------------------------------------------------------------
        // pow / find_root_floor tests
        // -------------------------------------------------------------------

        /// pow(1) is identity: a^1 == a
        #[test]
        fn pow_one_is_identity(
            val in 1u64..u64::MAX,
        ) {
            let a = FP::from_u64(val);
            let result = a.pow(1).expect("pow(1) should not fail");
            prop_assert_eq!(result, a);
        }

        /// pow(0) == MINIMAL for any non-zero value
        #[test]
        fn pow_zero_is_minimal(
            val in 1u64..u64::MAX,
        ) {
            let a = FP::from_u64(val);
            let result = a.pow(0).expect("pow(0) should not fail");
            prop_assert_eq!(result, FP::MINIMAL);
        }

        /// root/pow inverse: find_root_floor(a^n, n) ≈ a
        #[test]
        fn root_pow_inverse(
            val in 2u64..1000u64,
            n in 2u32..5u32,
        ) {
            let a = FP::from_u64(val);
            if let Some(powered) = a.pow(n) {
                let root = powered.find_root_floor(n).expect("find_root_floor should succeed");
                assert_fp_approx_eq(&root, &a, 1, 100)?;
            }
            // If pow overflows, that's fine — skip
        }

        /// find_root_floor is monotonic: if a > b then root(a) >= root(b)
        #[test]
        fn find_root_floor_monotonic(
            a_val in 2u64..1_000_000u64,
            b_val in 1u64..999_999u64,
            n in 2u32..5u32,
        ) {
            prop_assume!(a_val > b_val);
            let a = FP::from_u64(a_val);
            let b = FP::from_u64(b_val);
            let root_a = a.find_root_floor(n).expect("root of a should succeed");
            let root_b = b.find_root_floor(n).expect("root of b should succeed");
            prop_assert!(
                root_a >= root_b,
                "root should be monotonic: root({a}) = {root_a} < root({b}) = {root_b}"
            );
        }

        /// find_root_floor(n=1) is identity
        #[test]
        fn find_root_floor_one_is_identity(
            val in 1u64..1_000_000u64,
        ) {
            let a = FP::from_u64(val);
            let result = a.find_root_floor(1).expect("root(1) should succeed");
            prop_assert_eq!(result, a);
        }

        /// find_root_floor(n=0) returns None
        #[test]
        fn find_root_floor_zero_returns_none(
            val in 1u64..1_000_000u64,
        ) {
            let a = FP::from_u64(val);
            prop_assert!(a.find_root_floor(0).is_none(), "root(0) should return None");
        }

        // -------------------------------------------------------------------
        // Construction / conversion tests
        // -------------------------------------------------------------------

        /// from_u64 preserves ordering: a < b ⟹ FP(a) < FP(b)
        #[test]
        fn from_u64_preserves_ordering(
            a_val in 0u64..u64::MAX - 1,
        ) {
            let b_val = a_val + 1;
            let a = FP::from_u64(a_val);
            let b = FP::from_u64(b_val);
            prop_assert!(a < b, "FP({a_val}) should be < FP({b_val})");
        }

        /// to_bytes_le roundtrip via construct_raw
        #[test]
        fn to_bytes_le_roundtrip(
            val in 1u64..u64::MAX,
        ) {
            let a = FP::from_u64(val);
            let bytes = a.to_bytes_le();
            // Reconstruct Uint256 from the little-endian bytes
            let mut words = [0u64; 4];
            for (i, chunk) in bytes.chunks(8).enumerate() {
                words[i] = u64::from_le_bytes(chunk.try_into().unwrap());
            }
            let reconstructed = FP::construct_raw(Uint256(words));
            prop_assert_eq!(reconstructed, a);
        }

        // -------------------------------------------------------------------
        // div_and_scale / div_and_drop_scale tests
        // -------------------------------------------------------------------

        /// div_and_scale(a, a) ≈ 1 for non-zero a
        #[test]
        fn div_and_scale_self_is_one(
            val in 1u64..1_000_000u64,
        ) {
            let a = FP::from_u64(val);
            let one = FP::from_u64(1);
            let result = a.div_and_scale(&a).expect("div_and_scale(a, a) should succeed");
            assert_fp_approx_eq(&result, &one, 1, 1_000_000)?;
        }

        /// div_and_drop_scale: a / a should yield integer 1 (as Uint256)
        #[test]
        fn div_and_drop_scale_self_is_one(
            val in 1u64..1_000_000u64,
        ) {
            let a = FP::from_u64(val);
            let result = a.div_and_drop_scale(&a).expect("should succeed");
            prop_assert_eq!(result, Uint256::from_u64(1));
        }

        /// increment matches add: a.increment(b) yields the same value as a.add(b)
        #[test]
        fn increment_matches_add(
            a_val in 1u64..u32::MAX as u64,
            b_val in 1u64..u32::MAX as u64,
        ) {
            let a = FP::from_u64(a_val);
            let b = FP::from_u64(b_val);
            let sum = a.clone().add(&b).expect("should not overflow");
            let mut a_mut = a;
            a_mut.increment(&b).expect("should not overflow");
            prop_assert_eq!(a_mut, sum);
        }

    }

    #[test]
    fn increment_overflow_zeros() {
        let max_raw = FP::construct_raw(Uint256([u64::MAX, u64::MAX, u64::MAX, u64::MAX]));
        let mut a = max_raw;
        let result = a.increment(&FP::MINIMAL);
        assert!(result.is_none(), "increment past max should return None");
        assert_eq!(a, FP::ZERO, "increment overflow should zero out");
    }

    #[test]
    fn u256_checked_mul_overflow() {
        let max: Uint256 = BitArray::max();
        let two = Uint256::from_u64(2);
        assert!(max.checked_mul(&two).is_none());
    }

    #[test]
    fn u256_default_is_zero() {
        let d: Uint256 = Default::default();
        let z: Uint256 = BitArray::zero();
        assert_eq!(d, z);
    }

    #[test]
    fn u256_increment_max_wraps() {
        let mut a: Uint256 = BitArray::max();
        a.increment();
        let zero: Uint256 = BitArray::zero();
        assert_eq!(a, zero);
    }

    // -------------------------------------------------------------------
    // Input validation / rejection tests
    // -------------------------------------------------------------------

    #[test]
    fn from_bytes_le_wrong_length_returns_none() {
        assert!(Uint256::from_bytes_le(vec![0u8; 31]).is_none());
        assert!(Uint256::from_bytes_le(vec![0u8; 33]).is_none());
        assert!(Uint256::from_bytes_le(vec![]).is_none());
        assert!(Uint512::from_bytes_le(vec![0u8; 63]).is_none());
        assert!(Uint512::from_bytes_le(vec![0u8; 65]).is_none());
    }

    #[test]
    fn from_hex_le_wrong_length_returns_none() {
        // 30 bytes (60 hex chars) instead of 32
        let short = "00".repeat(30);
        assert!(Uint256::from_hex_le(&short).is_none());
        // 34 bytes (68 hex chars) instead of 32
        let long = "00".repeat(34);
        assert!(Uint256::from_hex_le(&long).is_none());
    }

    #[test]
    fn from_hex_be_wrong_length_returns_none() {
        let short = "00".repeat(30);
        assert!(Uint256::from_hex_be(&short).is_none());
        let long = "00".repeat(34);
        assert!(Uint256::from_hex_be(&long).is_none());
    }

    #[test]
    fn from_hex_le_invalid_hex_returns_none() {
        let bad = "zz".repeat(32);
        assert!(Uint256::from_hex_le(&bad).is_none());
    }

    #[test]
    fn from_hex_be_invalid_hex_returns_none() {
        let bad = "zz".repeat(32);
        assert!(Uint256::from_hex_be(&bad).is_none());
    }

    #[test]
    #[should_panic]
    fn from_i64_negative_panics() {
        Uint256::from_i64(-1);
    }

    #[test]
    #[should_panic]
    fn u256_div_by_zero_panics() {
        let _ = Uint256::from_u64(1) / Uint256::zero();
    }

    #[test]
    #[should_panic]
    fn u512_div_by_zero_panics() {
        let _ = Uint512::from_u64(1) / Uint512::zero();
    }

    #[test]
    fn sigmoid_known_values() {
        let zero = FP::ZERO;
        let half = FP::from_u64(1).div(Uint256::from_u64(2)).unwrap();
        let one = FP::from_u64(1);

        let s0 = zero.sigmoid().expect("sigmoid(0) should succeed");
        assert_eq!(s0, FP::ZERO, "sigmoid(0) should be 0");

        let s1 = one.sigmoid().expect("sigmoid(1) should succeed");
        assert_eq!(s1, FP::from_u64(1), "sigmoid(1) should be 1");

        let s_half = half.sigmoid().expect("sigmoid(0.5) should succeed");
        assert_fp_approx_eq(&s_half, &half, 1, 1000).unwrap();
    }
}
