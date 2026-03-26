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

//! Arbitrary-precision unsigned integer arithmetic for the weighted geometric mean
//! computation in the STX/BTC ratio smoothing. Represents big integers as little-endian
//! `Vec<u64>` limbs.

use stacks_common::util::uint::Uint256;

/// Remove trailing zero limbs, keeping at least one limb.
pub fn normalize(value: &mut Vec<u64>) {
    while value.len() > 1 && value.last().copied() == Some(0) {
        value.pop();
    }
}

/// Compare two big integers (little-endian limb representation).
pub fn cmp_bigint(a: &[u64], b: &[u64]) -> std::cmp::Ordering {
    if a.len() != b.len() {
        return a.len().cmp(&b.len());
    }
    a.iter().rev().cmp(b.iter().rev())
}

/// Convert a `Uint256` to a normalized big integer.
pub fn bigint_from_uint256(value: &Uint256) -> Vec<u64> {
    let mut result = vec![value.0[0], value.0[1], value.0[2], value.0[3]];
    normalize(&mut result);
    result
}

/// Schoolbook multiplication of two big integers.
pub fn mul_bigint(lhs: &[u64], rhs: &[u64]) -> Vec<u64> {
    if lhs.len() == 1 && lhs.first() == Some(&0) {
        return vec![0];
    }
    if rhs.len() == 1 && rhs.first() == Some(&0) {
        return vec![0];
    }

    let mut result = vec![0u64; lhs.len() + rhs.len()];
    for (i, lhs_limb) in lhs.iter().enumerate() {
        let mut carry = 0u128;
        {
            let (_, result_tail) = result.split_at_mut(i);

            for (slot, rhs_limb) in result_tail.iter_mut().zip(rhs.iter()) {
                let accum =
                    u128::from(*lhs_limb) * u128::from(*rhs_limb) + u128::from(*slot) + carry;
                *slot = accum as u64;
                carry = accum >> 64;
            }

            for slot in result_tail.iter_mut().skip(rhs.len()) {
                if carry == 0 {
                    break;
                }
                let accum = u128::from(*slot) + carry;
                *slot = accum as u64;
                carry = accum >> 64;
            }
        }

        while carry > 0 {
            result.push(carry as u64);
            carry >>= 64;
        }
    }

    normalize(&mut result);
    result
}

/// Exponentiation by squaring for big integers.
pub fn pow_bigint(base: &[u64], exponent: u32) -> Vec<u64> {
    let mut result = vec![1u64];
    let mut power = base.to_vec();
    let mut exp = exponent;
    while exp > 0 {
        if (exp & 1) == 1 {
            result = mul_bigint(&result, &power);
        }
        exp >>= 1;
        if exp > 0 {
            power = mul_bigint(&power, &power);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mul_identity() {
        assert_eq!(mul_bigint(&[1], &[42]), vec![42]);
        assert_eq!(mul_bigint(&[42], &[1]), vec![42]);
    }

    #[test]
    fn mul_zero() {
        assert_eq!(mul_bigint(&[0], &[999]), vec![0]);
        assert_eq!(mul_bigint(&[999], &[0]), vec![0]);
    }

    #[test]
    fn mul_small() {
        // 3 * 7 = 21
        assert_eq!(mul_bigint(&[3], &[7]), vec![21]);
    }

    #[test]
    fn mul_overflow_single_limb() {
        // (2^64 - 1) * 2 = 2^65 - 2 → two limbs: [0xFFFF...FE, 1]
        let max = u64::MAX;
        let result = mul_bigint(&[max], &[2]);
        assert_eq!(result, vec![max - 1, 1]);
    }

    #[test]
    fn mul_multi_limb() {
        // (2^64) * (2^64) = 2^128
        // Represented as [0, 1] * [0, 1] = [0, 0, 1]
        let result = mul_bigint(&[0, 1], &[0, 1]);
        assert_eq!(result, vec![0, 0, 1]);
    }

    #[test]
    fn pow_zero_exponent() {
        assert_eq!(pow_bigint(&[42], 0), vec![1]);
    }

    #[test]
    fn pow_one_exponent() {
        assert_eq!(pow_bigint(&[42], 1), vec![42]);
    }

    #[test]
    fn pow_small() {
        // 3^5 = 243
        assert_eq!(pow_bigint(&[3], 5), vec![243]);
    }

    #[test]
    fn pow_large_base() {
        // (2^64)^2 = 2^128 → [0, 0, 1]
        let result = pow_bigint(&[0, 1], 2);
        assert_eq!(result, vec![0, 0, 1]);
    }

    #[test]
    fn cmp_equal() {
        assert_eq!(cmp_bigint(&[1, 2], &[1, 2]), std::cmp::Ordering::Equal);
    }

    #[test]
    fn cmp_different_lengths() {
        // Longer (more limbs) is always greater after normalization.
        assert_eq!(cmp_bigint(&[1, 0, 1], &[1, 2]), std::cmp::Ordering::Greater);
    }

    #[test]
    fn cmp_same_length_different_values() {
        // [1, 3] > [1, 2] because the most-significant limb (index 1) differs.
        assert_eq!(cmp_bigint(&[1, 3], &[1, 2]), std::cmp::Ordering::Greater);
        assert_eq!(cmp_bigint(&[1, 2], &[1, 3]), std::cmp::Ordering::Less);
    }

    #[test]
    fn normalize_removes_trailing_zeros() {
        let mut v = vec![5, 0, 0, 0];
        normalize(&mut v);
        assert_eq!(v, vec![5]);
    }

    #[test]
    fn normalize_keeps_single_zero() {
        let mut v = vec![0];
        normalize(&mut v);
        assert_eq!(v, vec![0]);
    }

    #[test]
    fn bigint_from_uint256_normalizes() {
        let val = Uint256::from_u64(42);
        let big = bigint_from_uint256(&val);
        assert_eq!(big, vec![42]);
    }
}
