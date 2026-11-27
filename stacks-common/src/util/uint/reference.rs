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

//! Reference arithmetic on little-endian `u64` words, written independently of the `Uint*`
//! implementations: carries and borrows go through `u128` in a single pass, and bits are read
//! straight from the words.

/// Bit `index` of `words`; `false` past the most significant bit.
#[cfg(kani)]
pub fn bit<const N: usize>(words: &[u64; N], index: usize) -> bool {
    index < 64 * N && (words[index / 64] >> (index % 64)) & 1 == 1
}

/// `a + b`, wrapping at `2^(64·N)`.
#[cfg(kani)]
pub fn add<const N: usize>(a: &[u64; N], b: &[u64; N]) -> [u64; N] {
    let mut out = [0u64; N];
    let mut carry = 0u128;
    for i in 0..N {
        let sum = u128::from(a[i]) + u128::from(b[i]) + carry;
        out[i] = sum as u64;
        carry = sum >> 64;
    }
    out
}

/// `a - b`, wrapping at `2^(64·N)`, and whether it borrowed (i.e. `a < b`).
pub fn sub<const N: usize>(a: &[u64; N], b: &[u64; N]) -> ([u64; N], bool) {
    let mut out = [0u64; N];
    let mut borrow = false;
    for i in 0..N {
        let (diff, borrow_a) = a[i].overflowing_sub(b[i]);
        let (diff, borrow_b) = diff.overflowing_sub(u64::from(borrow));
        out[i] = diff;
        borrow = borrow_a || borrow_b;
    }
    (out, borrow)
}

/// `a · m` for a single-word multiplier, wrapping at `2^(64·N)`.
#[cfg(test)]
pub fn mul_word<const N: usize>(a: &[u64; N], m: u64) -> [u64; N] {
    let mut out = [0u64; N];
    let mut carry = 0u128;
    for i in 0..N {
        let product = u128::from(a[i]) * u128::from(m) + carry;
        out[i] = product as u64;
        carry = product >> 64;
    }
    out
}

/// The full `2·N`-word product `a · b`, least significant word first.
#[cfg(test)]
pub fn mul_full<const N: usize>(a: &[u64; N], b: &[u64; N]) -> Vec<u64> {
    let mut out = vec![0u64; 2 * N];
    for i in 0..N {
        let mut carry = 0u128;
        for j in 0..N {
            let acc = u128::from(out[i + j]) + u128::from(a[i]) * u128::from(b[j]) + carry;
            out[i + j] = acc as u64;
            carry = acc >> 64;
        }
        out[i + N] = carry as u64;
    }
    out
}
