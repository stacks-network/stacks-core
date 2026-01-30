// Copyright (C) 2025 Stacks Open Internet Foundation
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

//! MARF integration tests exercising behavior with compression always disabled.

use crate::tests::marf::marf_compress_dyn;

/// Test copied from `stacks-node::tests::signer::large_mempool_original_constant_fee`
/// Interesting because with full MARF compression produces patch nodes with 256 diffs (max diff allowed)
///
/// In this scenario, MARF compression is always disabled.
#[test]
#[ignore]
fn large_mempool_with_marf_compression() {
    marf_compress_dyn::utils::large_mempool_base(false, false);
}
