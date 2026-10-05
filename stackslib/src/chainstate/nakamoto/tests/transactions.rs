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

use clarity::types::StacksEpochId;
use clarity::util::hash::{MerkleTree, Sha512Trunc256Sum};

use crate::chainstate::stacks::Error as ChainstateError;
use crate::net::test::{TestEventObserver, TestPeer};
use crate::net::tests::inv::nakamoto::make_nakamoto_peers_from_invs_ext;

/// Creates a `TestPeer` that runs in the given epoch, which must be a Nakamoto epoch.
fn make_test_peer_for_epoch<'a>(
    epoch: StacksEpochId,
    observer: &'a TestEventObserver,
) -> TestPeer<'a> {
    let bitvecs = vec![
        // one reward cycle
        vec![true, true, true, true, true, true, true, true, true, true],
    ];

    let (peer, _) =
        make_nakamoto_peers_from_invs_ext(function_name!(), observer, bitvecs, |boot_plan| {
            boot_plan.with_epoch(epoch).with_pox_constants(10, 3)
        });

    peer
}

/// Create an otherwise valid transaction whose only fault is that its signature is the high-S
/// variant. Have a peer process the block with that transaction and return the result.
fn process_high_s_tx_in_epoch(epoch: StacksEpochId) -> Result<bool, ChainstateError> {
    let observer = TestEventObserver::new();
    let mut peer = make_test_peer_for_epoch(epoch, &observer);

    let private_key = peer.config.private_key.clone();

    let (block, ..) = peer.single_block_tenure(
        &private_key,
        |_| {},
        |_| {},
        |block| {
            // Modify the block so its first transaction has a high-S signature

            block.txs[0] = block.txs[0].with_negated_s_in_signature();

            // tweaking the signature changes the transaction id (which is
            // the main problem with high-S signatures), so we need to update
            // the transaction merkle root
            let txid_vecs: Vec<_> = block
                .txs
                .iter()
                .map(|tx| tx.txid().as_bytes().to_vec())
                .collect();

            let merkle_tree = MerkleTree::<Sha512Trunc256Sum>::new(&txid_vecs);
            let tx_merkle_root = merkle_tree.root();
            block.header.tx_merkle_root = tx_merkle_root;

            false // don't try to process, we'll do that ourselves as we might be expecting failure
        },
    );

    peer.try_process_block(&block)
}

/// Assert that pre-4.0, the peer accepts a block in which a transaction signature
/// is not normalized to a low S. While this was never allowed according to SIP 005,
/// it has worked (and there are a few dozen such transactions in mainnet), and thus
/// it has to remain allowed for old blocks.
#[test]
fn test_high_s_signature_transaction_accepted_before_epoch_4() {
    let result = process_high_s_tx_in_epoch(StacksEpochId::Epoch34);
    assert!(result.is_ok());
}

/// Assert that as of 4.0, the peer rejects a block in which a transaction signature
/// is not normalized to a low S.
#[test]
fn test_high_s_signature_transaction_not_accepted_in_epoch_4() {
    let result = process_high_s_tx_in_epoch(StacksEpochId::Epoch40);

    let Err(err) = result else {
        panic!("block with high-S transaction signature should not be accepted in epoch 4");
    };

    if !err.to_string().contains("Invalid signature: high-S") {
        panic!("block with high-S transaction signature caused unexpected error {err}");
    }
}
