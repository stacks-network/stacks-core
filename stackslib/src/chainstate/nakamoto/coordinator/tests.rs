// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2023 Stacks Open Internet Foundation
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

use crate::net::test::{TestPeer, TestPeerConfig};

use clarity::vm::types::PrincipalData;

use crate::chainstate::stacks::address::PoxAddress;
use crate::chainstate::stacks::boot::test::make_pox_4_lockup;
use crate::chainstate::stacks::CoinbasePayload;
use crate::chainstate::stacks::StacksTransaction;
use crate::chainstate::stacks::StacksTransactionSigner;
use crate::chainstate::stacks::TenureChangeCause;
use crate::chainstate::stacks::TransactionAnchorMode;
use crate::chainstate::stacks::TransactionAuth;
use crate::chainstate::stacks::TransactionPayload;
use crate::chainstate::stacks::TransactionVersion;

use crate::clarity::vm::types::StacksAddressExtensions;

use stacks_common::address::C32_ADDRESS_VERSION_TESTNET_SINGLESIG;
use stacks_common::address::AddressHashMode;
use stacks_common::types::chainstate::StacksAddress;
use stacks_common::types::chainstate::StacksPublicKey;
use stacks_common::types::chainstate::StacksPrivateKey;
use stacks_common::types::StacksEpoch;
use stacks_common::util::vrf::VRFProof;

use crate::core::StacksEpochExtension;

/// Make a peer and transition it into the Nakamoto epoch.
/// The node needs to be stacking; otherwise, Nakamoto won't activate.
fn boot_nakamoto(test_name: &str, mut initial_balances: Vec<(PrincipalData, u64)>) -> TestPeer {
    let mut peer_config = TestPeerConfig::new(test_name, 0, 0);
    let private_key = peer_config.private_key.clone();
    let addr = StacksAddress::from_public_keys(
        C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
        &AddressHashMode::SerializeP2PKH,
        1,
        &vec![StacksPublicKey::from_private(&private_key)],
    )
    .unwrap();

    // reward cycles are 5 blocks long
    // first 25 blocks are boot-up
    // reward cycle 6 instantiates pox-3
    // we stack in reward cycle 7 so pox-3 is evaluated to find reward set participation
    peer_config.epochs = Some(StacksEpoch::unit_test_3_0_only(36));
    peer_config.initial_balances = vec![(addr.to_account_principal(), 1_000_000_000_000_000_000)];
    peer_config.initial_balances.append(&mut initial_balances);
    peer_config.burnchain.pox_constants.v2_unlock_height = 21;
    peer_config.burnchain.pox_constants.pox_3_activation_height = 26;
    peer_config.burnchain.pox_constants.v3_unlock_height = 27;
    peer_config.burnchain.pox_constants.pox_4_activation_height = 31;

    let mut peer = TestPeer::new(peer_config);
    let mut peer_nonce = 0;

    // advance through cycle 6
    for _ in 0..5 {
        peer.tenure_with_txs(&[], &mut peer_nonce);
    }

    // stack to pox-3 in cycle 7
    for sortition_height in 0..5 {
        let txs = if sortition_height == 0 {
            // stack them all
            let stack_tx = make_pox_4_lockup(&private_key, 0, 1_000_000_000_000_000_000, PoxAddress::from_legacy(AddressHashMode::SerializeP2PKH, addr.bytes.clone()), 12, 34);
            vec![stack_tx]
        }
        else {
            vec![]
        };
       
        peer.tenure_with_txs(&txs, &mut peer_nonce);
    }

    // peer is at the start of cycle 8
    peer
}

/// Mine a single Nakamoto tenure
#[test]
fn test_simple_nakamoto_coordinator_bootup() {
    let mut peer = boot_nakamoto(function_name!(), vec![]);

    let (burn_ops, tenure_change, vrf_proof) = peer.begin_nakamoto_tenure(TenureChangeCause::BlockFound);
    let (_, _, consensus_hash) = peer.next_burnchain_block(burn_ops);
    let blocks_and_sizes = peer.make_nakamoto_tenure(&consensus_hash, tenure_change, vrf_proof, |_miner, _chainstate, _sort_dbconn, _count| { vec![] });
    let blocks = blocks_and_sizes
        .into_iter()
        .map(|(block, _, _)| block)
        .collect();

    peer.process_nakamoto_tenure(blocks);
}
