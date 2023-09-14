use std::fs;

use stacks_common::consts::FIRST_BURNCHAIN_CONSENSUS_HASH;
use stacks_common::consts::FIRST_STACKS_BLOCK_HASH;
use stacks_common::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, ConsensusHash, StacksPrivateKey, StacksWorkScore,
    TrieHash,
};
use stacks_common::types::{StacksEpoch, StacksEpochId};
use stacks_common::util::hash::{Hash160, Sha512Trunc256Sum};
use stacks_common::util::secp256k1::MessageSignature;
use stacks_common::util::vrf::{VRFPrivateKey, VRFProof};
use stx_genesis::GenesisData;

use crate::burnchains::PoxConstants;
use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::coordinator::tests::{
    get_burnchain, get_burnchain_db, get_chainstate, get_sortition_db, p2pkh_from, pox_addr_from,
    setup_states_with_epochs,
};
use crate::chainstate::nakamoto::{NakamotoBlock, NakamotoBlockHeader, NakamotoChainState};
use crate::chainstate::stacks::db::StacksChainState;
use crate::chainstate::stacks::db::{
    ChainStateBootData, ChainstateAccountBalance, ChainstateAccountLockup, ChainstateBNSName,
    ChainstateBNSNamespace, StacksBlockHeaderTypes, StacksHeaderInfo,
};
use crate::chainstate::stacks::StacksBlockHeader;
use crate::core;
use crate::core::StacksEpochExtension;

fn test_path(name: &str) -> String {
    format!("/tmp/stacks-node-tests/nakamoto-tests/{}", name)
}

#[test]
pub fn nakamoto_advance_tip() {
    let path = test_path(function_name!());
    let _r = std::fs::remove_dir_all(&path);

    let burnchain_conf = get_burnchain(&path, None);

    let vrf_keys: Vec<_> = (0..50).map(|_| VRFPrivateKey::new()).collect();
    let committers: Vec<_> = (0..50).map(|_| StacksPrivateKey::new()).collect();

    let stacker = p2pkh_from(&StacksPrivateKey::new());
    let rewards = pox_addr_from(&StacksPrivateKey::new());
    let balance = 6_000_000_000 * (core::MICROSTACKS_PER_STACKS as u64);
    let stacked_amt = 1_000_000_000 * (core::MICROSTACKS_PER_STACKS as u128);
    let initial_balances = vec![(stacker.clone().into(), balance)];

    let pox_constants = PoxConstants::mainnet_default();

    setup_states_with_epochs(
        &[&path],
        &vrf_keys,
        &committers,
        None,
        Some(initial_balances),
        StacksEpochId::Epoch21,
        Some(StacksEpoch::all(0, 0, 1000000)),
    );

    let mut sort_db = get_sortition_db(&path, None);
    let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();

    let b = get_burnchain(&path, None);
    let mut burnchain = get_burnchain_db(&path, None);
    let mut chainstate = get_chainstate(&path);
    let (mut chainstate_tx, clarity_instance) = chainstate.chainstate_tx_begin().unwrap();

    let mut sortdb_tx = sort_db.tx_handle_begin(&tip.sortition_id).unwrap();

    let chain_tip_consensus_hash = ConsensusHash([0; 20]);
    let chain_tip_burn_header_hash = BurnchainHeaderHash([0; 32]);
    let chain_tip_burn_header_height = 1;
    let chain_tip_burn_header_timestamp = 100;
    let block = NakamotoBlock {
        header: NakamotoBlockHeader {
            version: 100,
            chain_length: 1,
            btc_spent: 5,
            parent: FIRST_STACKS_BLOCK_HASH,
            burn_view: tip.burn_header_hash.clone(),
            tx_merkle_root: Sha512Trunc256Sum([0; 32]),
            state_index_root: TrieHash([0; 32]),
            signature: MessageSignature([0; 65]),
        },
        txs: vec![],
    };
    let block_size = 10;
    let burnchain_commit_burn = 1;
    let burnchain_sortition_burn = 5;
    let user_burns = [];
    let affirmation_weight = 1;
    let parent_chain_tip = StacksHeaderInfo {
        anchored_header: StacksBlockHeader {
            version: 100,
            total_work: StacksWorkScore::genesis(),
            proof: VRFProof::empty(),
            parent_block: BlockHeaderHash([0; 32]),
            parent_microblock: BlockHeaderHash([0; 32]),
            parent_microblock_sequence: 0,
            tx_merkle_root: Sha512Trunc256Sum([0; 32]),
            state_index_root: TrieHash([0; 32]),
            microblock_pubkey_hash: Hash160([1; 20]),
        }
        .into(),
        microblock_tail: None,
        stacks_block_height: 0,
        index_root: TrieHash([0; 32]),
        consensus_hash: FIRST_BURNCHAIN_CONSENSUS_HASH.clone(),
        burn_header_hash: tip.burn_header_hash.clone(),
        burn_header_height: 2,
        burn_header_timestamp: 50,
        anchored_block_size: 10,
    };

    NakamotoChainState::append_block(
        &mut chainstate_tx,
        clarity_instance,
        &mut sortdb_tx,
        &pox_constants,
        &parent_chain_tip,
        &chain_tip_consensus_hash,
        &chain_tip_burn_header_hash,
        chain_tip_burn_header_height,
        chain_tip_burn_header_timestamp,
        &block,
        block_size,
        burnchain_commit_burn,
        burnchain_sortition_burn,
        &user_burns,
        affirmation_weight,
    )
    .unwrap();
}
