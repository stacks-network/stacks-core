use crate::rand::RngCore;
use stacks::vm::Value as ClarityValue;
use stacks::{
    burnchains::{
        events::{ContractEvent, NewBlock, NewBlockTxEvent, TxEventType},
        Txid,
    },
    types::chainstate::StacksBlockId,
    util::hash::to_hex,
    vm::types::{QualifiedContractIdentifier, TupleData},
};

pub mod db_indexer;

pub fn random_sortdb_test_dir() -> String {
    let mut rng = rand::thread_rng();
    let mut buf = [0u8; 32];
    rng.fill_bytes(&mut buf);
    format!("/tmp/stacks-node-tests/sortdb/test-{}", to_hex(&buf))
}

/// Creates a `NewBlock` using hash created as `[block_idx; 32]`, and parent hash
/// `[parent_block_idx; 32]`. The `block-commit` in the underlying contract is also `[block_idx; 32]`.
/// The time stamp of the created block is `block_idx`.
fn make_test_new_block(
    block_height: u64,
    block_idx: u8,
    parent_block_idx: u8,
    contract_identifier: QualifiedContractIdentifier,
) -> NewBlock {
    let tx_event = {
        let mocked_txid = Txid([0; 32]);
        let topic = "print".into();
        let value = TupleData::from_data(vec![
            (
                "event".into(),
                ClarityValue::string_ascii_from_bytes("block-commit".as_bytes().to_vec()).unwrap(),
            ),
            (
                "block-commit".into(),
                ClarityValue::buff_from([block_idx; 32].to_vec()).unwrap(),
            ),
        ])
        .expect("Should be a legal Clarity tuple")
        .into();

        let contract_event = Some(ContractEvent {
            topic,
            contract_identifier,
            value,
        });

        NewBlockTxEvent {
            txid: mocked_txid,
            event_index: 0,
            committed: true,
            event_type: TxEventType::ContractEvent,
            contract_event,
        }
    };

    let new_block = NewBlock {
        block_height,
        burn_block_time: block_idx as u64,
        index_block_hash: StacksBlockId([block_idx; 32]),
        parent_index_block_hash: StacksBlockId([parent_block_idx; 32]),
        events: vec![tx_event],
    };

    new_block
}
