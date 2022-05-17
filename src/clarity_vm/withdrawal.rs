use chainstate::stacks::events::StacksTransactionReceipt;
use chainstate::stacks::StacksBlockHeader;
use clarity::types::chainstate::{BlockHeaderHash, ConsensusHash, StacksBlockId, TrieHash};
use clarity::util::hash::{MerkleTree, Sha512Trunc256Sum};
use clarity::vm::database::ClarityBackingStore;
use clarity::vm::events::{
    FTEventType, NFTEventType, NFTWithdrawEventData, STXEventType, STXWithdrawEventData,
    StacksTransactionEvent,
};
use clarity::vm::types::PrincipalData;
use clarity_vm::database::marf::MarfedKV;
use regex::internal::Input;
use vm::events::FTWithdrawEventData;

pub fn make_key_for_withdrawal(data: String, sender: &PrincipalData, withdrawal_id: u32) -> String {
    format!(
        "withdrawal::{}::{}::{}",
        withdrawal_id,
        data,
        sender.to_string()
    )
}

pub fn make_key_for_ft_withdrawal(data: &FTWithdrawEventData, withdrawal_id: u32) -> String {
    let str_data = format!("{}::{}", data.asset_identifier, data.amount);
    make_key_for_withdrawal(str_data, &data.sender, withdrawal_id)
}

pub fn make_key_for_nft_withdrawal(data: &NFTWithdrawEventData, withdrawal_id: u32) -> String {
    let str_data = format!("{}", data.asset_identifier);
    make_key_for_withdrawal(str_data, &data.sender, withdrawal_id)
}

pub fn make_key_for_stx_withdrawal(data: &STXWithdrawEventData, withdrawal_id: u32) -> String {
    let str_data = format!("{}", data.amount);
    make_key_for_withdrawal(str_data, &data.sender, withdrawal_id)
}

pub fn generate_key_from_event(event: &StacksTransactionEvent, withdrawal_id: u32) -> Option<String> {
    match event {
        StacksTransactionEvent::NFTEvent(NFTEventType::NFTWithdrawEvent(data)) => {
            Some(make_key_for_nft_withdrawal(data, withdrawal_id))
        }
        StacksTransactionEvent::FTEvent(FTEventType::FTWithdrawEvent(data)) => {
            Some(make_key_for_ft_withdrawal(data, withdrawal_id))
        }
        StacksTransactionEvent::STXEvent(STXEventType::STXWithdrawEvent(data)) => {
            Some(make_key_for_stx_withdrawal(data, withdrawal_id))
        }
        _ => {
            None
        }
    }
}

pub fn convert_withdrawal_key_to_bytes(key: &String) -> Vec<u8> {
    key.as_bytes().to_vec()
}

pub fn generate_withdrawal_keys(tx_receipts: &Vec<StacksTransactionReceipt>) -> Vec<Vec<u8>> {
    let mut items = Vec::new();
    let mut withdrawal_id = 0;
    for receipt in tx_receipts {
        for event in &receipt.events {
            if let Some(key) = generate_key_from_event(event, withdrawal_id) {
                withdrawal_id += 1;
                items.push(key);
            }
        }
    }
    // Sort items before converting them to a byte vector to be inserted into a Merkle tree.
    items.sort();

    items.iter().map(|item: &String| convert_withdrawal_key_to_bytes(item)).collect()
}

/// Put all withdrawal keys and values into a single Merkle tree
/// The order of the transaction receipts will affect the final tree
pub fn create_withdrawal_merkle_tree(
    tx_receipts: &Vec<StacksTransactionReceipt>,
) -> MerkleTree<Sha512Trunc256Sum> {
    let items = generate_withdrawal_keys(tx_receipts);

    MerkleTree::<Sha512Trunc256Sum>::new(&items)
}
