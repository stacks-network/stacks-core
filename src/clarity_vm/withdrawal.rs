use clarity_vm::database::marf::MarfedKV;
use clarity::types::chainstate::{TrieHash, StacksBlockId, ConsensusHash, BlockHeaderHash};
use clarity::vm::database::ClarityBackingStore;
use chainstate::stacks::StacksBlockHeader;
use chainstate::stacks::events::StacksTransactionReceipt;
use clarity::vm::events::{StacksTransactionEvent, STXEventType, FTEventType, NFTWithdrawEventData, STXWithdrawEventData, NFTEventType};
use vm::events::FTWithdrawEventData;
use clarity::vm::types::PrincipalData;
use clarity::util::hash::{Sha512Trunc256Sum, MerkleTree};
use regex::internal::Input;

pub fn make_key_for_withdrawal(data: String, sender: &PrincipalData, withdrawal_id: u32) -> String {
    format!("withdrawal::{}::{}::{}", withdrawal_id, data, sender.to_string())
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

pub fn generate_withdrawal_keys(tx_receipts: &Vec<StacksTransactionReceipt>) -> Vec<Vec<u8>> {
    let mut items = Vec::new();
    let mut withdrawal_id = 0;
    for receipt in tx_receipts {
        for event in &receipt.events {
            if let StacksTransactionEvent::NFTEvent(NFTEventType::NFTWithdrawEvent(data)) = event {
                let key = make_key_for_nft_withdrawal(data, withdrawal_id);
                withdrawal_id += 1;
                items.push(key);
            } else if let StacksTransactionEvent::FTEvent(FTEventType::FTWithdrawEvent(data)) = event {
                let key = make_key_for_ft_withdrawal(data, withdrawal_id);
                withdrawal_id += 1;
                items.push(key);
            } else if let StacksTransactionEvent::STXEvent(STXEventType::STXWithdrawEvent(data)) = event {
                let key = make_key_for_stx_withdrawal(data, withdrawal_id);
                withdrawal_id += 1;
                items.push(key);
            }
        }

    }
    // Sort items before converting them to a byte vector to be inserted into a Merkle tree.
    items.sort();

    items.iter().map(|item| item.as_bytes().to_vec()).collect()
}

/// Put all withdrawal keys and values into a single Merkle tree
/// The order of the transaction receipts will affect the final tree
pub fn create_withdrawal_merkle_tree(
    tx_receipts: &Vec<StacksTransactionReceipt>
) -> Sha512Trunc256Sum {
    let items = generate_withdrawal_keys(tx_receipts);

    let merkle_tree = MerkleTree::<Sha512Trunc256Sum>::new(&items);
    let tx_merkle_root = merkle_tree.root();

    tx_merkle_root
}
