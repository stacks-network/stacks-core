use crate::chainstate::stacks::events::StacksTransactionReceipt;
use clarity::types::chainstate::{BlockHeaderHash, ConsensusHash, StacksBlockId, TrieHash};
use clarity::util::hash::{MerkleTree, Sha512Trunc256Sum};
use clarity::vm::database::ClarityBackingStore;
use clarity::vm::events::{
    FTEventType, FTWithdrawEventData, NFTEventType, NFTWithdrawEventData, STXEventType,
    STXWithdrawEventData, StacksTransactionEvent,
};
use clarity::vm::types::PrincipalData;
use regex::internal::Input;

pub fn make_key_for_withdrawal(
    data: String,
    recipient: &PrincipalData,
    withdrawal_id: u32,
) -> String {
    format!(
        "withdrawal::{}::{}::{}",
        data,
        recipient.to_string(),
        withdrawal_id,
    )
}

pub fn make_key_for_ft_withdrawal(data: &FTWithdrawEventData, withdrawal_id: u32) -> String {
    let str_data = format!("ft::{}::{}", data.asset_identifier, data.amount);
    make_key_for_withdrawal(str_data, &data.sender, withdrawal_id)
}

pub fn make_key_for_nft_withdrawal(data: &NFTWithdrawEventData, withdrawal_id: u32) -> String {
    let str_data = format!("nft::{}::{}", data.asset_identifier, data.value);
    make_key_for_withdrawal(str_data, &data.sender, withdrawal_id)
}

pub fn make_key_for_stx_withdrawal(data: &STXWithdrawEventData, withdrawal_id: u32) -> String {
    let str_data = format!("stx::{}", data.amount);
    make_key_for_withdrawal(str_data, &data.sender, withdrawal_id)
}

pub fn generate_key_from_event(
    event: &StacksTransactionEvent,
    withdrawal_id: u32,
) -> Option<String> {
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
        _ => None,
    }
}

pub fn convert_withdrawal_key_to_bytes(key: &str) -> Vec<u8> {
    key.as_bytes().to_vec()
}

/// The order of withdrawal events in the transaction receipts will determine the withdrawal IDs
/// that correspond to each event. These IDs are used to generate the withdrawal key that is
/// ultimately inserted in the withdrawal Merkle tree.
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

    items
        .iter()
        .map(|item: &String| convert_withdrawal_key_to_bytes(item))
        .collect()
}

/// Put all withdrawal keys and values into a single Merkle tree
/// The order of the transaction receipts will affect the final tree
pub fn create_withdrawal_merkle_tree(
    tx_receipts: &Vec<StacksTransactionReceipt>,
) -> MerkleTree<Sha512Trunc256Sum> {
    // The specific keys generated is dependent on the order of the provided transaction receipts
    let items = generate_withdrawal_keys(tx_receipts);

    MerkleTree::<Sha512Trunc256Sum>::new(&items)
}

#[cfg(test)]
mod test {
    use crate::chainstate::stacks::events::{StacksTransactionReceipt, TransactionOrigin};
    use crate::chainstate::stacks::{
        CoinbasePayload, StacksTransaction, TransactionAuth, TransactionPayload,
        TransactionSpendingCondition, TransactionVersion,
    };
    use crate::clarity::types::chainstate::{
        BlockHeaderHash, ConsensusHash, StacksBlockId, StacksPrivateKey, StacksPublicKey, TrieHash,
    };
    use crate::clarity::util::hash::{MerkleTree, Sha512Trunc256Sum};
    use crate::clarity::vm::costs::ExecutionCost;
    use crate::clarity::vm::events::FTEventType::FTWithdrawEvent;
    use crate::clarity::vm::events::NFTEventType::NFTWithdrawEvent;
    use crate::clarity::vm::events::STXEventType::STXWithdrawEvent;
    use crate::clarity::vm::events::{STXWithdrawEventData, StacksTransactionEvent};
    use crate::clarity::vm::types::{AssetIdentifier, QualifiedContractIdentifier};
    use crate::clarity::vm::Value;
    use crate::clarity_vm::withdrawal::{
        convert_withdrawal_key_to_bytes, create_withdrawal_merkle_tree, generate_key_from_event,
    };
    use crate::net::test::to_addr;
    use crate::vm::events::{FTWithdrawEventData, NFTWithdrawEventData};
    use crate::vm::ClarityName;
    use crate::vm::ContractName;

    #[test]
    fn test_verify_withdrawal_merkle_tree() {
        let pk: StacksPrivateKey = StacksPrivateKey::from_hex(
            "aaf57b4730f713cf942bc63f0801c4a62abe5a6ac8e3da10389f9ca3420b0dc701",
        )
        .unwrap();
        let user_addr = to_addr(&pk);
        let mut spending_condition =
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(&pk))
                .expect("Failed to create p2pkh spending condition from public key.");
        spending_condition.set_nonce(0);
        spending_condition.set_tx_fee(1000);
        let auth = TransactionAuth::Standard(spending_condition);
        let stx_withdraw_event =
            StacksTransactionEvent::STXEvent(STXWithdrawEvent(STXWithdrawEventData {
                sender: user_addr.into(),
                amount: 1,
            }));
        let ft_withdraw_event =
            StacksTransactionEvent::FTEvent(FTWithdrawEvent(FTWithdrawEventData {
                asset_identifier: AssetIdentifier {
                    contract_identifier: QualifiedContractIdentifier::new(
                        user_addr.into(),
                        ContractName::from("simple-ft"),
                    ),
                    asset_name: ClarityName::from("ft-token"),
                },
                sender: user_addr.into(),
                amount: 1,
            }));
        let nft_withdraw_event =
            StacksTransactionEvent::NFTEvent(NFTWithdrawEvent(NFTWithdrawEventData {
                asset_identifier: AssetIdentifier {
                    contract_identifier: QualifiedContractIdentifier::new(
                        user_addr.into(),
                        ContractName::from("simple-nft"),
                    ),
                    asset_name: ClarityName::from("nft-token"),
                },
                sender: user_addr.into(),
                value: Value::UInt(1),
            }));
        let withdrawal_receipt = StacksTransactionReceipt {
            transaction: TransactionOrigin::Stacks(StacksTransaction::new(
                TransactionVersion::Testnet,
                auth.clone(),
                TransactionPayload::Coinbase(CoinbasePayload([0u8; 32])),
            )),
            events: vec![
                stx_withdraw_event.clone(),
                ft_withdraw_event.clone(),
                nft_withdraw_event.clone(),
            ],
            post_condition_aborted: false,
            result: Value::err_none(),
            stx_burned: 0,
            contract_analysis: None,
            execution_cost: ExecutionCost::zero(),
            microblock_header: None,
            tx_index: 0,
        };

        let withdrawal_tree = create_withdrawal_merkle_tree(&vec![withdrawal_receipt]);
        let root_hash = withdrawal_tree.root();

        // manually construct the expected Merkle tree
        let stx_withdrawal_key = generate_key_from_event(&stx_withdraw_event, 0).unwrap();
        let stx_withdrawal_key_bytes = convert_withdrawal_key_to_bytes(&stx_withdrawal_key);
        let stx_withdrawal_leaf_hash =
            MerkleTree::<Sha512Trunc256Sum>::get_leaf_hash(stx_withdrawal_key_bytes.as_slice());
        assert_eq!(
            stx_withdrawal_leaf_hash.as_bytes().to_vec(),
            vec![
                166, 126, 56, 176, 32, 46, 181, 232, 203, 157, 163, 237, 42, 69, 2, 20, 196, 115,
                199, 233, 214, 168, 217, 10, 100, 144, 59, 114, 68, 88, 116, 34
            ]
        );

        let ft_withdrawal_key = generate_key_from_event(&ft_withdraw_event, 1).unwrap();
        let ft_withdrawal_key_bytes = convert_withdrawal_key_to_bytes(&ft_withdrawal_key);
        let ft_withdrawal_leaf_hash =
            MerkleTree::<Sha512Trunc256Sum>::get_leaf_hash(ft_withdrawal_key_bytes.as_slice());
        assert_eq!(
            ft_withdrawal_leaf_hash.as_bytes().to_vec(),
            vec![
                168, 206, 151, 196, 231, 103, 99, 34, 213, 247, 225, 237, 184, 34, 243, 125, 125,
                213, 140, 199, 41, 34, 35, 208, 125, 174, 10, 55, 139, 82, 34, 213
            ]
        );

        let nft_withdrawal_key = generate_key_from_event(&nft_withdraw_event, 2).unwrap();
        let nft_withdrawal_key_bytes = convert_withdrawal_key_to_bytes(&nft_withdrawal_key);
        let nft_withdrawal_leaf_hash =
            MerkleTree::<Sha512Trunc256Sum>::get_leaf_hash(nft_withdrawal_key_bytes.as_slice());
        assert_eq!(
            nft_withdrawal_leaf_hash.as_bytes().to_vec(),
            vec![
                8, 0, 211, 114, 10, 69, 44, 38, 38, 104, 140, 88, 105, 75, 97, 72, 218, 204, 55,
                225, 59, 120, 37, 235, 204, 33, 229, 37, 45, 39, 75, 116
            ]
        );

        let first_level_first_node = MerkleTree::<Sha512Trunc256Sum>::get_node_hash(
            &stx_withdrawal_leaf_hash,
            &ft_withdrawal_leaf_hash,
        );
        assert_eq!(
            first_level_first_node.as_bytes().to_vec(),
            vec![
                94, 66, 211, 71, 239, 174, 90, 87, 146, 231, 42, 206, 116, 57, 31, 8, 128, 148,
                191, 242, 102, 223, 86, 35, 241, 182, 144, 23, 12, 76, 40, 102
            ]
        );
        let first_level_second_node = MerkleTree::<Sha512Trunc256Sum>::get_node_hash(
            &nft_withdrawal_leaf_hash,
            &nft_withdrawal_leaf_hash,
        );
        assert_eq!(
            first_level_second_node.as_bytes().to_vec(),
            vec![
                125, 135, 145, 128, 20, 186, 79, 199, 225, 200, 112, 161, 40, 176, 202, 130, 69,
                245, 254, 231, 47, 73, 129, 255, 238, 48, 165, 14, 175, 180, 192, 121
            ]
        );

        let calculated_root_hash = MerkleTree::<Sha512Trunc256Sum>::get_node_hash(
            &first_level_first_node,
            &first_level_second_node,
        );
        assert_eq!(
            calculated_root_hash.as_bytes().to_vec(),
            vec![
                186, 138, 157, 125, 128, 50, 197, 200, 75, 139, 27, 104, 110, 157, 182, 49, 140,
                62, 51, 70, 251, 139, 131, 82, 67, 53, 118, 168, 54, 239, 111, 30
            ]
        );
        assert_eq!(root_hash, calculated_root_hash);
    }
}
