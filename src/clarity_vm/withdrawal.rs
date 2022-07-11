use crate::chainstate::stacks::events::StacksTransactionReceipt;
use clarity::types::chainstate::{BlockHeaderHash, ConsensusHash, StacksBlockId, TrieHash};
use clarity::util::hash::{MerkleTree, Sha512Trunc256Sum};
use clarity::vm::database::ClarityBackingStore;
use clarity::vm::events::{
    FTEventType, FTWithdrawEventData, NFTEventType, NFTWithdrawEventData, STXEventType,
    STXWithdrawEventData, StacksTransactionEvent,
};
use clarity::vm::types::{AssetIdentifier, PrincipalData};
use clarity::vm::Value;
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

pub fn buffer_from_hash(hash: Sha512Trunc256Sum) -> Value {
    Value::buff_from(hash.0.to_vec()).expect("Failed to construct buffer from hash")
}

pub fn make_key_for_ft_withdrawal_event(data: &FTWithdrawEventData, block_height: u64) -> String {
    let withdrawal_id = data
        .withdrawal_id
        .expect("Tried to serialize a withdraw event before setting withdrawal ID");
    info!("Parsed L2 withdrawal event";
          "type" => "ft",
          "block_height" => block_height,
          "sender" => %data.sender,
          "withdrawal_id" => withdrawal_id,
          "amount" => %data.amount,
          "asset_id" => %data.asset_identifier);
    make_key_for_ft_withdrawal(
        &data.sender,
        withdrawal_id,
        &data.asset_identifier,
        data.amount,
    )
}

pub fn make_key_for_nft_withdrawal_event(data: &NFTWithdrawEventData, block_height: u64) -> String {
    let withdrawal_id = data
        .withdrawal_id
        .expect("Tried to serialize a withdraw event before setting withdrawal ID");
    info!("Parsed L2 withdrawal event";
          "type" => "nft",
          "block_height" => block_height,
          "sender" => %data.sender,
          "withdrawal_id" => withdrawal_id,
          "asset_id" => %data.asset_identifier);
    make_key_for_nft_withdrawal(&data.sender, withdrawal_id, &data.asset_identifier)
}

pub fn make_key_for_stx_withdrawal_event(data: &STXWithdrawEventData, block_height: u64) -> String {
    let withdrawal_id = data
        .withdrawal_id
        .expect("Tried to serialize a withdraw event before setting withdrawal ID");
    info!("Parsed L2 withdrawal event";
          "type" => "stx",
          "block_height" => block_height,
          "sender" => %data.sender,
          "withdrawal_id" => withdrawal_id,
          "amount" => %data.amount);
    make_key_for_stx_withdrawal(&data.sender, withdrawal_id, data.amount)
}

pub fn make_key_for_nft_withdrawal(
    sender: &PrincipalData,
    withdrawal_id: u32,
    asset_identifier: &AssetIdentifier,
) -> String {
    let str_data = format!("nft::{}", asset_identifier);
    make_key_for_withdrawal(str_data, sender, withdrawal_id)
}

pub fn make_key_for_ft_withdrawal(
    sender: &PrincipalData,
    withdrawal_id: u32,
    asset_identifier: &AssetIdentifier,
    amount: u128,
) -> String {
    let str_data = format!("ft::{}::{}", asset_identifier, amount);
    make_key_for_withdrawal(str_data, sender, withdrawal_id)
}

pub fn make_key_for_stx_withdrawal(
    sender: &PrincipalData,
    withdrawal_id: u32,
    amount: u128,
) -> String {
    let str_data = format!("stx::{}", amount);
    make_key_for_withdrawal(str_data, sender, withdrawal_id)
}

/// The supplied withdrawal ID is inserted into the supplied withdraw event
/// (this is why the event are supplied as a mutable argument).
pub fn generate_key_from_event(
    event: &mut StacksTransactionEvent,
    withdrawal_id: u32,
    block_height: u64,
) -> Option<String> {
    match event {
        StacksTransactionEvent::NFTEvent(NFTEventType::NFTWithdrawEvent(data)) => {
            data.withdrawal_id = Some(withdrawal_id);
            Some(make_key_for_nft_withdrawal_event(data, block_height))
        }
        StacksTransactionEvent::FTEvent(FTEventType::FTWithdrawEvent(data)) => {
            data.withdrawal_id = Some(withdrawal_id);
            Some(make_key_for_ft_withdrawal_event(data, block_height))
        }
        StacksTransactionEvent::STXEvent(STXEventType::STXWithdrawEvent(data)) => {
            data.withdrawal_id = Some(withdrawal_id);
            Some(make_key_for_stx_withdrawal_event(data, block_height))
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
pub fn generate_withdrawal_keys(
    tx_receipts: &mut [StacksTransactionReceipt],
    block_height: u64,
) -> Vec<Vec<u8>> {
    let mut items = Vec::new();
    let mut withdrawal_id = 0;
    for receipt in tx_receipts.iter_mut() {
        for event in receipt.events.iter_mut() {
            if let Some(key) = generate_key_from_event(event, withdrawal_id, block_height) {
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

/// Put all withdrawal keys and values into a single Merkle tree.
/// The order of the transaction receipts will affect the final tree.
/// The generated withdrawal IDs are inserted into the supplied withdraw events
/// (this is why the receipts are supplied as a mutable argument).
pub fn create_withdrawal_merkle_tree(
    tx_receipts: &mut [StacksTransactionReceipt],
    block_height: u64,
) -> MerkleTree<Sha512Trunc256Sum> {
    // The specific keys generated is dependent on the order of the provided transaction receipts
    let items = generate_withdrawal_keys(tx_receipts, block_height);

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
        let mut stx_withdraw_event =
            StacksTransactionEvent::STXEvent(STXWithdrawEvent(STXWithdrawEventData {
                sender: user_addr.into(),
                amount: 1,
                withdrawal_id: None,
            }));
        let mut ft_withdraw_event =
            StacksTransactionEvent::FTEvent(FTWithdrawEvent(FTWithdrawEventData {
                asset_identifier: AssetIdentifier {
                    contract_identifier: QualifiedContractIdentifier::new(
                        user_addr.into(),
                        ContractName::from("simple-ft"),
                    ),
                    asset_name: ClarityName::from("ft-token"),
                },
                withdrawal_id: None,
                sender: user_addr.into(),
                amount: 1,
            }));
        let mut nft_withdraw_event =
            StacksTransactionEvent::NFTEvent(NFTWithdrawEvent(NFTWithdrawEventData {
                asset_identifier: AssetIdentifier {
                    contract_identifier: QualifiedContractIdentifier::new(
                        user_addr.into(),
                        ContractName::from("simple-nft"),
                    ),
                    asset_name: ClarityName::from("nft-token"),
                },
                withdrawal_id: None,
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

        let mut receipts = vec![withdrawal_receipt];
        // supplying block height = 0 is okay in tests, because block height is only used for logging
        let withdrawal_tree = create_withdrawal_merkle_tree(receipts.as_mut(), 0);
        let root_hash = withdrawal_tree.root();

        // manually construct the expected Merkle tree
        let stx_withdrawal_key = generate_key_from_event(&mut stx_withdraw_event, 0, 0).unwrap();
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

        let ft_withdrawal_key = generate_key_from_event(&mut ft_withdraw_event, 1, 0).unwrap();
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

        let nft_withdrawal_key = generate_key_from_event(&mut nft_withdraw_event, 2, 0).unwrap();
        let nft_withdrawal_key_bytes = convert_withdrawal_key_to_bytes(&nft_withdrawal_key);
        let nft_withdrawal_leaf_hash =
            MerkleTree::<Sha512Trunc256Sum>::get_leaf_hash(nft_withdrawal_key_bytes.as_slice());
        assert_eq!(
            nft_withdrawal_leaf_hash.as_bytes().to_vec(),
            vec![
                153, 10, 43, 242, 160, 228, 145, 217, 85, 36, 235, 59, 148, 118, 109, 81, 120, 23,
                174, 225, 19, 149, 220, 102, 116, 49, 228, 44, 66, 78, 232, 74
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
                162, 136, 132, 170, 231, 227, 33, 135, 19, 92, 199, 182, 216, 230, 39, 31, 30, 191,
                124, 1, 38, 84, 237, 67, 218, 68, 255, 186, 146, 179, 26, 214
            ]
        );

        let calculated_root_hash = MerkleTree::<Sha512Trunc256Sum>::get_node_hash(
            &first_level_first_node,
            &first_level_second_node,
        );
        assert_eq!(
            calculated_root_hash.as_bytes().to_vec(),
            vec![
                3, 71, 251, 33, 201, 246, 155, 190, 62, 133, 213, 253, 91, 188, 69, 162, 137, 13,
                175, 192, 20, 117, 147, 103, 70, 7, 196, 149, 56, 193, 5, 107
            ]
        );
        assert_eq!(root_hash, calculated_root_hash);
    }
}
