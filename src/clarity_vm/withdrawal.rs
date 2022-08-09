use crate::chainstate::stacks::events::StacksTransactionReceipt;
use clarity::codec::StacksMessageCodec;
use clarity::types::chainstate::{BlockHeaderHash, ConsensusHash, StacksBlockId, TrieHash};
use clarity::util::hash::{MerkleTree, Sha512Trunc256Sum};
use clarity::vm::database::ClarityBackingStore;
use clarity::vm::events::{
    FTEventType, FTWithdrawEventData, NFTEventType, NFTWithdrawEventData, STXEventType,
    STXWithdrawEventData, StacksTransactionEvent,
};
use clarity::vm::types::{AssetIdentifier, PrincipalData, SequenceData, TupleData};
use clarity::vm::Value;
use regex::internal::Input;

fn clarity_ascii_str(input: &str) -> Value {
    Value::string_ascii_from_bytes(input.as_bytes().to_vec())
        .expect("Supplied string was not ASCII")
}

pub fn buffer_from_hash(hash: Sha512Trunc256Sum) -> Value {
    Value::buff_from(hash.0.to_vec()).expect("Failed to construct buffer from hash")
}

/// The supplied withdrawal ID is inserted into the supplied withdraw event
/// (this is why the event are supplied as a mutable argument).
///
/// The format for withdrawal event keys is that each key in the
/// Merkle withdrawal tree is the consensus serialization of one of the following
/// tuples:
///
/// ```javascript
///   { type: "stx",
///     height: u128,
///     withdrawal-id: u128,
///     recipient: principal,
///     amount: u128 }
/// ```
///
/// *NOTE*: because subnets support SIP-009 and SIP-010 tokens only,
///   these wire formats *do not* include the `asset-name`, because
///   only one asset can be supported per contract.
/// ```javascript
///   { type: "nft",
///     asset-contract: principal,
///     height: u128,
///     withdrawal-id: u128,
///     recipient: principal,
///     nft-id: u128 }
/// ```
///
/// ```javascript
///   { type: "ft",
///     asset-contract: principal,
///     height: u128,
///     withdrawal-id: u128,
///     recipient: principal,
///     amount: u128 }
/// ```

pub fn generate_key_from_event(
    event: &mut StacksTransactionEvent,
    withdrawal_id: u32,
    block_height: u64,
) -> Option<Value> {
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

pub fn make_key_for_ft_withdrawal_event(data: &FTWithdrawEventData, block_height: u64) -> Value {
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
        block_height,
    )
}

pub fn make_key_for_nft_withdrawal_event(data: &NFTWithdrawEventData, block_height: u64) -> Value {
    let withdrawal_id = data
        .withdrawal_id
        .expect("Tried to serialize a withdraw event before setting withdrawal ID");
    info!("Parsed L2 withdrawal event";
          "type" => "nft",
          "block_height" => block_height,
          "sender" => %data.sender,
          "withdrawal_id" => withdrawal_id,
          "asset_id" => %data.asset_identifier);
    make_key_for_nft_withdrawal(
        &data.sender,
        withdrawal_id,
        &data.asset_identifier,
        data.id,
        block_height,
    )
}

pub fn make_key_for_stx_withdrawal_event(data: &STXWithdrawEventData, block_height: u64) -> Value {
    let withdrawal_id = data
        .withdrawal_id
        .expect("Tried to serialize a withdraw event before setting withdrawal ID");
    info!("Parsed L2 withdrawal event";
          "type" => "stx",
          "block_height" => block_height,
          "sender" => %data.sender,
          "withdrawal_id" => withdrawal_id,
          "amount" => %data.amount);
    make_key_for_stx_withdrawal(&data.sender, withdrawal_id, data.amount, block_height)
}

pub fn make_key_for_stx_withdrawal(
    recipient: &PrincipalData,
    withdrawal_id: u32,
    amount: u128,
    block_height: u64,
) -> Value {
    TupleData::from_data(vec![
        ("type".into(), clarity_ascii_str("stx")),
        ("height".into(), Value::UInt(u128::from(block_height))),
        (
            "withdrawal-id".into(),
            Value::UInt(u128::from(withdrawal_id)),
        ),
        ("recipient".into(), Value::Principal(recipient.clone())),
        ("amount".into(), Value::UInt(amount)),
    ])
    .expect("Withdrawal key tuple is too large for Clarity")
    .into()
}

pub fn make_key_for_nft_withdrawal(
    sender: &PrincipalData,
    withdrawal_id: u32,
    asset_identifier: &AssetIdentifier,
    id: u128,
    block_height: u64,
) -> Value {
    let asset_contract = Value::Principal(PrincipalData::from(
        asset_identifier.contract_identifier.clone(),
    ));
    TupleData::from_data(vec![
        ("type".into(), clarity_ascii_str("nft")),
        ("asset-contract".into(), asset_contract),
        ("height".into(), Value::UInt(u128::from(block_height))),
        (
            "withdrawal-id".into(),
            Value::UInt(u128::from(withdrawal_id)),
        ),
        ("recipient".into(), Value::Principal(sender.clone())),
        ("nft-id".into(), Value::UInt(id)),
    ])
    .expect("Withdrawal key tuple is too large for Clarity")
    .into()
}

pub fn make_key_for_ft_withdrawal(
    sender: &PrincipalData,
    withdrawal_id: u32,
    asset_identifier: &AssetIdentifier,
    amount: u128,
    block_height: u64,
) -> Value {
    let asset_contract = Value::Principal(PrincipalData::from(
        asset_identifier.contract_identifier.clone(),
    ));
    TupleData::from_data(vec![
        ("type".into(), clarity_ascii_str("ft")),
        ("asset-contract".into(), asset_contract),
        ("height".into(), Value::UInt(u128::from(block_height))),
        (
            "withdrawal-id".into(),
            Value::UInt(u128::from(withdrawal_id)),
        ),
        ("recipient".into(), Value::Principal(sender.clone())),
        ("amount".into(), Value::UInt(amount)),
    ])
    .expect("Withdrawal key tuple is too large for Clarity")
    .into()
}

pub fn convert_withdrawal_key_to_bytes(key: &Value) -> Vec<u8> {
    key.serialize_to_vec()
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
                items.push(convert_withdrawal_key_to_bytes(&key));
            }
        }
    }

    items
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
    use clarity::types::chainstate::StacksAddress;
    use clarity::types::Address;
    use clarity::util::hash::to_hex;
    use clarity::vm::types::StandardPrincipalData;

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
        let contract_addr =
            StacksAddress::from_string("ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM").unwrap();

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
                        contract_addr.into(),
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
                        contract_addr.into(),
                        ContractName::from("simple-nft"),
                    ),
                    asset_name: ClarityName::from("nft-token"),
                },
                withdrawal_id: None,
                sender: user_addr.into(),
                id: 1,
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
            to_hex(stx_withdrawal_leaf_hash.as_bytes()),
            "bde3658bbc38952599ef925ea3075a2fbfc5619cebf48cce140994c8b328fe35",
        );

        let ft_withdrawal_key = generate_key_from_event(&mut ft_withdraw_event, 1, 0).unwrap();
        let ft_withdrawal_key_bytes = convert_withdrawal_key_to_bytes(&ft_withdrawal_key);
        eprintln!("BYTES: {}", to_hex(&ft_withdrawal_key_bytes));
        let ft_withdrawal_leaf_hash =
            MerkleTree::<Sha512Trunc256Sum>::get_leaf_hash(ft_withdrawal_key_bytes.as_slice());
        assert_eq!(
            to_hex(ft_withdrawal_leaf_hash.as_bytes()),
            "be7bcffde781f217150cfc63c88fc2e78bca424b318f5421abdfe96842321e79"
        );

        let nft_withdrawal_key = generate_key_from_event(&mut nft_withdraw_event, 2, 0).unwrap();
        let nft_withdrawal_key_bytes = convert_withdrawal_key_to_bytes(&nft_withdrawal_key);
        let nft_withdrawal_leaf_hash =
            MerkleTree::<Sha512Trunc256Sum>::get_leaf_hash(nft_withdrawal_key_bytes.as_slice());
        assert_eq!(
            to_hex(nft_withdrawal_leaf_hash.as_bytes()),
            "6456c2cdb1c1016fddf2e9b7eb88cd677741f0420614a824ac8b774a24285a35"
        );

        let first_level_first_node = MerkleTree::<Sha512Trunc256Sum>::get_node_hash(
            &stx_withdrawal_leaf_hash,
            &ft_withdrawal_leaf_hash,
        );
        assert_eq!(
            to_hex(first_level_first_node.as_bytes()),
            "a00db116739a78d6547e18399924b8ec0201079149369b43422e816587f97ede"
        );
        let first_level_second_node = MerkleTree::<Sha512Trunc256Sum>::get_node_hash(
            &nft_withdrawal_leaf_hash,
            &nft_withdrawal_leaf_hash,
        );
        assert_eq!(
            to_hex(first_level_second_node.as_bytes()),
            "8bec7ac5a0ec8eed899374f25fa8c0aa67e852b0c5a99ff6595e589a8d123ea0"
        );

        let calculated_root_hash = MerkleTree::<Sha512Trunc256Sum>::get_node_hash(
            &first_level_first_node,
            &first_level_second_node,
        );
        assert_eq!(
            to_hex(calculated_root_hash.as_bytes()),
            "b02609e344ebb6525c83cd6c2bd3d2a1c73daa2c9344119f036d615b110aad15",
        );
        assert_eq!(root_hash, calculated_root_hash);
    }
}
