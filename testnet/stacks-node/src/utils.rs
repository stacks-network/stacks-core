use clarity::vm::{ClarityName, ContractName, Value};
use stacks::address::{AddressHashMode, C32_ADDRESS_VERSION_TESTNET_SINGLESIG};
use stacks::chainstate::stacks::{
    StacksTransaction, StacksTransactionSigner, TransactionAnchorMode, TransactionAuth,
    TransactionContractCall, TransactionPayload, TransactionPostConditionMode,
    TransactionSpendingCondition, TransactionVersion,
};
use stacks::codec::StacksMessageCodec;
use stacks::core::CHAIN_ID_TESTNET;
use stacks::net::api::getaccount::AccountEntryResponse;
use stacks::types::chainstate::{StacksAddress, StacksPrivateKey, StacksPublicKey};

#[derive(Debug)]
pub struct Account {
    pub balance: u128,
    pub locked: u128,
    pub nonce: u64,
}

pub fn get_account<F: std::fmt::Display>(http_origin: &str, account: &F) -> Account {
    let client = reqwest::blocking::Client::new();
    let path = format!("{}/v2/accounts/{}?proof=0", http_origin, account);
    let res = client
        .get(&path)
        .send()
        .unwrap()
        .json::<AccountEntryResponse>()
        .unwrap();
    info!("Account response: {:#?}", res);
    Account {
        balance: u128::from_str_radix(&res.balance[2..], 16).unwrap(),
        locked: u128::from_str_radix(&res.locked[2..], 16).unwrap(),
        nonce: res.nonce,
    }
}

pub fn to_addr(sk: &StacksPrivateKey) -> StacksAddress {
    StacksAddress::from_public_keys(
        C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
        &AddressHashMode::SerializeP2PKH,
        1,
        &vec![StacksPublicKey::from_private(sk)],
    )
    .unwrap()
}

pub fn serialize_sign_standard_single_sig_tx(
    payload: TransactionPayload,
    sender: &StacksPrivateKey,
    nonce: u64,
    tx_fee: u64,
) -> Vec<u8> {
    serialize_sign_standard_single_sig_tx_anchor_mode(
        payload,
        sender,
        nonce,
        tx_fee,
        TransactionAnchorMode::OnChainOnly,
    )
}

pub fn serialize_sign_standard_single_sig_tx_anchor_mode(
    payload: TransactionPayload,
    sender: &StacksPrivateKey,
    nonce: u64,
    tx_fee: u64,
    anchor_mode: TransactionAnchorMode,
) -> Vec<u8> {
    serialize_sign_standard_single_sig_tx_anchor_mode_version(
        payload,
        sender,
        nonce,
        tx_fee,
        anchor_mode,
        TransactionVersion::Testnet,
    )
}

pub fn serialize_sign_standard_single_sig_tx_anchor_mode_version(
    payload: TransactionPayload,
    sender: &StacksPrivateKey,
    nonce: u64,
    tx_fee: u64,
    anchor_mode: TransactionAnchorMode,
    version: TransactionVersion,
) -> Vec<u8> {
    serialize_sign_tx_anchor_mode_version(
        payload,
        sender,
        None,
        nonce,
        None,
        tx_fee,
        anchor_mode,
        version,
    )
}

pub fn serialize_sign_tx_anchor_mode_version(
    payload: TransactionPayload,
    sender: &StacksPrivateKey,
    payer: Option<&StacksPrivateKey>,
    sender_nonce: u64,
    payer_nonce: Option<u64>,
    tx_fee: u64,
    anchor_mode: TransactionAnchorMode,
    version: TransactionVersion,
) -> Vec<u8> {
    let mut sender_spending_condition =
        TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(sender))
            .expect("Failed to create p2pkh spending condition from public key.");
    sender_spending_condition.set_nonce(sender_nonce);

    let auth = match (payer, payer_nonce) {
        (Some(payer), Some(payer_nonce)) => {
            let mut payer_spending_condition = TransactionSpendingCondition::new_singlesig_p2pkh(
                StacksPublicKey::from_private(payer),
            )
            .expect("Failed to create p2pkh spending condition from public key.");
            payer_spending_condition.set_nonce(payer_nonce);
            payer_spending_condition.set_tx_fee(tx_fee);
            TransactionAuth::Sponsored(sender_spending_condition, payer_spending_condition)
        }
        _ => {
            sender_spending_condition.set_tx_fee(tx_fee);
            TransactionAuth::Standard(sender_spending_condition)
        }
    };
    let mut unsigned_tx = StacksTransaction::new(version, auth, payload);
    unsigned_tx.anchor_mode = anchor_mode;
    unsigned_tx.post_condition_mode = TransactionPostConditionMode::Allow;
    unsigned_tx.chain_id = CHAIN_ID_TESTNET;

    let mut tx_signer = StacksTransactionSigner::new(&unsigned_tx);
    tx_signer.sign_origin(sender).unwrap();
    if let (Some(payer), Some(_)) = (payer, payer_nonce) {
        tx_signer.sign_sponsor(payer).unwrap();
    }

    let mut buf = vec![];
    tx_signer
        .get_tx()
        .unwrap()
        .consensus_serialize(&mut buf)
        .unwrap();
    buf
}

pub fn make_contract_call(
    sender: &StacksPrivateKey,
    nonce: u64,
    tx_fee: u64,
    contract_addr: &StacksAddress,
    contract_name: &str,
    function_name: &str,
    function_args: &[Value],
) -> Vec<u8> {
    let contract_name = ContractName::from(contract_name);
    let function_name = ClarityName::from(function_name);

    let payload = TransactionContractCall {
        address: contract_addr.clone(),
        contract_name,
        function_name,
        function_args: function_args.iter().map(|x| x.clone()).collect(),
    };

    serialize_sign_standard_single_sig_tx(payload.into(), sender, nonce, tx_fee)
}

/// returns Txid string
pub fn submit_tx(http_origin: &str, tx: &Vec<u8>) -> String {
    let client = reqwest::blocking::Client::new();
    let path = format!("{}/v2/transactions", http_origin);
    let res = client
        .post(&path)
        .header("Content-Type", "application/octet-stream")
        .body(tx.clone())
        .send()
        .unwrap();
    if res.status().is_success() {
        let res: String = res.json().unwrap();
        assert_eq!(
            res,
            StacksTransaction::consensus_deserialize(&mut &tx[..])
                .unwrap()
                .txid()
                .to_string()
        );
        return res;
    } else {
        eprintln!("Submit tx error: {}", res.text().unwrap());
        panic!("");
    }
}
