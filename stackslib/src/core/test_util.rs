use std::io::Cursor;

use chrono::Utc;
use clarity::codec::StacksMessageCodec;
use clarity::types::chainstate::{
    BlockHeaderHash, ConsensusHash, StacksAddress, StacksPrivateKey, StacksPublicKey,
};
use clarity::vm::costs::ExecutionCost;
use clarity::vm::tests::BurnStateDB;
use clarity::vm::types::PrincipalData;
use clarity::vm::{ClarityName, ClarityVersion, ContractName, Value};

use crate::chainstate::stacks::db::StacksChainState;
use crate::chainstate::stacks::miner::{BlockBuilderSettings, StacksMicroblockBuilder};
use crate::chainstate::stacks::{
    CoinbasePayload, StacksBlock, StacksMicroblock, StacksMicroblockHeader, StacksTransaction,
    StacksTransactionSigner, TokenTransferMemo, TransactionAnchorMode, TransactionAuth,
    TransactionContractCall, TransactionPayload, TransactionPostConditionMode,
    TransactionSmartContract, TransactionSpendingCondition, TransactionVersion,
};
use crate::util_lib::strings::StacksString;

#[allow(clippy::too_many_arguments)]
pub fn sign_sponsored_sig_tx_anchor_mode_version(
    payload: TransactionPayload,
    sender: &StacksPrivateKey,
    payer: &StacksPrivateKey,
    sender_nonce: u64,
    payer_nonce: u64,
    tx_fee: u64,
    chain_id: u32,
    anchor_mode: TransactionAnchorMode,
    version: TransactionVersion,
) -> StacksTransaction {
    sign_tx_anchor_mode_version(
        payload,
        sender,
        Some(payer),
        sender_nonce,
        Some(payer_nonce),
        tx_fee,
        chain_id,
        anchor_mode,
        version,
    )
}

pub fn sign_standard_single_sig_tx(
    payload: TransactionPayload,
    sender: &StacksPrivateKey,
    nonce: u64,
    tx_fee: u64,
    chain_id: u32,
) -> StacksTransaction {
    sign_standard_single_sig_tx_anchor_mode(
        payload,
        sender,
        nonce,
        tx_fee,
        chain_id,
        TransactionAnchorMode::OnChainOnly,
    )
}

pub fn sign_standard_single_sig_tx_anchor_mode(
    payload: TransactionPayload,
    sender: &StacksPrivateKey,
    nonce: u64,
    tx_fee: u64,
    chain_id: u32,
    anchor_mode: TransactionAnchorMode,
) -> StacksTransaction {
    sign_standard_single_sig_tx_anchor_mode_version(
        payload,
        sender,
        nonce,
        tx_fee,
        chain_id,
        anchor_mode,
        TransactionVersion::Testnet,
    )
}

pub fn sign_standard_single_sig_tx_anchor_mode_version(
    payload: TransactionPayload,
    sender: &StacksPrivateKey,
    nonce: u64,
    tx_fee: u64,
    chain_id: u32,
    anchor_mode: TransactionAnchorMode,
    version: TransactionVersion,
) -> StacksTransaction {
    sign_tx_anchor_mode_version(
        payload,
        sender,
        None,
        nonce,
        None,
        tx_fee,
        chain_id,
        anchor_mode,
        version,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn sign_tx_anchor_mode_version(
    payload: TransactionPayload,
    sender: &StacksPrivateKey,
    payer: Option<&StacksPrivateKey>,
    sender_nonce: u64,
    payer_nonce: Option<u64>,
    tx_fee: u64,
    chain_id: u32,
    anchor_mode: TransactionAnchorMode,
    version: TransactionVersion,
) -> StacksTransaction {
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
    unsigned_tx.chain_id = chain_id;

    let mut tx_signer = StacksTransactionSigner::new(&unsigned_tx);
    tx_signer.sign_origin(sender).unwrap();
    if let (Some(payer), Some(_)) = (payer, payer_nonce) {
        tx_signer.sign_sponsor(payer).unwrap();
    }

    tx_signer.get_tx().unwrap()
}

#[allow(clippy::too_many_arguments)]
pub fn serialize_sign_tx_anchor_mode_version(
    payload: TransactionPayload,
    sender: &StacksPrivateKey,
    payer: Option<&StacksPrivateKey>,
    sender_nonce: u64,
    payer_nonce: Option<u64>,
    tx_fee: u64,
    chain_id: u32,
    anchor_mode: TransactionAnchorMode,
    version: TransactionVersion,
) -> Vec<u8> {
    let tx = sign_tx_anchor_mode_version(
        payload,
        sender,
        payer,
        sender_nonce,
        payer_nonce,
        tx_fee,
        chain_id,
        anchor_mode,
        version,
    );

    let mut buf = vec![];
    tx.consensus_serialize(&mut buf).unwrap();
    buf
}

pub fn make_contract_publish_versioned(
    sender: &StacksPrivateKey,
    nonce: u64,
    tx_fee: u64,
    chain_id: u32,
    contract_name: &str,
    contract_content: &str,
    version: Option<ClarityVersion>,
) -> Vec<u8> {
    let name = ContractName::from(contract_name);
    let code_body = StacksString::from_string(&contract_content.to_string()).unwrap();

    let payload =
        TransactionPayload::SmartContract(TransactionSmartContract { name, code_body }, version);

    let tx = sign_standard_single_sig_tx(payload, sender, nonce, tx_fee, chain_id);
    let mut tx_bytes = vec![];
    tx.consensus_serialize(&mut tx_bytes).unwrap();
    tx_bytes
}

pub fn make_contract_publish(
    sender: &StacksPrivateKey,
    nonce: u64,
    tx_fee: u64,
    chain_id: u32,
    contract_name: &str,
    contract_content: &str,
) -> Vec<u8> {
    make_contract_publish_versioned(
        sender,
        nonce,
        tx_fee,
        chain_id,
        contract_name,
        contract_content,
        None,
    )
}

pub fn make_contract_publish_microblock_only_versioned(
    sender: &StacksPrivateKey,
    nonce: u64,
    tx_fee: u64,
    chain_id: u32,
    contract_name: &str,
    contract_content: &str,
    version: Option<ClarityVersion>,
) -> Vec<u8> {
    let name = ContractName::from(contract_name);
    let code_body = StacksString::from_string(&contract_content.to_string()).unwrap();

    let payload =
        TransactionPayload::SmartContract(TransactionSmartContract { name, code_body }, version);

    let tx = sign_standard_single_sig_tx_anchor_mode(
        payload,
        sender,
        nonce,
        tx_fee,
        chain_id,
        TransactionAnchorMode::OffChainOnly,
    );
    let mut tx_bytes = vec![];
    tx.consensus_serialize(&mut tx_bytes).unwrap();
    tx_bytes
}

pub fn make_contract_publish_microblock_only(
    sender: &StacksPrivateKey,
    nonce: u64,
    tx_fee: u64,
    chain_id: u32,
    contract_name: &str,
    contract_content: &str,
) -> Vec<u8> {
    make_contract_publish_microblock_only_versioned(
        sender,
        nonce,
        tx_fee,
        chain_id,
        contract_name,
        contract_content,
        None,
    )
}

pub fn to_addr(sk: &StacksPrivateKey) -> StacksAddress {
    StacksAddress::p2pkh(false, &StacksPublicKey::from_private(sk))
}

pub fn make_stacks_transfer_tx(
    sender: &StacksPrivateKey,
    nonce: u64,
    tx_fee: u64,
    chain_id: u32,
    recipient: &PrincipalData,
    amount: u64,
) -> StacksTransaction {
    let payload =
        TransactionPayload::TokenTransfer(recipient.clone(), amount, TokenTransferMemo([0; 34]));
    sign_standard_single_sig_tx(payload, sender, nonce, tx_fee, chain_id)
}

/// Make a stacks transfer transaction, returning the serialized transaction bytes
pub fn make_stacks_transfer_serialized(
    sender: &StacksPrivateKey,
    nonce: u64,
    tx_fee: u64,
    chain_id: u32,
    recipient: &PrincipalData,
    amount: u64,
) -> Vec<u8> {
    let tx = make_stacks_transfer_tx(sender, nonce, tx_fee, chain_id, recipient, amount);
    let mut tx_bytes = vec![];
    tx.consensus_serialize(&mut tx_bytes).unwrap();
    tx_bytes
}

#[allow(clippy::too_many_arguments)]
pub fn make_sponsored_stacks_transfer_on_testnet(
    sender: &StacksPrivateKey,
    payer: &StacksPrivateKey,
    sender_nonce: u64,
    payer_nonce: u64,
    tx_fee: u64,
    chain_id: u32,
    recipient: &PrincipalData,
    amount: u64,
) -> Vec<u8> {
    let payload =
        TransactionPayload::TokenTransfer(recipient.clone(), amount, TokenTransferMemo([0; 34]));
    let tx = sign_sponsored_sig_tx_anchor_mode_version(
        payload,
        sender,
        payer,
        sender_nonce,
        payer_nonce,
        tx_fee,
        chain_id,
        TransactionAnchorMode::OnChainOnly,
        TransactionVersion::Testnet,
    );
    let mut tx_bytes = vec![];
    tx.consensus_serialize(&mut tx_bytes).unwrap();
    tx_bytes
}

pub fn make_stacks_transfer_mblock_only(
    sender: &StacksPrivateKey,
    nonce: u64,
    tx_fee: u64,
    chain_id: u32,
    recipient: &PrincipalData,
    amount: u64,
) -> Vec<u8> {
    let payload =
        TransactionPayload::TokenTransfer(recipient.clone(), amount, TokenTransferMemo([0; 34]));
    let tx = sign_standard_single_sig_tx_anchor_mode(
        payload,
        sender,
        nonce,
        tx_fee,
        chain_id,
        TransactionAnchorMode::OffChainOnly,
    );
    let mut tx_bytes = vec![];
    tx.consensus_serialize(&mut tx_bytes).unwrap();
    tx_bytes
}

pub fn make_poison(
    sender: &StacksPrivateKey,
    nonce: u64,
    tx_fee: u64,
    chain_id: u32,
    header_1: StacksMicroblockHeader,
    header_2: StacksMicroblockHeader,
) -> Vec<u8> {
    let payload = TransactionPayload::PoisonMicroblock(header_1, header_2);
    let tx = sign_standard_single_sig_tx(payload, sender, nonce, tx_fee, chain_id);
    let mut tx_bytes = vec![];
    tx.consensus_serialize(&mut tx_bytes).unwrap();
    tx_bytes
}

pub fn make_coinbase(sender: &StacksPrivateKey, nonce: u64, tx_fee: u64, chain_id: u32) -> Vec<u8> {
    let payload = TransactionPayload::Coinbase(CoinbasePayload([0; 32]), None, None);
    let tx = sign_standard_single_sig_tx(payload, sender, nonce, tx_fee, chain_id);
    let mut tx_bytes = vec![];
    tx.consensus_serialize(&mut tx_bytes).unwrap();
    tx_bytes
}

#[allow(clippy::too_many_arguments)]
pub fn make_contract_call(
    sender: &StacksPrivateKey,
    nonce: u64,
    tx_fee: u64,
    chain_id: u32,
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
        function_args: function_args.to_vec(),
    };

    let tx = sign_standard_single_sig_tx(payload.into(), sender, nonce, tx_fee, chain_id);
    let mut tx_bytes = vec![];
    tx.consensus_serialize(&mut tx_bytes).unwrap();
    tx_bytes
}

#[allow(clippy::too_many_arguments)]
pub fn make_contract_call_mblock_only(
    sender: &StacksPrivateKey,
    nonce: u64,
    tx_fee: u64,
    chain_id: u32,
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
        function_args: function_args.to_vec(),
    };

    let tx = sign_standard_single_sig_tx_anchor_mode(
        payload.into(),
        sender,
        nonce,
        tx_fee,
        chain_id,
        TransactionAnchorMode::OffChainOnly,
    );
    let mut tx_bytes = vec![];
    tx.consensus_serialize(&mut tx_bytes).unwrap();
    tx_bytes
}

pub fn make_microblock(
    privk: &StacksPrivateKey,
    chainstate: &mut StacksChainState,
    burn_dbconn: &dyn BurnStateDB,
    consensus_hash: ConsensusHash,
    block: StacksBlock,
    txs: Vec<StacksTransaction>,
) -> StacksMicroblock {
    let mut block_bytes = vec![];
    block.consensus_serialize(&mut block_bytes).unwrap();

    let mut microblock_builder = StacksMicroblockBuilder::new(
        block.block_hash(),
        consensus_hash,
        chainstate,
        burn_dbconn,
        BlockBuilderSettings::max_value(),
    )
    .unwrap();
    let mempool_txs: Vec<_> = txs
        .into_iter()
        .map(|tx| {
            // TODO: better fee estimation
            let mut tx_bytes = vec![];
            tx.consensus_serialize(&mut tx_bytes).unwrap();
            (tx, tx_bytes.len() as u64)
        })
        .collect();

    // NOTE: we intentionally do not check the block's microblock pubkey hash against the private
    // key, because we may need to test that microblocks get rejected due to bad signatures.
    microblock_builder
        .mine_next_microblock_from_txs(mempool_txs, privk)
        .unwrap()
}

pub fn insert_tx_in_mempool(
    db_tx: &rusqlite::Transaction,
    tx_hex: Vec<u8>,
    origin_addr: &StacksAddress,
    origin_nonce: u64,
    fee: u64,
    consensus_hash: &ConsensusHash,
    block_header_hash: &BlockHeaderHash,
    height: u64,
) {
    let sql = "INSERT OR REPLACE INTO mempool (
        txid,
        origin_address,
        origin_nonce,
        sponsor_address,
        sponsor_nonce,
        tx_fee,
        length,
        consensus_hash,
        block_header_hash,
        height,
        accept_time,
        tx,
        fee_rate)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)";

    let origin_addr_str = origin_addr.to_string();
    let length = tx_hex.len() as u64;
    let fee_rate = fee / length * 30;

    let txid = {
        let mut cursor = Cursor::new(&tx_hex);
        StacksTransaction::consensus_deserialize(&mut cursor)
            .expect("Failed to deserialize transaction")
            .txid()
    };
    let args = rusqlite::params![
        txid,
        origin_addr_str,
        origin_nonce,
        origin_addr_str,
        origin_nonce,
        fee,
        length,
        consensus_hash,
        block_header_hash,
        height,
        Utc::now().timestamp(),
        tx_hex,
        fee_rate
    ];
    db_tx
        .execute(sql, args)
        .expect("Failed to insert transaction into mempool");
}

/// Generate source code for a contract that exposes a public function
/// `big-tx`. This function uses `proportion` of read_count when called
pub fn make_big_read_count_contract(limit: ExecutionCost, proportion: u64) -> String {
    let read_count = (limit.read_count * proportion) / 100;

    let read_lines = (0..read_count)
        .map(|_| format!("(var-get my-var)"))
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        "
(define-data-var my-var uint u0)
(define-public (big-tx)
(begin
{}
(ok true)))
        ",
        read_lines
    )
}
